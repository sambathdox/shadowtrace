import re
import Evtx.Evtx as evtx 
from datetime import datetime as dt, timezone
from collections import Counter
from operator import itemgetter
import matplotlib.pyplot as plt
from elasticsearch import Elasticsearch
import pyfiglet


# Function to print the banner
def print_banner():
    banner = pyfiglet.figlet_format("Sh@d0wTrace", font="big")
    print(banner)
    author = "Author - Sambath T"
    print(author.rjust(80))  # Right-align if needed


# Call the function to display the banners
print_banner()


# Function to read log files
def openLogFile(path):
    with open(path) as logfile:
        for log_entry in logfile:
            yield log_entry


# Function to read EVTX files
def openEvtxFile(path):
    with evtx.Evtx(path) as log_file:
        for log_entry in log_file.records():
            yield log_entry.lxml()


# Parsing functions for various log formats
def parseZeekConn(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["timestamp"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[1]
    r["source_ip"] = log_data[2]
    r["source_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["destination_port"] = log_data[5]
    r["protocol"] = log_data[6]
    r["service"] = log_data[7]
    r["duration"] = log_data[8]
    r["srcbytes"] = log_data[9]
    r["dst_bytes"] = log_data[10]
    r["conn_state"] = log_data[11]
    r["local_src"] = log_data[12]
    r["local_rsp"] = log_data[13]
    r["missed_bytes"] = log_data[14]
    r["history"] = log_data[15]
    r["srk_pkts"] = log_data[16]
    r["src_ip_bytes"] = log_data[17]
    r["dst_pkts"] = log_data[18]
    r["dst_ip_bytes"] = log_data[19]
    r["tunnel_parents"] = log_data[20]
    return r


def parseEvtx(event):
    sys_tag = event.find("System", event.nsmap)
    event_id = sys_tag.find("EventID", event.nsmap)
    event_ts = sys_tag.find("TimeCreated", event.nsmap)
    event_data = event.find("EventData", event.nsmap)
    r = {}
    r["ts"] = event_ts.values()[0]
    r["eid"] = event_id.text
    for data in event_data.getchildren():
        r[data.attrib["Name"]] = data.text
    return r


def parseSmb(log_entry):
    pattern = r"^(?P<timestamp>[0-9]{2}:[0-9]{2}:[0-9]{2})\s:\s(?P<client_hostname>[a-zA-Z0-9\-]+)\|(?P<client_ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\|(?P<share>[a-zA-Z0-9\-]+)\|(?P<operation>[a-zA-Z]+)\|ok\|(?P<path>.*)$"
    log_data = re.search(pattern, log_entry)
    r = log_data.groupdict()
    r['timestamp'] = dt.strptime(r['timestamp'], "%H:%M:%S")
    if r['operation'] == 'rename':
        r['path'] = r['path'].split("|")[-1]
    return r
def parseZeekHttp(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["ts"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[1]
    r["src_ip"] = log_data[2]
    r["src_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["dst_port"] = log_data[5]
    r["trans_depth"] = log_data[6]
    r["methods"] = log_data[7]
    r["host"] = log_data[8]
    r["uri"] = log_data[9]
    r["referrer"] = log_data[10]
    r["version"] = log_data[11]
    r["user_agent"] = log_data[12]
    r["origin"] = log_data[13]
    r["request_body_len"] = log_data[14]
    r["response_body_len"] = log_data[15]
    r["status_code"] = log_data[16]
    r["status_msg"] = log_data[17]
    r["info_code"] = log_data[18]
    r["info_msg"] = log_data[19]
    r["tags"] = log_data[20]
    r["username"] = log_data[21]
    r["password"] = log_data[22]
    r["proxied"] = log_data[23]
    r["src_fuids"] = log_data[24]
    r["src_filenames"] = log_data[25]
    r["src_mime_types"] = log_data[26]
    r["dst_fuids"] = log_data[27]
    r["dst_filenames"] = log_data[28]
    r["dst_mime_types"] = log_data[29]
    return r



def parseAuth(log_entry):
    log_data = re.search(
        # Jul 28 18:02:26
        r"^(?P<ts>\w{3}\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})" +
        # hostname-01
        r"\s(?P<host>[\w\-]+)" +
        # sshd[5577]:
        r"\s(sshd\[\d{1,6}\]):" +
        # Failed password for[ invalid user]
        r"\s(?P<action>Failed|Accepted) password for(\s(?P<invalid>invalid user))?" +
        # root
        r"\s(?P<user>[^\s]+)" +
        r"\s(from)" +
        # 127.0.0.1
        r"\s(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})" +
        # port 51106 ssh2
        r".*$", log_entry)

    r = log_data.groupdict()
    r['ts'] = dt.strptime(r['ts'], r"%b %d %H:%M:%S")
    r['ts'] = r['ts'].replace(year=dt.now().year)
    return r


# Function to detect Rundll32 usage
def detectRundll32(path):
    log_file = openEvtxFile(path)
    for log_entry in log_file:
        try:
            log_data = parseEvtx(log_entry)
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd",
                                                                          log_data["ParentProcessName"]):
                    print(log_data["CommandLine"])
        except:
            pass


# Function to get HTTP requests by UID
def gethttpbyuid(path):
    r = Counter()
    log_file = openLogFile(path)
    for log_entry in log_file:
        try:
            log_data = parseZeekHttp(log_entry)
            r.update([log_data['uid']])
        except:
            pass
    return r


# Function to detect beacons
def detectbeacons(conn_path, http_path):
    req = gethttpbyuid(http_path)
    conn_log = openLogFile(conn_path)
    beacons = []
    for log_entry in conn_log:
        try:
            log_data = parseZeekConn(log_entry)
            if log_data['service'] == "http":
                log_data['requests'] = req[log_data['uid']]
                beacons.append(log_data)
        except:
            pass
    beacons.sort(key=itemgetter("requests"), reverse=True)
    header = "{:20}\t{:5}\t{:5}".format("Dst. IP", "Duration", "Requests")
    print(header)
    print("-" * len(header))
    for entry in beacons[:8]:
        print("{:20}\t{:5}\t{:5}".format(entry['dst_ip'], entry['duration'], entry['requests']))


# Function to plot a bar chart
def plotBarChart(events, users):
    plt.subplot(211)
    plt.bar(range(len(events)), list(events.values()), align="center")
    plt.xticks(range(len(events)), list(events.keys()))
    plt.subplot(212)
    plt.bar(range(len(users)), list(users.values()), align="center")
    plt.xticks(range(len(users)), list(users.keys()))
    plt.show()


# Function to get the base timestamp
def getBaseTs(ts, interval):
    # divide an hour into the interval number of sections
    interval = int(60 / interval)
    hours = ts.time().hour
    minutes = ts.time().minute
    base_minutes = int(minutes / interval) * interval
    return "{}:{}".format(hours, base_minutes)


# Function to plot SMB activity
def plotSmbActivity(path):
    """
    Reads SMB logs, aggregates activity by time intervals, and generates a bar chart.
    Args:
        path (str): Path to the SMB log file.
    """
    log_file = openLogFile(path)
    users = Counter()  # Counts activities per user
    events = Counter()  # Counts activities by timestamp

    # Process each log entry
    for log_entry in log_file:
        try:
            log_data = parseSmb(log_entry)  # Parse SMB log entry
            if log_data:  # Ensure valid parsed data
                users.update([log_data['client_hostname']])  # Count by user
                ts = getBaseTs(log_data['timestamp'], 4)  # Aggregate timestamp by 15-min intervals
                events.update([ts])  # Count events by time interval
        except Exception as e:
            print(f"Error processing log entry: {e}")

    # Check if data is available for plotting
    if not events or not users:
        print("No valid SMB activity data found for plotting.")
        return

    # Generate the bar chart
    try:
        plt.figure(figsize=(10, 6))  # Set figure size
        plt.subplot(211)  # Top subplot for event trends
        plt.bar(range(len(events)), list(events.values()), align="center", color="blue")
        plt.xticks(range(len(events)), list(events.keys()), rotation=45)
        plt.title("SMB Events Over Time")
        plt.ylabel("Event Count")

        plt.subplot(212)  # Bottom subplot for user activity
        plt.bar(range(len(users)), list(users.values()), align="center", color="green")
        plt.xticks(range(len(users)), list(users.keys()), rotation=45)
        plt.title("SMB Activity by User")
        plt.ylabel("Activity Count")

        plt.tight_layout()  # Adjust layout to avoid overlap
        plt.savefig("smb_activity_plot.png")  # Save plot as an image
        print("Plot saved as 'smb_activity_plot.png'.")
    except Exception as e:
        print(f"Error generating plot: {e}")



def parseSmb(log_entry):
    pattern = r"^(?P<timestamp>[0-9]{2}:[0-9]{2}:[0-9]{2})\s:\s(?P<client_hostname>[a-zA-Z0-9\-]+)\|(?P<client_ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\|(?P<share>[a-zA-Z0-9\-]+)\|(?P<operation>[a-zA-Z]+)\|ok\|(?P<path>.*)$"
    log_data = re.search(pattern, log_entry)

    if log_data:  # Check if log_data is not None
        r = log_data.groupdict()
        r['timestamp'] = dt.strptime(r['timestamp'], "%H:%M:%S")
        if r['operation'] == 'rename':
            r['path'] = r['path'].split("|")[-1]
        return r
    else:
        return None  # Return None if the log entry doesn't match the pattern


# Function to alert ransomware activity and write to a file
import re
from datetime import datetime as dt, timezone


def ransomwareAlert(path="logs/smb.log"):
        # Pattern to detect common ransomware extensions in file paths (case-insensitive)
        ext_re = r"\.encrypted|\.locked|\.wncry"
        ransomware_count = 0  # Counter for the number of ransomware activities detected
        # Open the SMB log file
        try:
            smb_log = openLogFile(path)
        except Exception as e:
            print(f"Error opening log file: {e}")
            return
        # Process each log entry
        for log_entry in smb_log:
            try:
                # Parse the log entry
                log_data = parseSmb(log_entry)
                # Check if log_data is valid and matches ransomware extensions
                if log_data and re.search(ext_re, log_data['path'], re.IGNORECASE):
                    ransomware_count += 1
                    print(f"Ransomware activity detected #{ransomware_count}:")
                    print(f"Client Name  : {log_data['client_hostname']}")
                    print(f"Client IP    : {log_data['client_ip']}")
                    print(f"Share        : {log_data['share']}")
                    print(f"Operation    : {log_data['operation']}")
                    print(f"Path         : {log_data['path']}\n")
            except Exception as e:
                print(f"Error processing log entry: {e}")
        # Display the total count of ransomware activities detected
        print(f"Total number of ransomware activities detected: {ransomware_count}")

# Function to export SSH activity to Elasticsearch
def exportSshActivity(path="logs/auth.log"):
    es = Elasticsearch("http://localhost:9200")
    log_file = openLogFile(path)
    for log_entry in log_file:
        try:
            log_data = parseAuth(log_entry)
            es.index(index="auth", document=log_data)
        except:
            pass


# Function to display the menu and execute the selected function
def main():
    while True:
        print("\nSelect an option:")
        print("1. Detect Malicious rootkit ")
        print("2. Detect Beacons")
        print("3. Detect Ransomware Activity")
        print("4. Timeline analysis SMB Activity")
        print("5. Elasticsearch analyze")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            path = input("Enter the path to the EVTX file: ")
            detectRundll32(path)
        elif choice == "2":
            conn_path = input("Enter the path to the connection log file: ")
            http_path = input("Enter the path to the HTTP log file: ")
            detectbeacons(conn_path, http_path)
        elif choice == "3":
            path = input("Enter the path to the SMB log file: ")
            ransomwareAlert(path)
        elif choice == "4":
            path = input("Enter the path to the SMB log file: ")
            plotSmbActivity(path)
        elif choice == "5":
            path = input("Enter the path to the SSH auth log file: ")
            exportSshActivity(path)
        elif choice == "6":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()