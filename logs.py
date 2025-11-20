#log analyzer program 
import re
from collections import Counter

# Define the log file path
log_file_path = 'example.log'

# Define a regular expression pattern to parse log entries
# Example log format: "2024-05-17 10:15:30,123 - INFO - This is an info message"
log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (.*)')

# Initialize a counter for log levels
log_level_counter = Counter()

# Function to parse a log entry
def parse_log_entry(entry):
    match = log_pattern.match(entry)
    if match:
        timestamp, log_level, message = match.groups()
        return timestamp, log_level, message
    return None

# Read and analyze the log file
with open(log_file_path, 'r') as file:
    for line in file:
        parsed_entry = parse_log_entry(line)
        if parsed_entry:
            timestamp, log_level, message = parsed_entry
            log_level_counter[log_level] += 1

# Generate the report
print("Log Level Analysis:")
for log_level, count in log_level_counter.items():
    print(f"{log_level}: {count}")

# (Optional) Save the analysis to a file
with open('log_analysis_report.txt', 'w') as report_file:
    report_file.write("Log Level Analysis:\n")
    for log_level, count in log_level_counter.items():
        report_file.write(f"{log_level}: {count}\n")
