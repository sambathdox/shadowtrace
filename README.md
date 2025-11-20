# 🛡️ **Shadowtrace – Log Analyzer with SIEM Tool Integration**

Shadowtrace is a simple and powerful Python log analysis tool that helps cybersecurity professionals and system administrators detect anomalies in log files, visualize activities, and export data for further analysis.  
It supports multiple log formats and integrates smoothly with Elasticsearch.

---

## 📚 **Table of Contents**
- [ℹ️ About](#about)
- [✨ Features](#features)
- [🧩 Requirements](#requirements)
- [⚙️ Installation](#installation)
- [🚀 Usage](#usage)
- [📄 License](#license)

---

## ℹ️ **About**

**Shadowtrace** is a Python-based tool that processes various log formats such as **Zeek**, **EVTX**, **SMB**, **DNS**, and **SSH**.  
It helps detect potential threats like ransomware activity, beaconing patterns, and rootkit behavior.  
The tool can also generate SMB activity visualizations and export SSH logs to Elasticsearch for SIEM-level analysis.

---

## ✨ **Features**

- 📄 **Log Parsing**: Supports Zeek, EVTX, SMB, DNS, and SSH logs.
- 🦠 **Malware Detection**:
  - Detects ransomware-like behavior in SMB logs.
  - Identifies rootkit-like activity through EVTX logs.
- 📡 **Beacon Detection**: Analyzes Zeek HTTP and connection logs to spot beaconing behavior.
- 📊 **SMB Activity Visualization**: Generates simple bar charts for analyzing SMB trends.
- 🔎 **Elasticsearch Integration**: Export SSH log data to Elasticsearch for deeper searching and visualization.
- 💻 **Command-Line Interface**: Easy-to-use, menu-based interface.

---

## 🧩 **Requirements**

To run this project, you will need:

- Python **3.7 or later**
- Required Python packages:
  - `Evtx`
  - `matplotlib`
  - `elasticsearch`
  - `pyfiglet`
    
These dependencies are listed in the `requirements.txt` file, which can be installed using `pip`.

---

## ⚙️ **Installation**

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/sambathdox/shadowtrace.git
   cd shadowtrace

   ```
2.Install the required Dependence: 
```bash
pip install -r requirements.txt
```
3.Ensure Elasticsearch is running on http://localhost:9200 for exporting SSH logs.

---

## 🚀  **Usage**
Run the tool by executing the following command in your terminal:

```bash
python log_analyzer.py
```
### 🧭 **Main Menu Options**

- 🛡️ **Detect Malicious Rootkit**
- 📡 **Detect Beacons**
- 🦠 **Detect Ransomware Activity**
- 📊 **SMB Activity Timeline Analysis**
- 🔎 **Export SSH Logs to Elasticsearch**
- ❌ **Exit**

---

## 📝 **Final Notes**

Shadowtrace is a small project built to make log analysis easier for learners and professionals.  
Feel free to explore, modify, or extend the tool based on your needs.

If you find any bugs or have ideas for improvements, contributions are always welcome.  
Thank you for checking out Shadowtrace!

---


## **License**
This project is licensed under the MIT License. See the LICENSE file for more information.
