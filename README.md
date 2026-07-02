# Basic Antivirus Simulation V2

A modern, professional desktop application simulating signature-based antivirus scanning and file integrity monitoring (FIM). Inspired by industry standards like Microsoft Defender and CrowdStrike Falcon, this simulation offers a full-featured graphical user dashboard alongside background automation to secure a mock test environment.

---

## Project Overview

In the cybersecurity landscape, **Signature-based Antivirus** solutions identify malicious software by comparing the unique structural characteristics of a file (its cryptographic fingerprint) against a database of known threat signatures. If a file's hash matches an entry in the signature database, it is flagged as a threat.

This project implements a complete pipeline demonstrating these concepts, including SHA-256 fingerprint generation, signature matching, automated threat isolation (quarantining), historical logs tracking, file integrity verification (baselining), and visual reporting.

---

## Objective

The objective of this simulation is to demonstrate security protection mechanisms on a mock target environment (`test_files/`). It accomplishes this by:
1. **Scanning Directories:** Reading target folders recursively.
2. **Generating Cryptographic Fingerprints:** Safely calculating SHA-256 hashes of files.
3. **Database Lookups:** Cross-referencing computed hashes against a flat-file database of known threat hashes.
4. **Threat Isolation (Quarantining):** Automatically moving infected items to a secure folder to prevent further execution.
5. **FIM Integrity Checking:** Tracking unauthorized creation, deletion, or modifications of files against a trusted baseline snapshot.
6. **Information Logging:** Storing scan history and generating audit reports.

---

## Features

- **SHA-256 Cryptographic Hashing:** Reads target files in 64KB blocks to generate safe, memory-efficient SHA-256 signatures.
- **Malware Signature Database:** A hash-only signature file ignoring comments, whitespace, or invalid keys.
- **Threat Detection Engine:** Cross-references file signatures with the database instantly.
- **Automated Quarantine:** Automatically relocates malicious files to a quarantine folder using `shutil.move` with full collision handling.
- **Scan History Logging:** Saves results and logs metrics to a JSON database with timestamped entries.
- **Professional Reports Generator:** Outputs detailed txt logs for every scan and integrity run.
- **File Integrity Monitoring (FIM):** Compares live files against a JSON baseline, reporting newly created, modified, or deleted files.
- **Modern CustomTkinter GUI Dashboard:** Features a dark slate responsive interface (`1400x800`) with:
  - Metric summary cards
  - Dynamic system health indicator
  - Real-time progress bar animation
  - Multi-threaded operations keeping the interface highly responsive
  - Inline reports viewer and historical log layout

---

## Project Architecture

- **`scanner.py`**: The backend engine implementing SHA-256 hashing, signature loading, malware scan operations, automatic quarantine moving, and history logging.
- **`integrity_monitor.py`**: Implements the File Integrity Monitoring (FIM) backend, managing trusted baseline generation and delta scanning.
- **`gui.py`**: The CustomTkinter graphical dashboard that orchestrates the simulation. It launches backend actions asynchronously on background worker threads.
- **`malware_signatures.txt`**: The signature database containing SHA-256 hashes of known malicious files.
- **`scan_history.json`**: An incremental log record storing scan metrics (total files, safe files, threats, quarantined) over time.
- **`baseline.json`**: A trusted database snapshot of the target directory containing trusted file paths, hashes, and baseline generation timestamps.
- **`reports/`**: Destination directory for all generated scan and integrity logs.
- **`quarantine/`**: Destination directory where detected malicious files are securely isolated.
- **`test_files/`**: The target directory acting as the simulated user environment containing clean and suspicious files.

---

## Technologies Used

- **Python:** The core scripting language.
- **CustomTkinter:** Modern UI design package built on Tkinter.
- **JSON:** Formatting and storage for baseline snapshots and historical scan logs.
- **SHA-256 Cryptographic Hashing:** Used to uniquely identify file content.
- **Python Subprocesses & Threading:** Used to execute backend modules asynchronously to prevent GUI lockups.
- **File Handling & Standard Libraries:** Utilized (`shutil`, `os`, `hashlib`, `sys`, `datetime`) for filesystem operations.

---

## Installation

1. **Clone or Download the Project:**
   Download the source folder and make sure it is placed in:
   ```text
   D:\Basic_Antivirus_Simulation_V2
   ```

2. **Navigate to the Project Folder:**
   Open a terminal (e.g. PowerShell) and change directory:
   ```powershell
   cd D:\Basic_Antivirus_Simulation_V2
   ```

3. **Install Dependencies:**
   A virtual environment is bundled or can be configured. Install CustomTkinter using:
   ```powershell
   # If using the provided virtual environment
   .venv\Scripts\pip install -r requirements.txt
   
   # Or install via system pip
   pip install customtkinter
   ```

4. **Run the Application:**
   Start the desktop GUI:
   ```powershell
   python gui.py
   ```

---

## Usage

### 🔍 Running Malware Scans
1. In the sidebar, click **Malware Scan**.
2. The tab will automatically switch to **Scan Results**, pulsing the blue progress bar while running.
3. Once completed, a completion alert will show. The console box will list files scanned and indicate whether they are `SAFE` or `MALICIOUS` (and if they were moved to `quarantine/`).

### ➕ Creating Baseline
1. In the sidebar, click **Create Baseline**.
2. This captures a snapshot of the current state of files inside the `test_files/` folder and saves their SHA-256 hashes into `baseline.json`.

### 🔄 Running Integrity Scans
1. In the sidebar, click **Integrity Scan**.
2. It compares the live filesystem against the trusted baseline snapshot and reports any Modified, Deleted, or New files.
3. Check the **Reports** or **Dashboard** tabs to view the summarized delta alert metrics.

### 📁 Viewing Reports
1. In the sidebar, click **Reports** (or click the **Reports** tab directly).
2. Click on any report log in the left panel list. The content of the report will render instantly in the inline reader on the right.

### 📜 Viewing Scan History
1. In the sidebar, click **Scan History** (or click the **History** tab).
2. Review the list of historic runs, noting timestamps, files scanned, and if threats were found.

---

## Sample Workflow

1. A suspicious file is dropped into `test_files/`, e.g., `suspicious_file.txt`.
2. A malware signature scan is initiated.
3. The engine hashes the file and checks its SHA-256 against `malware_signatures.txt`.
4. If a match is found:
   - The file is flagged as `MALICIOUS`.
   - The engine calls `shutil.move()` to relocate the file into the `quarantine/` directory, removing it from `test_files/`.
   - The UI dashboard automatically increments the **Threats Detected** and **Files Quarantined** counts.
   - A txt report is written to `reports/` and the scan history log is updated.

---

## Screenshots Section

> [!NOTE]
> Below are placeholders for visual documentation of the desktop client interface.

### Dashboard Screenshot
![Dashboard Screen](https://placehold.co/1400x800/1e293b/ffffff?text=Dashboard+Overview+Card+Grid)

### Malware Scan Screenshot
![Malware Scan Screen](https://placehold.co/1400x800/1e293b/ffffff?text=Malware+Scan+Results+Console)

### Integrity Scan Screenshot
![Integrity Scan Screen](https://placehold.co/1400x800/1e293b/ffffff?text=FIM+Integrity+Scan+Report+Logs)

### Reports Screenshot
![Reports Screen](https://placehold.co/1400x800/1e293b/ffffff?text=Interactive+Reports+File+Viewer)

---

## Learning Outcomes

By building and working with this simulation, several core cybersecurity concepts are demonstrated:
- **Cryptographic Hashing:** Learning how hashing converts variable-length input data into a fixed-size unique key (SHA-256) used for file verification.
- **Malware Signature Matching:** Understanding how antivirus solutions perform static analysis and fast fingerprint database lookups to identify known bad files.
- **Isolation/Quarantine Management:** Implementing safe threat mitigations by moving files to an isolated directory and modifying execution scopes.
- **File Integrity Monitoring (FIM):** Tracking drift, configurations, and baseline states to verify system configuration and detect potential tampering.

---

## Future Enhancements

- **Real-Time Monitoring:** Utilizing filesystem watchdogs (`watchdog` library) to automatically trigger scans as soon as a new file is created or modified.
- **YARA Rule Support:** Integrating YARA rules for advanced, pattern-matching classification of threat files beyond basic hashing.
- **VirusTotal API Integration:** Querying the VirusTotal API to cross-reference hash metrics with dozens of cloud antivirus engines.
- **Email Alerts:** Automatically sending email notifications to sysadmins when threats or integrity baseline violations occur.
- **Cloud Dashboard:** Syncing local scan metrics and reports to a centralized web monitoring dashboard.

---

## Author

- **Name:** Likhith H L
- **Program:** B.E. CSE (IoT, Cybersecurity including Blockchain Technology)
- **College:** Alva's Institute of Engineering and Technology
