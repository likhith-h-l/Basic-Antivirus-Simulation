import os
import json
import sys
from datetime import datetime
from typing import Dict, Any, List

# Local imports
from scanner import calculate_sha256

# Define relative paths dynamically
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(BASE_DIR, "baseline.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
TEST_FOLDER = os.path.join(BASE_DIR, "test_files")


def create_baseline(folder_path: str = TEST_FOLDER) -> None:
    """
    Creates a new baseline of file hashes for the specified folder.
    Saves the baseline data to baseline.json.
    
    Args:
        folder_path (str): The directory to baseline.
    """
    baseline_data = {}
    
    print("=================================")
    print("CREATING INTEGRITY BASELINE")
    print("===========================")
    
    try:
        if not os.path.exists(folder_path):
            print(f"[ERROR] Target folder not found: {folder_path}")
            return

        # Loop through all files in the test folder
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            
            # Ensure we only hash files
            if os.path.isfile(file_path):
                file_hash = calculate_sha256(file_path)
                
                # Store the absolute path with its hash and timestamp
                baseline_data[file_path] = {
                    "hash": file_hash,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
        # Save to baseline.json
        with open(BASELINE_FILE, "w", encoding='utf-8') as f:
            json.dump(baseline_data, f, indent=4)
            
        print(f"[INFO] Baseline created successfully. Tracked {len(baseline_data)} files.")
    except Exception as e:
        print(f"[ERROR] Failed to create baseline: {e}")
        
    print("=================================\n")


def load_baseline() -> Dict[str, Any]:
    """
    Loads the existing baseline from baseline.json.
    
    Returns:
        Dict[str, Any]: The baseline dictionary, or an empty dictionary if not found.
    """
    if not os.path.exists(BASELINE_FILE):
        print(f"[WARNING] Baseline file not found at {BASELINE_FILE}.")
        return {}
        
    try:
        with open(BASELINE_FILE, "r", encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load baseline: {e}")
        return {}


def scan_integrity(folder_path: str = TEST_FOLDER) -> None:
    """
    Scans the folder and compares it against the loaded baseline.
    Detects modified, deleted, and newly created files.
    
    Args:
        folder_path (str): The directory to scan.
    """
    baseline = load_baseline()
    if not baseline:
        print("[ERROR] Cannot run integrity scan without a valid baseline.")
        return
        
    modified_files = []
    deleted_files = []
    new_files = []
    safe_files = []
    
    current_files = []
    
    # 1. Check for New and Modified files
    try:
        if not os.path.exists(folder_path):
            print(f"[ERROR] Target folder not found: {folder_path}")
            return

        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            
            if os.path.isfile(file_path):
                current_files.append(file_path)
                file_hash = calculate_sha256(file_path)
                
                if file_path in baseline:
                    # Compare the hashes
                    if baseline[file_path]["hash"] != file_hash:
                        modified_files.append(filename)
                    else:
                        safe_files.append(filename)
                else:
                    # File wasn't in baseline, therefore it's new
                    new_files.append(filename)
    except Exception as e:
        print(f"[ERROR] Failed during directory scan: {e}")
        return
        
    # 2. Check for Deleted files
    # Any file in the baseline that isn't in current_files was deleted
    for baseline_file in baseline.keys():
        if baseline_file not in current_files:
            deleted_files.append(os.path.basename(baseline_file))
            
    # Output the results of the scan
    print("=================================")
    print("FILE INTEGRITY SCAN")
    print("===================")
    print()
    
    print(f"Modified Files: {len(modified_files)}")
    for f in modified_files:
        print(f"  - {f}")
        
    print(f"Deleted Files: {len(deleted_files)}")
    for f in deleted_files:
        print(f"  - {f}")
        
    print(f"New Files: {len(new_files)}")
    for f in new_files:
        print(f"  - {f}")
        
    print(f"Safe Files: {len(safe_files)}")
    print()
    print("=================================")
    
    # Generate the professional FIM report
    generate_integrity_report(modified_files, deleted_files, new_files, safe_files)


def generate_integrity_report(modified: List[str], deleted: List[str], new_f: List[str], safe: List[str]) -> None:
    """
    Generates a professional integrity report and saves it to the reports folder.
    
    Args:
        modified (List[str]): List of modified filenames.
        deleted (List[str]): List of deleted filenames.
        new_f (List[str]): List of newly created filenames.
        safe (List[str]): List of unchanged filenames.
    """
    try:
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
            
        timestamp_obj = datetime.now()
        timestamp_str = timestamp_obj.strftime("%Y-%m-%d %H:%M:%S")
        file_timestamp = timestamp_obj.strftime("%Y%m%d_%H%M%S")
        
        report_filename = f"integrity_report_{file_timestamp}.txt"
        report_path = os.path.join(REPORTS_DIR, report_filename)
        
        with open(report_path, "w", encoding='utf-8') as f:
            f.write("=================================\n")
            f.write("FILE INTEGRITY MONITORING REPORT\n")
            f.write("=================================\n\n")
            f.write(f"Timestamp: {timestamp_str}\n\n")
            
            f.write("## SUMMARY\n\n")
            f.write(f"Modified Files: {len(modified)}\n")
            f.write(f"Deleted Files: {len(deleted)}\n")
            f.write(f"New Files: {len(new_f)}\n")
            f.write(f"Safe Files: {len(safe)}\n\n")
            
            f.write("## DETAILS\n\n")
            
            if modified:
                f.write("Modified Files:\n")
                for item in modified:
                    f.write(f"  - {item}\n")
                f.write("\n")
                
            if deleted:
                f.write("Deleted Files:\n")
                for item in deleted:
                    f.write(f"  - {item}\n")
                f.write("\n")
                
            if new_f:
                f.write("New Files:\n")
                for item in new_f:
                    f.write(f"  - {item}\n")
                f.write("\n")
                
            f.write("=================================\n")
            
        print(f"[INFO] Integrity report generated successfully: {report_filename}")
    except Exception as e:
        print(f"[ERROR] Failed to generate integrity report: {e}")


if __name__ == "__main__":
    # Check command-line arguments to determine what action to take
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        scan_integrity()
    else:
        create_baseline()
        print("To scan for changes, run the script with the 'scan' argument:")
        print("python integrity_monitor.py scan")
