import hashlib
import os
import shutil
import json
from datetime import datetime

def calculate_sha256(file_path):
    """
    Calculates the SHA-256 hash of a given file.
    Reads the file in chunks to handle large files efficiently.
    """
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Define the chunk size (64 KB)
    chunk_size = 65536 
    
    try:
        # Open the file in binary mode for safe reading
        with open(file_path, "rb") as f:
            # Read the file chunk by chunk until it's empty
            for byte_block in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(byte_block)
                
        # Return the calculated hash as a hexadecimal string
        return sha256_hash.hexdigest()
        
    except FileNotFoundError:
        return "Error: File not found. Please check the path."
    except PermissionError:
        return "Error: Permission denied to read the file."
    except Exception as e:
        # Catch any other unexpected exceptions
        return f"Error: An unexpected error occurred: {e}"

def load_signatures():
    """
    Loads malware signatures from a text file.
    Ignores empty lines, comments, and invalid hashes.
    """
    signatures = []
    signatures_file = r"D:\Basic_Antivirus_Simulation_V2\malware_signatures.txt"
    
    try:
        with open(signatures_file, "r") as f:
            for line in f:
                clean_line = line.strip()
                
                # Ignore empty lines and comments
                if clean_line and not clean_line.startswith('#'):
                    # Check if it looks like a valid SHA-256 hash
                    if len(clean_line) == 64 and all(c in '0123456789abcdefABCDEF' for c in clean_line):
                        signatures.append(clean_line.lower())
                    
        return signatures
        
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error loading signatures: {e}")
        return []

def is_malicious(file_hash, signatures):
    """
    Checks if the calculated file hash matches any known malware signature.
    Returns True if a match is found, False otherwise.
    """
    if file_hash in signatures:
        return True
    return False

def quarantine_file(file_path):
    """
    Moves a malicious file to the quarantine directory safely.
    Preserves the original filename.
    """
    quarantine_dir = r"D:\Basic_Antivirus_Simulation_V2\quarantine"
    filename = os.path.basename(file_path)
    destination = os.path.join(quarantine_dir, filename)
    
    try:
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
            
        shutil.move(file_path, destination)
        print(f"Moved {filename} to quarantine")
        return True
        
    except Exception as e:
        print(f"Error quarantining {filename}: {e}")
        return False

def save_scan_history(total, safe, malicious, quarantined):
    """
    Saves the scan results to scan_history.json.
    Appends new records to the existing history.
    """
    history_file = r"D:\Basic_Antivirus_Simulation_V2\scan_history.json"
    
    # Create the new record
    new_record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files": total,
        "safe_files": safe,
        "malicious_files": malicious,
        "files_quarantined": quarantined
    }
    
    # Load existing history if the file exists
    history_data = []
    if os.path.exists(history_file):
        try:
            with open(history_file, "r") as f:
                history_data = json.load(f)
        except Exception:
            # If the file is corrupted or empty, start fresh
            history_data = []
            
    # Append the new record
    history_data.append(new_record)
    
    # Save back to the JSON file
    try:
        with open(history_file, "w") as f:
            json.dump(history_data, f, indent=4)
        print("[INFO] Scan history saved successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to save scan history: {e}")

def generate_report(total, safe, malicious, quarantined, file_details):
    """
    Generates a professional scan report and saves it to the reports folder.
    """
    reports_dir = r"D:\Basic_Antivirus_Simulation_V2\reports"
    
    # Create reports directory if it doesn't exist
    try:
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
    except Exception as e:
        print(f"[ERROR] Failed to create reports directory: {e}")
        return
        
    timestamp_obj = datetime.now()
    timestamp_str = timestamp_obj.strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = timestamp_obj.strftime("%Y%m%d_%H%M%S")
    
    report_filename = f"scan_report_{file_timestamp}.txt"
    report_path = os.path.join(reports_dir, report_filename)
    
    try:
        with open(report_path, "w") as f:
            f.write("=================================\n")
            f.write("BASIC ANTIVIRUS SIMULATION REPORT\n")
            f.write("=================================\n\n")
            f.write(f"Timestamp: {timestamp_str}\n\n")
            
            f.write("## SCAN SUMMARY\n\n")
            f.write(f"Total Files Scanned: {total}\n")
            f.write(f"Safe Files: {safe}\n")
            f.write(f"Malicious Files: {malicious}\n")
            f.write(f"Files Quarantined: {quarantined}\n\n")
            
            f.write("## FILE DETAILS\n\n")
            for filename, status in file_details:
                f.write(f"Filename: {filename}\n")
                f.write(f"Status: {status}\n\n")
                
            f.write("=================================\n")
            
        print("[INFO] Report generated successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to generate report: {e}")

def scan_folder(folder_path, signatures):
    """
    Scans a folder, calculating the hash of each file and checking for threats.
    Outputs a report of safe and malicious files.
    """
    total_scanned = 0
    safe_files = 0
    malicious_files = 0
    quarantined_files = 0

    print("=================================")
    print("SCAN RESULTS")
    print("============")
    print()

    to_quarantine = []
    file_details = []

    try:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            
            if os.path.isfile(file_path):
                total_scanned += 1
                file_hash = calculate_sha256(file_path)
                
                print(f"File: {filename}")
                
                if is_malicious(file_hash, signatures):
                    print("Status: MALICIOUS")
                    malicious_files += 1
                    to_quarantine.append(file_path)
                    file_details.append((filename, "MALICIOUS"))
                else:
                    print("Status: SAFE")
                    safe_files += 1
                    file_details.append((filename, "SAFE"))
                print()
                
        if to_quarantine:
            print("=================================")
            print("QUARANTINE ACTION")
            print("=================")
            print()
            for file_path in to_quarantine:
                if quarantine_file(file_path):
                    quarantined_files += 1
            print()
            
    except Exception as e:
        print(f"Error while scanning folder: {e}")

    print("=================================")
    print("SCAN SUMMARY")
    print("============")
    print()
    print(f"Total Files: {total_scanned}")
    print(f"Safe Files: {safe_files}")
    print(f"Malicious Files: {malicious_files}")
    print(f"Files Quarantined: {quarantined_files}")
    print("==================")
    print()
    
    # Save scan history
    save_scan_history(total_scanned, safe_files, malicious_files, quarantined_files)
    
    # Generate report
    generate_report(total_scanned, safe_files, malicious_files, quarantined_files, file_details)

if __name__ == "__main__":
    suspicious_file = r"D:\Basic_Antivirus_Simulation_V2\test_files\suspicious_file.txt"
    try:
        suspicious_hash = calculate_sha256(suspicious_file)
        if "Error" not in suspicious_hash:
            print("=================================")
            print(f"Hash of suspicious_file.txt:")
            print(f"{suspicious_hash}")
            print("Copy this hash into malware_signatures.txt to detect it as malicious.")
            print("=================================")
            print()
    except Exception:
        pass

    print("=================================")
    print("LOADING MALWARE SIGNATURES")
    print("=================================")
    print()
    
    loaded_signatures = load_signatures()
    
    if not loaded_signatures:
        print("[WARNING] No malware signatures found.")
    else:
        print(f"Total Signatures Loaded: {len(loaded_signatures)}")
        
    print()
    
    test_folder = r"D:\Basic_Antivirus_Simulation_V2\test_files"
    scan_folder(test_folder, loaded_signatures)
