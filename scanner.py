import hashlib
import os
import shutil
import json
from datetime import datetime
from typing import List, Tuple

# Base directory for relative path resolution
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIGNATURES_FILE = os.path.join(BASE_DIR, "malware_signatures.txt")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
TEST_FOLDER = os.path.join(BASE_DIR, "test_files")


def calculate_sha256(file_path: str) -> str:
    """
    Calculates the SHA-256 hash of a given file.
    Reads the file in chunks to handle large files efficiently.
    
    Args:
        file_path (str): The absolute or relative path to the file.
        
    Returns:
        str: The SHA-256 hash string, or an error message if failed.
    """
    sha256_hash = hashlib.sha256()
    chunk_size = 65536  # 64 KB
    
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    except FileNotFoundError:
        return "Error: File not found. Please check the path."
    except PermissionError:
        return "Error: Permission denied to read the file."
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}"


def load_signatures() -> List[str]:
    """
    Loads malware signatures from a text file.
    Ignores empty lines, comments, and invalid hashes.
    
    Returns:
        List[str]: A list of valid SHA-256 malware signatures.
    """
    signatures = []
    
    try:
        with open(SIGNATURES_FILE, "r") as f:
            for line in f:
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    if len(clean_line) == 64 and all(c in '0123456789abcdefABCDEF' for c in clean_line):
                        signatures.append(clean_line.lower())
        return signatures
        
    except FileNotFoundError:
        print(f"[WARNING] Signature file not found at {SIGNATURES_FILE}")
        return []
    except Exception as e:
        print(f"[ERROR] Failed loading signatures: {e}")
        return []


def is_malicious(file_hash: str, signatures: List[str]) -> bool:
    """
    Checks if the calculated file hash matches any known malware signature.
    
    Args:
        file_hash (str): The SHA-256 hash of the target file.
        signatures (List[str]): The list of known malware hashes.
        
    Returns:
        bool: True if a match is found, False otherwise.
    """
    return file_hash in signatures


def quarantine_file(file_path: str) -> bool:
    """
    Moves a malicious file to the quarantine directory safely.
    Appends '.quarantined' to prevent accidental execution.
    
    Args:
        file_path (str): The path of the file to quarantine.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    filename = os.path.basename(file_path)
    # Add .quarantined suffix to neutralize the file
    destination = os.path.join(QUARANTINE_DIR, f"{filename}.quarantined")
    
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
            
        shutil.move(file_path, destination)
        print(f"Moved {filename} to quarantine (neutralized as .quarantined)")
        return True
        
    except Exception as e:
        print(f"[ERROR] Error quarantining {filename}: {e}")
        return False


def save_scan_history(total: int, safe: int, malicious: int, quarantined: int) -> None:
    """
    Saves the scan results to scan_history.json.
    Appends new records to the existing history.
    
    Args:
        total (int): Total files scanned.
        safe (int): Number of safe files.
        malicious (int): Number of malicious files found.
        quarantined (int): Number of files successfully quarantined.
    """
    new_record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files": total,
        "safe_files": safe,
        "malicious_files": malicious,
        "files_quarantined": quarantined
    }
    
    history_data = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history_data = json.load(f)
        except Exception:
            history_data = []
            
    history_data.append(new_record)
    
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history_data, f, indent=4)
        print("[INFO] Scan history saved successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to save scan history: {e}")


def generate_report(total: int, safe: int, malicious: int, quarantined: int, file_details: List[Tuple[str, str]]) -> None:
    """
    Generates a professional scan report and saves it to the reports folder.
    
    Args:
        total (int): Total files scanned.
        safe (int): Number of safe files.
        malicious (int): Number of malicious files.
        quarantined (int): Number of files quarantined.
        file_details (List[Tuple[str, str]]): List of tuples containing (filename, status).
    """
    try:
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
    except Exception as e:
        print(f"[ERROR] Failed to create reports directory: {e}")
        return
        
    timestamp_obj = datetime.now()
    timestamp_str = timestamp_obj.strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = timestamp_obj.strftime("%Y%m%d_%H%M%S")
    
    report_filename = f"scan_report_{file_timestamp}.txt"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
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


def scan_folder(folder_path: str, signatures: List[str]) -> None:
    """
    Scans a folder, calculating the hash of each file and checking for threats.
    Outputs a report of safe and malicious files.
    
    Args:
        folder_path (str): The directory to scan.
        signatures (List[str]): List of known malware signatures.
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
        if not os.path.exists(folder_path):
            print(f"[ERROR] Target folder not found: {folder_path}")
            return

        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            
            if os.path.isfile(file_path):
                total_scanned += 1
                file_hash = calculate_sha256(file_path)
                
                print(f"File: {filename}")
                
                # Check for errors in hashing (e.g. Permission errors)
                if file_hash.startswith("Error:"):
                    print(f"Status: ERROR ({file_hash})")
                    file_details.append((filename, "ERROR"))
                    print()
                    continue

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
        print(f"[ERROR] Error while scanning folder: {e}")

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
    print("=================================")
    print("LOADING MALWARE SIGNATURES")
    print("==========================")
    print()
    
    loaded_signatures = load_signatures()
    
    if not loaded_signatures:
        print("[WARNING] No malware signatures found.")
    else:
        print(f"Total Signatures Loaded: {len(loaded_signatures)}")
        
    print()
    scan_folder(TEST_FOLDER, loaded_signatures)
