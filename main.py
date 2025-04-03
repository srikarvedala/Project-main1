import sqlite3
import hashlib
import os
import time
import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Function to calculate file hash
def get_file_hash(filename):
    hasher = hashlib.md5()
    with open(filename, "rb") as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Function to scan a file using YARA rules
def scan_with_yara(filename):
    rules = yara.compile(filepath="malware_rules.yar")
    matches = rules.match(filename)
    return matches

# Function to scan a file and check against the database
def scan_file(filename):
    if not os.path.exists(filename):
        print(f"❌ Error: File '{filename}' not found.")
        return

    file_hash = get_file_hash(filename)
    file_path = os.path.abspath(filename)
    print(f"\n🔍 Scanning file: {file_path}")
    print(f"🔍 Calculated Hash: {file_hash}")

    # YARA scan
    yara_match = scan_with_yara(filename)
    if yara_match:
        print(f"⚠️ YARA Alert: Suspicious file detected! {yara_match}")

    # Connect to the database
    conn = sqlite3.connect("malware_signatures.db")
    cursor = conn.cursor()

    # Check if the file hash is already in the database
    cursor.execute("SELECT malware_name FROM signatures WHERE hash=?", (file_hash,))
    result = cursor.fetchone()

    if result:
        print(f"\n🚨 WARNING: Malware Detected! ({result[0]})")
    else:
        print("\n⚠️ New file detected. No match found in database.")

        # Ask user for malware name (since it's a new threat)
        malware_name = input("Enter malware name to store: ")

        # Insert new signature into database
        cursor.execute('''
            INSERT INTO signatures (malware_name, hash, file_path)
            VALUES (?, ?, ?)
        ''', (malware_name, file_hash, file_path))

        conn.commit()
        print("✅ New malware signature added to database.")

    conn.close()

# File system event handler to monitor a folder
class MalwareMonitor(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"\n📂 New file detected: {event.src_path}")
            scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"\n🔄 File modified: {event.src_path}")
            scan_file(event.src_path)

# Start monitoring a folder for new files
def start_monitoring(folder_path):
    observer = Observer()
    event_handler = MalwareMonitor()
    observer.schedule(event_handler, folder_path, recursive=False)
    observer.start()
    print(f"👀 Monitoring folder: {folder_path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Run the monitoring system
monitor_folder = "./watched_folder"
os.makedirs(monitor_folder, exist_ok=True)  # Ensure folder exists
start_monitoring(monitor_folder)
