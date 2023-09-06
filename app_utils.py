import logging
import csv
import json
import datetime
import tkinter as tk
from tkinter import filedialog

headers_map = {
    "IP": ['ip', 'reputation', 'vt_link'],
    "URL": ['url', 'reputation', 'vt_link'],
    "MD5 Hash": ['hash', 'hash_type', 'malicious_detections', 'vt_link'],
    "SHA1 Hash": ['hash', 'hash_type', 'malicious_detections', 'vt_link'],
    "SHA256 Hash": ['hash', 'hash_type', 'malicious_detections', 'vt_link']
}

logging.basicConfig(filename="vt_checker.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def choose_file(entry_widget):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_widget.delete(0, 'end')
        entry_widget.insert(0, file_path)

def log_event(message, widget=None):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] {message}"
    print(log_message)  # print the log message to console
    if widget:  # append the log message to the provided widget
        widget.insert(tk.END, log_message + "\n")
        widget.yview(tk.END)  # auto-scroll to the end

def save_as_csv(output_filename, data, headers):
    with open(output_filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)

def save_as_json(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

def save_as_txt(filename, data):
    with open(filename, 'w') as file:
        for item in data:
            file.write(str(item) + "\n")
