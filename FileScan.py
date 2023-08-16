import os
import hashlib
import requests
import time
import tkinter as tk
import sys
from tkinter import filedialog
from colorama import Fore, Style, init

# Themed Colors
PRIMARY_COLOR = Fore.CYAN
SUCCESS_COLOR = Fore.GREEN
ERROR_COLOR = Fore.RED
INFO_COLOR = Fore.CYAN
RESET_COLOR = Style.RESET_ALL

VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
API_KEY_FILE = 'YOUR_API_KEY.txt'

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, 'r') as f:
            api_key = f.read().strip()
            if api_key:
                return api_key
    return None

def print_colored(text, color):
    print(color + text + RESET_COLOR)

def check_and_display_api(api_key):
    init(autoreset=True)
    
    if api_key:
        print_colored("Checking API...", INFO_COLOR)
        sys.stdout.flush()
        countdown_timer(5)
        print_colored(f"API FOUND: \"{api_key}\"", SUCCESS_COLOR)
        sys.stdout.flush()
    else:
        print_colored("NO API Found. Please paste your API key from VirusTotal in [ YOUR_API_KEY.txt ] file.", ERROR_COLOR)
        input("Press Enter to exit...")
        sys.exit(1)

def countdown_timer(seconds):
    for i in range(seconds, 0, -1):
        print(f"\r{' ' * 50}", end="")
        print(f"\rTime remaining: {i} seconds", end="")
        sys.stdout.flush()
        time.sleep(1)
    print()

def countdown_message(message, seconds):
    for i in range(seconds, 0, -1):
        print(f"\r{message} in {i} seconds", end="")
        sys.stdout.flush()
        time.sleep(1)
    print()

def animate_typography(text, delay=0.1, color=Fore.WHITE):
    for char in text:
        print(color + char + RESET_COLOR, end='', flush=True)
        time.sleep(delay)
    print()

def display_intro():
    intro_text = (
        "FileScan utilizes the VirusTotal API to scan files for malware and display the scan results using a graphical user interface (GUI) built with the Tkinter library. VirusTotal is a service that aggregates multiple antivirus engines and performs malware scans on files using these engines."
    )
    animate_typography("Loading...\n", color=Fore.RED)
    time.sleep(1)
    animate_typography("A tool to keep your files safe\n", color=Fore.RED)
    time.sleep(1)
    animate_typography(intro_text, delay=0.02, color=Fore.CYAN)
    time.sleep(0.5)
    animate_typography("By: Rajput Shubhraj Singh", color=Fore.GREEN)
    animate_typography("@Shuuubhraj (Github)\n", color=Fore.GREEN)

def generate_text_report(report):
    report_text = ""
    report_text += "Scan results:\n"
    report_text += f"Scan date: {report.get('scan_date', 'N/A')}\n"
    report_text += f"File MD5 hash: {report.get('md5', 'N/A')}\n"
    report_text += f"File SHA-1 hash: {report.get('sha1', 'N/A')}\n"
    report_text += f"File SHA-256 hash: {report.get('sha256', 'N/A')}\n"
    report_text += f"File resource: {report.get('resource', 'N/A')}\n"
    report_text += f"File response code: {report.get('response_code', 'N/A')}\n"
    report_text += f"File scan date: {report.get('scan_date', 'N/A')}\n"
    report_text += f"File permalink: {report.get('permalink', 'N/A')}\n"
    report_text += f"File verbose message: {report.get('verbose_msg', 'N/A')}\n"
    report_text += f"Total scans performed: {report.get('total', 'N/A')}\n"
    report_text += f"Number of positive scans: {report.get('positives', 'N/A')}\n"
    report_text += f"Number of engines detecting malware: {report.get('positives', 'N/A')}\n"
    report_text += f"File scan result: {report.get('scan_result', 'N/A')}\n"

    scans = report.get('scans', {})
    if scans:
        report_text += "Scan details by antivirus:\n"
        for antivirus, result in scans.items():
            scan_result = result.get('result')
            report_text += f"{antivirus}: {scan_result if scan_result else 'No result'}\n"
    else:
        report_text += "No scan details available.\n"

    return report_text

def show_scan_results(report):
    result_window = tk.Toplevel()
    result_window.title("Scan Results")
    
    text_widget = tk.Text(result_window, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)
    
    report_text = generate_text_report(report)
    text_widget.insert(tk.END, report_text)

def scan_file(file_path, api_key):
    md5_hash = calculate_md5(file_path)
    params = {'apikey': api_key}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    
    print_colored("Uploading file to VirusTotal...", PRIMARY_COLOR)
    response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, params=params)
    response_data = response.json()
    scan_id = response_data.get('scan_id')
    
    if scan_id:
        print_colored("File uploaded successfully. Waiting for scan results...", PRIMARY_COLOR)
        
        while True:
            countdown_message("Checking, kindly wait", 10)
            sys.stdout.flush()
            report_params = {'apikey': api_key, 'resource': md5_hash}
            report_response = requests.get(VIRUSTOTAL_REPORT_URL, params=report_params)
            
            try:
                report_data = report_response.json()
            except ValueError:
                print_colored("Error decoding JSON response. Retrying...", ERROR_COLOR)
                sys.stdout.flush()
                time.sleep(10)
                continue
            
            if report_data.get('response_code') == 1:
                return report_data
            else:
                time.sleep(10)

def main():
    display_intro()  # Display the introductory animation and info

    api_key = load_api_key()

    root = tk.Tk()
    root.withdraw()

    check_and_display_api(api_key)

    while True:
        countdown_message("Select target file from the window opening", 2)
        sys.stdout.flush()

        if not api_key:
            input("Press Enter to exit...")
            break
        
        file_path = filedialog.askopenfilename(title="Select a file to scan", filetypes=[("All files", "*.*")])

        if not file_path:
            break

        if os.path.exists(file_path):
            report = scan_file(file_path, api_key)
            if report:
                show_scan_results(report)

                while True:
                    action = input("Enter 1 to scan a new file, or press Enter to exit: ")
                    if action == '1':
                        break
                    elif not action:
                        return
            else:
                print_colored("Error while scanning the file.", ERROR_COLOR)
        else:
            print_colored("File not found.", ERROR_COLOR)

if __name__ == "__main__":
    main()