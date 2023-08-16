<h1 align="left">FileScan v1.0</h1>

<p align="left">
  <img src="https://img.shields.io/badge/FileScan-v1.0-00FFFF">
  <img src="https://img.shields.io/badge/Python-3.6+-blue.svg">
</p>

FileScan is a command-line tool that uses the VirusTotal API to scan files for malware and presents scan results using a graphical user interface (GUI) built with the Tkinter library. With FileScan, you can efficiently scan multiple files sequentially without manual uploads.

---

<h2>Why Use FileScan?</h2>

VirusTotal is a valuable online resource for scanning files and URLs for malware. However, using their website directly might be cumbersome, especially when dealing with numerous files. FileScan offers several key benefits:

- **Batch Scanning**: With FileScan, you can efficiently scan multiple files sequentially without manual uploads.
- **Automated Results**: FileScan fetches scan results from VirusTotal and presents them in an organized GUI, simplifying scan report interpretation.

---

<h2>Features</h2>

- Scan files for malware using the VirusTotal API.
- Save and store the API key, eliminating the need for repeated pasting.
- Display detailed scan results in a user-friendly Tkinter GUI.
- Streamline batch scanning: Sequentially scan multiple files without manual intervention.
- Automated fetching and display of comprehensive scan reports from VirusTotal.

---

<h2>Prerequisites</h2>

- Python 3.6+
- Required Python libraries: `requests`, `tkinter`, `colorama`

---

<h2>Important Notes and Tips</h2>

- Your VirusTotal API key is required for FileScan to communicate with the VirusTotal service and perform scans.
- Do not delete or share your `YOUR_API_KEY.txt` file. It contains your API key.
- Each VirusTotal user has a daily usage limit for API requests. Free users typically have a limit of <Strong>x4</Strong> requests per minute and <Strong>[ 5760 ]</Strong> requests per day.
- If you reach your daily limit, you'll need to wait until the next day for your API usage to reset.

---

<h2>Usage</h2>

1. Obtain your VirusTotal API key and save it in a file named `YOUR_API_KEY.txt` in the project directory.
2. Open a terminal and navigate to the project directory.
3. Run the following command to execute FileScan:

   ```bash
   python FileScan.py

## Executable Version
An executable version of FileScan V1.0 is available for Windows users. You can download it. The executable version doesn't require Python to be installed.

## Author
GitHub: [@Shuuubhraj](https://github.com/shuuubhraj)

## Disclaimer
**WARNING!** This tool might experience slowdowns or potential unresponsiveness when analyzing large files. 

<h2>Acknowledgement</h2>

FileScan utilizes the VirusTotal API, a service provided by VirusTotal, to perform malware scans on files. I acknowledge and appreciate the functionality and resources made available by VirusTotal for the cybersecurity community.

VirusTotal is a free and valuable platform that aggregates multiple antivirus engines, allowing users to scan files and URLs for potential threats. By integrating VirusTotal's API, FileScan enhances the process of file scanning and malware detection, contributing to a safer digital environment.

I thank VirusTotal for their efforts in providing advanced security solutions and resources that benefit users and help keep digital systems secure.

Learn more about VirusTotal and their services at [https://www.virustotal.com/](https://www.virustotal.com/).


