# Origin IP Finder

Origin IP Finder is a Python tool that gathers IP addresses associated with a domain using multiple sources, including VirusTotal, AlienVault, and URLScan.

## Features
- Fetches IP addresses from:
  - **VirusTotal** (API key required)
  - **AlienVault OTX**
  - **URLScan**
- Saves results to a text file.
- Simple command-line interface.

## Installation
### Requirements
Make sure you have Python installed on your system. You can install the required dependencies using:
```bash
pip install requests termcolor
```

## Usage
Run the script with the following command:
```bash
python ipfinder.py -d example.com
```
You'll be prompted to enter a VirusTotal API key.

### Arguments
- `-d`, `--domain` : Specify the target domain to retrieve associated IP addresses.

## Example
```bash
python ipfinder.py -d example.com
VirusTotal API Açari: YOUR_API_KEY
[*] IP adresleri toplanir...
192.168.1.1
203.0.113.5
...
```
The collected IPs will be saved in `ip.txt`.

## Author
- **SilverX**
- Telegram: [t.me/silverxvip](https://t.me/silverxvip)

## Disclaimer
This tool is intended for educational and research purposes only. Use it responsibly and only on domains you have permission to test.

