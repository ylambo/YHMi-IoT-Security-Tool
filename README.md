# YHMi-IoT-Security-Tool
Simple Tool to Discover IoT Devices on Network with Some Details (OS , Open Ports and Vulnerabilities)

## Prerequisites
- Python 3.10 (or newer) 
- Import Libraries (Scapy , Matplotlib , PyQt5 , Nmap , sys , Time) 
- Hardware Minimum Requirements : CPU Intel Core i3 , RAM : 4GB

## Installation Instructions
1. Download any python development environment (such as visual code).
2. install necessary libraries :
   (pip install Scapy , PyQt5 , Nmap)
3. Run the code

## Excution Steps
After running the code you should see this window :

![image](https://github.com/user-attachments/assets/152b1fca-01bb-4e11-bacf-072e754acd1e)


- Enter IP Range: Text box where the user can specify the IP range to scan, such as 192.168.1.0/24. This defines the network range for the device discovery process.
- Start Scan Button: Button that initiates a network scan to discover devices within the specified IP range.
- Discovered Devices Section: Displays a list of discovered devices, including their IP Address and MAC Address. for each device you will have three buttons (Detect OS button to detect device operating system with accuracy info (%0-100) , Scan Ports button to detect open ports , Scan for Vulnerabilities button to scan device for any vulnerabilities)

## Troubleshooting
We faced the following issues :
- Device Detection Accuracy: Some devices would appear intermittently. Therefore, we used advanced libraries to ensure all devices are consistently detected (Resolved).
- Device OS Detection : some devices OS can not be detected (Need Improvment).
- Device Ports : somtimes not all open prots will scanned (Need Improvments).
- Readability of Vulnerabilities Output : some vulnerabilities scan for some devices will return only hashes of running services or you may see detection errors.

## Screenshots 
The tool can detect local devices :

![image](https://github.com/user-attachments/assets/8ca0dd81-0c01-470c-80f7-3e090143c99f)

The tool can detect OS , open ports and vulnerabilities for chosen devices :

![image](https://github.com/user-attachments/assets/293b182b-f9b4-4808-81ab-17f8294161ed)
