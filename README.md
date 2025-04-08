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

![image](https://github.com/user-attachments/assets/4e983de2-d23a-43c0-8263-d4e121f143c7)



- Enter IP Range: Text box where the user can specify the IP range to scan, such as 192.168.1.0/24. This defines the network range for the device discovery process.
- Start Scan Button: Button that initiates a network scan to discover devices within the specified IP range using Nmap or ARP.
- Discovered Devices Section: Displays a list of discovered devices, including their IP Address, MAC Address and vendor. for each device you will have three buttons (Detect OS button to detect device operating system with accuracy info (%0-100) , Traffic button to show live network traffic for the device , Full Port Scan button to show open ports with their details and Generate Report to show complete scan report for device)

## Troubleshooting
We faced the following issues :
- Device Detection Accuracy: Some devices would appear intermittently. Therefore, we used advanced libraries to ensure all devices are consistently detected (Resolved).
- Device OS Detection : some devices OS can not be detected (Need Improvment).
- Device Ports : somtimes not all open prots will scanned (Need Improvments).

## Screenshots 
The tool can detect local devices using Nmap Or ARP scan :

![image](https://github.com/user-attachments/assets/fdbe7503-8043-436b-9f16-af8e9efcee39)


The tool can detect OS , show live traffic and generate risk assessment report for chosen devices.
