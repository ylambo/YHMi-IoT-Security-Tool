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
- Scan for Devices Button: Button that initiates a network scan to discover devices within the specified IP range.
- Discovered Devices Section: Displays a list of discovered devices, including their IP Address and MAC Address. The Select column might allow the user to select specific devices for further action, such as monitoring.
- Currently Monitoring: Indicates the current status of monitoring, which in this case is "None," meaning no device is being monitored at the moment.
- Start Monitoring: Used to start monitoring the selected device.
- Stop Monitoring: Used to stop monitoring the selected device.
- Real-Time Traffic: A graph that shows real-time network traffic data, such as packet sizes over time, to monitor the activity of the selected device.
- Check Cryptographic Details Button: A button that allows the user to check cryptographic information related to the selected device or connection.
- Cryptographic Details: Displays the cryptographic details, such as encryption or security protocols in use.

## Troubleshooting
We faced the following issues :
- Device Detection Accuracy: Some devices would appear intermittently. Therefore, we used advanced libraries to ensure all devices are consistently detected. (Resolved)
- Encryption Protocol Check: Some lag occurred during the encryption protocol check. (Need Improvment)

## Screenshots 
The tool can detect devices :
