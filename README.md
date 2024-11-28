# YHMi-IoT-Security-Tool
Simple Tool To Discover IoT Devices For Scan Security Issues

## Prerequisites
- Python 3.13 
- Libraries (Scapy , Matplotlib , PyQt5 , Nmap , sys , Time) 
- Hardware Minimum Requirements : CPU Intel Core i3 , RAM : 4GB

## Installation Instructions
1. Download any python development environment (such as visual code).
2. install necessary libraries :
   (pip install Scapy , Matplotlib , PyQt5 , Nmap)
3. Run the code

## Excution Steps
After running the code you should see this screenshot :

![image](https://github.com/user-attachments/assets/ca0a00c1-03ef-4289-9b73-ccf24daddbf4)

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

![image](https://github.com/user-attachments/assets/be37ff24-b19f-4bcc-8a67-e7f21363c292)

The tool can track network traffic for the chosen device :

![image](https://github.com/user-attachments/assets/8cde0abf-78f2-4a97-87e2-b3ebb068d32b)

The tool can detect some cryptographic details :

![image](https://github.com/user-attachments/assets/4fb0cd9b-85ae-4802-b3ec-d76a6d9e756c)
