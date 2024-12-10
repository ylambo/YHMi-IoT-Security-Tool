import sys
import nmap
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QTextEdit
)
from PyQt5.QtGui import QFont, QColor, QBrush
from PyQt5.QtCore import Qt, QTimer

def scan_network(ip_range):
    """Use Nmap to discover devices on the network within the specified IP range."""
    nm = nmap.PortScanner()
    devices = []
    nm.scan(hosts=ip_range, arguments='-sn')  # -sn for ping scan to find live hosts

    for host in nm.all_hosts():
        if nm[host].state() == "up":
            ip_address = nm[host]['addresses'].get('ipv4')
            mac_address = nm[host]['addresses'].get('mac', 'N/A')
            devices.append({'ip': ip_address, 'mac': mac_address})

    return devices

def detect_os(ip):
    """Use Nmap to detect OS on the specified IP address."""
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O')  # -O for OS detection

    if 'osmatch' in nm[ip] and len(nm[ip]['osmatch']) > 0:
        os_name = nm[ip]['osmatch'][0]['name']
        accuracy = nm[ip]['osmatch'][0]['accuracy']
        return f"{os_name} ({accuracy}%)"
    else:
        return "OS detection failed"

def scan_ports(ip):
    """Use Nmap to scan ports 1-1000 on the specified IP address."""
    nm = nmap.PortScanner()
    open_ports = []
    nm.scan(ip, arguments='-p 1-1000')  # Scan ports 1-1000

    if 'tcp' in nm[ip]:
        for port in nm[ip]['tcp']:
            if nm[ip]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
    
    return open_ports

def run_vulnerability_scan(ip):
    """Run a comprehensive vulnerability scan on the specified IP address."""
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-Pn -sV -p- --script=vuln')  # Run the vulnerability scan with specified arguments
    return nm

def format_vulnerability_output(ip, nm_scan):
    """Format the output of the vulnerability scan results with colors and segmentation for better readability."""
    output = f"<h2 style='color:blue;'>Vulnerability Scan Results for IP: {ip}</h2><hr>"

    for port, port_data in nm_scan[ip]['tcp'].items():
        # Port header
        service_name = port_data['name']
        output += f"<h3 style='color:green;'>Port {port}/tcp - {service_name}</h3>"
        
        # Check if there are scripts and vulnerabilities
        if 'script' in port_data:
            for script_id, result in port_data['script'].items():
                output += (
                    f"<div style='margin-left:20px;'>"
                    f"<p style='color:red;'><strong>Vulnerability:</strong> {script_id}</p>"
                    f"<p style='color:black;'><strong>Details:</strong> {result}</p>"
                    f"</div><br>"
                )
        else:
            output += "<p style='color:gray; margin-left:20px;'>No vulnerabilities found on this port.</p>"

        # Add a line separator for each port
        output += "<hr>"

    if not nm_scan[ip]['tcp']:
        output += "<p style='color:gray;'>No vulnerabilities detected.</p>"

    return output

class NetworkScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("YHMi IoT Security Tool")
        self.setGeometry(100, 100, 1400, 600)

        # IP Range input
        self.ip_label = QLabel("Enter IP Range:")
        self.ip_entry = QLineEdit(self)
        self.ip_entry.setText("192.168.1.0/24")

        # Start scan button
        self.scan_button = QPushButton("Start Scan", self)
        self.scan_button.clicked.connect(self.start_scan)

        # Loading indicator label
        self.loading_label = QLabel("")
        self.loading_label.setFont(QFont("Arial", 8))  # Smaller font size
        self.loading_label.setStyleSheet("color: red")  # Set text color to red
        self.loading_label.setAlignment(Qt.AlignCenter)

        # Table for displaying results
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(7)  # Reduced column count
        self.result_table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Detect OS", "Detected OS", "Open Ports Button", "Port Scan Result", "Scan for Vulnerabilities"
        ])
        
        # Apply color to each column
        self.result_table.setStyleSheet("""
            QHeaderView::section { background-color: lightblue; }
            QTableWidget::item { padding: 8px; }
            QTableWidget::item:selected { background-color: lightgray; }
        """)

        # Detailed result text box for vulnerabilities
        self.vuln_result_textbox = QTextEdit()
        self.vuln_result_textbox.setReadOnly(True)
        self.vuln_result_textbox.setFont(QFont("Courier", 10))
        self.vuln_result_textbox.setStyleSheet("background-color: #f5f5f5;")
        self.vuln_result_textbox.setPlaceholderText("Vulnerability scan results will appear here.")

        # Layouts
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(self.ip_label)
        ip_layout.addWidget(self.ip_entry)

        # Main left layout for controls and table
        left_layout = QVBoxLayout()
        left_layout.addLayout(ip_layout)
        left_layout.addWidget(self.scan_button)
        left_layout.addWidget(self.loading_label)  # Place loading label right below the scan button
        left_layout.addWidget(self.result_table)

        # Right layout for the vulnerability result text box
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Vulnerability Scan Results:"))
        right_layout.addWidget(self.vuln_result_textbox)

        # Horizontal layout to place the table and the result text box side by side
        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout, 70)  # 70% width for left side
        main_layout.addLayout(right_layout, 30)  # 30% width for right side

        self.setLayout(main_layout)

    def start_scan(self):
        # Display loading indicator while scanning
        self.loading_label.setText("Scanning connected devices...")
        QApplication.processEvents()  # Update the GUI immediately

        # Get IP range from input
        ip_range = self.ip_entry.text().strip()
        if not ip_range:
            self.result_table.setRowCount(0)
            self.result_table.setColumnCount(1)
            self.result_table.setHorizontalHeaderLabels(["Error"])
            self.result_table.setItem(0, 0, QTableWidgetItem("Please enter a valid IP range."))
            self.loading_label.setText("")  # Clear loading label if error
            return

        # Clear previous results and start scan
        self.result_table.setRowCount(0)
        devices = scan_network(ip_range)

        # Display results in the table
        self.result_table.setRowCount(len(devices))
        for row, device in enumerate(devices):
            ip_item = QTableWidgetItem(device['ip'])
            mac_item = QTableWidgetItem(device['mac'])
            
            # Button to detect OS for each device
            detect_os_button = QPushButton("Detect OS")
            detect_os_button.clicked.connect(lambda _, row=row, ip=device['ip']: self.detect_os_for_device(row, ip))
            
            # Button to scan ports for each device
            scan_ports_button = QPushButton("Scan Ports")
            scan_ports_button.clicked.connect(lambda _, row=row, ip=device['ip']: self.scan_ports_for_device(row, ip))
            
            # Button to scan for vulnerabilities for each device
            scan_vuln_button = QPushButton("Scan for Vulnerabilities")
            scan_vuln_button.clicked.connect(lambda _, row=row, ip=device['ip']: self.run_vulnerability_scan_for_device(row, ip))

            # Place items in the table
            self.result_table.setItem(row, 0, ip_item)
            self.result_table.setItem(row, 1, mac_item)
            self.result_table.setCellWidget(row, 2, detect_os_button)
            self.result_table.setItem(row, 3, QTableWidgetItem("Unknown"))  # Initialize "Detected OS" column
            self.result_table.setCellWidget(row, 4, scan_ports_button)
            self.result_table.setItem(row, 5, QTableWidgetItem("None"))  # Initialize "Port Scan Result" column
            self.result_table.setCellWidget(row, 6, scan_vuln_button)

        # Clear loading indicator after the device scan completes
        self.loading_label.setText("")

    def detect_os_for_device(self, row, ip):
        # Display loading indicator while detecting OS
        self.loading_label.setText("Detecting OS... Please wait.")
        QApplication.processEvents()  # Update the GUI immediately
        
        # Perform OS detection
        os_info = detect_os(ip)
        
        # Update the Detected OS column with the OS detection results
        self.result_table.setItem(row, 3, QTableWidgetItem(os_info))
        
        # Clear the loading indicator after OS detection
        self.loading_label.setText("")

    def scan_ports_for_device(self, row, ip):
        # Display loading indicator while scanning ports
        self.loading_label.setText("Scanning ports... Please wait.")
        QApplication.processEvents()  # Update the GUI immediately
        
        # Perform port scan
        open_ports = scan_ports(ip)
        open_ports_str = ", ".join(map(str, open_ports)) if open_ports else "None"

        # Update the Port Scan Result column with the scan results
        self.result_table.setItem(row, 5, QTableWidgetItem(open_ports_str))

        # Store the open ports for vulnerability scanning
        self.result_table.item(row, 5).setData(Qt.UserRole, open_ports)

        # Clear the loading indicator after port scan completion
        self.loading_label.setText("")

    def run_vulnerability_scan_for_device(self, row, ip):
        # Display loading indicator while scanning for vulnerabilities
        self.loading_label.setText("Scanning for vulnerabilities... Please wait.")
        QApplication.processEvents()  # Update the GUI immediately

        # Run the vulnerability scan and format the output
        nm_scan = run_vulnerability_scan(ip)
        vulnerabilities = format_vulnerability_output(ip, nm_scan)
        
        # Update the right-side text box with detailed vulnerability scan results
        self.vuln_result_textbox.setText(vulnerabilities)
        
        # Clear the loading indicator after vulnerability scan completion
        self.loading_label.setText("")

# Run the application
app = QApplication(sys.argv)
window = NetworkScannerApp()
window.show()
sys.exit(app.exec_())
