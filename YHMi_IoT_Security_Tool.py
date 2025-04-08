
import sys
import nmap
import shodan
import random
import requests
import time , threading
import numpy as np
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, DNS
from collections import defaultdict
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton, 
                            QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
                            QTextEdit, QMessageBox)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QTimer, QTime
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from itertools import zip_longest

SHODAN_API_KEY = "s0PhWvIsTTPuptQK6mL39gxaMW4jPFZK"

class VulnerabilityScanner:
    NVD_API_KEY = "5367e97c-aa0b-45e3-afd8-6382d70fba46"
    VULNERS_API_KEY = "66N8VQKN2OX8YPKQAOAGNWNTD3S6O27ER6NDSD7EKL888PX1VSGRXRJKO5WN30ZG"

    @staticmethod
    def query_nvd(cpe_name):
        """Query NVD API for CVEs related to a CPE (Common Platform Enumeration)."""
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe_name}"
        headers = {"apiKey": VulnerabilityScanner.NVD_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json().get('result', {}).get('CVE_Items', [])
        except Exception as e:
            print(f"NVD API Error: {e}")
            return []

    @staticmethod
    def query_vulners(query):
        """Query Vulners API for vulnerabilities."""
        url = "https://vulners.com/api/v3/search/lucene/"
        params = {
            "apiKey": VulnerabilityScanner.VULNERS_API_KEY,
            "query": query
        }
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response.json().get('data', {}).get('search', [])
        except Exception as e:
            print(f"Vulners API Error: {e}")
            return []

class NetworkScanner:
    @staticmethod
    def nmap_scan(ip_range):
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sn')
        devices = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                host_info = nm[host]
                addresses = host_info.get('addresses', {})
                vendor = host_info.get('vendor', {})
                devices.append({
                    'ip': addresses.get('ipv4', 'N/A'),
                    'mac': addresses.get('mac', 'N/A'),
                    'manufacturer': vendor.get(addresses.get('mac', ''), 'Unknown')
                })
        return devices

    @staticmethod
    def arp_scan(ip_range):
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=False)[0]
        return [{'ip': recv.psrc, 'mac': recv.hwsrc} for sent, recv in ans]

    @staticmethod
    def detect_os(ip):
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O')
        if nm[ip].get('osmatch'):
            return f"{nm[ip]['osmatch'][0]['name']} ({nm[ip]['osmatch'][0]['accuracy']}%)"
        return "OS detection failed"

    @staticmethod
    def scan_ports(ip):
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-p 1-65535')
        return [port for port in nm[ip].get('tcp', {}) if nm[ip]['tcp'][port]['state'] == 'open']

class EnhancedTrafficMonitor(QWidget):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
        self.setWindowTitle(f"Traffic Monitor - {ip}")
        self.setAttribute(Qt.WA_DeleteOnClose)
        
        # Constants
        self.MAX_TRAFFIC = 0.01 * 1024  # 5MB pool in KB
        self.WINDOW_SECONDS = 30
        self.BAR_WIDTH = 0.2  # Width of each bar (narrower for side-by-side)

        # Data storage
        self.real_packets = []  # Stores (timestamp, size) tuples
        self.dummy_packets = []
        self.dummy_enabled = False
        
        # UI Setup
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_ylim(0, self.MAX_TRAFFIC)
        self.ax.set_xlabel('Time (seconds)')
        self.ax.set_ylabel('Traffic (KB)')
        self.ax.grid(True, axis='y')
        
        # Toggle button
        self.toggle_btn = QPushButton("Enable Traffic Padding")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.clicked.connect(self.toggle_padding)
        
        layout = QVBoxLayout()
        layout.addWidget(self.canvas)
        layout.addWidget(self.toggle_btn)
        self.setLayout(layout)
        
        # Start threads
        self.sniffer_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        self.sniffer_thread.start()
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(1000)  # Update every second

    def toggle_padding(self):
        self.dummy_enabled = not self.dummy_enabled
        self.toggle_btn.setText(
            "Disable Padding" if self.dummy_enabled 
            else "Enable Padding"
        )
        self.toggle_btn.setStyleSheet(
            "background-color: #ffcccc;" if self.dummy_enabled 
            else ""
        )

    def packet_handler(self, packet):
        if IP in packet and (packet[IP].src == self.ip or packet[IP].dst == self.ip):
            kb = len(packet) / 1024
            if sum(p[1] for p in self.real_packets) + kb <= self.MAX_TRAFFIC:
                self.real_packets.append((time.time(), kb))
            
            if self.dummy_enabled:
                dummy_kb = random.uniform(0.5, 3.0)
                if sum(p[1] for p in self.dummy_packets) + dummy_kb <= self.MAX_TRAFFIC:
                    self.dummy_packets.append((time.time(), dummy_kb))

    def start_sniffing(self):
        sniff(
            prn=self.packet_handler,
            filter=f"host {self.ip}",
            store=False
        )

    def update_graph(self):
        current_time = time.time()
        time_min = current_time - self.WINDOW_SECONDS
        
        # Filter and bin packets
        real_bins = {}
        dummy_bins = {}
        
        # Bin real packets
        for ts, kb in self.real_packets:
            if ts >= time_min:
                bin_time = int(ts)
                real_bins[bin_time] = real_bins.get(bin_time, 0) + kb
        
        # Bin dummy packets
        if self.dummy_enabled:
            for ts, kb in self.dummy_packets:
                if ts >= time_min:
                    bin_time = int(ts)
                    dummy_bins[bin_time] = dummy_bins.get(bin_time, 0) + kb
        
        # Prepare plot data
        all_times = sorted(set(real_bins.keys()).union(set(dummy_bins.keys())))
        real_values = [real_bins.get(t, 0) for t in all_times]
        dummy_values = [dummy_bins.get(t, 0) for t in all_times]
        
        # Clear and redraw
        self.ax.clear()
        
        # Plot side-by-side bars
        if all_times:
            x = range(len(all_times))
            
            # Real packets (blue) - slightly left
            self.ax.bar(
                [i - self.BAR_WIDTH/2 for i in x], real_values,
                width=self.BAR_WIDTH, color='#3498db', label='Real Traffic'
            )
            
            # Dummy packets (red) - slightly right
            if self.dummy_enabled:
                self.ax.bar(
                    [i + self.BAR_WIDTH/2 for i in x], dummy_values,
                    width=self.BAR_WIDTH, color='#e74c3c', label='Padding'
                )
        
        # Formatting
        self.ax.set_xticks(range(len(all_times)))
        self.ax.set_xticklabels([str(t - int(time_min)) for t in all_times])
        self.ax.set_ylim(0, self.MAX_TRAFFIC)
        self.ax.set_xlabel('Time (seconds ago)')
        self.ax.legend()
        self.ax.grid(True, axis='y')
        self.canvas.draw()

class NetworkScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.scanners = {
            'nmap': NetworkScanner.nmap_scan,
            'arp': NetworkScanner.arp_scan
        }
        self.traffic_windows = []

    def initUI(self):
        self.setWindowTitle("YHMi IoT Security Tool")
        self.setGeometry(100, 100, 1400, 600)

        # UI Components
        self.ip_entry = QLineEdit("192.168.1.0/24")
        self.result_table = QTableWidget(0, 8)
        self.vuln_display = QTextEdit()
        self.loading_label = QLabel()
        
        # Configure components
        self._setup_table()
        self._setup_ui_style()

        # Layout
        main_layout = QHBoxLayout()
        main_layout.addLayout(self._create_left_panel(), 70)
        #main_layout.addLayout(self._create_right_panel(), 30)
        self.setLayout(main_layout)

    def _setup_table(self):
        headers = ["IP Address", "MAC Address", "Vendor", "Detect OS", "Detected OS", "Traffic", "Full Port Scan" ,"Generate Report"]
        self.result_table.setHorizontalHeaderLabels(headers)
        self.result_table.setStyleSheet("QHeaderView::section { background-color: lightblue; }")

    def _setup_ui_style(self):
        self.loading_label.setAlignment(Qt.AlignCenter)
        self.loading_label.setStyleSheet("color: red; font: 8pt Arial")
        self.vuln_display.setReadOnly(True)
        self.vuln_display.setStyleSheet("background-color: #f5f5f5; font: 10pt Courier")

    def _create_left_panel(self):
        left = QVBoxLayout()
        left.addWidget(QLabel("Enter IP Range:"))
        left.addWidget(self.ip_entry)
        left.addWidget(self._create_button("Nmap Scan", self.start_scan, 'nmap'))
        left.addWidget(self._create_button("ARP Scan", self.start_scan, 'arp'))
        left.addWidget(self.loading_label)
        left.addWidget(self.result_table)
        return left

    def _create_right_panel(self):
        right = QVBoxLayout()
        right.addWidget(QLabel("Vulnerability Results:"))
        right.addWidget(self.vuln_display)
        return right

    def _create_button(self, text, handler, arg=None):
        btn = QPushButton(text)
        btn.clicked.connect(lambda: handler(arg) if arg else handler())
        return btn

    def start_scan(self, scan_type):
        self._set_loading(f"Scanning with {scan_type.upper()}...")
        ip_range = self.ip_entry.text().strip()
        if not ip_range:
            return self._show_error("Invalid IP range")
        
        try:
            devices = self.scanners[scan_type](ip_range)
            self._display_devices(devices, scan_type == 'nmap')
        except Exception as e:
            self._show_error(f"Scan error: {str(e)}")
        finally:
            self._clear_loading()

    def _display_devices(self, devices, full_scan):
        self.result_table.setRowCount(len(devices))
        for row in range(len(devices)):
            self.result_table.insertRow(row)
            for col in range(self.result_table.columnCount()):
                if self.result_table.item(row, col) is None:
                    self.result_table.setItem(row, col, QTableWidgetItem())
                    
        for row, dev in enumerate(devices):
            self._add_device_row(row, dev, full_scan)
            headers = ["IP Address", "MAC Address", "Vendor", "Detect OS", "Detected OS", "Traffic", "Full Port Scan" ,"Generate Report"]
    def _add_device_row(self, row, dev, full_scan):
        # Set base items
        self.result_table.item(row, 0).setText(dev['ip'])
        self.result_table.item(row, 1).setText(dev.get('mac', 'N/A'))
        self.result_table.item(row, 2).setText(dev.get('manufacturer', 'N/A') if full_scan else 'Unknown')
        
        # Initialize empty columns
        self.result_table.item(row, 4).setText("Unknown")  # Detected OS
        
        # Add buttons
        self.result_table.setCellWidget(row, 3, self._create_action_btn("Detect OS", self.detect_os, row, dev['ip']))
        self.result_table.setCellWidget(row, 5, self._create_action_btn("Traffic", self.show_traffic, None, dev['ip']))
        self.result_table.setCellWidget(row, 6, self._create_action_btn("Full Port Scan", self.run_advanced_scan, row, dev['ip']))
        self.result_table.setCellWidget(row, 7, self._create_action_btn("Generate Report", self.generate_report, row, dev['ip']))

    def _create_action_btn(self, text, handler, row, ip):
        btn = QPushButton(text)
        btn.clicked.connect(lambda: handler(ip, row) if row is not None else handler(ip))
        return btn

    def detect_os(self, ip, row):
        self._set_loading("Detecting OS...")
        try:
            os_info = NetworkScanner.detect_os(ip)
            self.result_table.item(row, 4).setText(os_info)
        except Exception as e:
            self._show_error(f"OS Detection failed: {str(e)}")
        self._clear_loading()

    def scan_ports(self, ip, row):
        self._set_loading("Scanning ports...")
        try:
            ports = NetworkScanner.scan_ports(ip)
            self.result_table.item(row, 6).setText(", ".join(map(str, ports)) or "None")
        except Exception as e:
            self._show_error(f"Port scan failed: {str(e)}")
        self._clear_loading()

    def shodan_scan(self, ip):
        self._set_loading("Querying Shodan...")
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            info = api.host(ip)
            result = "\n".join([
                f"IP: {ip}",
                f"Organization: {info.get('org', 'N/A')}",
                f"OS: {info.get('os', 'N/A')}",
                f"Ports: {', '.join(map(str, info.get('ports', [])))}",
                f"ISP: {info.get('isp', 'N/A')}",
                f"Country: {info.get('country_name', 'N/A')}",
                f"City: {info.get('city', 'N/A')}",
                f"Hostnames: {', '.join(info.get('hostnames', []))}"
            ])
            QMessageBox.information(self, "Shodan Results", result)
        except Exception as e:
            self._show_error(f"Shodan query failed: {str(e)}")
        self._clear_loading()

    def show_traffic(self, ip):
        traffic_window = EnhancedTrafficMonitor(ip)
        self.traffic_windows.append(traffic_window)
        traffic_window.show()

    def run_advanced_scan(self, ip, row):
        self._set_loading(f"Running advanced scan on {ip}...")
        try:
            # Run the Nmap scan
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments='-sS -sV -T4 -Pn')
        
            # Store results in the row's data
            if ip in nm.all_hosts():
                host_info = nm[ip]
                self.result_table.item(row, 5).setText(",".join(map(str, host_info['tcp'].keys())))  # Update ports
            
                # Store full scan results for the report
                if not hasattr(self, 'advanced_scan_results'):
                    self.advanced_scan_results = {}
                self.advanced_scan_results[ip] = host_info
            
                QMessageBox.information(self, "Scan Complete", 
                                      f"Advanced scan completed for {ip}\nFound {len(host_info['tcp'])} open ports")
        except Exception as e:
            self._show_error(f"Advanced scan failed: {str(e)}")
        finally:
            self._clear_loading()

    def generate_report(self, ip, row):
        self._set_loading("Generating security assessment report...")
        try:
            # Collect traffic analysis data if available
            traffic_analysis = self._get_traffic_analysis(ip)
            
            report_data = {
                'ip': ip,
                'mac': self._get_table_data(row, 1, 'N/A'),
                'vendor': self._get_table_data(row, 2, 'Unknown'),
                'os': self._get_os_info(row),
                'open_ports': self._get_port_info(row),
                'shodan_data': "Not queried",
                'traffic_findings': traffic_analysis
            }

            report_content = self._create_report_content(report_data)
            
            filename = f"Security_Report_{ip.replace('.', '_')}.html"
            with open(filename, 'w') as f:
                f.write(report_content)
            
            self._show_report_popup(filename, report_content)
            
        except Exception as e:
            self._show_error(f"Report generation failed: {str(e)}")
        finally:
            self._clear_loading()

    def _get_traffic_analysis(self, ip):
        """Retrieve traffic analysis from open traffic monitor windows"""
        for window in self.traffic_windows:
            try:
                if window.ip == ip and window.isVisible():
                   security_recommendations = []
                   # Extract data from security table
                   table = window.security_table
                   for row in range(table.rowCount()):
                        protocol_item = table.item(row, 0)
                        risk_item = table.item(row, 1)
                        recommendation_item = table.item(row, 2)                 
                        if all((protocol_item, risk_item, recommendation_item)):
                            security_recommendations.append({
                            'protocol': protocol_item.text(),
                            'risk': risk_item.text(),
                            'recommendation': recommendation_item.text()
                        })               
                return {
                    'protocols': dict(window.protocols),
                    'ports': dict(window.ports),
                    'suspicious': window.suspicious_activities.copy(),
                    'recommendations': security_recommendations
                }
            except RuntimeError:
              # Window might have been deleted
              self.traffic_windows.remove(window)
        return None

    def _get_table_data(self, row, col, default):
        item = self.result_table.item(row, col)
        return item.text() if item and item.text() else default

    def _get_os_info(self, row):
        os_item = self.result_table.item(row, 4)
        return os_item.text() if os_item and os_item.text() not in ["", "Unknown"] else "Not detected"

    def _get_port_info(self, row):
        port_item = self.result_table.item(row, 6)
        if port_item and port_item.text() not in ["", "None"]:
            return [p.strip() for p in port_item.text().split(',')]
        return []

    def _generate_risk_assessment(self, scan_data):
        #Generate port risks and version vulnerabilities from Nmap results
        PORT_RISKS = {
            # Critical
            21: ('FTP', 'Critical', 'Use SFTP/FTPS'),
            23: ('Telnet', 'Critical', 'Disable immediately'),
            445: ('SMB', 'Critical', 'Update Windows'),
            # Medium
            22: ('SSH', 'Medium', 'Use key authentication'),
            3389: ('RDP', 'Medium', 'Enable Network Level Auth'),
            # Low
            80: ('HTTP', 'Low', 'Redirect to HTTPS'),
            443: ('HTTPS', 'Low', 'Check TLS configuration')
        }
    
        risk_table = []
        version_warnings = []
    
        for port, info in scan_data['tcp'].items():
            port = int(port)
        
            # 1. Port Risk Assessment
            if port in PORT_RISKS:
                service, risk, advice = PORT_RISKS[port]
                risk_table.append(f"""
                <tr>
                    <td>{port}</td>
                    <td>{service}</td>
                    <td style="color: {'red' if 'Critical' in risk else 'orange' if 'Medium' in risk else 'green'}">
                        {risk}
                    </td>
                    <td>{advice}</td>
                </tr>
                """)
        
            # 2. Version Vulnerability Check
            if 'product' in info and 'version' in info:
                version_warnings.append(
                    f"<li>Port {port}: {info['product']} {info['version']} - "
                    f"<a href='https://nvd.nist.gov/vuln/search/results?cpe={info.get('cpe','')}'>Check CVEs</a></li>"
                )
    
        return risk_table, version_warnings

    def _create_report_content(self, data):
        # Device Information Section
        device_info = f"""
        <html>
        <head>
            <title>Security Report - {data['ip']}</title>
        </head>
        <body>
            <h1>Device Scan Report</h1>
        
            <h2>Device Information</h2>
            <table border="1" style="border-collapse: collapse;">
                <tr>
                    <td><strong>IP Address</strong></td>
                    <td>{data['ip']}</td>
                </tr>
                <tr>
                    <td><strong>MAC Address</strong></td>
                    <td>{data['mac']}</td>
                </tr>
                <tr>
                    <td><strong>Vendor</strong></td>
                    <td>{data['vendor']}</td>
                </tr>
                <tr>
                    <td><strong>Detected OS</strong></td>
                    <td>{data['os']}</td>
                </tr>
            </table>
        """

        # Advanced Scan Section (only if scan was performed)
        if data['ip'] in getattr(self, 'advanced_scan_results', {}):
            scan_data = self.advanced_scan_results[data['ip']]
            table_rows = []
        
            for port, info in scan_data['tcp'].items():
                table_rows.append(f"""
                <tr>
                    <td>{port}/{info['name']}</td>
                    <td>{info['product']}</td>
                    <td>{info.get('version', 'N/A')}</td>
                    <td>{info.get('extrainfo', 'N/A')}</td>
                    <td>{info.get('cpe', 'N/A')}</td>
                </tr>
                """)
        
            device_info += f"""
            <h2>Full Port Scan Results</h2>
        
            <table border="1" style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                <tr style="background-color: #f0f0f0;">
                    <th style="padding: 8px;">Port/Protocol</th>
                    <th style="padding: 8px;">Service</th>
                    <th style="padding: 8px;">Version</th>
                    <th style="padding: 8px;">Additional Info</th>
                    <th style="padding: 8px;">CPE (cpe:/part:vendor:product:version)</th>
                </tr>
                {"".join(table_rows)}
            </table>
        """
        # Here is Risk Assessment On the Report
        if data['ip'] in getattr(self, 'advanced_scan_results', {}):
            scan_data = self.advanced_scan_results[data['ip']]
            risk_table, version_warnings = self._generate_risk_assessment(scan_data)
    
            device_info += f"""
            <h2>Security Assessment</h2>
    
            <h3>Port Risk Analysis</h3>
            <table border="1" style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <tr style="background-color: #f0f0f0;">
                    <th>Port</th>
                    <th>Service</th>
                    <th>Risk Level</th>
                    <th>Recommendation</th>
                </tr>
                {"".join(risk_table)}
            </table>
    
            <h3>Version Checks</h3>
            <ul>
                {"".join(version_warnings)}
            </ul>
            """


        # Close HTML tags
        device_info += """
        </body>
        </html>
        """
    
        return device_info


    def _format_finding(self, finding):
        return f"""
        <div class="finding {finding['risk'].lower()}">
            <h4>{finding['type']} - {finding['description']}</h4>
            <p><strong>Risk Level:</strong> {finding['risk']}</p>
            <p><strong>Recommendation:</strong> {finding['mitigation']}</p>
        </div>
        """

    def _format_vulnerability(self, vuln):
        risk_level = 'low'
        if isinstance(vuln['cvss_score'], (int, float)):
            if vuln['cvss_score'] >= 9.0:
                risk_level = 'critical'
            elif vuln['cvss_score'] >= 7.0:
                risk_level = 'high'
            elif vuln['cvss_score'] >= 4.0:
                risk_level = 'medium'
        
        return f"""
        <div class="vulnerability {risk_level}">
            <h4>{vuln['id']} (CVSS: {vuln['cvss_score']})</h4>
            <p><strong>Source:</strong> {vuln['source']}</p>
            <p><strong>Description:</strong> {vuln['description']}</p>
        </div>
        """

    def _show_report_popup(self, filename, content):
        msg = QMessageBox()
        msg.setWindowTitle("Report Generated")
        msg.setText(f"Security report saved as {filename}\n\nOpen now?")
        msg.setStandardButtons(QMessageBox.Open | QMessageBox.Close)
        msg.setDefaultButton(QMessageBox.Open)
        
        if msg.exec_() == QMessageBox.Open:
            import webbrowser
            webbrowser.open(filename)

    def _set_loading(self, text):
        self.loading_label.setText(text)
        QApplication.processEvents()

    def _clear_loading(self):
        self.loading_label.clear()

    def _show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self._clear_loading()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkScannerApp()
    window.show()
    sys.exit(app.exec_())








