import sys
from scapy.all import ARP, Ether, srp, sniff
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import nmap
import time


class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(int)  # Signal to send captured packet size

    def __init__(self, target_ips):
        super().__init__()
        self.target_ips = target_ips
        self.running = True

    def run(self):
        # Start sniffing packets
        sniff(prn=self.process_packet, stop_filter=self.should_stop)

    def process_packet(self, packet):
        if not self.running:
            return False

        # Filter packets by target IPs
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            length = len(packet)  # Packet size

            if src_ip in self.target_ips or dst_ip in self.target_ips:
                self.packet_captured.emit(length)  # Emit the packet size to the GUI

    def should_stop(self, packet):
        return not self.running

    def stop(self):
        self.running = False


class TrafficGraph(FigureCanvas):
    def __init__(self):
        self.figure = Figure()
        super().__init__(self.figure)
        self.ax = self.figure.add_subplot(111)
        self.reset_graph()

    def reset_graph(self):
        """Reset the graph to an empty state."""
        self.ax.clear()
        self.ax.set_title("Real-Time Traffic")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Packet Size (bytes)")
        self.ax.grid()
        self.packet_sizes = []
        self.timestamps = []
        self.draw()

    def update_graph(self, packet_size):
        """Update the graph with new packet data."""
        current_time = time.time()
        self.timestamps.append(current_time)
        self.packet_sizes.append(packet_size)

        # Keep only the last 100 points for better visualization
        if len(self.timestamps) > 100:
            self.timestamps = self.timestamps[-100:]
            self.packet_sizes = self.packet_sizes[-100:]

        # Update the graph
        self.ax.clear()
        self.ax.set_title("Real-Time Traffic")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Packet Size (bytes)")
        self.ax.grid()
        self.ax.plot(self.timestamps, self.packet_sizes, color="blue", marker="o")
        self.draw()


class IntegratedApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("YHMi IoT Security Tool")
        self.setGeometry(100, 100, 1200, 700)

        # IP Range input for device discovery
        self.ip_label = QLabel("Enter IP Range:")
        self.ip_input = QLineEdit(self)
        self.ip_input.setText("192.168.1.0/24")  # Default subnet

        # Buttons for device discovery
        self.scan_button = QPushButton("Scan for Devices", self)
        self.scan_button.clicked.connect(self.scan_devices)

        # Buttons for packet monitoring
        self.start_monitoring_button = QPushButton("Start Monitoring", self)
        self.start_monitoring_button.clicked.connect(self.start_monitoring)
        self.start_monitoring_button.setEnabled(False)  # Enable only after device discovery
        self.stop_monitoring_button = QPushButton("Stop Monitoring", self)
        self.stop_monitoring_button.clicked.connect(self.stop_monitoring)
        self.stop_monitoring_button.setEnabled(False)

        # Button for checking cryptographic details
        self.crypto_button = QPushButton("Check Cryptographic Details", self)
        self.crypto_button.clicked.connect(self.check_cryptographic_details)
        self.crypto_button.setEnabled(False)  # Enable only after device discovery

        # Table for displaying discovered devices with checkboxes
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(["Select", "IP Address", "MAC Address"])

        # Real-time traffic graph
        self.traffic_graph = TrafficGraph()

        # Label to display the currently monitored IP
        self.current_ip_label = QLabel("Currently Monitoring: None")
        self.current_ip_label.setAlignment(Qt.AlignCenter)
        self.current_ip_label.setStyleSheet("font-weight: bold; color: green;")

        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)

        # Label for cryptographic details
        self.crypto_label = QLabel("Cryptographic Details: None")
        self.crypto_label.setAlignment(Qt.AlignCenter)
        self.crypto_label.setStyleSheet("font-weight: bold; color: blue;")

        # Layouts
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.ip_label)
        input_layout.addWidget(self.ip_input)

        device_layout = QVBoxLayout()
        device_layout.addWidget(QLabel("Discovered Devices:"))
        device_layout.addWidget(self.device_table)

        monitoring_button_layout = QHBoxLayout()
        monitoring_button_layout.addWidget(self.start_monitoring_button)
        monitoring_button_layout.addWidget(self.stop_monitoring_button)

        crypto_button_layout = QHBoxLayout()
        crypto_button_layout.addWidget(self.crypto_button)

        main_layout = QVBoxLayout()
        main_layout.addLayout(input_layout)
        main_layout.addWidget(self.scan_button)
        main_layout.addWidget(self.status_label)
        main_layout.addLayout(device_layout)
        main_layout.addWidget(self.current_ip_label)
        main_layout.addLayout(monitoring_button_layout)
        main_layout.addWidget(QLabel("Traffic Graph:"))
        main_layout.addWidget(self.traffic_graph)
        main_layout.addLayout(crypto_button_layout)
        main_layout.addWidget(self.crypto_label)

        self.setLayout(main_layout)

        self.sniffer_thread = None

    def scan_devices(self):
        # Clear previous results
        self.device_table.setRowCount(0)

        # Get IP range from user input
        ip_range = self.ip_input.text().strip()
        self.status_label.setText("Scanning for devices...")
        self.status_label.setStyleSheet("color: blue;")
        QApplication.processEvents()  # Update GUI immediately

        try:
            # Create ARP request packet
            arp_request = ARP(pdst=ip_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Send the request and receive responses
            answered, _ = srp(arp_request_broadcast, timeout=2, verbose=0)

            if not answered:
                # No devices found
                self.status_label.setText("No devices found.")
                self.status_label.setStyleSheet("color: red;")
                return

            # Populate table with results
            for i, (sent, received) in enumerate(answered):
                self.device_table.insertRow(i)

                # Checkbox for selecting devices
                checkbox = QCheckBox()
                self.device_table.setCellWidget(i, 0, checkbox)

                # IP and MAC addresses
                self.device_table.setItem(i, 1, QTableWidgetItem(received.psrc))  # IP Address
                self.device_table.setItem(i, 2, QTableWidgetItem(received.hwsrc))  # MAC Address

            # Update status label
            self.status_label.setText(f"Scan complete: {len(answered)} device(s) found.")
            self.status_label.setStyleSheet("color: green;")
            self.start_monitoring_button.setEnabled(True)  # Enable monitoring button
            self.crypto_button.setEnabled(True)  # Enable cryptographic analysis button

        except Exception as e:
            # Handle errors during scanning
            self.status_label.setText(f"Error: {e}")
            self.status_label.setStyleSheet("color: red;")

    def start_monitoring(self):
        # Get selected devices
        target_ips = []
        for row in range(self.device_table.rowCount()):
            checkbox = self.device_table.cellWidget(row, 0)
            if checkbox.isChecked():
                ip = self.device_table.item(row, 1).text()
                target_ips.append(ip)

        if not target_ips:
            self.status_label.setText("Error: No devices selected for monitoring.")
            self.status_label.setStyleSheet("color: red;")
            return

        # Display the currently monitored IP(s)
        self.current_ip_label.setText(f"Currently Monitoring: {', '.join(target_ips)}")

        # Reset the graph
        self.traffic_graph.reset_graph()

        # Start packet sniffer thread
        self.sniffer_thread = PacketSnifferThread(target_ips)
        self.sniffer_thread.packet_captured.connect(self.traffic_graph.update_graph)
        self.sniffer_thread.start()

        # Update UI
        self.status_label.setText("Monitoring started...")
        self.status_label.setStyleSheet("color: blue;")
        self.start_monitoring_button.setEnabled(False)
        self.stop_monitoring_button.setEnabled(True)

    def stop_monitoring(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()

        # Reset current IP label
        self.current_ip_label.setText("Currently Monitoring: None")

        # Update UI
        self.status_label.setText("Monitoring stopped.")
        self.status_label.setStyleSheet("color: green;")
        self.start_monitoring_button.setEnabled(True)
        self.stop_monitoring_button.setEnabled(False)

    def check_cryptographic_details(self):
        # Get selected devices
        selected_ips = []
        for row in range(self.device_table.rowCount()):
            checkbox = self.device_table.cellWidget(row, 0)
            if checkbox.isChecked():
                ip = self.device_table.item(row, 1).text()
                selected_ips.append(ip)

        if not selected_ips:
            self.crypto_label.setText("Cryptographic Details: No device selected.")
            self.crypto_label.setStyleSheet("color: red;")
            return

        # Use nmap to check for open ports and infer encryption status
        nm = nmap.PortScanner()
        details = []

        for ip in selected_ips:
            try:
                nm.scan(ip, arguments='-p 1-1000')  # Scan ports 1-1000
                open_ports = [port for port, data in nm[ip]['tcp'].items() if data['state'] == 'open']

                # Analyze open ports for cryptographic inference
                if 443 in open_ports or 22 in open_ports:
                    details.append(f"Device {ip}: Strong Encryption (e.g., HTTPS or SSH detected)")
                elif 23 in open_ports or 80 in open_ports:
                    details.append(f"Device {ip}: Weak or No Encryption (Telnet or HTTP detected)")
                else:
                    details.append(f"Device {ip}: Encryption status unknown")

            except Exception as e:
                details.append(f"Device {ip}: Error during port scan")

        # Update cryptographic label
        self.crypto_label.setText(" | ".join(details))
        self.crypto_label.setStyleSheet("color: blue;")


# Run the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IntegratedApp()
    window.show()
    sys.exit(app.exec_())
