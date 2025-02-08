# InvifiScan - Advanced Network Scanner 🕵️‍♂️

InvifiScan is a powerful and versatile network scanning tool designed for network administrators, security professionals, and enthusiasts. With its ability to perform both network discovery and port scanning, InvifiScan helps you identify active devices on your network and check for open ports, making it an essential tool for network security assessments.

## Features ✨
- **Network Discovery**: Identify active devices on your local network.
- **Port Scanning**: Scan for open ports on a target IP address or domain.
- **Stealth Mode**: Perform stealthy scans to avoid detection.
- **Fast Scan**: Quickly scan common ports for rapid assessments.
- **Service Detection**: Identify services running on open ports.

## Requirements 📦
- Python 3.x
- Scapy library (`pip install scapy`)

## Installation 🚀
1. Clone the repository or download the script.
2. Ensure you have Python 3.x installed on your system.
3. Install the required libraries:
   ```bash
   pip install scapy
   ```

## Usage 📖
To use InvifiScan, run the script from the command line with the desired options. Here are some examples:

### Basic Usage
```bash
python3 Invifi_scan.py <target>
```
- Replace `<target>` with an IP address, domain name, or subnet (e.g., `192.168.1.1`, `example.com`, `192.168.1.0/24`).

### Fast Scan (Common Ports Only)
```bash
python3 Invifi_scan.py <target> -f
```

### Stealth Mode
```bash
python3 Invifi_scan.py <target> -s
```

### Custom Delay in Stealth Mode
```bash
python3 Invifi_scan.py <target> -s -d <delay>
```
- Replace `<delay>` with the desired delay in seconds (default is 0.1 seconds).

### Network Devices Discovery
```bash
python3 Invifi_scan.py <subnet> -n
```
- Replace `<subnet>` with the subnet you want to scan (e.g., `192.168.1.0/24`).

## Example Output 📊
```
██╗███╗   ██╗██╗   ██╗██╗███████╗██╗███████╗ ██████╗ █████╗ ███╗   ██╗
...
[*] Scanning network 192.168.1.0/24 for active devices...
[+] Resolved example.com to IP: 93.184.216.34
Scan results for 93.184.216.34:
PORT     STATE   SERVICE
80      open    http
443     open    https
```

## To-Do List 📝
- [ ] **Windows Support**: Enhance the script to support Windows environments.
- [ ] **GUI Version**: Develop a graphical user interface for easier usage.
- [ ] **Advanced Scanning Options**: Add more scanning techniques and options.
- [ ] **Output Formats**: Implement options to export scan results in different formats (e.g., JSON, CSV).
- [ ] **Integration with Other Tools**: Allow integration with other security tools for comprehensive assessments.

## Contributing 🤝
Contributions are welcome! If you have suggestions or improvements, feel free to open an issue or submit a pull request.


## Acknowledgments 🙏
- Thanks to the Scapy team for providing an excellent library for network packet manipulation.

---

Feel free to reach out if you have any questions or need assistance! Happy scanning! 🕵️‍♀️
