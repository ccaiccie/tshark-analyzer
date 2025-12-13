# PCAP Analyzer

An automated network traffic analysis tool with a PyQt6 GUI interface that uses tshark as a backend to detect network issues, performance problems, and anomalies in PCAP files.

## Features

### Analysis Capabilities
- **TCP Analysis**: Detects retransmissions, duplicate ACKs, connection resets, zero window events, out-of-order packets, and high RTT
- **DNS Analysis**: Identifies failed queries (NXDOMAIN, SERVFAIL), timeouts, and high query volumes
- **HTTP/HTTPS Analysis**: Finds 4xx/5xx errors, analyzes response codes, and identifies top URLs
- **Network Layer Analysis**: Detects ICMP errors, ARP conflicts, broadcast storms, and protocol distribution

### User Interface
- Modern PyQt6 GUI with tabbed interface
- Real-time progress indication during analysis
- Tree view for organized issue display
- Color-coded severity levels (Critical, Warning, Info)
- Statistics and detailed report tabs

### Export Options
- Export reports as Text, HTML, or JSON
- Professional HTML reports with styling
- JSON format for automation/integration

## Requirements

- Python 3.7+
- PyQt6
- tshark (part of Wireshark)

### Installing tshark

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download and install Wireshark from https://www.wireshark.org/download.html

## Installation

1. Clone or download this repository

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Make sure tshark is installed and accessible from command line:
```bash
tshark --version
```

## Usage

### GUI Mode (Recommended)

Run the GUI application:
```bash
python main_gui.py
```

Or make it executable:
```bash
chmod +x main_gui.py
./main_gui.py
```

**Steps:**
1. Click "Browse..." to select a PCAP file
2. Click "Analyze" to start the analysis
3. View results in the Overview, Statistics, and Detailed Report tabs
4. Export results using the export buttons at the bottom

### CLI Mode

You can also run the analyzer from command line:
```bash
python pcap_analyzer.py capture.pcap
```

Options:
- `-f, --format`: Output format (text, json, html) - default: text
- `-o, --output`: Output file path (default: stdout)

Examples:
```bash
# Text output to console
python pcap_analyzer.py capture.pcap

# HTML report to file
python pcap_analyzer.py capture.pcap -f html -o report.html

# JSON output
python pcap_analyzer.py capture.pcap -f json -o results.json
```

## Issue Categories

### Critical
- High numbers of TCP retransmissions (>100)
- Multiple HTTP 5xx server errors (>5)
- Significant DNS query timeouts (>20)

### Warning
- Moderate TCP retransmissions
- TCP connection resets
- Zero window events (flow control issues)
- DNS failures (NXDOMAIN, SERVFAIL)
- HTTP 4xx client errors
- ICMP destination unreachable
- ARP conflicts
- High broadcast traffic

### Informational
- TCP fast retransmissions
- Out-of-order packets
- Protocol distribution
- Top bandwidth consumers
- Top DNS queries
- Top HTTP URLs

## Project Structure

```
pcap_analyzer/
├── main_gui.py              # GUI entry point
├── pcap_analyzer.py         # CLI entry point and main analyzer class
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── core/
│   ├── __init__.py
│   ├── tshark_wrapper.py   # Wrapper around tshark commands
│   └── report_generator.py # Report generation in multiple formats
├── analyzers/
│   ├── __init__.py
│   ├── base_analyzer.py    # Base class for analyzers
│   ├── tcp_analyzer.py     # TCP protocol analyzer
│   ├── dns_analyzer.py     # DNS protocol analyzer
│   ├── http_analyzer.py    # HTTP/HTTPS protocol analyzer
│   └── network_analyzer.py # Network layer analyzer
└── gui/
    ├── __init__.py
    └── main_window.py      # Main PyQt6 window
```

## How It Works

1. **TShark Wrapper**: Executes tshark commands to extract information from PCAP files
2. **Analyzers**: Specialized modules analyze different protocol layers
3. **Issue Detection**: Each analyzer identifies problems and categorizes by severity
4. **Report Generation**: Results are formatted for display or export
5. **GUI**: PyQt6 interface provides user-friendly interaction

## Use Cases

- **Network Troubleshooting**: "Why is this application slow?" - Identifies if it's network latency, packet loss, or server delays
- **Error Detection**: "Are there network errors?" - Finds retransmissions, resets, ICMP errors
- **DNS Issues**: "What's causing DNS problems?" - Detects slow/failed DNS queries
- **Security Analysis**: Spots unusual patterns, port scans, or anomalous traffic
- **Performance Analysis**: Analyzes RTT, throughput, and identifies bottlenecks

## Example Output

```
======================================================================
PCAP ANALYSIS REPORT
======================================================================
File: capture.pcap
Packets: 45,231
Duration: 5 minutes 32 seconds

CRITICAL ISSUES (3)
----------------------------------------------------------------------
  [TCP Retransmissions] Detected 234 TCP retransmissions
    Impact: Indicates packet loss or network congestion
  [DNS Timeouts] 12 DNS queries without responses
    Impact: DNS resolution failures or timeouts

WARNINGS (5)
----------------------------------------------------------------------
  [High Latency] Average RTT is 450.23ms (max: 1250.45ms)
    Impact: High network latency detected
  [TCP Resets] Detected 8 TCP connection resets
    Impact: Connections terminated abruptly
...
```

## Future Enhancements

- Real-time capture and analysis
- Baseline comparison mode
- Machine learning anomaly detection
- Integration with Wireshark (open filtered results)
- Plugin system for custom analyzers
- Scheduled analysis and monitoring
- Email alerts for critical issues

## License

This project is provided as-is for educational and professional use.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## Support

For questions or issues, please check the documentation or submit an issue on the project repository.
