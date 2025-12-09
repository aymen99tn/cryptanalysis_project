# TLS 1.3 Secure Document Server

A demonstration of a secure document retrieval system built with TLS 1.3, AEAD encryption, and perfect forward secrecy.

**University of New Brunswick** | **Winter 2025**

---

## 🎯 Quick Start

### One-Command Demo
```bash
./scripts/start_demo.sh
```

This launches an interactive setup where you can choose:
1.  **Local Demo:** Runs Server and Client on the same machine.
2.  **Server Mode:** Starts the TLS server (displays LAN IP) and waits for connections.
3.  **Client Mode:** Connects to a remote TLS server (you provide the IP).

See [`docs/QUICK_START.md`](docs/QUICK_START.md) for more examples.

---

## ✨ Features

### Security
- **TLS 1.3 Only** - Rejects TLS 1.2 and below
- **AEAD Cipher Suites** - AES-256-GCM and AES-128-GCM
- **Perfect Forward Secrecy** - Ephemeral (EC)DHE key exchange
- **Certificate Validation** - Configurable verification (supports self-signed)

### Documents
- **15 Diverse Documents** - HTML, JSON, CSV, Markdown, plain text
- **UNB-Themed Content** - Course catalogs, student records, university info
- **Technical Documentation** - TLS specs, cryptography primers, guides
- **Performance Testing** - 1KB and 10KB test documents

### Presentation Features
- **Remote & Local Support** - Run client and server on different devices
- **Colored Client Output** - ANSI colors, emojis, syntax highlighting
- **Terminal UI Tests** - Live progress bars, real-time metrics
- **Terminal UI Monitor** - Real-time server monitoring (server-side)
- **Web Dashboard** - Browser-based monitoring (http://<server-ip>:5000)
- **Wireshark Integration** - Auto-launch with pre-configured filters
- **Packet Analysis** - Automated TLS traffic analysis

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [`QUICK_START.md`](docs/QUICK_START.md) | Quick reference for common operations |
| [`DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) | Comprehensive demonstration scenarios |
| [`docs/DASHBOARD_GUIDE.md`](docs/DASHBOARD_GUIDE.md) | TUI monitor and web dashboard guide |
| [`CLAUDE.md`](docs/dev_notes/CLAUDE.md) | Developer documentation and architecture |
| [`docs/README.md`](docs/README.md) | Detailed technical documentation |
| [`report.pdf`](docs/report.pdf) | ACM-style research report |

---

## 🏗️ Building

```bash
make clean && make
```

**Requirements:**
- C++17 compiler (g++ 9.0+)
- OpenSSL 3.x
- SQLite3

**Optional for full demo features:**
- Python 3.7+ with `rich` library (`pip3 install rich`) - For TUI monitor/tests
- Flask (`pip3 install flask`) - For web dashboard
- Wireshark/tshark - For packet capture
- netcat - For connectivity checks

---

## 🚀 Usage Examples

### Basic Usage (Local)
```bash
# Start server
export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
export TLS_CERT=certs/cert.pem
export TLS_KEY=certs/key.pem
./server

# Fetch a document
./client 127.0.0.1 8080 welcome certs/cert.pem 0
```

### Remote Usage (Different Machines)

**On Server Machine:**
```bash
./scripts/start_demo.sh
# Select Option 2 (Server Mode)
# Note the IP address displayed (e.g., 192.168.1.10)
```

**On Client Machine:**
```bash
# Connect to the server IP
./client 192.168.1.10 8080 welcome certs/cert.pem 0

# Or use the interactive demo:
./scripts/start_demo.sh
# Select Option 3 (Client Mode) and enter 192.168.1.10
```

### Demo Modes
```bash
# Interactive document browser
./scripts/demo_documents.sh <SERVER_IP>

# Beautiful TUI test runner
python3 scripts/run_tests_tui.py <SERVER_IP>

# Terminal UI monitor (Run on Server)
python3 scripts/tui_monitor.py --log-file logs/server.log

# Web dashboard (Run on Server)
./scripts/start_dashboard.sh

# Launch with Wireshark packet capture
./scripts/start_with_wireshark.sh <SERVER_IP>
```

---

## 📊 Performance Metrics

Based on real network testing (Kali VM → WSL):

| Metric | Value | Details |
|--------|-------|---------|
| **TLS 1.3 Latency (mean)** | 9.15 ms | 100 samples |
| **TLS 1.3 Latency (median)** | 8.59 ms | |
| **TLS 1.3 Latency (p99)** | 12.30 ms | |
| **Throughput** | ~53 RPS | Real network |
| **Network RTT** | ~1.0 ms | ICMP baseline |
| **Memory Footprint** | Stable | Zero growth over 100+ connections |
| **Security** | ✅ TLS 1.2 Rejected | Protocol enforcement validated |

See [`docs/EXPERIMENTAL_RESULTS_SUMMARY.md`](docs/EXPERIMENTAL_RESULTS_SUMMARY.md) for detailed analysis.

---

## 🎨 Visual Features

### Before Enhancement
```
Received 101 bytes (text/html):
<html><body><h1>Welcome</h1></body></html>
```

### After Enhancement
```
✓ Connected to 127.0.0.1:8080
🔒 TLSv1.3 (TLS_AES_256_GCM_SHA384) [Session: New]
📄 Document: welcome (text/html, 735 B)

─────────────────────────────────────────────────────────
<!DOCTYPE html><html>...
─────────────────────────────────────────────────────────

⏱  Response time: 6 ms
📊 Throughput: 0.93 Mbps
```

---

## 🔧 Testing

### Comprehensive Test Suite
```bash
# Run all tests (8 tests total)
./scripts/comprehensive_tests.sh 127.0.0.1

# With packet capture (requires sudo)
./scripts/run_all_kali_tests.sh <server-ip> --with-pcap
```

### Individual Tests
- Network baseline (ICMP RTT)
- TLS 1.3 handshake latency (100 samples)
- Throughput testing (10 trials)
- Memory footprint analysis
- Security validation (TLS 1.2 rejection)
- Sustained load testing
- Packet capture and wire-level analysis

---

## 📁 Project Structure

```
.
├── src/
│   ├── server-side.cpp         # TLS 1.3 server implementation
│   ├── client-side.cpp         # TLS 1.3 client with colored output
│   └── sqlite3.c/h             # Bundled SQLite database
├── scripts/
│   ├── start_demo.sh           # One-command demo launcher
│   ├── demo_documents.sh       # Interactive document browser
│   ├── run_tests_tui.py        # Beautiful TUI test runner
│   ├── start_with_wireshark.sh # Auto-launch Wireshark
│   ├── analyze_packets.sh      # Packet analysis tool
│   └── comprehensive_tests.sh  # Complete test suite
├── certs/
│   ├── cert.pem                # Self-signed certificate
│   └── key.pem                 # Private key
├── data/
│   └── documents.db            # SQLite database (auto-created)
├── docs/
│   └── acmart-primary/
│       └── report.tex          # ACM-style report source
├── config/
│   └── wireshark_colorfilters  # Custom Wireshark colors
├── QUICK_START.md              # Quick reference guide
├── DEMO_GUIDE.md               # Comprehensive demo guide
└── report.pdf                  # Compiled research report
```

---

## 🎓 Academic Context

This project demonstrates:
- Modern TLS 1.3 protocol implementation
- Cryptographic best practices (AEAD, PFS)
- Performance analysis and benchmarking
- Network protocol analysis with Wireshark
- Professional software presentation

**Report:** ACM-style 7-page paper documenting design, implementation, and experimental results.

---

## 🐛 Troubleshooting

### Server won't start
```bash
# Check port availability
sudo netstat -tulpn | grep 8080

# Verify library path
export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
```

### Certificate issues
```bash
# Regenerate certificates
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/key.pem -out certs/cert.pem -days 365 \
  -subj "/CN=localhost"
```

### Python dependencies
```bash
pip3 install rich  # For TUI test runner
```

---

## 📄 License

Educational/Research Use - University of New Brunswick

---

## 🤝 Contributing

This is an academic project. For questions or feedback, please refer to the documentation.

---

**Made with ❤️ at University of New Brunswick**
