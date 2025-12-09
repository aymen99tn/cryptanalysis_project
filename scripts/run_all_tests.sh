#!/bin/bash
# Master Script - Run ALL Client → Server Experiments
# This runs all tests from to-do.md and generates final report

if [ -z "$1" ]; then
  echo "╔═══════════════════════════════════════════════════════════════════╗"
  echo "║          Master Test Suite - Client → Server                     ║"
  echo "╚═══════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "Usage: $0 <wsl-ip> [--with-pcap]"
  echo ""
  echo "Arguments:"
  echo "  <wsl-ip>      : IP address of WSL server (e.g., 172.21.144.1)"
  echo "  --with-pcap   : Also run packet captures (requires sudo)"
  echo ""
  echo "Examples:"
  echo "  $0 172.21.144.1"
  echo "  $0 172.21.144.1 --with-pcap"
  echo ""
  echo "This will run:"
  echo "  1. Network baseline tests"
  echo "  2. TLS 1.3 latency analysis (100 samples)"
  echo "  3. Throughput with confidence intervals (10 trials)"
  echo "  4. Memory footprint analysis"
  echo "  5. TLS 1.2 rejection verification"
  echo "  6. Cold start vs warm cache"
  echo "  7. Sustained load test (5000 requests)"
  echo "  8. Packet captures (if --with-pcap)"
  echo ""
  exit 1
fi

WSL_IP=$1
WITH_PCAP=$2

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║     MASTER TEST SUITE - Client → Server                           ║"
echo "║     Implementing ALL experiments from to-do.md                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Configuration:"
echo "  WSL Server IP: $WSL_IP"
echo "  Client IP: $(hostname -I | awk '{print $1}')"
if [ "$WITH_PCAP" == "--with-pcap" ]; then
  echo "  Include packet capture: YES (requires sudo)"
else
  echo "  Include packet capture: NO"
fi
echo ""
echo "Press Enter to start, or Ctrl+C to cancel..."
read

# ═══════════════════════════════════════════════════════════════════
# Step 1: Verify connectivity
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "STEP 1: Verifying Connectivity"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

if ! ping -c 1 $WSL_IP &> /dev/null; then
  echo "❌ Cannot reach WSL server at $WSL_IP"
  echo "Please check:"
  echo "  1. WSL is running"
  echo "  2. Server is started: ./server"
  echo "  3. Network connectivity"
  exit 1
fi

if ! timeout 2 telnet $WSL_IP 8080 < /dev/null &> /dev/null; then
  echo "❌ Port 8080 not reachable on $WSL_IP"
  echo "Please ensure server is running: ./server"
  exit 1
fi

echo "✓ Connectivity verified"
echo ""

# ═══════════════════════════════════════════════════════════════════
# Step 2: Run comprehensive tests
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "STEP 2: Running Comprehensive Test Suite"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "This will take approximately 10-15 minutes..."
echo ""

chmod +x client_comprehensive_tests.sh
./comprehensive_tests.sh $WSL_IP

if [ $? -ne 0 ]; then
  echo "❌ Comprehensive tests failed"
  exit 1
fi

echo ""
echo "✓ Comprehensive tests complete"
echo ""

# ═══════════════════════════════════════════════════════════════════
# Step 3: Packet capture (optional)
# ═══════════════════════════════════════════════════════════════════
if [ "$WITH_PCAP" == "--with-pcap" ]; then
  echo ""
  echo "═══════════════════════════════════════════════════════════════════"
  echo "STEP 3: Packet Capture"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "This requires sudo privileges..."
  echo ""

  chmod +x packet_capture.sh
  sudo ./packet_capture.sh $WSL_IP

  if [ $? -ne 0 ]; then
    echo "⚠️  Packet capture failed (continuing anyway)"
  else
    echo ""
    echo "✓ Packet capture complete"
  fi
else
  echo ""
  echo "═══════════════════════════════════════════════════════════════════"
  echo "STEP 3: Packet Capture (SKIPPED)"
  echo "═══════════════════════════════════════════════════════════════════"
  echo ""
  echo "To include packet capture, run:"
  echo "  $0 $WSL_IP --with-pcap"
  echo ""
fi

# ═══════════════════════════════════════════════════════════════════
# Step 4: Generate final report
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "STEP 4: Generating Final Report"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

REPORT_FILE="EXPERIMENTAL_RESULTS_KALI.md"

cat > $REPORT_FILE << 'EOF'
# Experimental Results - Kali VM → WSL Server

## Network Topology

```
┌─────────────────────┐         ┌─────────────────────┐
│                     │ Network │     
│   (Client)          │ ←─────→ │   (Server)          │
│                     │         │                     │
│ Custom TLS Client   │  TLS    │ Custom TLS Server   │
│ OpenSSL 3.x         │  1.3    │ OpenSSL 3.0.2       │
└─────────────────────┘         └─────────────────────┘
    Real VM Network              NOT Loopback
```

## Test Environment

- **TLS Library**: OpenSSL 3.x (both sides)
- **Test Date**: $(date +"%B %d, %Y")

## Significance of Network Topology

Unlike loopback testing (127.0.0.1), this setup demonstrates:
- ✅ Real network stack traversal
- ✅ VM network interface overhead
- ✅ Realistic latency measurements
- ✅ Actual packet routing

EOF

# Extract results from comprehensive test output
RESULTS_DIR="kali_comprehensive_results"

echo "## Experimental Results" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Add detailed results
if [ -f "$RESULTS_DIR/03_throughput_stats.txt" ]; then
  echo "### 1. Throughput Analysis (Statistical Rigor)" >> $REPORT_FILE
  echo "" >> $REPORT_FILE
  echo "\`\`\`" >> $REPORT_FILE
  cat $RESULTS_DIR/03_throughput_stats.txt >> $REPORT_FILE
  echo "\`\`\`" >> $REPORT_FILE
  echo "" >> $REPORT_FILE
fi

if [ -f "$RESULTS_DIR/02_tls13_handshake_latency.txt" ]; then
  echo "### 2. TLS 1.3 Latency Distribution" >> $REPORT_FILE
  echo "" >> $REPORT_FILE
  echo "100 samples analyzed. See \`$RESULTS_DIR/02_tls13_handshake_latency.txt\`" >> $REPORT_FILE
  echo "" >> $REPORT_FILE
fi

# Add packet capture info if available
if [ -d "kali_pcap_captures" ]; then
  echo "### 3. Packet Captures" >> $REPORT_FILE
  echo "" >> $REPORT_FILE
  echo "Captured scenarios:" >> $REPORT_FILE
  echo "\`\`\`" >> $REPORT_FILE
  ls -lh kali_pcap_captures/*.pcap 2>/dev/null | awk '{print $9, $5}' >> $REPORT_FILE
  echo "\`\`\`" >> $REPORT_FILE
  echo "" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "---" >> $REPORT_FILE
echo "" >> $REPORT_FILE
echo "**Generated**: $(date)" >> $REPORT_FILE
echo "**Test Duration**: Complete test suite execution" >> $REPORT_FILE

echo "✓ Report generated: $REPORT_FILE"
echo ""

# ═══════════════════════════════════════════════════════════════════
# Final Summary
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    ALL TESTS COMPLETE                             ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Results Location:"
echo "  • Test results: kali_comprehensive_results/"
echo "  • Packet captures: kali_pcap_captures/ (if captured)"
echo "  • Final report: $REPORT_FILE"
echo ""
echo "Files generated:"
ls -lh kali_comprehensive_results/ 2>/dev/null
echo ""
if [ -d "kali_pcap_captures" ]; then
  echo "Packet captures:"
  ls -lh kali_pcap_captures/*.pcap 2>/dev/null
  echo ""
fi
echo "═══════════════════════════════════════════════════════════════════"
echo "Next steps:"
echo "  1. Review results in kali_comprehensive_results/"
echo "  2. Analyze packet captures with Wireshark"
echo "  3. Use data for ACM report: $REPORT_FILE"
echo "═══════════════════════════════════════════════════════════════════"
