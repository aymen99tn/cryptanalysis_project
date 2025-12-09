#!/bin/bash
# Packet Capture Script - Kali VM → WSL Server
# Must-Have Test 1.2: Wire-Level Overhead Analysis
# Requires: sudo privileges

if [ -z "$1" ]; then
  echo "Usage: sudo $0 <wsl-ip>"
  echo "Example: sudo $0 172.21.144.1"
  exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "This script requires sudo privileges for tcpdump"
  echo "Please run: sudo $0 $1"
  exit 1
fi

WSL_IP=$1
PCAP_DIR="kali_pcap_captures"
mkdir -p $PCAP_DIR

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║     Wire-Level Packet Capture - Kali VM → WSL Server             ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Target: $WSL_IP:8080"
echo "Capture interface: any (all interfaces)"
echo "Filter: host $WSL_IP and port 8080"
echo ""

# Function to capture scenario
capture_scenario() {
  scenario_name=$1
  description=$2
  pcap_file="${PCAP_DIR}/${scenario_name}.pcap"

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Scenario: $description"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "File: $pcap_file"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# Scenario A: TLS 1.3 Single Request (Kali → WSL)
# ═══════════════════════════════════════════════════════════════════
capture_scenario "scenario_a_tls13_single_kali_wsl" "TLS 1.3 single request (Kali client → WSL server)"

echo "Starting capture..."
timeout 10 tcpdump -i any -w $PCAP_DIR/scenario_a_tls13_single_kali_wsl.pcap \
  host $WSL_IP and port 8080 &
TCPDUMP_PID=$!

sleep 1
echo "Sending request..."
./client $WSL_IP 8080 welcome > /dev/null 2>&1

sleep 2
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

if [ -f "$PCAP_DIR/scenario_a_tls13_single_kali_wsl.pcap" ]; then
  packets=$(tcpdump -r $PCAP_DIR/scenario_a_tls13_single_kali_wsl.pcap 2>/dev/null | wc -l)
  size=$(ls -lh $PCAP_DIR/scenario_a_tls13_single_kali_wsl.pcap | awk '{print $5}')
  echo "✓ Captured: $packets packets ($size)"
else
  echo "✗ Failed"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════
# Scenario B: TLS 1.2 Rejection Attempt
# ═══════════════════════════════════════════════════════════════════
capture_scenario "scenario_b_tls12_rejected_kali_wsl" "TLS 1.2 connection attempt (should be rejected)"

echo "Starting capture..."
timeout 10 tcpdump -i any -w $PCAP_DIR/scenario_b_tls12_rejected_kali_wsl.pcap \
  host $WSL_IP and port 8080 &
TCPDUMP_PID=$!

sleep 1
echo "Attempting TLS 1.2 connection..."
echo "GET welcome" | timeout 3 openssl s_client -connect $WSL_IP:8080 -tls1_2 -quiet > /dev/null 2>&1 || true

sleep 2
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

if [ -f "$PCAP_DIR/scenario_b_tls12_rejected_kali_wsl.pcap" ]; then
  packets=$(tcpdump -r $PCAP_DIR/scenario_b_tls12_rejected_kali_wsl.pcap 2>/dev/null | wc -l)
  size=$(ls -lh $PCAP_DIR/scenario_b_tls12_rejected_kali_wsl.pcap | awk '{print $5}')
  echo "✓ Captured: $packets packets ($size)"
else
  echo "✗ Failed"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════
# Scenario C: Multiple Sequential Requests (5x)
# ═══════════════════════════════════════════════════════════════════
capture_scenario "scenario_c_multiple_requests_kali_wsl" "5 sequential TLS 1.3 requests"

echo "Starting capture..."
timeout 15 tcpdump -i any -w $PCAP_DIR/scenario_c_multiple_requests_kali_wsl.pcap \
  host $WSL_IP and port 8080 &
TCPDUMP_PID=$!

sleep 1
echo "Sending 5 sequential requests..."
for i in {1..5}; do
  ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  echo "  Request $i/5 sent"
done

sleep 2
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

if [ -f "$PCAP_DIR/scenario_c_multiple_requests_kali_wsl.pcap" ]; then
  packets=$(tcpdump -r $PCAP_DIR/scenario_c_multiple_requests_kali_wsl.pcap 2>/dev/null | wc -l)
  size=$(ls -lh $PCAP_DIR/scenario_c_multiple_requests_kali_wsl.pcap | awk '{print $5}')
  echo "✓ Captured: $packets packets ($size)"
else
  echo "✗ Failed"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════
# Scenario D: TLS 1.3 with OpenSSL s_client
# ═══════════════════════════════════════════════════════════════════
capture_scenario "scenario_d_openssl_client_kali_wsl" "TLS 1.3 with openssl s_client"

echo "Starting capture..."
timeout 10 tcpdump -i any -w $PCAP_DIR/scenario_d_openssl_client_kali_wsl.pcap \
  host $WSL_IP and port 8080 &
TCPDUMP_PID=$!

sleep 1
echo "Connecting with openssl s_client..."
if [ -f "cert.pem" ]; then
  echo "GET welcome" | timeout 3 openssl s_client -connect $WSL_IP:8080 -tls1_3 -CAfile cert.pem -quiet > /dev/null 2>&1 || true
else
  echo "GET welcome" | timeout 3 openssl s_client -connect $WSL_IP:8080 -tls1_3 -quiet > /dev/null 2>&1 || true
fi

sleep 2
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

if [ -f "$PCAP_DIR/scenario_d_openssl_client_kali_wsl.pcap" ]; then
  packets=$(tcpdump -r $PCAP_DIR/scenario_d_openssl_client_kali_wsl.pcap 2>/dev/null | wc -l)
  size=$(ls -lh $PCAP_DIR/scenario_d_openssl_client_kali_wsl.pcap | awk '{print $5}')
  echo "✓ Captured: $packets packets ($size)"
else
  echo "✗ Failed"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════
# Scenario E: Handshake-Only (Connection without application data)
# ═══════════════════════════════════════════════════════════════════
capture_scenario "scenario_e_handshake_only_kali_wsl" "TLS handshake only (no application data)"

echo "Starting capture..."
timeout 10 tcpdump -i any -w $PCAP_DIR/scenario_e_handshake_only_kali_wsl.pcap \
  host $WSL_IP and port 8080 &
TCPDUMP_PID=$!

sleep 1
echo "Initiating handshake without sending application data..."
timeout 2 openssl s_client -connect $WSL_IP:8080 -tls1_3 > /dev/null 2>&1 || true

sleep 2
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

if [ -f "$PCAP_DIR/scenario_e_handshake_only_kali_wsl.pcap" ]; then
  packets=$(tcpdump -r $PCAP_DIR/scenario_e_handshake_only_kali_wsl.pcap 2>/dev/null | wc -l)
  size=$(ls -lh $PCAP_DIR/scenario_e_handshake_only_kali_wsl.pcap | awk '{print $5}')
  echo "✓ Captured: $packets packets ($size)"
else
  echo "✗ Failed"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                 Packet Capture Complete                          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Captured files in $PCAP_DIR:"
echo ""
ls -lh $PCAP_DIR/*.pcap 2>/dev/null | awk '{printf "  %-50s %8s\n", $9, $5}'
echo ""

# Quick analysis
echo "Packet counts per scenario:"
for f in $PCAP_DIR/*.pcap; do
  if [ -f "$f" ]; then
    count=$(tcpdump -r "$f" 2>/dev/null | wc -l)
    printf "  %-50s %4d packets\n" "$(basename $f):" "$count"
  fi
done
echo ""

echo "═══════════════════════════════════════════════════════════════════"
echo "Analysis Commands:"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "# View in Wireshark:"
echo "  wireshark $PCAP_DIR/*.pcap &"
echo ""
echo "# Show TLS handshake messages:"
echo "  tshark -r $PCAP_DIR/scenario_a_tls13_single_kali_wsl.pcap -Y \"tls.handshake\" -V"
echo ""
echo "# Count bytes exchanged:"
echo "  tcpdump -r $PCAP_DIR/scenario_a_tls13_single_kali_wsl.pcap -n -q"
echo ""
echo "# Export to CSV:"
echo "  tshark -r $PCAP_DIR/scenario_a_tls13_single_kali_wsl.pcap -T fields -E separator=, -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e frame.len > analysis.csv"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
