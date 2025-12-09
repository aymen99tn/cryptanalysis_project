#!/bin/bash
# This demonstrates real network communication (not loopback)

if [ -z "$1" ]; then
  echo "Usage: $0 <wsl-ip>"
  echo "Example: $0 172.21.144.1"
  exit 1
fi

WSL_IP=$1
RESULTS_DIR="results"
mkdir -p $RESULTS_DIR

echo "╔════════════════════════════════════════════════════════╗"
echo "║  TLS 1.3 Experiments: Client→ Server             ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Network Setup:"
echo "  Client: ($(hostname -I | awk '{print $1}'))"
echo "  Server: WSL ($WSL_IP:8080)"
echo "  Connection: Real network (not loopback)"
echo ""

# ============================================
# Test 1: Network Latency Baseline
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Network Latency Baseline (ICMP ping)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ping -c 10 $WSL_IP | tee $RESULTS_DIR/01_ping_baseline.txt | tail -2
echo ""

# ============================================
# Test 2: TLS 1.3 Handshake Latency
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: TLS 1.3 Handshake Latency (20 samples)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

> $RESULTS_DIR/02_tls_latency.txt

for i in $(seq 1 20); do
  start=$(date +%s%N)
  ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  end=$(date +%s%N)
  elapsed_ms=$(echo "scale=2; ($end - $start) / 1000000" | bc)
  echo "$elapsed_ms" >> $RESULTS_DIR/02_tls_latency.txt
  echo "  Sample $i: $elapsed_ms ms"
done

# Calculate statistics
avg=$(awk '{sum+=$1} END {printf "%.2f", sum/NR}' $RESULTS_DIR/02_tls_latency.txt)
min=$(sort -n $RESULTS_DIR/02_tls_latency.txt | head -1)
max=$(sort -n $RESULTS_DIR/02_tls_latency.txt | tail -1)

echo ""
echo "Summary:"
echo "  Average: $avg ms"
echo "  Min: $min ms"
echo "  Max: $max ms"
echo ""

# ============================================
# Test 3: Throughput Test
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: Throughput (1000 requests)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

start=$(date +%s%N)

for i in $(seq 1 1000); do
  ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  if [ $((i % 200)) -eq 0 ]; then
    echo "  Progress: $i/1000 requests..."
  fi
done

end=$(date +%s%N)
elapsed_s=$(echo "scale=6; ($end - $start) / 1000000000" | bc)
rps=$(echo "scale=2; 1000 / $elapsed_s" | bc)

echo ""
echo "Summary:"
echo "  Total time: $elapsed_s seconds"
echo "  Requests per second: $rps RPS"
echo "$rps" > $RESULTS_DIR/03_throughput.txt
echo ""

# ============================================
# Test 4: Packet Capture (if sudo available)
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 4: Packet Capture"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v tcpdump &> /dev/null; then
  echo "Attempting packet capture (requires sudo)..."

  # Capture single request
  sudo timeout 5 tcpdump -i any -w $RESULTS_DIR/kali_to_wsl_single.pcap host $WSL_IP and port 8080 &
  TCPDUMP_PID=$!
  sleep 1
  ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  sleep 1
  sudo kill $TCPDUMP_PID 2>/dev/null
  wait $TCPDUMP_PID 2>/dev/null

  if [ -f "$RESULTS_DIR/kali_to_wsl_single.pcap" ]; then
    packets=$(tcpdump -r $RESULTS_DIR/kali_to_wsl_single.pcap 2>/dev/null | wc -l)
    echo "  ✓ Captured: $packets packets"
    echo "  File: $RESULTS_DIR/kali_to_wsl_single.pcap"
  else
    echo "  ✗ Capture failed (may need sudo)"
  fi
else
  echo "  ⚠️  tcpdump not available, skipping packet capture"
fi

echo ""

# ============================================
# Summary
# ============================================
echo "╔════════════════════════════════════════════════════════╗"
echo "║              Experiment Results Summary                ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Network Configuration:"
echo "  Topology: (real network)"
echo "  Not loopback: Traffic routed through VM network stack"
echo ""
echo "Results:"
echo "  1. Network RTT (ping): $(grep 'rtt min/avg/max' $RESULTS_DIR/01_ping_baseline.txt | awk -F'/' '{print $5}') ms avg"
echo "  2. TLS 1.3 Latency: $avg ms avg (20 samples)"
echo "  3. Throughput: $rps RPS (1000 requests)"
echo ""
echo "Files saved in: $RESULTS_DIR/"
ls -lh $RESULTS_DIR/
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "These results demonstrate real network performance,"
echo "not artificial loopback performance."
echo "═══════════════════════════════════════════════════════════"
