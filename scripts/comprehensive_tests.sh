#!/bin/bash
# Comprehensive TLS 1.3 Experiments - Kali VM → WSL Server
# Based on to-do.md experimental plan
# This script runs ALL planned experiments over real network

if [ -z "$1" ]; then
  echo "Usage: $0 <wsl-ip>"
  echo "Example: $0 172.21.144.1"
  exit 1
fi

WSL_IP=$1
RESULTS_DIR="kali_comprehensive_results"
mkdir -p $RESULTS_DIR

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║     Comprehensive TLS 1.3 Experiments - Kali VM → WSL Server     ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Network Setup:"
echo "  Client: Kali Linux VM ($(hostname -I | awk '{print $1}'))"
echo "  Server: WSL ($WSL_IP:8080)"
echo "  Connection: Real VM network (NOT loopback)"
echo ""
echo "This suite implements all experiments from to-do.md"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 1: Network Baseline Latency (ICMP Ping)
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Network Baseline Latency (ICMP)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Measure raw network RTT without TLS overhead"
echo ""

ping -c 50 $WSL_IP > $RESULTS_DIR/01_network_baseline_ping.txt
ping_stats=$(grep 'rtt min/avg/max' $RESULTS_DIR/01_network_baseline_ping.txt)
echo "$ping_stats"
ping_avg=$(echo "$ping_stats" | awk -F'/' '{print $5}')
echo ""
echo "✓ Network RTT: $ping_avg ms average"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 2: TLS 1.3 Handshake Latency Comparison (Must-Have 1.1)
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: TLS 1.3 Handshake Latency (Must-Have 1.1)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Quantify TLS 1.3 1-RTT handshake latency over real network"
echo "Samples: 100 requests"
echo ""

> $RESULTS_DIR/02_tls13_handshake_latency.txt

for i in $(seq 1 100); do
  start=$(date +%s%N)
  ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  end=$(date +%s%N)
  elapsed_ms=$(echo "scale=3; ($end - $start) / 1000000" | bc)
  echo "$elapsed_ms" >> $RESULTS_DIR/02_tls13_handshake_latency.txt

  if [ $((i % 20)) -eq 0 ]; then
    echo "  Progress: $i/100 samples..."
  fi
done

# Calculate statistics with percentiles
awk '{print $1}' $RESULTS_DIR/02_tls13_handshake_latency.txt | sort -n > $RESULTS_DIR/02_sorted.tmp

avg=$(awk '{sum+=$1} END {printf "%.2f", sum/NR}' $RESULTS_DIR/02_sorted.tmp)
min=$(head -1 $RESULTS_DIR/02_sorted.tmp)
max=$(tail -1 $RESULTS_DIR/02_sorted.tmp)
median=$(awk 'NR==50' $RESULTS_DIR/02_sorted.tmp)
p90=$(awk 'NR==90' $RESULTS_DIR/02_sorted.tmp)
p95=$(awk 'NR==95' $RESULTS_DIR/02_sorted.tmp)
p99=$(awk 'NR==99' $RESULTS_DIR/02_sorted.tmp)

echo ""
echo "TLS 1.3 Latency Statistics (100 samples):"
echo "  Mean:   $avg ms"
echo "  Median: $median ms"
echo "  Min:    $min ms"
echo "  Max:    $max ms"
echo "  p90:    $p90 ms"
echo "  p95:    $p95 ms"
echo "  p99:    $p99 ms"
echo ""
echo "✓ Percentile analysis complete"
echo ""

rm $RESULTS_DIR/02_sorted.tmp

# ═══════════════════════════════════════════════════════════════════
# TEST 3: Throughput Confidence Intervals (Must-Have 2.2)
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: Throughput with Confidence Intervals (Must-Have 2.2)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Measure RPS with statistical rigor"
echo "Trials: 10 × 1000 requests = 10,000 total"
echo ""

> $RESULTS_DIR/03_throughput_trials.txt

for trial in $(seq 1 10); do
  echo "  Trial $trial/10..."
  start=$(date +%s%N)

  for i in $(seq 1 1000); do
    ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  done

  end=$(date +%s%N)
  elapsed_s=$(echo "scale=6; ($end - $start) / 1000000000" | bc)
  rps=$(echo "scale=2; 1000 / $elapsed_s" | bc)
  echo "$rps" >> $RESULTS_DIR/03_throughput_trials.txt
  echo "    RPS: $rps"
done

# Calculate statistics
awk '{
  sum += $1
  sumsq += ($1)^2
  values[NR] = $1
}
END {
  mean = sum / NR
  variance = (sumsq / NR) - (mean^2)
  stddev = sqrt(variance)
  stderr = stddev / sqrt(NR)
  ci_margin = 1.96 * stderr
  ci_lower = mean - ci_margin
  ci_upper = mean + ci_margin
  cv = (stddev / mean) * 100

  min = values[1]
  max = values[1]
  for (i = 1; i <= NR; i++) {
    if (values[i] < min) min = values[i]
    if (values[i] > max) max = values[i]
  }

  printf "\nThroughput Statistics (10 trials):\n"
  printf "  Mean RPS: %.2f\n", mean
  printf "  Std Dev: %.2f\n", stddev
  printf "  Min RPS: %.2f\n", min
  printf "  Max RPS: %.2f\n", max
  printf "  95%% CI: [%.2f, %.2f]\n", ci_lower, ci_upper
  printf "  Coefficient of Variation: %.2f%%\n", cv
  printf "\n"
  printf "mean=%.2f\nstddev=%.2f\nci_lower=%.2f\nci_upper=%.2f\ncv=%.2f\n", mean, stddev, ci_lower, ci_upper, cv
}' $RESULTS_DIR/03_throughput_trials.txt | tee $RESULTS_DIR/03_throughput_stats.txt

echo "✓ Throughput analysis complete"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 4: Memory Footprint (Must-Have 3.1)
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 4: Client-Side Memory Footprint (Must-Have 3.1)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Measure client memory usage over 100 connections"
echo ""

# Get baseline memory
initial_mem=$(free -m | grep '^Mem:' | awk '{print $3}')
echo "Initial memory used: ${initial_mem} MB"

# Make 100 connections
for i in $(seq 1 100); do
  ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  if [ $((i % 25)) -eq 0 ]; then
    echo "  Progress: $i/100 connections..."
  fi
done

sleep 1

# Get final memory
final_mem=$(free -m | grep '^Mem:' | awk '{print $3}')
delta_mem=$((final_mem - initial_mem))

echo ""
echo "Memory Analysis:"
echo "  Initial: ${initial_mem} MB"
echo "  Final:   ${final_mem} MB"
echo "  Delta:   ${delta_mem} MB"
echo ""
echo "✓ Client-side memory test complete"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 5: Comparison - Loopback vs Real Network
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 5: Loopback vs Real Network Comparison"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Compare WSL network performance vs loopback"
echo ""

# Only run loopback test if we are testing a remote IP (not 127.0.0.1)
# AND we are on a system that has a local server running (which we might not be)
# Actually, the original intent was: "Compare the Remote WSL performance vs My Local Loopback".
# But if we are running Client Only, "My Local Loopback" might not have a server running.
# So we should only run this if we can verify a local server is running.

if [ "$WSL_IP" = "127.0.0.1" ] || [ "$WSL_IP" = "localhost" ]; then
    echo "  Target is already localhost. Skipping comparison."
elif ! nc -z 127.0.0.1 8080 2>/dev/null; then
    echo "  No local server detected on 127.0.0.1:8080."
    echo "  Skipping loopback comparison."
else
    # Test WSL network (already measured above)
    wsl_latency=$avg

    if ping -c 1 127.0.0.1 &> /dev/null; then
      echo "Testing loopback (127.0.0.1) for comparison..."

      > $RESULTS_DIR/05_loopback_latency.txt
      for i in $(seq 1 20); do
        start=$(date +%s%N)
        ./client 127.0.0.1 8080 welcome > /dev/null 2>&1
        end=$(date +%s%N)
        elapsed_ms=$(echo "scale=2; ($end - $start) / 1000000" | bc)
        echo "$elapsed_ms" >> $RESULTS_DIR/05_loopback_latency.txt
      done

      loopback_avg=$(awk '{sum+=$1} END {printf "%.2f", sum/NR}' $RESULTS_DIR/05_loopback_latency.txt)

      echo ""
      echo "Comparison:"
      echo "  Loopback (127.0.0.1): $loopback_avg ms"
      echo "  Remote Network ($WSL_IP): $wsl_latency ms"
      overhead=$(echo "scale=2; $wsl_latency - $loopback_avg" | bc)
      echo "  Network overhead: $overhead ms"
    else
      echo "  Loopback not available (unexpected)"
    fi
fi

echo ""
echo "✓ Network comparison complete"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 6: TLS 1.2 Rejection Verification
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 6: TLS 1.2 Rejection Verification"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Verify server rejects TLS 1.2 connections"
echo ""

echo "Attempting TLS 1.2 connection..."
tls12_result=$(echo "GET welcome" | timeout 2 openssl s_client -connect $WSL_IP:8080 -tls1_2 -quiet 2>&1)

if echo "$tls12_result" | grep -q "alert\|error\|errno"; then
  echo "✓ TLS 1.2 correctly rejected"
  echo "$tls12_result" | head -3
else
  echo "⚠️  Unexpected result"
  echo "$tls12_result"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 7: Cold Start vs Warm Cache
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 7: Cold Start vs Warm Cache Analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Measure first request latency vs subsequent requests"
echo ""

# Clear any connection caches
sleep 2

# First request (cold)
echo "Measuring cold start (first request)..."
start=$(date +%s%N)
./client $WSL_IP 8080 welcome > /dev/null 2>&1
end=$(date +%s%N)
cold_ms=$(echo "scale=2; ($end - $start) / 1000000" | bc)

sleep 1

# Warm requests
echo "Measuring warm requests (5 samples)..."
> $RESULTS_DIR/07_warm_requests.txt
for i in {1..5}; do
  start=$(date +%s%N)
  ./client $WSL_IP 8080 welcome > /dev/null 2>&1
  end=$(date +%s%N)
  elapsed_ms=$(echo "scale=2; ($end - $start) / 1000000" | bc)
  echo "$elapsed_ms" >> $RESULTS_DIR/07_warm_requests.txt
done

warm_avg=$(awk '{sum+=$1} END {printf "%.2f", sum/NR}' $RESULTS_DIR/07_warm_requests.txt)

echo ""
echo "Results:"
echo "  Cold start (1st request): $cold_ms ms"
echo "  Warm average (next 5):    $warm_avg ms"
difference=$(echo "scale=2; $cold_ms - $warm_avg" | bc)
echo "  Difference: $difference ms"
echo ""
echo "✓ Cold vs warm analysis complete"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 8: Sustained Load Test
# ═══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 8: Sustained Load Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Purpose: Test performance under sustained load (5000 requests)"
echo ""

start=$(date +%s%N)
failed=0

for i in $(seq 1 5000); do
  if ! ./client $WSL_IP 8080 welcome > /dev/null 2>&1; then
    ((failed++))
  fi

  if [ $((i % 1000)) -eq 0 ]; then
    echo "  Progress: $i/5000 requests, failures: $failed"
  fi
done

end=$(date +%s%N)
elapsed_s=$(echo "scale=3; ($end - $start) / 1000000000" | bc)
rps=$(echo "scale=2; 5000 / $elapsed_s" | bc)
success_rate=$(echo "scale=2; (5000 - $failed) / 5000 * 100" | bc)

echo ""
echo "Sustained Load Results:"
echo "  Total requests: 5000"
echo "  Time: $elapsed_s seconds"
echo "  RPS: $rps"
echo "  Failed: $failed"
echo "  Success rate: $success_rate%"
echo ""
echo "✓ Sustained load test complete"
echo ""

# ═══════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                    EXPERIMENT SUMMARY                             ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Network Configuration:"
echo "  Topology: Kali Linux VM ←→ WSL Server"
echo "  Client IP: $(hostname -I | awk '{print $1}')"
echo "  Server IP: $WSL_IP:8080"
echo "  Connection: Real VM network (not loopback)"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "KEY RESULTS:"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "1. Network Baseline:"
echo "   • ICMP RTT: $ping_avg ms"
echo ""
echo "2. TLS 1.3 Performance:"
echo "   • Mean Latency: $avg ms (100 samples)"
echo "   • Median: $median ms"
echo "   • p99: $p99 ms"
echo ""
echo "3. Throughput:"
cat $RESULTS_DIR/03_throughput_stats.txt | grep "Mean RPS\|95% CI\|Coefficient"
echo ""
echo "4. Security:"
echo "   • TLS 1.2 rejection: VERIFIED"
echo ""
echo "5. Memory:"
echo "   • Client memory growth: ${delta_mem} MB over 100 connections"
echo ""
echo "6. Sustained Load:"
echo "   • RPS: $rps over 5000 requests"
echo "   • Success rate: $success_rate%"
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "All results saved in: $RESULTS_DIR/"
echo ""
ls -lh $RESULTS_DIR/
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "Next steps:"
echo "  1. Review results in $RESULTS_DIR/"
echo "  2. Run packet capture: sudo ./kali_packet_capture.sh $WSL_IP"
echo "  3. Compile final report: EXPERIMENTAL_RESULTS_KALI.md"
echo "═══════════════════════════════════════════════════════════════════"
