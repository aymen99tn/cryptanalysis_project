#!/usr/bin/env python3
"""Analyze TLS 1.3 handshake latency data."""

import sys
import math

def calculate_stats(data):
    """Calculate statistics for a dataset."""
    n = len(data)
    if n == 0:
        return {}

    # Sort for percentile calculation
    sorted_data = sorted(data)

    # Calculate mean
    mean = sum(data) / n

    # Calculate standard deviation
    variance = sum((x - mean) ** 2 for x in data) / n
    stddev = math.sqrt(variance)

    # Calculate percentiles
    def percentile(p):
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_data[int(k)]
        d0 = sorted_data[int(f)] * (c - k)
        d1 = sorted_data[int(c)] * (k - f)
        return d0 + d1

    return {
        'n': n,
        'mean': mean,
        'stddev': stddev,
        'min': sorted_data[0],
        'max': sorted_data[-1],
        'p50': percentile(0.50),
        'p90': percentile(0.90),
        'p95': percentile(0.95),
        'p99': percentile(0.99)
    }

def main():
    # Read latency data
    with open('kali_comprehensive_results/02_tls13_handshake_latency.txt', 'r') as f:
        raw_data = [float(line.strip()) for line in f if line.strip()]

    print(f"Raw data points: {len(raw_data)}")
    print(f"Raw mean: {sum(raw_data) / len(raw_data):.2f} ms")

    # Filter outliers (> 1000ms are clearly anomalies)
    filtered_data = [x for x in raw_data if x < 1000]
    outliers = [x for x in raw_data if x >= 1000]

    print(f"\nOutliers detected (>1000ms): {len(outliers)}")
    if outliers:
        print(f"Outlier values: {outliers}")

    print(f"Filtered data points: {len(filtered_data)}")

    # Calculate statistics on filtered data
    stats = calculate_stats(filtered_data)

    print("\n=== TLS 1.3 Latency Statistics (Filtered) ===")
    print(f"Sample size: {stats['n']}")
    print(f"Mean: {stats['mean']:.2f} ms")
    print(f"Std Dev: {stats['stddev']:.2f} ms")
    print(f"Min: {stats['min']:.2f} ms")
    print(f"Max: {stats['max']:.2f} ms")
    print(f"Median (p50): {stats['p50']:.2f} ms")
    print(f"p90: {stats['p90']:.2f} ms")
    print(f"p95: {stats['p95']:.2f} ms")
    print(f"p99: {stats['p99']:.2f} ms")

    # Calculate 95% confidence interval (t-distribution approximation)
    # For n=98, df=97, t-critical ≈ 1.985
    t_critical = 1.985
    margin_of_error = t_critical * (stats['stddev'] / math.sqrt(stats['n']))
    ci_lower = stats['mean'] - margin_of_error
    ci_upper = stats['mean'] + margin_of_error

    print(f"\n95% Confidence Interval: [{ci_lower:.2f}, {ci_upper:.2f}] ms")

    # Output LaTeX table format
    print("\n=== LaTeX Table Row ===")
    print(f"{stats['mean']:.2f} & {stats['stddev']:.2f} & {stats['p50']:.2f} & {stats['p90']:.2f} & {stats['p95']:.2f} & {stats['p99']:.2f}")

if __name__ == '__main__':
    main()
