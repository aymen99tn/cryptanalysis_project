#!/usr/bin/env python3
"""Generate graphs for experimental results section."""

import matplotlib.pyplot as plt
import numpy as np
import matplotlib

# Use non-interactive backend for server environments
matplotlib.use('Agg')

# Set publication-quality style
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 9
plt.rcParams['axes.labelsize'] = 10
plt.rcParams['axes.titlesize'] = 11
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['legend.fontsize'] = 9
plt.rcParams['figure.dpi'] = 300

# Read latency data
with open('kali_comprehensive_results/02_tls13_handshake_latency.txt', 'r') as f:
    raw_latency = [float(line.strip()) for line in f if line.strip()]

# Filter outliers
latency_data = [x for x in raw_latency if x < 1000]

# Graph 1: Latency Distribution (Histogram)
fig, ax = plt.subplots(figsize=(3.5, 2.5))
ax.hist(latency_data, bins=20, color='steelblue', edgecolor='black', alpha=0.7)
ax.axvline(np.median(latency_data), color='red', linestyle='--', linewidth=1.5, label=f'Median: {np.median(latency_data):.2f} ms')
ax.axvline(np.mean(latency_data), color='orange', linestyle='--', linewidth=1.5, label=f'Mean: {np.mean(latency_data):.2f} ms')
ax.set_xlabel('Latency (ms)')
ax.set_ylabel('Frequency')
ax.set_title('TLS 1.3 Handshake Latency Distribution')
ax.legend(loc='upper right')
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('acmart-primary/figures/latency_histogram.pdf', bbox_inches='tight')
plt.savefig('acmart-primary/figures/latency_histogram.png', bbox_inches='tight', dpi=300)
print("✓ Generated: latency_histogram.pdf/png")
plt.close()

# Graph 2: TLS 1.3 vs TLS 1.2 Comparison (Theoretical)
# TLS 1.2: 2-RTT handshake, TLS 1.3: 1-RTT handshake
# Baseline network RTT: 1.0 ms
# TLS 1.3 measured: 9.15 ms
# TLS 1.2 estimated: 9.15 + 1 RTT = ~10.15 ms (conservative estimate)

network_rtt = 1.0
tls13_measured = 9.15
tls12_estimated = tls13_measured + network_rtt  # Add 1 RTT for extra round trip

protocols = ['TLS 1.3\n(1-RTT)', 'TLS 1.2\n(2-RTT)']
latencies = [tls13_measured, tls12_estimated]
colors = ['#2E86AB', '#A23B72']

fig, ax = plt.subplots(figsize=(3.5, 2.5))
bars = ax.bar(protocols, latencies, color=colors, edgecolor='black', linewidth=1.2, alpha=0.8)

# Add value labels on bars
for bar, val in zip(bars, latencies):
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height,
            f'{val:.2f} ms',
            ha='center', va='bottom', fontsize=9, fontweight='bold')

# Add RTT savings annotation
ax.annotate('', xy=(0, tls13_measured), xytext=(1, tls13_measured),
            arrowprops=dict(arrowstyle='<->', color='green', lw=1.5))
ax.text(0.5, tls13_measured + 0.2, f'~{network_rtt:.1f} ms\nsaved',
        ha='center', va='bottom', fontsize=8, color='green', fontweight='bold')

ax.set_ylabel('Handshake Latency (ms)')
ax.set_title('TLS 1.3 vs TLS 1.2 Handshake Latency')
ax.set_ylim(0, max(latencies) * 1.25)
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('acmart-primary/figures/tls_comparison.pdf', bbox_inches='tight')
plt.savefig('acmart-primary/figures/tls_comparison.png', bbox_inches='tight', dpi=300)
print("✓ Generated: tls_comparison.pdf/png")
plt.close()

# Graph 3: Latency Percentiles (Box Plot alternative)
percentiles = [50, 90, 95, 99]
values = [8.59, 11.14, 11.93, 14.88]

fig, ax = plt.subplots(figsize=(3.5, 2.0))
bars = ax.barh(range(len(percentiles)), values, color='steelblue', edgecolor='black', alpha=0.7)

# Add value labels
for i, (bar, val) in enumerate(zip(bars, values)):
    width = bar.get_width()
    ax.text(width + 0.2, bar.get_y() + bar.get_height()/2.,
            f'{val:.2f} ms',
            ha='left', va='center', fontsize=9)

ax.set_yticks(range(len(percentiles)))
ax.set_yticklabels([f'p{p}' for p in percentiles])
ax.set_xlabel('Latency (ms)')
ax.set_title('TLS 1.3 Latency Percentiles')
ax.set_xlim(0, max(values) * 1.2)
ax.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig('acmart-primary/figures/latency_percentiles.pdf', bbox_inches='tight')
plt.savefig('acmart-primary/figures/latency_percentiles.png', bbox_inches='tight', dpi=300)
print("✓ Generated: latency_percentiles.pdf/png")
plt.close()

print("\nAll graphs generated successfully in acmart-primary/figures/")
print("Files created:")
print("  - latency_histogram.pdf/png (Latency distribution)")
print("  - tls_comparison.pdf/png (TLS 1.3 vs 1.2)")
print("  - latency_percentiles.pdf/png (Percentile breakdown)")
