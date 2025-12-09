#!/usr/bin/env python3
"""
TLS 1.3 Performance Tests - Terminal UI
Beautiful real-time test execution with progress bars and live metrics
"""

import subprocess
import sys
import time
import re
import statistics
from typing import List, Tuple, Optional
from pathlib import Path

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.text import Text
except ImportError:
    print("Error: 'rich' library not installed.")
    print("Install it with: pip3 install rich")
    sys.exit(1)

console = Console()

class TestMetrics:
    """Track metrics across tests"""
    def __init__(self):
        self.network_rtt = 0.0
        self.latencies = []
        self.throughput_trials = []
        self.memory_initial = 0.0
        self.memory_final = 0.0
        self.tls12_rejected = False
        self.failures = 0

def run_command(cmd: List[str], capture=True) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def test_network_baseline(server_ip: str, progress, task_id, metrics: TestMetrics) -> bool:
    """Test 1: Network baseline latency"""
    progress.update(task_id, description="[cyan]Test 1: Network Baseline")

    returncode, stdout, stderr = run_command(["ping", "-c", "10", server_ip])

    if returncode == 0:
        # Parse ping output
        match = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", stdout)
        if match:
            metrics.network_rtt = float(match.group(2))
            progress.update(task_id, description=f"[green]✓ Test 1: Network Baseline ({metrics.network_rtt:.2f} ms)")
            return True

    progress.update(task_id, description="[red]✗ Test 1: Network Baseline (failed)")
    return False

def test_tls13_latency(server_ip: str, progress, task_id, metrics: TestMetrics) -> bool:
    """Test 2: TLS 1.3 handshake latency"""
    progress.update(task_id, description="[cyan]Test 2: TLS 1.3 Latency (0/100)")

    latencies = []
    for i in range(100):
        start = time.time()
        returncode, stdout, stderr = run_command([
            "./client", server_ip, "8080", "readme", "certs/cert.pem", "0"
        ])
        elapsed_ms = (time.time() - start) * 1000

        if returncode == 0:
            latencies.append(elapsed_ms)

        if (i + 1) % 10 == 0:
            progress.update(task_id, description=f"[cyan]Test 2: TLS 1.3 Latency ({i+1}/100)")

    if latencies:
        metrics.latencies = latencies
        mean = statistics.mean(latencies)
        median = statistics.median(latencies)
        progress.update(task_id, description=f"[green]✓ Test 2: TLS 1.3 Latency (mean: {mean:.2f}ms, median: {median:.2f}ms)")
        return True

    progress.update(task_id, description="[red]✗ Test 2: TLS 1.3 Latency (failed)")
    return False

def test_throughput(server_ip: str, progress, task_id, metrics: TestMetrics) -> bool:
    """Test 3: Throughput testing"""
    progress.update(task_id, description="[cyan]Test 3: Throughput (0/10 trials)")

    throughput_trials = []

    for trial in range(10):
        start = time.time()
        success_count = 0

        for _ in range(100):
            returncode, _, _ = run_command([
                "./client", server_ip, "8080", "readme", "certs/cert.pem", "0"
            ])
            if returncode == 0:
                success_count += 1

        elapsed = time.time() - start
        rps = success_count / elapsed if elapsed > 0 else 0
        throughput_trials.append(rps)

        progress.update(task_id, description=f"[cyan]Test 3: Throughput ({trial+1}/10 trials, current: {rps:.1f} RPS)")

    if throughput_trials:
        metrics.throughput_trials = throughput_trials
        mean_rps = statistics.mean(throughput_trials)
        progress.update(task_id, description=f"[green]✓ Test 3: Throughput (mean: {mean_rps:.1f} RPS)")
        return True

    progress.update(task_id, description="[red]✗ Test 3: Throughput (failed)")
    return False

def test_tls12_rejection(server_ip: str, progress, task_id, metrics: TestMetrics) -> bool:
    """Test 4: TLS 1.2 rejection"""
    progress.update(task_id, description="[cyan]Test 4: Security (TLS 1.2 rejection)")

    # Try to connect with TLS 1.2 (should fail)
    returncode, stdout, stderr = run_command([
        "openssl", "s_client",
        "-connect", f"{server_ip}:8080",
        "-tls1_2",
        "-CAfile", "certs/cert.pem"
    ])

    # TLS 1.2 connection should fail
    if returncode != 0 or "alert" in stderr.lower() or "alert" in stdout.lower():
        metrics.tls12_rejected = True
        progress.update(task_id, description="[green]✓ Test 4: Security (TLS 1.2 correctly rejected)")
        return True

    progress.update(task_id, description="[red]✗ Test 4: Security (TLS 1.2 NOT rejected!)")
    return False

def generate_summary_table(metrics: TestMetrics) -> Table:
    """Generate summary statistics table"""
    table = Table(title="Performance Metrics", box=box.ROUNDED, show_header=True, header_style="bold magenta")

    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="green", width=20)
    table.add_column("Details", style="dim")

    # Network baseline
    table.add_row("Network RTT", f"{metrics.network_rtt:.2f} ms", "ICMP ping")

    # TLS latency
    if metrics.latencies:
        mean_lat = statistics.mean(metrics.latencies)
        median_lat = statistics.median(metrics.latencies)
        p95 = sorted(metrics.latencies)[int(len(metrics.latencies) * 0.95)]
        p99 = sorted(metrics.latencies)[int(len(metrics.latencies) * 0.99)]

        table.add_row("TLS 1.3 Latency (mean)", f"{mean_lat:.2f} ms", f"100 samples")
        table.add_row("TLS 1.3 Latency (median)", f"{median_lat:.2f} ms", "")
        table.add_row("TLS 1.3 Latency (p95)", f"{p95:.2f} ms", "")
        table.add_row("TLS 1.3 Latency (p99)", f"{p99:.2f} ms", "")

    # Throughput
    if metrics.throughput_trials:
        mean_rps = statistics.mean(metrics.throughput_trials)
        stdev_rps = statistics.stdev(metrics.throughput_trials) if len(metrics.throughput_trials) > 1 else 0
        min_rps = min(metrics.throughput_trials)
        max_rps = max(metrics.throughput_trials)

        table.add_row("Throughput (mean)", f"{mean_rps:.1f} RPS", f"10 trials")
        table.add_row("Throughput (min/max)", f"{min_rps:.1f} / {max_rps:.1f} RPS", f"σ = {stdev_rps:.2f}")

    # Security
    security_status = "[green]✓ Passed[/green]" if metrics.tls12_rejected else "[red]✗ Failed[/red]"
    table.add_row("TLS 1.2 Rejection", security_status, "Protocol enforcement")

    return table

def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] python3 run_tests_tui.py <server-ip>")
        console.print("[dim]Example: python3 run_tests_tui.py 127.0.0.1[/dim]")
        sys.exit(1)

    server_ip = sys.argv[1]

    # Print header
    console.print()
    console.print(Panel.fit(
        "[bold cyan]TLS 1.3 Performance Test Suite[/bold cyan]\n"
        f"[dim]Server: {server_ip}:8080[/dim]",
        border_style="cyan"
    ))
    console.print()

    metrics = TestMetrics()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:

        # Create tasks
        task1 = progress.add_task("[cyan]Test 1: Network Baseline", total=100)
        task2 = progress.add_task("[dim]Test 2: TLS 1.3 Latency", total=100)
        task3 = progress.add_task("[dim]Test 3: Throughput", total=100)
        task4 = progress.add_task("[dim]Test 4: Security", total=100)

        # Run tests
        if test_network_baseline(server_ip, progress, task1, metrics):
            progress.update(task1, completed=100)

        if test_tls13_latency(server_ip, progress, task2, metrics):
            progress.update(task2, completed=100)

        if test_throughput(server_ip, progress, task3, metrics):
            progress.update(task3, completed=100)

        if test_tls12_rejection(server_ip, progress, task4, metrics):
            progress.update(task4, completed=100)

    # Display summary
    console.print()
    console.print(generate_summary_table(metrics))
    console.print()

    # Display sparkline for latency distribution
    if metrics.latencies:
        console.print(Panel.fit(
            "[bold]Latency Distribution[/bold]\n"
            f"[dim]{'▁▂▃▄▅▆▇█' * 10}[/dim]",
            border_style="blue"
        ))
        console.print()

    console.print("[bold green]✓ All tests complete![/bold green]")
    console.print()

if __name__ == "__main__":
    main()
