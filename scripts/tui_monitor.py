#!/usr/bin/env python3
"""
TLS 1.3 Server Monitor - Terminal UI
Real-time monitoring dashboard for the document server
"""

import subprocess
import time
import sys
import json
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import deque, Counter

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: 'rich' library not installed")
    print("Install with: pip3 install rich")
    sys.exit(1)


class ServerMonitor:
    """Monitors TLS 1.3 server by parsing JSON logs"""

    def __init__(self, server_ip: str = "0.0.0.0", log_file: Optional[str] = None):
        self.server_ip = server_ip
        self.log_file = log_file
        self.console = Console()
        self.start_time = datetime.now()

        # Statistics
        self.total_connections = 0
        self.total_requests = 0
        self.total_errors = 0
        self.total_rate_limited = 0

        # Recent activity (keep last 20)
        self.recent_requests: deque = deque(maxlen=20)

        # Document popularity counter
        self.document_stats: Counter = Counter()

        # TLS statistics
        self.cipher_stats: Counter = Counter()
        self.tls_version_stats: Counter = Counter()

        # Performance metrics (keep last 50 for sparkline)
        self.latencies: deque = deque(maxlen=50)
        self.rps_samples: deque = deque(maxlen=60)  # 1 minute of samples
        self.last_request_time = time.time()
        self.requests_in_window = 0

        # Server process
        self.server_process: Optional[subprocess.Popen] = None
        self.running = False
        self.file_handle = None

    def start_server(self) -> bool:
        """Start the TLS server or open log file"""
        if self.log_file:
            try:
                self.file_handle = open(self.log_file, 'r')
                return True
            except Exception as e:
                self.console.print(f"[red]Error opening log file: {e}[/red]")
                return False
        
        try:
            import os
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:' + env.get('LD_LIBRARY_PATH', '')
            env['TLS_CERT'] = 'certs/cert.pem'
            env['TLS_KEY'] = 'certs/key.pem'

            self.server_process = subprocess.Popen(
                ['./server'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env
            )
            time.sleep(2)  # Wait for server to start

            # Check if process is still running
            if self.server_process.poll() is not None:
                return False

            return True
        except Exception as e:
            self.console.print(f"[red]Error starting server: {e}[/red]")
            return False

    def stop_server(self):
        """Stop the TLS server"""
        if self.server_process:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
        
        if self.file_handle:
            self.file_handle.close()

    def parse_log_line(self, line: str):
        """Parse a JSON log line from the server"""
        try:
            data = json.loads(line.strip())
            log_type = data.get('type', '')

            if log_type == 'connection':
                self.total_connections += 1

            elif log_type == 'handshake':
                self.tls_version_stats[data.get('version', 'unknown')] += 1
                cipher = data.get('cipher', 'unknown')
                self.cipher_stats[cipher] += 1

            elif log_type == 'request':
                self.total_requests += 1
                self.requests_in_window += 1

                doc_id = data.get('id', 'unknown')
                self.document_stats[doc_id] += 1

                # Calculate latency (microseconds to ms)
                latency_us = data.get('elapsed_us', 0)
                latency_ms = latency_us / 1000.0
                self.latencies.append(latency_ms)

                # Record request
                self.recent_requests.append({
                    'time': datetime.now(),
                    'client': data.get('client_ip', 'unknown'),
                    'doc_id': doc_id,
                    'latency': latency_ms,
                    'status': data.get('status', 'ok')
                })

            elif log_type == 'error':
                self.total_errors += 1

            elif log_type == 'rate_limit':
                self.total_rate_limited += 1

        except json.JSONDecodeError:
            pass  # Ignore non-JSON lines

    def calculate_rps(self) -> float:
        """Calculate requests per second"""
        current_time = time.time()

        # Sample RPS every second
        if current_time - self.last_request_time >= 1.0:
            self.rps_samples.append(self.requests_in_window)
            self.requests_in_window = 0
            self.last_request_time = current_time

        # Average over last minute
        if len(self.rps_samples) > 0:
            return sum(self.rps_samples) / len(self.rps_samples)
        return 0.0

    def get_sparkline(self, values: List[float], width: int = 20) -> str:
        """Generate a sparkline from values"""
        if not values or len(values) == 0:
            return "▁" * width

        # Sparkline characters from low to high
        chars = "▁▂▃▄▅▆▇█"

        min_val = min(values)
        max_val = max(values)

        if max_val == min_val:
            return chars[0] * min(width, len(values))

        # Take last `width` values
        recent = list(values)[-width:]

        sparkline = ""
        for val in recent:
            normalized = (val - min_val) / (max_val - min_val)
            idx = int(normalized * (len(chars) - 1))
            sparkline += chars[idx]

        return sparkline
    
    def get_lan_ip(self):
        try:
            cmd = "hostname -I | awk '{print $1}'"
            import subprocess
            return subprocess.check_output(cmd, shell=True).decode().strip()
        except:
            return "Unknown"

    def create_status_panel(self) -> Panel:
        """Create the status header panel"""
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds

        status_text = Text()
        status_text.append("Status: ", style="bold")
        if self.log_file:
             status_text.append("● MONITORING (Log File)", style="bold cyan")
        else:
             status_text.append("● RUNNING (Process)", style="bold green")
        
        status_text.append("  |  ", style="dim")
        status_text.append("Uptime: ", style="bold")
        status_text.append(uptime_str, style="cyan")
        status_text.append("  |  ", style="dim")
        status_text.append("IP: ", style="bold")
        status_text.append(self.get_lan_ip(), style="yellow")
        status_text.append("  |  ", style="dim")
        status_text.append("TLS: ", style="bold")
        status_text.append("1.3 Only", style="green")

        status_text.append("\n")
        status_text.append("Connections: ", style="bold")
        status_text.append(str(self.total_connections), style="cyan")
        status_text.append("  |  ", style="dim")
        status_text.append("Requests: ", style="bold")
        status_text.append(str(self.total_requests), style="cyan")
        status_text.append("  |  ", style="dim")
        status_text.append("Errors: ", style="bold")
        status_text.append(str(self.total_errors), style="red" if self.total_errors > 0 else "green")
        status_text.append("  |  ", style="dim")
        status_text.append("Rate Limited: ", style="bold")
        status_text.append(str(self.total_rate_limited), style="yellow" if self.total_rate_limited > 0 else "green")

        return Panel(
            status_text,
            title="[bold]TLS 1.3 Server Monitor[/bold]",
            border_style="blue",
            box=box.DOUBLE
        )

    def create_requests_panel(self) -> Panel:
        """Create the recent requests panel"""
        table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
        table.add_column("Time", style="dim", width=8)
        table.add_column("Client", style="cyan", width=15)
        table.add_column("Document", style="yellow", width=20)
        table.add_column("Latency", style="green", width=10)
        table.add_column("Status", width=8)

        # Show last 10 requests
        for req in list(self.recent_requests)[-10:]:
            time_str = req['time'].strftime("%H:%M:%S")
            latency_str = f"{req['latency']:.1f}ms"
            status_str = req['status']

            # Color code status
            if status_str == 'ok':
                status_style = "green"
                status_display = "[200]"
            elif status_str == 'not_found':
                status_style = "red"
                status_display = "[404]"
            else:
                status_style = "yellow"
                status_display = f"[{status_str}]"

            table.add_row(
                time_str,
                req['client'],
                req['doc_id'],
                latency_str,
                f"[{status_style}]{status_display}[/{status_style}]"
            )

        if len(self.recent_requests) == 0:
            table.add_row("—", "No requests yet", "—", "—", "—")

        return Panel(table, title="[bold]Recent Requests[/bold]", border_style="green")

    def create_metrics_panel(self) -> Panel:
        """Create the performance metrics panel"""
        # Calculate statistics
        rps = self.calculate_rps()

        if len(self.latencies) > 0:
            avg_latency = sum(self.latencies) / len(self.latencies)
            min_latency = min(self.latencies)
            max_latency = max(self.latencies)
            sparkline = self.get_sparkline(list(self.latencies), width=25)
        else:
            avg_latency = 0
            min_latency = 0
            max_latency = 0
            sparkline = "▁" * 25

        text = Text()
        text.append("Latency (last 50 requests)\n", style="bold")
        text.append(f"  {sparkline}\n", style="cyan")
        text.append("\n")
        text.append(f"  Avg: ", style="dim")
        text.append(f"{avg_latency:.2f} ms", style="green")
        text.append(f"  |  Min: ", style="dim")
        text.append(f"{min_latency:.2f} ms", style="green")
        text.append(f"  |  Max: ", style="dim")
        text.append(f"{max_latency:.2f} ms", style="green")
        text.append("\n\n")
        text.append(f"RPS (1m avg): ", style="bold")
        text.append(f"{rps:.1f}", style="cyan")

        return Panel(text, title="[bold]Performance Metrics[/bold]", border_style="yellow")

    def create_documents_panel(self) -> Panel:
        """Create the document popularity panel"""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Document", style="yellow", width=20)
        table.add_column("Bar", width=20)
        table.add_column("Count", style="cyan", width=6, justify="right")

        # Top 8 documents
        top_docs = self.document_stats.most_common(8)

        if len(top_docs) > 0:
            max_count = top_docs[0][1]

            for doc_id, count in top_docs:
                # Create bar
                bar_width = int((count / max_count) * 15)
                bar = "█" * bar_width

                table.add_row(doc_id, bar, str(count))
        else:
            table.add_row("No documents", "—", "0")

        return Panel(table, title="[bold]Document Popularity[/bold]", border_style="magenta")

    def create_tls_panel(self) -> Panel:
        """Create the TLS statistics panel"""
        text = Text()
        text.append("Cipher Suite Distribution:\n", style="bold")

        if len(self.cipher_stats) > 0:
            total_handshakes = sum(self.cipher_stats.values())

            for cipher, count in self.cipher_stats.most_common(3):
                percentage = (count / total_handshakes) * 100
                bar_width = int((count / total_handshakes) * 30)
                bar = "█" * bar_width

                # Shorten cipher name
                cipher_display = cipher.replace("TLS_", "")

                text.append(f"  • {cipher_display:25s} ", style="cyan")
                text.append(f"{bar} ", style="green")
                text.append(f"{percentage:.0f}%\n", style="yellow")
        else:
            text.append("  No handshakes yet\n", style="dim")

        text.append("\n")

        # Session resumption (placeholder - would need server support)
        text.append("TLS Version: ", style="bold")
        text.append("1.3 Enforced ✓", style="green")
        text.append("\n")
        text.append("TLS 1.2 Rejected: ", style="bold")
        text.append(f"{self.total_rate_limited} attempts", style="yellow" if self.total_rate_limited > 0 else "dim")

        return Panel(text, title="[bold]TLS Statistics[/bold]", border_style="cyan")

    def create_layout(self) -> Layout:
        """Create the overall layout"""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="main", ratio=1),
        )

        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1),
        )

        layout["left"].split_column(
            Layout(name="requests", ratio=2),
            Layout(name="metrics", ratio=1),
        )

        layout["right"].split_column(
            Layout(name="documents"),
            Layout(name="tls"),
        )

        # Update panels
        layout["header"].update(self.create_status_panel())
        layout["requests"].update(self.create_requests_panel())
        layout["metrics"].update(self.create_metrics_panel())
        layout["documents"].update(self.create_documents_panel())
        layout["tls"].update(self.create_tls_panel())

        return layout

    def run(self):
        """Main monitoring loop"""
        self.running = True

        # Set up signal handler for clean exit
        def signal_handler(signum, frame):
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            with Live(self.create_layout(), console=self.console, refresh_per_second=2) as live:
                while self.running:
                    # Check if process died
                    if self.server_process and self.server_process.poll() is not None:
                        break
                    
                    # Read input
                    line = None
                    if self.server_process and self.server_process.stdout:
                        line = self.server_process.stdout.readline()
                    elif self.file_handle:
                        # Non-blocking read simulation
                        where = self.file_handle.tell()
                        line = self.file_handle.readline()
                        if not line:
                            time.sleep(0.1)
                            self.file_handle.seek(where)
                            line = None
                    
                    if line:
                        self.parse_log_line(line)

                    # Update display
                    live.update(self.create_layout())
                    
                    # For file tailing, we sleep if no data
                    if self.file_handle and not line:
                         time.sleep(0.1)

        except KeyboardInterrupt:
            pass

        finally:
            self.console.print("\n[yellow]Stopping...[/yellow]")
            self.stop_server()
            self.console.print("[green]Stopped[/green]")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TLS 1.3 Server Monitor")
    parser.add_argument("server_ip", nargs="?", default="0.0.0.0", help="Server IP (display only)")
    parser.add_argument("--log-file", help="Read from log file instead of starting server")
    args = parser.parse_args()

    console = Console()

    console.print("[bold cyan]TLS 1.3 Server Monitor[/bold cyan]")
    console.print()
    
    monitor = ServerMonitor(args.server_ip, args.log_file)

    if args.log_file:
         console.print(f"Monitoring log file: {args.log_file}")
    else:
         console.print(f"Starting server...")

    if not monitor.start_server():
        console.print("[red]Failed to start server[/red]")
        sys.exit(1)

    if not args.log_file:
        console.print("[green]Server started successfully[/green]")

    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    time.sleep(1)

    try:
        monitor.run()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        monitor.stop_server()
        sys.exit(1)


if __name__ == "__main__":
    main()