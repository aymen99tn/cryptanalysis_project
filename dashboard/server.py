#!/usr/bin/env python3
"""
TLS 1.3 Server Dashboard - Web Interface
Real-time monitoring dashboard using Flask and Server-Sent Events (SSE)
"""

import subprocess
import time
import json
import threading
import queue
import os
import signal
from datetime import datetime
from collections import deque, Counter
from typing import Dict, List, Optional

try:
    from flask import Flask, render_template, jsonify, Response, stream_with_context
except ImportError:
    print("Error: Flask not installed")
    print("Install with: pip3 install flask")
    exit(1)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tls13-demo-secret'

# Global state
class DashboardState:
    def __init__(self):
        self.server_process: Optional[subprocess.Popen] = None
        self.start_time = datetime.now()
        self.running = False

        # Statistics
        self.total_connections = 0
        self.total_requests = 0
        self.total_errors = 0
        self.total_rate_limited = 0

        # Recent activity
        self.recent_requests: deque = deque(maxlen=100)

        # Document stats
        self.document_stats: Counter = Counter()

        # TLS stats
        self.cipher_stats: Counter = Counter()
        self.tls_version_stats: Counter = Counter()

        # Performance
        self.latencies: deque = deque(maxlen=100)
        self.rps_samples: deque = deque(maxlen=60)
        self.last_request_time = time.time()
        self.requests_in_window = 0

        # Event queue for SSE
        self.event_queue: queue.Queue = queue.Queue(maxsize=100)

        # Lock for thread safety
        self.lock = threading.Lock()

state = DashboardState()


def start_server():
    """Start the TLS server"""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    server_path = os.path.join(project_root, 'server')

    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:' + env.get('LD_LIBRARY_PATH', '')
    env['TLS_CERT'] = os.path.join(project_root, 'certs/cert.pem')
    env['TLS_KEY'] = os.path.join(project_root, 'certs/key.pem')

    state.server_process = subprocess.Popen(
        [server_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        cwd=project_root
    )

    state.running = True
    state.start_time = datetime.now()


def stop_server():
    """Stop the TLS server"""
    if state.server_process:
        state.server_process.terminate()
        try:
            state.server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            state.server_process.kill()
        state.running = False


def parse_log_line(line: str):
    """Parse JSON log line and update state"""
    try:
        data = json.loads(line.strip())
        log_type = data.get('type', '')

        with state.lock:
            if log_type == 'connection':
                state.total_connections += 1
                emit_event('connection', data)

            elif log_type == 'handshake':
                version = data.get('version', 'unknown')
                cipher = data.get('cipher', 'unknown')
                state.tls_version_stats[version] += 1
                state.cipher_stats[cipher] += 1
                emit_event('handshake', data)

            elif log_type == 'request':
                state.total_requests += 1
                state.requests_in_window += 1

                doc_id = data.get('id', 'unknown')
                state.document_stats[doc_id] += 1

                latency_us = data.get('elapsed_us', 0)
                latency_ms = latency_us / 1000.0
                state.latencies.append(latency_ms)

                request_data = {
                    'time': datetime.now().isoformat(),
                    'client': data.get('client_ip', 'unknown'),
                    'doc_id': doc_id,
                    'latency': latency_ms,
                    'status': data.get('status', 'ok')
                }
                state.recent_requests.append(request_data)
                emit_event('request', request_data)

            elif log_type == 'error':
                state.total_errors += 1
                emit_event('error', data)

            elif log_type == 'rate_limit':
                state.total_rate_limited += 1
                emit_event('rate_limit', data)

    except json.JSONDecodeError:
        pass


def emit_event(event_type: str, data: Dict):
    """Emit an SSE event"""
    try:
        state.event_queue.put_nowait({
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    except queue.Full:
        pass


def monitor_server_output():
    """Background thread to monitor server output"""
    while state.running and state.server_process:
        if state.server_process.poll() is not None:
            break

        if state.server_process.stdout:
            line = state.server_process.stdout.readline()
            if line:
                parse_log_line(line)

        time.sleep(0.01)


def calculate_rps() -> float:
    """Calculate requests per second"""
    current_time = time.time()

    if current_time - state.last_request_time >= 1.0:
        with state.lock:
            state.rps_samples.append(state.requests_in_window)
            state.requests_in_window = 0
            state.last_request_time = current_time

    if len(state.rps_samples) > 0:
        return sum(state.rps_samples) / len(state.rps_samples)
    return 0.0


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    with state.lock:
        uptime = (datetime.now() - state.start_time).total_seconds()

        if len(state.latencies) > 0:
            avg_latency = sum(state.latencies) / len(state.latencies)
            min_latency = min(state.latencies)
            max_latency = max(state.latencies)
        else:
            avg_latency = 0
            min_latency = 0
            max_latency = 0

        rps = calculate_rps()

        return jsonify({
            'status': 'running' if state.running else 'stopped',
            'uptime': uptime,
            'total_connections': state.total_connections,
            'total_requests': state.total_requests,
            'total_errors': state.total_errors,
            'total_rate_limited': state.total_rate_limited,
            'performance': {
                'avg_latency': avg_latency,
                'min_latency': min_latency,
                'max_latency': max_latency,
                'rps': rps
            },
            'top_documents': [
                {'doc_id': doc, 'count': count}
                for doc, count in state.document_stats.most_common(10)
            ],
            'cipher_distribution': [
                {'cipher': cipher, 'count': count}
                for cipher, count in state.cipher_stats.most_common(5)
            ],
            'recent_requests': list(state.recent_requests)[-20:]
        })


@app.route('/api/events')
def sse_events():
    """Server-Sent Events stream"""
    def event_stream():
        while True:
            try:
                # Wait for event with timeout
                event = state.event_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # Send keepalive
                yield f": keepalive\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/control/start', methods=['POST'])
def start_server_endpoint():
    """Start the server"""
    if not state.running:
        try:
            start_server()
            monitor_thread = threading.Thread(target=monitor_server_output, daemon=True)
            monitor_thread.start()
            return jsonify({'success': True, 'message': 'Server started'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    return jsonify({'success': False, 'message': 'Server already running'}), 400


@app.route('/api/control/stop', methods=['POST'])
def stop_server_endpoint():
    """Stop the server"""
    if state.running:
        stop_server()
        return jsonify({'success': True, 'message': 'Server stopped'})
    return jsonify({'success': False, 'message': 'Server not running'}), 400


def cleanup():
    """Cleanup on exit"""
    stop_server()


if __name__ == '__main__':
    import atexit
    atexit.register(cleanup)

    # Auto-start server
    print("Starting TLS 1.3 server...")
    try:
        start_server()
        time.sleep(2)  # Wait for server to start

        if state.server_process.poll() is None:
            print("Server started successfully")

            # Start monitoring thread
            monitor_thread = threading.Thread(target=monitor_server_output, daemon=True)
            monitor_thread.start()

            print("\n" + "="*60)
            print("TLS 1.3 Dashboard starting...")
            print("="*60)
            print("\nOpen your browser to: http://localhost:5000")
            print("\nPress Ctrl+C to stop\n")

            app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
        else:
            print("Failed to start server")
            exit(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        cleanup()
    except Exception as e:
        print(f"Error: {e}")
        cleanup()
        exit(1)
