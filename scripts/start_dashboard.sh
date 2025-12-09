#!/bin/bash
# Launch script for TLS 1.3 Web Dashboard
# Automatically starts the server and opens the dashboard in browser

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}\")\" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║         TLS 1.3 Server - Web Dashboard                           ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  University of New Brunswick"
echo "  Real-time Monitoring & Analytics"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Python and Flask
echo "Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found"
    echo "Install with: sudo apt-get install python3"
    exit 1
fi
echo "✓ Python3 found"

if ! python3 -c "import flask" 2>/dev/null; then
    echo "⚠️  Flask not installed"
    echo ""
    read -p "Install Flask now? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip3 install flask
        echo "✓ Flask installed"
    else
        echo "Install manually with: pip3 install flask"
        exit 1
    fi
else
    echo "✓ Flask found"
fi

# Check if server binary exists
if [ ! -f "./server" ]; then
    echo "❌ Server binary not found"
    echo "Build with: make"
    exit 1
fi
echo "✓ Server binary found"

# Check certificates
if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
    echo "⚠️  Certificates not found, generating..."
    mkdir -p certs
    /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout certs/key.pem -out certs/cert.pem -days 365 \
        -subj "/CN=localhost" 2>/dev/null
    echo "✓ Certificates generated"
else
    echo "✓ Certificates found"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Starting dashboard..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start the dashboard (which auto-starts the TLS server)
python3 dashboard/server.py &
DASHBOARD_PID=$!

# Wait for dashboard to start
sleep 3

# Check if dashboard is running
if ps -p $DASHBOARD_PID > /dev/null 2>&1; then
    echo "✓ Dashboard started (PID: $DASHBOARD_PID)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    LAN_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$LAN_IP" ]; then LAN_IP="127.0.0.1"; fi
    echo "  Dashboard URL: http://localhost:5000"
    echo "  Remote Access: http://$LAN_IP:5000"
    echo ""
    echo "  Opening browser..."
    echo ""

    # Try to open browser
    if command -v xdg-open &> /dev/null; then
        xdg-open "http://localhost:5000" 2>/dev/null &
    elif command -v open &> /dev/null; then
        open "http://localhost:5000" 2>/dev/null &
    else
        echo "  (Couldn't auto-open browser, please navigate manually)"
    fi

    echo "  Press Ctrl+C to stop dashboard and server"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Wait for dashboard process
    wait $DASHBOARD_PID
else
    echo "❌ Dashboard failed to start"
    echo "Check for errors above"
    exit 1
fi
