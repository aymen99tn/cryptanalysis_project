#!/bin/bash
# Auto-launch Wireshark with TLS 1.3 capture and pre-configured filters

SERVER_IP="${1:-127.0.0.1}"
INTERFACE="${2:-lo}"  # Default to loopback, can use eth0, wlan0, etc.

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║           TLS 1.3 Server with Wireshark Packet Capture           ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# Check if Wireshark is installed
if ! command -v wireshark &> /dev/null && ! command -v tshark &> /dev/null; then
    echo "❌ Wireshark/tshark not installed"
    echo ""
    echo "Install with:"
    echo "  sudo apt-get install wireshark tshark"
    exit 1
fi

# Check if server is running
if ! nc -z "$SERVER_IP" 8080 2>/dev/null; then
    if [ "$SERVER_IP" = "127.0.0.1" ] || [ "$SERVER_IP" = "localhost" ]; then
        echo "⚠️  Server not detected at $SERVER_IP:8080"
        echo ""
        echo "Starting local server..."
        export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
        ./server &
        SERVER_PID=$!
        echo "✓ Server started (PID: $SERVER_PID)"
        sleep 2
    else
        echo "⚠️  Remote server at $SERVER_IP:8080 is not reachable."
        echo "   (It might be firewalled or not running. Starting capture anyway...)"
        SERVER_PID=""
    fi
else
    echo "✓ Server detected at $SERVER_IP:8080"
    SERVER_PID=""
fi

echo ""
echo "Starting packet capture..."
echo "  Interface: $INTERFACE"
echo "  Filter: tcp port 8080"
echo ""

# Create directory for captures
CAPTURE_DIR="captures"
mkdir -p "$CAPTURE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="$CAPTURE_DIR/tls13_capture_${TIMESTAMP}.pcap"

# Start tshark capture in background
tshark -i "$INTERFACE" -f "tcp port 8080" -w "$CAPTURE_FILE" -q &
TSHARK_PID=$!

echo "✓ tshark capturing to: $CAPTURE_FILE (PID: $TSHARK_PID)"
sleep 1

# Try to launch Wireshark GUI if available
if command -v wireshark &> /dev/null; then
    echo "✓ Launching Wireshark with live capture..."
    echo ""

    # Launch Wireshark with pre-configured settings
    wireshark \
        -i "$INTERFACE" \
        -k \
        -f "tcp port 8080" \
        -Y "tls" \
        -o "gui.window_title:TLS 1.3 Demo - Live Capture" \
        2>/dev/null &
    WIRESHARK_PID=$!

    echo "✓ Wireshark launched (PID: $WIRESHARK_PID)"
else
    echo "ℹ️  Wireshark GUI not available, using tshark only"
    WIRESHARK_PID=""
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Capture setup complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Running processes:"
if [ -n "$SERVER_PID" ]; then
    echo "  • Server:    PID $SERVER_PID"
fi
echo "  • tshark:    PID $TSHARK_PID"
if [ -n "$WIRESHARK_PID" ]; then
    echo "  • Wireshark: PID $WIRESHARK_PID"
fi
echo ""
echo "Capture file: $CAPTURE_FILE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Recommended Wireshark Display Filters:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  View all TLS traffic:"
echo "    tls"
echo ""
echo "  View TLS handshakes only:"
echo "    tls.handshake"
echo ""
echo "  View TLS 1.3 only:"
echo "    tls.handshake.version == 0x0304"
echo ""
echo "  View application data:"
echo "    tls.app_data"
echo ""
echo "  View ClientHello messages:"
echo "    tls.handshake.type == 1"
echo ""
echo "  View ServerHello messages:"
echo "    tls.handshake.type == 2"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Now run the client in another terminal:"
echo "  ./client $SERVER_IP 8080 welcome certs/cert.pem 0"
echo ""
echo "Or run the interactive demo:"
echo "  ./scripts/demo_documents.sh $SERVER_IP"
echo ""
echo "Press Ctrl+C to stop capture and view results..."
echo ""

# Trap Ctrl+C to cleanly stop capture
trap cleanup INT

cleanup() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Stopping capture..."

    if [ -n "$TSHARK_PID" ]; then
        kill $TSHARK_PID 2>/dev/null
        echo "✓ tshark stopped"
    fi

    if [ -n "$WIRESHARK_PID" ]; then
        # Wireshark may already be closed by user
        kill $WIRESHARK_PID 2>/dev/null
        echo "✓ Wireshark stopped"
    fi

    if [ -n "$SERVER_PID" ]; then
        echo ""
        read -p "Stop server? (y/n): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kill $SERVER_PID 2>/dev/null
            echo "✓ Server stopped"
        fi
    fi

    echo ""
    echo "Capture saved to: $CAPTURE_FILE"

    # Show capture statistics
    if [ -f "$CAPTURE_FILE" ]; then
        echo ""
        echo "Capture statistics:"
        capinfos "$CAPTURE_FILE" 2>/dev/null | grep -E "(Number of packets|File size|Capture duration)"

        echo ""
        echo "TLS packet breakdown:"
        tshark -r "$CAPTURE_FILE" -Y tls -q -z io,phs 2>/dev/null | head -20
    fi

    echo ""
    echo "To analyze the capture:"
    echo "  wireshark $CAPTURE_FILE"
    echo ""
    echo "To view TLS handshakes:"
    echo "  tshark -r $CAPTURE_FILE -Y 'tls.handshake'"
    echo ""

    exit 0
}

# Wait for Ctrl+C
wait
