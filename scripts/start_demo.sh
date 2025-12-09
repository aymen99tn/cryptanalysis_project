#!/bin/bash
# Integrated launch script - starts everything for a complete demo
# This is the ONE-COMMAND startup for presentations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Configuration
DEFAULT_IP=$(hostname -I | awk '{print $1}')
if [ -z "$DEFAULT_IP" ]; then
    DEFAULT_IP="127.0.0.1"
fi
SERVER_IP="${1:-$DEFAULT_IP}"
ENABLE_WIRESHARK="${2:-yes}"
INTERFACE="lo"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║     TLS 1.3 Secure Document Server - Complete Demo Suite         ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  University of New Brunswick"
echo "  TLS 1.3 + AEAD + Perfect Forward Secrecy"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Track PIDs for cleanup
declare -a PIDS_TO_KILL

cleanup() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Shutting down demo environment..."
    echo ""

    for pid in "${PIDS_TO_KILL[@]}"; do
        if ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid" 2>/dev/null || true
            echo "  ✓ Stopped process $pid"
        fi
    done

    echo ""
    echo "✓ Demo environment stopped"
    echo ""
    exit 0
}

trap cleanup INT TERM

# Mode Selection
echo "Select Operation Mode:"
echo "  1. Local Demo (Server + Client on this machine)"
echo "  2. Server Mode (Start Server only, wait for connections)"
echo "  3. Client Mode (Connect to a remote server)"
echo ""
read -p "Enter choice [1-3]: " mode_choice

if [ "$mode_choice" = "3" ]; then
    read -p "Enter Server IP [$DEFAULT_IP]: " input_ip
    SERVER_IP="${input_ip:-$DEFAULT_IP}"
    echo "Using Server IP: $SERVER_IP"
    SKIP_SERVER_START=true
else
    SERVER_IP="127.0.0.1" # Force localhost for local demo to ensure connectivity
    if [ "$mode_choice" = "2" ]; then
         # For server mode, we want to listen and show the LAN IP
         SERVER_IP="0.0.0.0" 
         DISPLAY_IP="$DEFAULT_IP"
    fi
    SKIP_SERVER_START=false
fi

# Step 1: Check prerequisites
echo "Step 1/6: Checking prerequisites..."
echo ""

# Check if binaries exist
if [ "$SKIP_SERVER_START" = "false" ]; then
    if [ ! -f "./server" ]; then
        echo "  ⚠️  Server binary not found. Building..."
        make clean && make
        echo "  ✓ Built server and client"
    else
        echo "  ✓ Server binary found"
    fi
fi

if [ ! -f "./client" ]; then
    echo "  ⚠️  Client binary not found"
    echo "  Run: make"
    exit 1
fi
echo "  ✓ Client binary found"

# Check certificates
if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
    echo "  ⚠️  Certificates not found. Generating..."
    mkdir -p certs
    /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout certs/key.pem -out certs/cert.pem -days 365 \
        -subj "/CN=localhost" 2>/dev/null
    echo "  ✓ Generated self-signed certificates"
else
    echo "  ✓ Certificates found"
fi

# Check database
if [ ! -f "data/documents.db" ]; then
    echo "  ℹ️  Database will be created and seeded on first run"
else
    echo "  ✓ Database found"
fi

echo ""

# Step 2: Start the TLS server
if [ "$SKIP_SERVER_START" = "false" ]; then
    echo "Step 2/6: Starting TLS 1.3 server..."
    echo ""

    export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
    export TLS_CERT=certs/cert.pem
    export TLS_KEY=certs/key.pem

    ./server > logs/server.log 2>&1 &
    SERVER_PID=$!
    PIDS_TO_KILL+=($SERVER_PID)

    echo "  ✓ Server started (PID: $SERVER_PID)"
    if [ "$mode_choice" = "2" ]; then
        echo "    Listening on: 0.0.0.0:8080 (Accessible at $DISPLAY_IP:8080)"
    else
        echo "    Listening on: 0.0.0.0:8080"
    fi
    echo "    Logs: logs/server.log"

    # Wait for server to start
    sleep 2

    # Verify server is running
    if ! ps -p $SERVER_PID > /dev/null; then
        echo "  ✗ Server failed to start. Check logs/server.log"
        exit 1
    fi
    
    # Check port
    if ! nc -z 127.0.0.1 8080 2>/dev/null; then
         # Try checking with lsof or netstat if nc fails (sometimes nc -z is tricky with 0.0.0.0)
         if ! lsof -i :8080 >/dev/null 2>&1; then
             echo "  ✗ Server not responding on port 8080"
             exit 1
         fi
    fi

    echo "  ✓ Server is responding"
    echo ""
else
    echo "Step 2/6: Skipping server start (Client Mode)"
    echo "  Target Server: $SERVER_IP:8080"
    echo ""
fi

# Step 3: Start packet capture (optional)
# Only capture if we started the server OR if we explicitly want to capture client traffic locally
if [ "$ENABLE_WIRESHARK" = "yes" ] && command -v tshark &> /dev/null; then
    echo "Step 3/6: Starting packet capture..."
    echo ""

    if [ "$mode_choice" != "1" ]; then
        INTERFACE="any"
    fi

    mkdir -p captures
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    CAPTURE_FILE="captures/demo_${TIMESTAMP}.pcap"

    tshark -i $INTERFACE -f "tcp port 8080" -w "$CAPTURE_FILE" -q &
    TSHARK_PID=$!
    PIDS_TO_KILL+=($TSHARK_PID)

    echo "  ✓ tshark capturing (PID: $TSHARK_PID)"
    echo "    Interface: $INTERFACE"
    echo "    Output: $CAPTURE_FILE"

    sleep 1

    # Try to launch Wireshark GUI
    if command -v wireshark &> /dev/null; then
        wireshark -i $INTERFACE -k -f "tcp port 8080" -Y "tls" 2>/dev/null &
        WIRESHARK_PID=$!
        PIDS_TO_KILL+=($WIRESHARK_PID)
        echo "  ✓ Wireshark GUI launched (PID: $WIRESHARK_PID)"
    fi
    echo ""
else
    echo "Step 3/6: Packet capture skipped"
    echo "  ℹ️  tshark not installed or disabled"
    echo ""
fi

# Step 4: Display system status
echo "Step 4/6: System status"
echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  Component          Status        PID               │"
echo "  ├─────────────────────────────────────────────────────┤"
if [ "$SKIP_SERVER_START" = "false" ]; then
    printf "  │  TLS Server         %-10s    %-10s        │\n" "RUNNING" "$SERVER_PID"
else
    printf "  │  TLS Server         %-10s    %-10s        │\n" "REMOTE" "$SERVER_IP"
fi
if [ -n "$TSHARK_PID" ]; then
    printf "  │  Packet Capture     %-10s    %-10s        │\n" "RUNNING" "$TSHARK_PID"
fi
if [ -n "$WIRESHARK_PID" ]; then
    printf "  │  Wireshark GUI      %-10s    %-10s        │\n" "RUNNING" "$WIRESHARK_PID"
fi
echo "  └─────────────────────────────────────────────────────┘"
echo ""

# Step 5: Show available features
echo "Step 5/6: Available demo features"
echo ""
echo "  📚 Document Library (15 documents)"
echo "  🎨 Enhanced Client (Colors, Emojis)"
echo "  📊 Testing Tools (TUI Runner, Packet Analysis)"
echo ""

# Step 6: Interactive menu
echo "Step 6/6: Demo mode selection"
echo ""

# If Server Mode, default to Monitor
if [ "$mode_choice" = "2" ]; then
    echo "ℹ️  Running in Server Mode."
    echo "   Use 'Terminal UI Monitor' to watch traffic."
    echo ""
fi

while true; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Mode: $(if [ "$mode_choice" = "1" ]; then echo "Local Demo"; elif [ "$mode_choice" = "2" ]; then echo "Server Only"; else echo "Client Only"; fi)"
    echo "Target: $SERVER_IP"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Choose action:"
    echo "  1. Interactive document browser (Client)"
    echo "  2. Run comprehensive tests (TUI)"
    echo "  3. Fetch single document (Client)"
    echo "  4. Auto-demo (showcase all features)"
    echo "  5. Terminal UI Monitor (Server Logs)"
    echo "  6. Exit"
    echo ""
    read -p "Enter choice (1-6): " choice
    echo ""

    case $choice in
        1)
            echo "🚀 Launching interactive document browser..."
            echo ""
            ./scripts/demo_documents.sh $SERVER_IP
            ;;
        2)
            echo "🚀 Running comprehensive tests..."
            echo ""
            if command -v python3 &> /dev/null; then
                # Check if rich is installed
                if python3 -c "import rich" 2>/dev/null; then
                    python3 scripts/run_tests_tui.py $SERVER_IP
                else
                    echo "⚠️  Python 'rich' library not installed"
                    echo "Install with: pip3 install rich"
                    echo ""
                    echo "Falling back to basic tests..."
                    sleep 2
                    ./scripts/comprehensive_tests.sh $SERVER_IP 2>/dev/null || echo "Basic test script not found"
                fi
            else
                echo "⚠️  Python3 not installed"
            fi
            ;;
        3)
            echo "🚀 Fetching document..."
            echo ""
            echo "Available documents:"
            echo "  welcome, course-catalog, student-records, tls13-spec,"
            echo "  architecture-diagram, cryptography-primer, unb-info, etc."
            echo ""
            read -p "Enter document ID: " doc_id
            echo ""
            ./client $SERVER_IP 8080 "$doc_id" certs/cert.pem 0
            echo ""
            ;;
        4)
            echo "🚀 Starting auto-demo..."
            echo ""
            echo "This will automatically showcase:"
            echo "  • Multiple document types"
            echo "  • Colored client output"
            echo "  • TLS 1.3 handshake"
            echo "  • Performance metrics"
            echo ""
            sleep 2

            # Demo sequence
            docs=("welcome" "course-catalog" "architecture-diagram" "cryptography-primer" "research-data")

            for doc in "${docs[@]}"; do
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Fetching: $doc"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                ./client $SERVER_IP 8080 "$doc" certs/cert.pem 0
                echo ""
                sleep 3
            done

            echo "✓ Auto-demo complete!"
            echo ""
            ;;
        5)
            echo "🚀 Launching Server Monitor..."
            echo ""
            if [ "$mode_choice" = "3" ]; then
                echo "⚠️  Error: Server Monitor requires access to server logs."
                echo "   You are in Client Mode connected to a remote server."
                echo "   Cannot monitor remote server logs from here."
                echo ""
            else
                # We are in Local or Server mode, so logs/server.log exists and is being written to.
                # Use the new --log-file option to tail it.
                python3 scripts/tui_monitor.py "$SERVER_IP" --log-file logs/server.log
            fi
            ;;
        6)
            echo "Exiting..."
            cleanup
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
done

