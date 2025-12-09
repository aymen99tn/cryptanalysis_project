#!/bin/bash
# Demo script to showcase the enhanced document library and colored client output

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║        TLS 1.3 Document Server - Interactive Demo                ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

SERVER_IP="${1:-127.0.0.1}"
PORT="8080"

# Check if server is running
if ! nc -z "$SERVER_IP" "$PORT" 2>/dev/null; then
    echo "❌ Server not running on $SERVER_IP:$PORT"
    echo ""
    echo "Please start the server first:"
    echo "  export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:\$LD_LIBRARY_PATH"
    echo "  ./server"
    exit 1
fi

echo "✓ Server detected at $SERVER_IP:$PORT"
echo ""

# Array of documents to demonstrate
declare -a documents=(
    "welcome:UNB Welcome Page (HTML)"
    "course-catalog:Course Catalog (JSON)"
    "student-records:Student Records (JSON)"
    "tls13-spec:TLS 1.3 Specification"
    "architecture-diagram:System Architecture (ASCII Art)"
    "cryptography-primer:Cryptography Primer (HTML)"
    "openssl-guide:OpenSSL Quick Reference"
    "performance-analysis:Performance Analysis (HTML)"
    "unb-info:University Information (HTML)"
    "security-practices:Security Best Practices"
    "lab-instructions:Lab Instructions"
    "research-data:Research Data (CSV)"
    "doc-1kb:1KB Test Document"
    "doc-10kb:10KB Test Document"
    "readme:Quick Reference"
)

echo "Available Documents:"
echo "───────────────────────────────────────────────────────────────────"
for i in "${!documents[@]}"; do
    IFS=':' read -r doc_id description <<< "${documents[$i]}"
    printf "%2d. %-20s - %s\n" $((i+1)) "$doc_id" "$description"
done
echo "───────────────────────────────────────────────────────────────────"
echo ""

# Interactive mode
echo "Enter document number to fetch (1-${#documents[@]}), 'a' for auto-demo, or 'q' to quit:"
echo ""

while true; do
    read -p "> " choice

    if [[ "$choice" == "q" ]]; then
        echo "Goodbye!"
        exit 0
    fi

    if [[ "$choice" == "a" ]]; then
        echo ""
        echo "🎬 Starting auto-demo..."
        echo ""
        sleep 1

        # Demo 5 interesting documents
        demo_docs=("welcome" "course-catalog" "architecture-diagram" "cryptography-primer" "research-data")

        for doc_id in "${demo_docs[@]}"; do
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Fetching: $doc_id"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            ./client "$SERVER_IP" "$PORT" "$doc_id" certs/cert.pem 0
            echo ""
            sleep 2
        done

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "✓ Auto-demo complete!"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "Enter document number, 'a' for auto-demo again, or 'q' to quit:"
        continue
    fi

    # Validate numeric input
    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo "Invalid input. Please enter a number (1-${#documents[@]}), 'a', or 'q'."
        continue
    fi

    if (( choice < 1 || choice > ${#documents[@]} )); then
        echo "Invalid number. Please enter 1-${#documents[@]}."
        continue
    fi

    # Get document ID
    index=$((choice - 1))
    IFS=':' read -r doc_id description <<< "${documents[$index]}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Fetching: $doc_id - $description"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    ./client "$SERVER_IP" "$PORT" "$doc_id" certs/cert.pem 0

    echo ""
    echo "Enter document number, 'a' for auto-demo, or 'q' to quit:"
done
