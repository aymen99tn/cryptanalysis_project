#!/bin/bash
# Analyze TLS 1.3 packet captures with detailed statistics

if [ $# -lt 1 ]; then
    echo "Usage: $0 <pcap_file>"
    echo ""
    echo "Example:"
    echo "  $0 captures/tls13_capture_20250109_143022.pcap"
    exit 1
fi

PCAP_FILE="$1"

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: File not found: $PCAP_FILE"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║              TLS 1.3 Packet Capture Analysis                      ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Analyzing: $PCAP_FILE"
echo ""

# Check if tshark is available
if ! command -v tshark &> /dev/null; then
    echo "Error: tshark not installed"
    echo "Install with: sudo apt-get install tshark"
    exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Capture Statistics"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
capinfos "$PCAP_FILE" 2>/dev/null | grep -E "(File size|Number of packets|Capture duration|Average packets)" || echo "No statistics available"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TLS Version Distribution"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
tshark -r "$PCAP_FILE" -Y tls.handshake.version -T fields -e tls.handshake.version 2>/dev/null | sort | uniq -c | while read count version; do
    case "$version" in
        "0x0304") echo "  TLS 1.3:  $count packets  ✓" ;;
        "0x0303") echo "  TLS 1.2:  $count packets  ⚠️" ;;
        "0x0302") echo "  TLS 1.1:  $count packets  ⚠️" ;;
        "0x0301") echo "  TLS 1.0:  $count packets  ⚠️" ;;
        *) echo "  Unknown:  $count packets ($version)" ;;
    esac
done
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TLS Handshake Types"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
tshark -r "$PCAP_FILE" -Y tls.handshake -T fields -e tls.handshake.type 2>/dev/null | sort | uniq -c | while read count type; do
    case "$type" in
        "1") echo "  ClientHello:              $count" ;;
        "2") echo "  ServerHello:              $count" ;;
        "4") echo "  NewSessionTicket:         $count" ;;
        "8") echo "  EncryptedExtensions:      $count" ;;
        "11") echo "  Certificate:              $count" ;;
        "13") echo "  CertificateRequest:       $count" ;;
        "15") echo "  CertificateVerify:        $count" ;;
        "20") echo "  Finished:                 $count" ;;
        *) echo "  Type $type:                $count" ;;
    esac
done
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Cipher Suites Negotiated"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 2" -T fields -e tls.handshake.ciphersuite 2>/dev/null | sort | uniq -c | while read count cipher; do
    case "$cipher" in
        "0x1301") echo "  TLS_AES_128_GCM_SHA256:      $count  ✓" ;;
        "0x1302") echo "  TLS_AES_256_GCM_SHA384:      $count  ✓" ;;
        "0x1303") echo "  TLS_CHACHA20_POLY1305_SHA256: $count  ✓" ;;
        "0x1304") echo "  TLS_AES_128_CCM_SHA256:      $count" ;;
        "0x1305") echo "  TLS_AES_128_CCM_8_SHA256:    $count" ;;
        *) echo "  Cipher $cipher:              $count" ;;
    esac
done
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Connection Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Count unique TCP streams
streams=$(tshark -r "$PCAP_FILE" -T fields -e tcp.stream 2>/dev/null | sort -u | wc -l)
echo "  Total TCP connections:    $streams"

# Count TLS handshakes (ClientHello)
handshakes=$(tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" 2>/dev/null | wc -l)
echo "  TLS handshakes:           $handshakes"

# Count application data records
app_data=$(tshark -r "$PCAP_FILE" -Y "tls.app_data" 2>/dev/null | wc -l)
echo "  Application data records: $app_data"

echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Detailed Packet List (First 20 TLS packets)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
tshark -r "$PCAP_FILE" -Y tls -c 20 2>/dev/null
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Export Options"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Extract TLS handshake details:"
echo "  tshark -r $PCAP_FILE -Y 'tls.handshake' -V"
echo ""
echo "Export to JSON:"
echo "  tshark -r $PCAP_FILE -Y tls -T json > output.json"
echo ""
echo "View specific stream (e.g., stream 0):"
echo "  tshark -r $PCAP_FILE -Y 'tcp.stream == 0' -V"
echo ""
echo "Open in Wireshark GUI:"
echo "  wireshark $PCAP_FILE"
echo ""
