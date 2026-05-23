#!/bin/bash

# Get the directory of the script to make paths dynamic
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Path to the proxy executable compiled in WSL
PROXY_EXE="$SCRIPT_DIR/../coap-http-reverseproxy/coap-http-reverseproxy"
PSK_FILE="$SCRIPT_DIR/psk.txt"

echo "=== STARTING COAP REVERSE PROXIES ==="

# Kill any existing proxy instances
echo "Stopping any existing proxy instances..."
killall coap-http-reverseproxy 2>/dev/null
sleep 1

# Dynamically determine the backend host.
# First check if the server is running locally inside WSL on port 3000.
if curl -s -o /dev/null http://127.0.0.1:3000/rsa/key; then
  BACKEND_IP="127.0.0.1"
  echo "Detected Node.js servers running locally inside WSL: using $BACKEND_IP"
else
  # Otherwise, assume they are running on the Windows host
  BACKEND_IP=$(ip route | grep default | awk '{print $3}')
  if [ -z "$BACKEND_IP" ]; then
    BACKEND_IP="127.0.0.1"
  fi
  echo "Detected Node.js servers running on Windows Host IP: $BACKEND_IP"
fi

# 1. Proxies for Decryption/Signature Server (serverE on port 3000)
echo "Launching plain CoAP proxy for serverE on UDP port 5683 -> http://$BACKEND_IP:3000..."
$PROXY_EXE --port 5683 http://$BACKEND_IP:3000 > /tmp/proxy_serverE_coap.log 2>&1 &

echo "Launching secure CoAPs (DTLS + PSK) proxy for serverE on UDP port 5684 -> http://$BACKEND_IP:3000..."
$PROXY_EXE --dtls psk --psk-file $PSK_FILE --port 5684 http://$BACKEND_IP:3000 > /tmp/proxy_serverE_coaps.log 2>&1 &

# 2. Proxies for Aggregator Server (aggregator on port 4000)
echo "Launching plain CoAP proxy for aggregator on UDP port 5685 -> http://$BACKEND_IP:4000..."
$PROXY_EXE --port 5685 http://$BACKEND_IP:4000 > /tmp/proxy_agg_coap.log 2>&1 &

echo "Launching secure CoAPs (DTLS + PSK) proxy for aggregator on UDP port 5686 -> http://$BACKEND_IP:4000..."
$PROXY_EXE --dtls psk --psk-file $PSK_FILE --port 5686 http://$BACKEND_IP:4000 > /tmp/proxy_agg_coaps.log 2>&1 &

sleep 2
echo "All proxies launched in the background!"
echo "Use 'killall coap-http-reverseproxy' to stop them."
echo "======================================"
