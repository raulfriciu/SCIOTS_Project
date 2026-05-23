#!/bin/bash

# Path to the proxy executable compiled in WSL
PROXY_EXE="/mnt/c/Users/janno/Desktop/SCIOTS/coap-http-reverseproxy/coap-http-reverseproxy"
PSK_FILE="/mnt/c/Users/janno/Desktop/SCIOTS/SCIOTS_Project/psk.txt"

echo "=== STARTING COAP REVERSE PROXIES ==="

# Kill any existing proxy instances
echo "Stopping any existing proxy instances..."
killall coap-http-reverseproxy 2>/dev/null
sleep 1

# Dynamically determine the Windows host IP address from WSL route
HOST_IP=$(ip route | grep default | awk '{print $3}')
if [ -z "$HOST_IP" ]; then
  HOST_IP="127.0.0.1"
fi
echo "Detected Windows host IP from WSL: $HOST_IP"

# 1. Proxies for Decryption/Signature Server (serverE on port 3000)
echo "Launching plain CoAP proxy for serverE on UDP port 5683 -> http://$HOST_IP:3000..."
$PROXY_EXE --port 5683 http://$HOST_IP:3000 > /tmp/proxy_serverE_coap.log 2>&1 &

echo "Launching secure CoAPs (DTLS + PSK) proxy for serverE on UDP port 5684 -> http://$HOST_IP:3000..."
$PROXY_EXE --dtls psk --psk-file $PSK_FILE --port 5684 http://$HOST_IP:3000 > /tmp/proxy_serverE_coaps.log 2>&1 &

# 2. Proxies for Aggregator Server (aggregator on port 4000)
echo "Launching plain CoAP proxy for aggregator on UDP port 5685 -> http://$HOST_IP:4000..."
$PROXY_EXE --port 5685 http://$HOST_IP:4000 > /tmp/proxy_agg_coap.log 2>&1 &

echo "Launching secure CoAPs (DTLS + PSK) proxy for aggregator on UDP port 5686 -> http://$HOST_IP:4000..."
$PROXY_EXE --dtls psk --psk-file $PSK_FILE --port 5686 http://$HOST_IP:4000 > /tmp/proxy_agg_coaps.log 2>&1 &

sleep 2
echo "All proxies launched in the background!"
echo "Use 'killall coap-http-reverseproxy' to stop them."
echo "======================================"
