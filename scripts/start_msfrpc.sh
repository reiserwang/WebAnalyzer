#!/bin/bash

# WebAnalyzer - Metasploit RPC Launcher
# Starts msfrpcd with settings compatible with WebAnalyzer backend.

echo "[*] Starting Metasploit RPC Daemon..."
echo "    User: msf"
echo "    Pass: toor"
echo "    Port: 55553"
echo "    SSL:  Enabled"

# Check if msfrpcd is in path
if ! command -v msfrpcd &> /dev/null; then
    echo "[!] Error: msfrpcd command not found."
    echo "    Please ensure Metasploit Framework is installed and in your PATH."
    exit 1
fi

# -P toor: Password
# -U msf:  Username
# -f:      Run in foreground (so you can see output/ctrl-c)
# -a:      Bind address
# -p:      Port (default 55553)
# -S:      Enable SSL (default is auto/on usually, but ensuring)
# Note: -n disables database (optional, remove if you need db for workspace tracking)

msfrpcd -P toor -U msf -f -a 127.0.0.1 -p 55553
