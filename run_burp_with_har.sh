#!/bin/bash
set -e

# Configuration
BURP_JAR="burpsuite_community_v2025.12.4.jar"
IMPORTER_JAR="burp-headless-har-importer.jar"
DOWNLOADS_DIR="$HOME/Downloads"
HAR_FILE="/home/david/Boolean/NETBEAR/reports/run_20260123_112337/netbear_requests.har"
CONFIG_FILE="har_files_to_import.json"

# Navigate to Downloads
cd "$DOWNLOADS_DIR"

# 1. Check for Importer JAR
if [ ! -f "$IMPORTER_JAR" ]; then
    echo "[-] Error: Importer JAR '$IMPORTER_JAR' not found in $DOWNLOADS_DIR."
    echo "Please download 'burp-headless-har-importer.jar' and place it in $DOWNLOADS_DIR."
    echo "You can find it at: https://github.com/Dynamic-Mobile-Security/burp-headless-har-importer/releases (or searching online)"
    exit 1
else
    echo "[+] Importer JAR found."
fi

# 2. Configure HAR Import
echo "[+] Creating $CONFIG_FILE configuration..."
cat > "$CONFIG_FILE" <<EOF
{
  "harfiles": [
    { "path": "$HAR_FILE" }
  ]
}
EOF

# 3. Launch Burp
if [ -f "$BURP_JAR" ]; then
    echo "[+] Launching Burp Suite with HAR Importer..."
    # Note: Using -classpath requires specifying the main class burp.StartBurp instead of -jar
    java -Xmx4g -classpath "$IMPORTER_JAR:$BURP_JAR" burp.StartBurp
else
    echo "[-] Error: Burp JAR ($BURP_JAR) not found in $DOWNLOADS_DIR"
    exit 1
fi
