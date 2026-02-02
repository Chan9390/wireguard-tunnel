#!/bin/bash
#
# wireguard-tunnel setup script
# https://github.com/Chan9390/wireguard-tunnel
#
# Routes all traffic from Cloud VM through a WireGuard server
# while keeping SSH alive.
#

set -uo pipefail

VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

usage() {
    cat << EOF
wireguard-tunnel v${VERSION}

Usage: sudo $0 [OPTIONS] <wireguard-config-file>

Options:
    -h, --help          Show this help
    -n, --name NAME     Interface name (default: wg-tunnel)
    -u, --uninstall     Remove tunnel configuration

Examples:
    sudo $0 ~/wireguard.conf
    sudo $0 -n wg0 ~/wireguard.conf
    sudo $0 --uninstall

EOF
    exit 0
}

# =============================================================================
# Configuration
# =============================================================================

WG_INTERFACE="wg-tunnel"
RT_TABLE="tunnelbypass"
RT_TABLE_ID="200"

# Parse arguments
UNINSTALL=false
CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)      usage ;;
        -n|--name)      WG_INTERFACE="$2"; shift 2 ;;
        -u|--uninstall) UNINSTALL=true; shift ;;
        -*)             error "Unknown option: $1" ;;
        *)              CONFIG_FILE="$1"; shift ;;
    esac
done

# =============================================================================
# Detect Network
# =============================================================================

detect_network() {
    MAIN_IF=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1) || true
    MAIN_GW=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1) || true
    SERVER_IP=$(ip -4 addr show "$MAIN_IF" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1) || true

    [[ -z "$MAIN_IF" ]] && error "Could not detect network interface"
    [[ -z "$MAIN_GW" ]] && error "Could not detect gateway"
    [[ -z "$SERVER_IP" ]] && error "Could not detect server IP"
    return 0
}

# =============================================================================
# Uninstall
# =============================================================================

uninstall() {
    log "Uninstalling wireguard-tunnel..."
    
    # Try to detect network (may fail if already partially uninstalled)
    detect_network || true

    # Stop services
    systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    systemctl disable "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    systemctl stop tunnel-watchdog.timer 2>/dev/null || true
    systemctl disable tunnel-watchdog.timer 2>/dev/null || true

    # Clean up routes/rules (may fail if not set up)
    ip rule del from "$SERVER_IP" table "$RT_TABLE" 2>/dev/null || true
    ip route flush table "$RT_TABLE" 2>/dev/null || true
    ip route del 0.0.0.0/1 dev "$WG_INTERFACE" 2>/dev/null || true
    ip route del 128.0.0.0/1 dev "$WG_INTERFACE" 2>/dev/null || true
    ip6tables -D OUTPUT -o "$MAIN_IF" -j REJECT 2>/dev/null || true

    # Remove files
    rm -f "/etc/wireguard/${WG_INTERFACE}.conf"
    rm -f /etc/wireguard/tunnel-routing.sh
    rm -f /usr/local/bin/tunnel-start
    rm -f /usr/local/bin/tunnel-stop
    rm -f /usr/local/bin/tunnel-status
    rm -f /usr/local/bin/tunnel-watchdog.sh
    rm -f /etc/systemd/system/tunnel-watchdog.service
    rm -f /etc/systemd/system/tunnel-watchdog.timer

    systemctl daemon-reload 2>/dev/null || true

    log "Uninstall complete"
    exit 0
}

[[ "$UNINSTALL" == "true" ]] && uninstall

# =============================================================================
# Validation
# =============================================================================

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0 <config-file>"
[[ -z "$CONFIG_FILE" ]] && usage
[[ ! -f "$CONFIG_FILE" ]] && error "Config file not found: $CONFIG_FILE"

log "Using config: $CONFIG_FILE"

detect_network || error "Failed to detect network configuration"

log "Detected network:"
log "  Interface: $MAIN_IF"
log "  Gateway:   $MAIN_GW"
log "  Server IP: $SERVER_IP"

# =============================================================================
# Install Packages
# =============================================================================

log "Installing packages..."
apt-get update -qq
apt-get install -y wireguard wireguard-tools iptables iproute2 resolvconf -qq

# =============================================================================
# Setup Routing Table
# =============================================================================

log "Setting up routing table..."
if ! grep -q "$RT_TABLE" /etc/iproute2/rt_tables 2>/dev/null; then
    echo "$RT_TABLE_ID $RT_TABLE" >> /etc/iproute2/rt_tables
fi

# =============================================================================
# Setup Docker (prevent IPAM conflicts with /1 routes)
# =============================================================================

if [[ ! -f /etc/docker/daemon.json ]]; then
    log "Configuring Docker address pool..."
    mkdir -p /etc/docker
    echo '{"default-address-pools":[{"base":"10.200.0.0/16","size":24}]}' > /etc/docker/daemon.json
fi

# =============================================================================
# Parse WireGuard Config
# =============================================================================

log "Parsing WireGuard config..."

PRIVATE_KEY=$(grep -i "^PrivateKey" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d ' ')
ADDRESS=$(grep -i "^Address" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d ' ')
DNS=$(grep -i "^DNS" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d ' ')
PUBLIC_KEY=$(grep -i "^PublicKey" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d ' ')
ENDPOINT=$(grep -i "^Endpoint" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d ' ')
WG_SERVER=$(echo "$ENDPOINT" | cut -d':' -f1)

[[ -z "$PRIVATE_KEY" ]] && error "Could not parse PrivateKey"
[[ -z "$PUBLIC_KEY" ]] && error "Could not parse PublicKey"
[[ -z "$ENDPOINT" ]] && error "Could not parse Endpoint"

log "WireGuard Server: $WG_SERVER"

# =============================================================================
# Create WireGuard Config
# =============================================================================

log "Creating WireGuard config..."

cat > "/etc/wireguard/${WG_INTERFACE}.conf" << EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${ADDRESS}
DNS = ${DNS:-10.2.0.1}
Table = off
MTU = 1420

PostUp = /etc/wireguard/tunnel-routing.sh up %i ${MAIN_IF} ${MAIN_GW} ${WG_SERVER} ${SERVER_IP}
PreDown = /etc/wireguard/tunnel-routing.sh down %i ${MAIN_IF} ${MAIN_GW} ${WG_SERVER} ${SERVER_IP}

[Peer]
PublicKey = ${PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = ${ENDPOINT}
PersistentKeepalive = 25
EOF

chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"

# =============================================================================
# Create Routing Script
# =============================================================================

log "Creating routing script..."

cat > /etc/wireguard/tunnel-routing.sh << 'ROUTING_SCRIPT'
#!/bin/bash
#
# Tunnel Routing Script
# Routes all traffic through WireGuard while keeping SSH alive
#

ACTION="$1"
WG_IF="$2"
MAIN_IF="$3"
MAIN_GW="$4"
WG_SERVER="$5"
SERVER_IP="$6"

RT_TABLE="tunnelbypass"

up() {
    echo "[tunnel] Starting routing..."

    # Loose reverse path filtering
    sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
    sysctl -w net.ipv4.conf.${MAIN_IF}.rp_filter=2 >/dev/null
    sysctl -w net.ipv4.conf.${WG_IF}.rp_filter=2 2>/dev/null || true

    # Route to WireGuard server via original gateway
    ip route add "$WG_SERVER/32" via "$MAIN_GW" dev "$MAIN_IF" 2>/dev/null || \
        ip route replace "$WG_SERVER/32" via "$MAIN_GW" dev "$MAIN_IF"

    # Setup bypass routing table (default route via main gateway)
    ip route add default via "$MAIN_GW" dev "$MAIN_IF" table "$RT_TABLE" 2>/dev/null || \
        ip route replace default via "$MAIN_GW" dev "$MAIN_IF" table "$RT_TABLE"

    # Source-based routing rule (keeps SSH alive)
    ip rule del from "$SERVER_IP" table "$RT_TABLE" 2>/dev/null || true
    ip rule add from "$SERVER_IP" table "$RT_TABLE" priority 100

    # Route link-local directly (cloud metadata services)
    ip route add 169.254.0.0/16 dev "$MAIN_IF" 2>/dev/null || true

    # Route everything else through WireGuard
    ip route add 0.0.0.0/1 dev "$WG_IF" 2>/dev/null || ip route replace 0.0.0.0/1 dev "$WG_IF"
    ip route add 128.0.0.0/1 dev "$WG_IF" 2>/dev/null || ip route replace 128.0.0.0/1 dev "$WG_IF"

    # Block IPv6 leaks
    ip6tables -C OUTPUT -o "$MAIN_IF" -j REJECT 2>/dev/null || ip6tables -A OUTPUT -o "$MAIN_IF" -j REJECT
    ip6tables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT -o lo -j ACCEPT

    echo "[tunnel] Routing active"
}

down() {
    echo "[tunnel] Stopping routing..."

    ip route del 0.0.0.0/1 dev "$WG_IF" 2>/dev/null || true
    ip route del 128.0.0.0/1 dev "$WG_IF" 2>/dev/null || true
    ip route del "$WG_SERVER/32" via "$MAIN_GW" dev "$MAIN_IF" 2>/dev/null || true
    ip rule del from "$SERVER_IP" table "$RT_TABLE" 2>/dev/null || true
    ip route del 169.254.0.0/16 dev "$MAIN_IF" 2>/dev/null || true

    ip route flush table "$RT_TABLE" 2>/dev/null || true
    ip6tables -D OUTPUT -o "$MAIN_IF" -j REJECT 2>/dev/null || true
    ip6tables -D OUTPUT -o lo -j ACCEPT 2>/dev/null || true

    echo "[tunnel] Routing stopped"
}

case "$ACTION" in
    up)   up ;;
    down) down ;;
    *)    echo "Usage: $0 {up|down} ..."; exit 1 ;;
esac
ROUTING_SCRIPT

chmod +x /etc/wireguard/tunnel-routing.sh

# =============================================================================
# Create Helper Commands
# =============================================================================

log "Creating helper commands..."

cat > /usr/local/bin/tunnel-start << EOF
#!/bin/bash
echo "Starting tunnel..."
wg-quick up ${WG_INTERFACE}
systemctl start tunnel-watchdog.timer 2>/dev/null || true
sleep 2
echo ""
echo "Public IP: \$(curl -4 -s --max-time 5 ifconfig.me || echo 'unknown')"
wg show ${WG_INTERFACE} 2>/dev/null | grep -E "latest handshake|transfer"
EOF

cat > /usr/local/bin/tunnel-stop << EOF
#!/bin/bash
echo "Stopping tunnel..."
systemctl stop tunnel-watchdog.timer 2>/dev/null || true
wg-quick down ${WG_INTERFACE} 2>/dev/null || true
echo "Tunnel stopped"
echo "Public IP: \$(curl -4 -s --max-time 5 ifconfig.me || echo 'unknown')"
EOF

cat > /usr/local/bin/tunnel-status << EOF
#!/bin/bash
echo "=== Tunnel Status ==="
wg show ${WG_INTERFACE} 2>/dev/null || echo "Tunnel is not running"
echo ""
echo "Public IP: \$(curl -4 -s --max-time 5 ifconfig.me || echo 'unknown')"
echo ""
echo "Routing rule:"
ip rule show | grep -E "from.*tunnelbypass" || echo "  (not active)"
EOF

chmod +x /usr/local/bin/tunnel-{start,stop,status}

# =============================================================================
# Create Watchdog
# =============================================================================

log "Creating watchdog..."

cat > /usr/local/bin/tunnel-watchdog.sh << EOF
#!/bin/bash
#
# Tunnel Watchdog - auto-recovers if routing breaks
#

SERVER_IP="${SERVER_IP}"
MAIN_IF="${MAIN_IF}"
MAIN_GW="${MAIN_GW}"
WG_SERVER="${WG_SERVER}"
WG_IF="${WG_INTERFACE}"
LOG_TAG="tunnel-watchdog"

# Only run if interface exists
ip link show "\$WG_IF" &>/dev/null || exit 0

# Check if routing rule exists
if ! ip rule show | grep -q "from \$SERVER_IP"; then
    logger -t "\$LOG_TAG" "Routing rule missing - reapplying"
    /etc/wireguard/tunnel-routing.sh up "\$WG_IF" "\$MAIN_IF" "\$MAIN_GW" "\$WG_SERVER" "\$SERVER_IP"
fi

# Check handshake freshness
LAST_HS=\$(wg show "\$WG_IF" latest-handshakes 2>/dev/null | awk '{print \$2}')
NOW=\$(date +%s)

if [[ -n "\$LAST_HS" && "\$LAST_HS" -gt 0 ]]; then
    AGE=\$((NOW - LAST_HS))
    if [[ \$AGE -gt 180 ]]; then
        logger -t "\$LOG_TAG" "Handshake stale (\${AGE}s) - restarting"
        systemctl restart wg-quick@\$WG_IF
    fi
fi
EOF

chmod +x /usr/local/bin/tunnel-watchdog.sh

# =============================================================================
# Create Systemd Timer
# =============================================================================

log "Creating systemd timer..."

cat > /etc/systemd/system/tunnel-watchdog.service << EOF
[Unit]
Description=Tunnel Watchdog
After=wg-quick@${WG_INTERFACE}.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tunnel-watchdog.sh
EOF

cat > /etc/systemd/system/tunnel-watchdog.timer << EOF
[Unit]
Description=Run Tunnel Watchdog every minute

[Timer]
OnBootSec=90
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable tunnel-watchdog.timer

# =============================================================================
# Done
# =============================================================================

echo ""
log "Setup complete!"
echo ""
echo "Commands:"
echo "  tunnel-start   - Start the tunnel"
echo "  tunnel-stop    - Stop the tunnel"  
echo "  tunnel-status  - Check status"
echo ""
echo "To start: sudo tunnel-start"
echo ""
