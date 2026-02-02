# wireguard-tunnel

Routing all traffic from a cloud VM through a WireGuard server (especially during pentest engagements) was painful. So I wrote this — full tunnel setup that keeps SSH alive.

Tested on Ubuntu 24.04 LTS

## Usage

```bash
sudo ./setup.sh /path/to/wireguard.conf
sudo tunnel-start
```

```bash
tunnel-start    # Start tunnel
tunnel-stop     # Stop tunnel
tunnel-status   # Check status
```

Uninstall:
```bash
sudo ./setup.sh --uninstall
```

## Features

- Full tunnel — all traffic routed through WireGuard
- SSH stays alive — incoming connections bypass the tunnel
- Self-healing — watchdog auto-recovers from `systemd daemon-reexec` issues
- Docker compatible — automatically configures Docker address pool
