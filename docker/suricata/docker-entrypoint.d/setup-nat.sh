#!/bin/bash
# Enable IP forwarding and NAT for transparent inline IDS/IPS routing
sysctl -w net.ipv4.ip_forward=1
iptables-legacy -F FORWARD 2>/dev/null || iptables -F FORWARD 2>/dev/null || true
iptables-legacy -A FORWARD -j ACCEPT 2>/dev/null || iptables -A FORWARD -j ACCEPT 2>/dev/null || true
iptables-legacy -t nat -A POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || true
iptables-legacy -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
