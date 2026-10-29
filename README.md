# IP Router

Reefy app for sharing an existing internet connection through a separate
Ethernet adapter. Source and releases for the Reefy IP Router app.

The UI chooses the current default-route interface as uplink and prefers a USB
adapter downstream. It chooses an unused private /24 subnet. Users may edit the
subnet (/24 through /28) and disable the default-enabled DHCP server. Apply is
explicit, so installing the app alone does not change networking.

Internet-only mode blocks private/local destinations, host addresses outside the downstream subnet, spoofed
sources, unsolicited inbound forwarding and IPv6 on the downstream adapter.
Checks run before Docker destination NAT so published container ports cannot
bypass isolation. DHCP exceptions apply only to the gateway and broadcast
address. DNS clients receive public resolvers. This is direct IPv4 NAT, without
UPnP, port forwarding, VLAN trunking or inbound internet mappings.

`/data/config.json` retains configuration; normal app startup restores network
settings, firewall and DHCP. The app writes only its own runtime `.network` file
and firewall chains. The networkd file disables competing DHCP/RA clients on the
selected adapter. The app locks ownership so a second Router cannot overwrite
these rules. Stop routing leaves the downstream port isolated and permits
selection of a different adapter. An app restart is covered separately from an
actual whole-device reboot; do not claim reboot verification without running it.

## Runtime permissions

The app manifest requests host networking, `NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE` and `SETGID`, with other capabilities dropped.
`SETGID` allows DHCP to clear supplementary groups during startup. The host must provide loaded IPv4/IPv6 netfilter modules; Router never receives
`SYS_MODULE` or loads kernel modules. Saved settings retry automatically while
host networking becomes ready after boot. The image runs as root
at runtime so it can manage firewall, DHCP and networkd. It mounts the runtime
networkd configuration directory and system D-Bus socket to coordinate with the
host network manager. System-bus access is significant host authority; install
only trusted Router source. The UI binds to the allocated loopback app port and
uses Reefy's authenticated Open app route. Mutations additionally require a
same-page token and reject cross-site requests.

The isolated build smoke check overrides the user to UID 65534, drops every
capability, grants no host mounts, and only checks HTTP. It never applies host
network settings. No host control executable or firmware file is replaced.

Manual host routing/DHCP configured outside the app must be retired before
applying Router settings on that same adapter. Otherwise a competing DHCP
server can prevent activation. A failed change restores the previous saved
configuration where possible and retains the saved file and other app data.
Do not remove unrelated host firewall rules or addresses during migration.

## Validation

```sh
python -m pytest tests --ignore=tests/e2e
sudo python -m pytest tests/e2e/router_lab/test_router_network.py -q
```

The Linux E2E uses isolated namespaces and synthetic interfaces. It exercises
actual app HTTP, DHCP, addresses, routing and NAT, blocks LAN/host access, checks
DHCP-shaped bypass traffic and IPv6 firewall rules, restarts the app after losing
runtime state, disables DHCP and checks data preservation. Only physical
inventory and networkd D-Bus reload are fixture substitutions. Whole-device reboot verification is separate from the isolated app restart checks.

LAN protection defaults on, including for settings saved by earlier releases.
`protect_lan` is an optional boolean in the app's local settings; omitting it
keeps protection enabled. When enabled, Router blocks private/CGNAT ranges
and IPv4 networks directly connected to the selected uplink. Interface
addresses and connected routes are checked every five seconds while active;
default and gateway-routed internet routes are excluded. A failed refresh
blocks forwarding until the saved policy can be restored. Turning protection
off permits upstream LAN access while retaining host-service, source-spoofing,
IPv6 and reserved-address protections. The setting is saved with other router
settings and can be turned back on without stopping internet sharing.


## Downstream protection

Protect downstream LAN is checked by default for new setups and settings
without a previous downstream choice. With protection on, clients can use DHCP
but cannot connect to services on the router. Turn it off to allow IPv4 clients
in the configured downstream subnet to reach services listening on the router's
address in that subnet, including ICMP, SSH and other TCP/UDP services.

The optional boolean `protect_downstream` replaces `allow_downstream`. Explicit
legacy values are accepted and inverted on migration, preserving existing
connectivity. Saved settings use only the new name. Status includes a derived inverse
allow_downstream alias so old open tabs retain their correct state. Matching
field pairs can round-trip; conflicting pairs and non-boolean values are rejected. Existing configurations with
allow_downstream=true therefore display protection off; no saved choice is
silently reset. Both positions persist across restart.

Protect upstream LAN remains independent. Access to other host addresses,
unsolicited forwarding from upstream, spoofed sources and IPv6 remains blocked.
No new listening services are started or rebound. The app UI stays loopback-only.
