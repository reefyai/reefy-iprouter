"""Host networking owned by one Router instance, with persistent configuration."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

PRIVATE = ('10.0.0.0/8', '100.64.0.0/10', '172.16.0.0/12', '192.168.0.0/16')
ALWAYS_BLOCK = ('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4')
NAME = re.compile(r'[a-zA-Z0-9_.-]{1,15}')


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if check and result.returncode:
        raise RuntimeError('Network operation failed: ' + args[0])
    return result.stdout


def interfaces():
    rows = json.loads(run('ip', '-j', 'address', 'show'))
    return [dict(name=r['ifname'], up='LOWER_UP' in r['flags'],
                 usb='usb' in str((Path('/sys/class/net') / r['ifname'] / 'device').resolve()),
                 addresses=[a['local'] + '/' + str(a['prefixlen']) for a in r['addr_info']
                            if a['family'] == 'inet'])
            for r in rows if (Path('/sys/class/net') / r['ifname'] / 'device').exists()]


def routes():
    return json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all'))


def downstream_protection(value):
    """Preserve explicit legacy choices; new configurations default protected."""
    for key in ('protect_downstream', 'allow_downstream'):
        if key in value and type(value[key]) is not bool:
            raise ValueError('Downstream protection must be enabled or disabled.')
    if 'protect_downstream' in value and 'allow_downstream' in value:
        if value['protect_downstream'] == value['allow_downstream']:
            raise ValueError('Downstream protection settings conflict.')
    if 'allow_downstream' in value:
        return not value['allow_downstream']
    return value.get('protect_downstream', True)


def validate(value, links, table):
    if not isinstance(value, dict) or set(value) - {'uplink', 'downstream', 'subnet', 'dhcp', 'protect_lan', 'allow_downstream', 'protect_downstream'} or not {'uplink', 'downstream', 'subnet', 'dhcp'} <= set(value):
        raise ValueError('Choose two interfaces, a subnet, and the DHCP setting.')
    value = dict(value, protect_lan=value.get('protect_lan', True),
                 protect_downstream=downstream_protection(value))
    value.pop('allow_downstream', None)
    if type(value['protect_lan']) is not bool:
        raise ValueError('LAN protection must be enabled or disabled.')
    known = {r['name'] for r in links}
    for field in ('uplink', 'downstream'):
        if not isinstance(value[field], str) or not NAME.fullmatch(value[field]) or value[field] not in known:
            raise ValueError('Choose an available physical network interface.')
    if value['uplink'] == value['downstream']:
        raise ValueError('The internet and downstream interfaces must be different.')
    if type(value['dhcp']) is not bool:
        raise ValueError('DHCP must be enabled or disabled.')
    if not any(r.get('dst') == 'default' and r.get('dev') == value['uplink'] for r in table):
        raise ValueError('The internet interface must have a default route.')
    if any(r.get('dst') == 'default' and r.get('dev') == value['downstream'] for r in table):
        raise ValueError('The downstream interface is currently an internet uplink.')
    try:
        subnet = ipaddress.IPv4Network(value['subnet'], strict=True)
    except (ValueError, TypeError):
        raise ValueError('Enter a subnet such as 10.77.0.0/24.') from None
    if not 24 <= subnet.prefixlen <= 28 or not any(subnet.subnet_of(ipaddress.ip_network(n))
                                                  for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('Use a private IPv4 subnet between /24 and /28.')
    for row in table:
        if row.get('dev') == value['downstream'] or row.get('dst') in (None, 'default'):
            continue
        if subnet.overlaps(ipaddress.ip_network(row['dst'], strict=False)):
            raise ValueError('That subnet overlaps another network on this device.')
    return dict(value, subnet=str(subnet))


def defaults(links, table):
    uplink = next((r.get('dev') for r in table if r.get('dst') == 'default'), '')
    downstream = next((r['name'] for r in links if r['name'] != uplink and r['usb']), '')
    if not downstream:
        downstream = next((r['name'] for r in links if r['name'] != uplink), '')
    for index in range(256):
        subnet = '10.77.' + str(index) + '.0/24'
        try:
            return validate(dict(uplink=uplink, downstream=downstream, subnet=subnet, dhcp=True), links, table)
        except ValueError:
            pass
    return dict(uplink=uplink, downstream=downstream, subnet='', dhcp=True, protect_lan=True, protect_downstream=True)


def upstream_networks(uplink, links, table):
    """Only connected IPv4 networks, never default or gateway-routed internet."""
    networks = set()
    for link in links:
        if link['name'] == uplink:
            for address in link.get('addresses', []):
                networks.add(ipaddress.IPv4Interface(address).network)
    for row in table:
        if (row.get('dev') == uplink and row.get('dst') not in (None, 'default')
                and not row.get('gateway') and row.get('type', 'unicast') == 'unicast'):
            network = ipaddress.IPv4Network(row['dst'], strict=False)
            if network.prefixlen:
                networks.add(network)
    return tuple(str(n) for n in sorted(networks))


def firewall_rules(config, detected=()):
    """Rules are applied before Docker DNAT, including DHCP exception checks."""
    usb, wan = config['downstream'], config['uplink']
    network = ipaddress.ip_network(config['subnet'])
    gateway = str(network.network_address + 1)
    guard = [('-d', target, '-p', 'udp', '--sport', '68', '--dport', '67', '-j', 'RETURN')
             for target in ('255.255.255.255', gateway)]
    guard += [('!', '-s', str(network), '-j', 'DROP')]
    if not downstream_protection(config):
        guard += [('-d', str(network), '-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'RETURN')]
    guard += [('-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'DROP')]
    targets = ALWAYS_BLOCK + (PRIVATE + tuple(detected) if config.get('protect_lan', True) else ())
    guard += [('-d', target, '-j', 'DROP') for target in dict.fromkeys(targets)]
    forward = [('-i', usb, '-s', str(network), '-o', wan, '-m', 'conntrack',
                '--ctstate', 'NEW,ESTABLISHED,RELATED', '-j', 'ACCEPT'),
               ('-i', usb, '-j', 'DROP'),
               ('-i', wan, '-o', usb, '-d', str(network), '-m', 'conntrack',
                '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'),
               ('-o', usb, '-j', 'DROP')]
    inbound = [('-p', 'udp', '--sport', '68', '--dport', '67', '-j', 'ACCEPT')]
    if not downstream_protection(config):
        inbound += [('-s', str(network), '-d', str(network), '-j', 'ACCEPT')]
    inbound += [('-j', 'DROP')]
    return guard, forward, inbound


class Router:
    def __init__(self, data='/data', host_network='/host-network'):
        self.data = Path(data)
        self.data.mkdir(parents=True, exist_ok=True)
        self.network_dir = Path(host_network)
        self.config = json.loads((self.data / 'config.json').read_text()) if (self.data / 'config.json').exists() else None
        if self.config is not None:
            self.config.setdefault('protect_lan', True)
            self.config['protect_downstream'] = downstream_protection(self.config)
            self.config.pop('allow_downstream', None)
        self.protected_networks = None
        self.lock = threading.RLock()
        self.dhcp = None
        self.error = None
        self.active = False
        self.iptables = None
        self.owner_lock = None
        self.stopped = (self.data / "disabled").exists()

    def ipt(self, *args, version=4, check=True):
        if self.iptables is None:
            for suffix in ('legacy', 'nft'):
                try:
                    run('iptables-' + suffix, '-w', '5', '-S', 'DOCKER')
                    self.iptables = suffix
                    break
                except (OSError, RuntimeError):
                    continue
            if self.iptables is None:
                self.iptables = 'legacy'
        return run(('iptables-' if version == 4 else 'ip6tables-') + self.iptables,
                   '-w', '5', *args, check=check)

    def ensure(self, table, chain, args, version=4):
        try:
            self.ipt('-t', table, '-C', chain, *args, version=version)
        except RuntimeError:
            self.ipt('-t', table, '-I', chain, '1', *args, version=version)

    def chain(self, table, name, rules):
        self.ipt('-t', table, '-N', name, check=False)
        # The kernel commits this table transaction atomically; other tables
        # and all unrelated Docker/host chains remain untouched.
        text = '*' + table + '\n-F ' + name + '\n'
        text += ''.join('-A ' + name + ' ' + ' '.join(rule) + '\n' for rule in rules)
        text += 'COMMIT\n'
        subprocess.run(['iptables-' + self.iptables + '-restore', '--wait', '5', '--noflush'],
                       input=text, text=True, capture_output=True, check=True, timeout=20)

    def network_reload(self, iface):
        run('busctl', '--system', 'call', 'org.freedesktop.network1',
            '/org/freedesktop/network1', 'org.freedesktop.network1.Manager', 'Reload')
        index = int((Path('/sys/class/net') / iface / 'ifindex').read_text())
        run('busctl', '--system', 'call', 'org.freedesktop.network1',
            '/org/freedesktop/network1', 'org.freedesktop.network1.Manager', 'ReconfigureLink', 'i', str(index))

    def _apply(self, config):
        usb = config['downstream']
        network = ipaddress.ip_network(config['subnet'])
        gateway = str(network.network_address + 1)
        if not self.network_dir.is_dir():
            raise RuntimeError('Router needs its network configuration mount.')
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
            raise RuntimeError('IPv4 forwarding must be enabled on this device.')
        if self.owner_lock is None:
            owner_lock = (self.network_dir / '.reefy-router.lock').open('a')
            try:
                fcntl.flock(owner_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                owner_lock.close()
                raise RuntimeError('Another Router instance already manages this device.') from None
            self.owner_lock = owner_lock
        # Fail closed before changing addresses or DHCP, and block IPv6 bypasses.
        self.ensure('filter', 'FORWARD', ('-i', usb, '-j', 'DROP'))
        for chain, args in [('INPUT', ('-i', usb, '-j', 'DROP')),
                            ('FORWARD', ('-i', usb, '-j', 'DROP')),
                            ('FORWARD', ('-o', usb, '-j', 'DROP'))]:
            self.ensure('filter', chain, args, version=6)
        detected = upstream_networks(config['uplink'], interfaces(), routes())
        guard, forward, inbound = firewall_rules(config, detected)
        self.chain('mangle', 'RFY-ROUTER-G', guard)
        self.ensure('mangle', 'PREROUTING', ('-i', usb, '-j', 'RFY-ROUTER-G'))
        self.chain('filter', 'RFY-ROUTER-I', inbound)
        self.ensure('filter', 'INPUT', ('-i', usb, '-j', 'RFY-ROUTER-I'))
        self.chain('filter', 'RFY-ROUTER-F', forward)
        self.chain('nat', 'RFY-ROUTER-N', [('-s', str(network), '-o', config['uplink'], '-j', 'MASQUERADE')])
        self.ensure('nat', 'POSTROUTING', ('-j', 'RFY-ROUTER-N'))
        self.ensure('filter', 'FORWARD', ('-j', 'RFY-ROUTER-F'))
        # A dedicated runtime network file outranks the firmware's DHCP wildcard.
        path = self.network_dir / ('00-reefy-router-' + usb + '.network')
        path.write_text('[Match]\nName=' + usb + '\n[Link]\nRequiredForOnline=no\n[Network]\n'
                        'DHCP=no\nKeepConfiguration=static\nAddress=' + gateway + '/' + str(network.prefixlen) + '\n'
                        'LinkLocalAddressing=no\nIPv6AcceptRA=no\nConfigureWithoutCarrier=yes\n')
        self.network_reload(usb)
        run('ip', 'link', 'set', usb, 'up')
        run('ip', 'addr', 'replace', gateway + '/' + str(network.prefixlen), 'dev', usb)
        if self.dhcp:
            self.dhcp.terminate()
            self.dhcp.wait(timeout=10)
            self.dhcp = None
        if config['dhcp']:
            start, end = str(network.network_address + 2), str(network.broadcast_address - 1)
            self.dhcp = subprocess.Popen(['dnsmasq', '--keep-in-foreground', '--conf-file=/dev/null',
                '--port=0', '--interface=' + usb, '--bind-dynamic', '--user=root', '--group=root',
                '--dhcp-authoritative', '--dhcp-range=' + ','.join((start, end, str(network.netmask), '12h')),
                '--dhcp-option=option:router,' + gateway, '--dhcp-option=option:dns-server,1.1.1.1,8.8.8.8',
                '--dhcp-leasefile=' + str(self.data / 'leases')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)
            if self.dhcp.poll() is not None:
                self.dhcp = None
                raise RuntimeError('DHCP could not start. Another DHCP server may already be running.')
        self.protected_networks = detected
        self.ipt('-D', 'FORWARD', '-i', usb, '-j', 'DROP')
        self.ipt('-D', 'INPUT', '-i', usb, '-j', 'DROP', check=False)

    def refresh_protection(self):
        """Refresh before-DNAT policy as connected upstream networks change."""
        with self.lock:
            if not self.active or self.stopped or not self.config:
                return
            usb = self.config['downstream']
            try:
                detected = upstream_networks(self.config['uplink'], interfaces(), routes())
                if detected != self.protected_networks:
                    self.ensure('filter', 'FORWARD', ('-i', usb, '-j', 'DROP'))
                    guard, _, _ = firewall_rules(self.config, detected)
                    self.chain('mangle', 'RFY-ROUTER-G', guard)
                    self.protected_networks = detected
                    self.ipt('-D', 'FORWARD', '-i', usb, '-j', 'DROP')
            except Exception:
                self.ensure('filter', 'FORWARD', ('-i', usb, '-j', 'DROP'))
                self.active = False
                raise


    def apply(self, value):
        with self.lock:
            value = validate(value, interfaces(), routes())
            if self.config and not self.stopped and value['downstream'] != self.config['downstream']:
                raise ValueError('Stop routing before changing the downstream adapter.')
            old = self.config
            try:
                self._apply(value)
            except Exception:
                if old:
                    try:
                        self._apply(old)
                    except Exception:
                        self.error = 'Restore failed; downstream forwarding remains blocked.'
                # Remove only the address introduced by this failed attempt.
                if not old or old['subnet'] != value['subnet'] or old['downstream'] != value['downstream']:
                    net = ipaddress.ip_network(value['subnet'])
                    run('ip', 'addr', 'del', str(net.network_address + 1) + '/' + str(net.prefixlen),
                        'dev', value['downstream'], check=False)
                raise
            if old and old['subnet'] != value['subnet']:
                net = ipaddress.ip_network(old['subnet'])
                run('ip', 'addr', 'del', str(net.network_address + 1) + '/' + str(net.prefixlen),
                    'dev', old['downstream'], check=False)
            temporary = self.data / 'config.tmp'
            temporary.write_text(json.dumps(value))
            temporary.replace(self.data / 'config.json')
            (self.data / 'disabled').unlink(missing_ok=True)
            self.config, self.error, self.stopped, self.active = value, None, False, True
            return self.status()

    def stop(self, persist=True):
        with self.lock:
            if self.config:
                usb = self.config['downstream']
                self.ensure('filter', 'FORWARD', ('-i', usb, '-j', 'DROP'))
                self.ensure('filter', 'INPUT', ('-i', usb, '-j', 'DROP'))
                if self.dhcp:
                    self.dhcp.terminate()
                    self.dhcp.wait(timeout=10)
                    self.dhcp = None
                path = self.network_dir / ('00-reefy-router-' + usb + '.network')
                path.write_text('[Match]\nName=' + usb + '\n[Network]\nDHCP=no\nKeepConfiguration=static\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n')
                self.network_reload(usb)
                net = ipaddress.ip_network(self.config['subnet'])
                run('ip', 'addr', 'del', str(net.network_address + 1) + '/' + str(net.prefixlen), 'dev', usb, check=False)
            if persist:
                (self.data / 'disabled').touch()
            self.stopped, self.active = True, False
            return self.status()

    def status(self):
        links, table = interfaces(), routes()
        clients = []
        leases = self.data / 'leases'
        if leases.exists():
            for line in leases.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4 and (parts[0] == '0' or int(parts[0]) > time.time()):
                    clients.append(dict(address=parts[2], hostname=parts[3] if parts[3] != '*' else 'Device'))
        config = self.config or defaults(links, table)
        # Old open tabs still read this inverse alias; persist only the new key.
        visible_config = dict(config, allow_downstream=not config['protect_downstream'])
        return dict(config=visible_config, configured=self.config is not None,
                    interfaces=links, clients=clients, error=self.error,
                    stopped=self.stopped, active=self.active, dhcp_running=self.dhcp is not None and self.dhcp.poll() is None)
