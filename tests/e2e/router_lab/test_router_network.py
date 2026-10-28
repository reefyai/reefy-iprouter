"""Real Router HTTP -> DHCP -> kernel firewall/NAT in disposable namespaces.

Only physical inventory and networkd's D-Bus reload are synthetic. The app,
DHCP server, addresses, routing, iptables, HTTP and restart use real processes.
No deployed backend or fleet device is contacted.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import time
import uuid
import pytest

ROOT = Path(__file__).resolve().parents[3]
pytestmark = pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                               reason='requires disposable Linux runner with namespace privileges')


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=25, check=check)


def test_router_dhcp_internet_isolation_and_restart(tmp_path):
    suffix = uuid.uuid4().hex[:7]
    ns = {key: 'rr-' + key + '-' + suffix for key in ('r', 'c', 'w')}
    processes, logs = [], []
    evidence = dict(result='failed', inventory='synthetic', networkd_reload='synthetic')
    def run(key, *args, check=True):
        return command('ip', 'netns', 'exec', ns[key], *args, check=check)
    def start(key, *args):
        log = (tmp_path / ('process-' + str(len(logs)) + '.log')).open('w+')
        logs.append(log)
        process = subprocess.Popen(['ip', 'netns', 'exec', ns[key], *args],
                                   stdout=log, stderr=log, start_new_session=True)
        processes.append(process)
        return process
    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
    def curl(key, url, *args, check=True):
        return run(key, 'curl', '--noproxy', '*', '--silent', '--show-error', '--max-time', '3', *args, url, check=check)
    def await_page():
        for _ in range(50):
            result = curl('w', 'http://10.200.0.1:8080/', check=False)
            if result.returncode == 0:
                return result.stdout
            time.sleep(0.2)
        raise AssertionError('Router HTTP did not become ready')
    def post(path, value, token):
        return curl('w', 'http://10.200.0.1:8080/' + path, '-H', 'Content-Type: application/json',
                    '-H', 'X-Router-Token: ' + token, '--data', json.dumps(value))
    try:
        for name in ns.values():
            command('ip', 'netns', 'add', name)
        for key in ns:
            command('ip', '-n', ns[key], 'link', 'set', 'lo', 'up')
        for router_iface, client_iface, target in [('wan0', 'peer0', 'w'), ('usb0', 'client0', 'c')]:
            command('ip', '-n', ns['r'], 'link', 'add', router_iface, 'type', 'veth', 'peer', 'name', client_iface)
            command('ip', '-n', ns['r'], 'link', 'set', client_iface, 'netns', ns[target])
            command('ip', '-n', ns['r'], 'link', 'set', router_iface, 'up')
            command('ip', '-n', ns[target], 'link', 'set', client_iface, 'up')
        command('ip', '-n', ns['r'], 'addr', 'add', '10.200.0.1/24', 'dev', 'wan0')
        command('ip', '-n', ns['w'], 'addr', 'add', '10.200.0.2/24', 'dev', 'peer0')
        command('ip', '-n', ns['w'], 'addr', 'add', '203.0.113.7/32', 'dev', 'lo')
        command('ip', '-n', ns['r'], 'route', 'add', 'default', 'via', '10.200.0.2')
        run('r', 'sysctl', '-w', 'net.ipv4.ip_forward=1')
        # The host provides loaded filters; Router never gets SYS_MODULE.
        # This matches the stock-filter readiness checked on the target host.
        for table in ('filter', 'mangle', 'nat'):
            run('r', 'iptables-legacy', '-t', table, '-S')
        run('r', 'ip6tables-legacy', '-t', 'filter', '-S')
        # Prepare Docker-like stock matches/targets and verify Router preserves
        # these unrelated rules. Their synthetic source never matches traffic.
        foreign_rules = [
            ('filter', 'OUTPUT', '-s', '198.51.100.0/24', '-p', 'udp', '--dport', '9', '-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-j', 'ACCEPT'),
            ('nat', 'POSTROUTING', '-s', '198.51.100.0/24', '-j', 'MASQUERADE'),
            ('mangle', 'PREROUTING', '-s', '198.51.100.0/24', '-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'DROP'),
        ]
        for table, chain, *rule in foreign_rules:
            run('r', 'iptables-legacy', '-t', table, '-A', chain, *rule)
        # Reefy already has Docker's legacy netfilter tables loaded. Prepare
        # that kernel precondition before dropping the app's SYS_MODULE power.
        for table in ('filter', 'mangle', 'nat'):
            run('r', 'iptables-legacy', '-t', table, '-S')
        network = tmp_path / 'network'; network.mkdir()
        data = tmp_path / 'data'; data.mkdir()
        (data / 'sentinel').write_text('synthetic-preserved')
        shim = tmp_path / 'router_fixture.py'
        shim.write_text('''import os,sys,threading
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import engine,server
engine.interfaces=lambda: [dict(name='wan0',usb=False,up=True),dict(name='usb0',usb=True,up=True)]
router=engine.Router(sys.argv[2],sys.argv[3])
router.network_reload=lambda interface: None
os.environ['ROUTER_DATA']=sys.argv[2]
server.Router=lambda *args,**kwargs: router
server.main()
''')
        internet = tmp_path / 'internet.py'
        internet.write_text('''from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(('synthetic-internet '+self.client_address[0]).encode())
HTTPServer(('0.0.0.0',8081),Handler).serve_forever()
''')
        start('w', sys.executable, str(internet))
        # Match the image: root owns /app. A capability-limited root process
        # must not depend on DAC_OVERRIDE to traverse the CI user's checkout.
        source = tmp_path / 'app-source'
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', 'results', '__pycache__', '.pytest_cache'))
        app_args = (sys.executable, str(shim), str(source), str(data), str(network))
        app_command = ('setpriv', '--bounding-set=-all,+net_admin,+net_raw,+net_bind_service,+setgid', *app_args)
        app = start('r', *app_command)
        token = re.search(r'name="router-token" content="([^"]+)"', await_page())[1]
        effective = next(line.split()[1] for line in Path('/proc/' + str(app.pid) + '/status').read_text().splitlines() if line.startswith('CapEff:'))
        assert int(effective, 16) == sum(1 << bit for bit in (6, 10, 12, 13))
        evidence['runtime_capabilities'] = ['SETGID', 'NET_BIND_SERVICE', 'NET_ADMIN', 'NET_RAW']
        config = dict(uplink='wan0', downstream='usb0', subnet='10.77.0.0/24', dhcp=True, protect_lan=True)
        run('r', 'ip', 'addr', 'add', '10.78.0.1/24', 'dev', 'usb0')
        result = json.loads(post('apply', config, token).stdout)
        evidence['initial_apply'] = result
        assert result.get('configured') and result.get('dhcp_running'), result
        for table, chain, *rule in foreign_rules:
            run('r', 'iptables-legacy', '-t', table, '-C', chain, *rule)
        evidence['unrelated_firewall_rules_preserved'] = True
        assert 'KeepConfiguration=static' in (network / '00-reefy-router-usb0.network').read_text()
        assert '10.78.0.1' in run('r', 'ip', '-4', 'addr', 'show', 'dev', 'usb0').stdout
        evidence['unrelated_static_address_preserved'] = True
        lease_script = tmp_path / 'dhcp.sh'
        lease_script.write_text('#!/bin/sh\ncase "$1" in bound|renew)\nip addr replace "$ip/24" dev "$interface"\nip route replace default via "$router" dev "$interface"\n;; esac\n')
        lease_script.chmod(0o755)
        run('c', 'busybox', 'udhcpc', '-i', 'client0', '-n', '-q', '-t', '3', '-T', '2', '-s', str(lease_script))
        addresses = json.loads(run('c', 'ip', '-j', '-4', 'addr', 'show', 'dev', 'client0').stdout)
        assert ipaddress.ip_address(addresses[0]['addr_info'][0]['local']) in ipaddress.ip_network(config['subnet'])
        assert curl('c', 'http://203.0.113.7:8081/').stdout == 'synthetic-internet 10.200.0.1'
        assert curl('c', 'http://10.200.0.2:8081/', check=False).returncode != 0
        assert curl('c', 'http://10.77.0.1:8080/', check=False).returncode != 0
        # Even DHCP-shaped traffic must not bypass the private-destination rule.
        before_rules = run('r', 'iptables-legacy', '-t', 'mangle', '-nvL', 'RFY-ROUTER-G').stdout
        before_drops = next(int(line.split()[0]) for line in before_rules.splitlines() if '10.0.0.0/8' in line)
        run('c', sys.executable, '-c', "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('',68));s.sendto(b'synthetic',(\"10.200.0.2\",67))")
        rules = run('r', 'iptables-legacy', '-t', 'mangle', '-nvL', 'RFY-ROUTER-G').stdout
        assert next(int(line.split()[0]) for line in rules.splitlines() if '10.0.0.0/8' in line) > before_drops
        v6 = run('r', 'ip6tables-legacy', '-S').stdout
        assert '-A FORWARD -i usb0 -j DROP' in v6 and '-A INPUT -i usb0 -j DROP' in v6
        # Discover an additional directly connected, non-private upstream subnet.
        run('r', 'ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'wan0')
        run('w', 'ip', 'addr', 'add', '198.18.0.2/24', 'dev', 'peer0')
        # Active policy must refresh without reapplying settings or restarting DHCP.
        for _ in range(10):
            rules = run('r', 'iptables-legacy', '-t', 'mangle', '-S', 'RFY-ROUTER-G').stdout
            if '198.18.0.0/24' in rules:
                break
            time.sleep(1)
        assert '198.18.0.0/24' in rules
        assert curl('c', 'http://198.18.0.2:8081/', check=False).returncode != 0
        post('apply', dict(config, protect_lan=False), token)
        assert curl('c', 'http://10.200.0.2:8081/').returncode == 0
        assert curl('c', 'http://198.18.0.2:8081/').returncode == 0
        assert curl('c', 'http://10.77.0.1:8080/', check=False).returncode != 0
        assert '-A FORWARD -i usb0 -j DROP' in run('r', 'ip6tables-legacy', '-S').stdout
        post('apply', config, token)
        assert curl('c', 'http://10.200.0.2:8081/', check=False).returncode != 0
        assert curl('c', 'http://198.18.0.2:8081/', check=False).returncode != 0
        assert curl('c', 'http://203.0.113.7:8081/').returncode == 0
        evidence.update(dynamic_upstream_blocked=True, protection_disable=True,
                        protection_reenable=True, host_protection_retained=True)
        # A malformed or overlapping update must preserve the saved settings/data.
        post('apply', dict(config, subnet='10.200.0.0/24'), token)
        assert json.loads((data / 'config.json').read_text()) == config
        evidence.update(dhcp_lease=True, internet_nat=True, lan_blocked=True, host_blocked=True,
                        dhcp_bypass_blocked=True, ipv6_blocked=True, rejected_update_preserves_data=True)
        stop(app)
        assert '-A FORWARD -i usb0 -j DROP' in run('r', 'iptables-legacy', '-S').stdout
        assert not (data / 'disabled').exists(), 'Container stop must retain automatic startup intent'
        evidence['container_stop_blocks_forwarding'] = True
        run('r', 'ip', 'addr', 'flush', 'dev', 'usb0')
        for table in ('filter', 'mangle', 'nat'):
            run('r', 'iptables-legacy', '-t', table, '-F')
        app = start('r', *app_command)
        page = await_page(); token = re.search(r'name="router-token" content="([^"]+)"', page)[1]
        assert curl('c', 'http://203.0.113.7:8081/').stdout == 'synthetic-internet 10.200.0.1'
        assert curl('c', 'http://10.200.0.2:8081/', check=False).returncode != 0
        result = json.loads(post('apply', dict(config, dhcp=False), token).stdout)
        assert not result['dhcp_running']
        assert (data / 'sentinel').read_text() == 'synthetic-preserved'
        evidence.update(result='passed', startup_restores_routing=True, dhcp_disable=True, app_data_preserved=True)
    finally:
        for process in reversed(processes):
            stop(process)
        for name in ns.values():
            command('ip', 'netns', 'del', name, check=False)
        output = Path(os.environ.get('REEFY_E2E_RESULTS_DIR', str(tmp_path)))
        output.mkdir(parents=True, exist_ok=True)
        (output / 'router-network.json').write_text(json.dumps(evidence, indent=2) + '\n')
        for index, log in enumerate(logs):
            log.seek(0); (output / ('router-process-' + str(index) + '.log')).write_text(log.read()); log.close()
