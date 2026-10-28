"""Synthetic policy and real local HTTP tests, without host network mutations."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import threading
import urllib.error
import urllib.request
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine import Router, defaults, firewall_rules, validate
from server import serve

LINKS = [dict(name='eth0', usb=False, up=True), dict(name='usb0', usb=True, up=True)]
ROUTES = [dict(dst='default', dev='eth0'), dict(dst='10.200.0.0/24', dev='eth0')]
CONFIG = dict(uplink='eth0', downstream='usb0', subnet='10.77.0.0/24', dhcp=True, protect_lan=True)


def test_defaults_choose_usb_and_avoid_route_overlap():
    assert defaults(LINKS, ROUTES) == CONFIG
    assert defaults(LINKS, ROUTES + [dict(dst='10.77.0.0/24', dev='eth0')])['subnet'] == '10.77.1.0/24'


@pytest.mark.parametrize('change', [dict(uplink='usb0'), dict(downstream='eth0'),
    dict(downstream='missing'), dict(subnet='10.200.0.0/24'), dict(subnet='8.8.8.0/24'),
    dict(subnet='10.77.0.1/24'), dict(subnet='10.0.0.0/8'), dict(dhcp='true'),
    dict(uplink='eth0;reboot'), dict(extra=True)])
def test_invalid_config_has_no_network_effect(change):
    with pytest.raises(ValueError):
        validate(dict(CONFIG, **change), LINKS, ROUTES)


def test_rule_order_blocks_lan_host_spoofing_and_dhcp_bypass():
    guard, forward, inbound = firewall_rules(CONFIG)
    assert guard[:2] == [('-d', dest, '-p', 'udp', '--sport', '68', '--dport', '67', '-j', 'RETURN')
                         for dest in ('255.255.255.255', '10.77.0.1')]
    assert ('-d', '192.168.0.0/16', '-j', 'DROP') in guard
    assert ('-d', '100.64.0.0/10', '-j', 'DROP') in guard
    assert guard[2] == ('!', '-s', CONFIG['subnet'], '-j', 'DROP')
    assert guard[3] == ('-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'DROP')
    assert forward[0][forward[0].index('-o') + 1] == 'eth0'
    assert forward[-1] == ('-o', 'usb0', '-j', 'DROP')
    assert inbound[-1] == ('-j', 'DROP')


def test_failed_apply_retains_saved_config_and_unrelated_data(tmp_path, monkeypatch):
    import engine
    router = Router(tmp_path)
    (tmp_path / 'config.json').write_text(json.dumps(CONFIG))
    (tmp_path / 'sentinel').write_text('synthetic-preserved')
    router.config = dict(CONFIG)
    monkeypatch.setattr(engine, 'interfaces', lambda: LINKS)
    monkeypatch.setattr(engine, 'routes', lambda: ROUTES)
    attempts = []
    def apply(config):
        attempts.append(config)
        if config['dhcp'] is False:
            raise RuntimeError('synthetic failure')
    monkeypatch.setattr(router, '_apply', apply)
    with pytest.raises(RuntimeError):
        router.apply(dict(CONFIG, dhcp=False))
    assert attempts == [dict(CONFIG, dhcp=False), CONFIG]
    assert json.loads((tmp_path / 'config.json').read_text()) == CONFIG
    assert (tmp_path / 'sentinel').read_text() == 'synthetic-preserved'


def test_dhcp_checkbox_and_persistent_restart(tmp_path, monkeypatch):
    import engine
    router = Router(tmp_path)
    monkeypatch.setattr(engine, 'interfaces', lambda: LINKS)
    monkeypatch.setattr(engine, 'routes', lambda: ROUTES)
    monkeypatch.setattr(router, '_apply', lambda config: None)
    router.apply(dict(CONFIG, dhcp=False))
    assert Router(tmp_path).config['dhcp'] is False
    assert not Router(tmp_path).stopped


class FakeRouter:
    error = None
    def __init__(self):
        self.applied = []
    def status(self):
        return dict(config=CONFIG, configured=False, interfaces=LINKS, clients=[], stopped=False, error=None)
    def apply(self, value):
        validate(value, LINKS, ROUTES)
        self.applied.append(value)
        return self.status()


def test_real_http_requires_same_page_token_and_preserves_input():
    router = FakeRouter()
    server = serve(router, '127.0.0.1', 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = 'http://127.0.0.1:' + str(server.server_port)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        page = opener.open(url).read().decode()
        assert 'DHCP server' in page and 'checked' in page
        token = page.split('name="router-token" content="')[1].split('"')[0]
        for headers in ({}, {'X-Router-Token': token, 'Sec-Fetch-Site': 'cross-site'}):
            req = urllib.request.Request(url + '/apply', data=json.dumps(CONFIG).encode(),
                headers={'Content-Type': 'application/json', **headers})
            with pytest.raises(urllib.error.HTTPError) as error:
                opener.open(req)
            assert error.value.code == 403
        assert router.applied == []
        req = urllib.request.Request(url + '/apply', data=json.dumps(dict(CONFIG, dhcp=False)).encode(),
            headers={'Content-Type': 'application/json', 'X-Router-Token': token})
        assert opener.open(req).status == 200
        assert router.applied == [dict(CONFIG, dhcp=False)]
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def test_upstream_protection_default_compatibility_and_boolean_validation():
    assert validate({k:v for k,v in CONFIG.items() if k != 'protect_lan'}, LINKS, ROUTES)['protect_lan'] is True
    assert defaults(LINKS, ROUTES)['protect_lan'] is True
    assert validate(dict(CONFIG, protect_lan=False), LINKS, ROUTES)['protect_lan'] is False
    with pytest.raises(ValueError):
        validate(dict(CONFIG, protect_lan='false'), LINKS, ROUTES)


def test_detected_upstream_network_is_blocked_only_when_protection_enabled():
    from engine import upstream_networks
    links = [dict(LINKS[0], addresses=['198.18.0.5/24']), LINKS[1]]
    table = ROUTES + [dict(dst='198.19.0.0/24',dev='eth0',scope='link'),
                     dict(dst='203.0.113.0/24',dev='eth0',gateway='10.200.0.1')]
    detected = upstream_networks('eth0', links, table)
    assert detected == ('10.200.0.0/24', '198.18.0.0/24', '198.19.0.0/24')
    guard, _, _ = firewall_rules(dict(CONFIG, protect_lan=True), detected)
    assert ('-d','198.18.0.0/24','-j','DROP') in guard
    guard, _, inbound = firewall_rules(dict(CONFIG, protect_lan=False), detected)
    assert ('-d','198.18.0.0/24','-j','DROP') not in guard
    assert ('-d','192.168.0.0/16','-j','DROP') not in guard
    assert ('-m','addrtype','--dst-type','LOCAL','-j','DROP') in guard
    assert ('-d','127.0.0.0/8','-j','DROP') in guard
    assert inbound[-1] == ('-j','DROP')


def test_old_saved_configuration_defaults_to_protection(tmp_path):
    (tmp_path/'config.json').write_text(json.dumps({k:v for k,v in CONFIG.items() if k != 'protect_lan'}))
    assert Router(tmp_path).config['protect_lan'] is True


def test_disabled_lan_protection_survives_restart(tmp_path, monkeypatch):
    import engine
    monkeypatch.setattr(engine, 'interfaces', lambda: LINKS)
    monkeypatch.setattr(engine, 'routes', lambda: ROUTES)
    router = Router(tmp_path)
    monkeypatch.setattr(router, '_apply', lambda value: None)
    (tmp_path/'sentinel').write_text('synthetic-preserved')
    router.apply(dict(CONFIG, protect_lan=False))
    assert Router(tmp_path).config['protect_lan'] is False
    assert (tmp_path/'sentinel').read_text() == 'synthetic-preserved'
