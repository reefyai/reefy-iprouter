"""Check only HTTP in a host-isolated, unprivileged candidate container."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import urllib.request
import uuid


def smoke(image):
    name = 'iprouter-smoke-' + uuid.uuid4().hex[:12]
    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True).strip()
    try:
        docker('run', '-d', '--name', name, '--user', '65534:65534', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--read-only',
               '--tmpfs', '/data:uid=65534,gid=65534', '--tmpfs', '/tmp:uid=65534,gid=65534',
               '-p', '127.0.0.1::8080', image)
        config = json.loads(docker('inspect', name))[0]
        assert config['Config']['User'] == '65534:65534'
        host = config['HostConfig']
        assert not host['Privileged'] and host['CapDrop'] == ['ALL'] and not host['CapAdd']
        assert host['NetworkMode'] != 'host' and host['ReadonlyRootfs']
        assert not host.get('Binds')
        port = config['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort']
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(40):
            try:
                with opener.open('http://127.0.0.1:' + port, timeout=2) as response:
                    page = response.read().decode()
                assert 'IP Router' in page and 'Protect upstream LAN' in page
                return dict(passed=True, image=image, user='65534:65534',
                            capabilities_dropped=True, host_network=False, host_mounts=False)
            except (OSError, AssertionError):
                if attempt == 39:
                    raise
                time.sleep(.5)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = smoke(args.image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
