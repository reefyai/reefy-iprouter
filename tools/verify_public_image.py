"""Verify anonymous download of every published IP Router image layer."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import urllib.request


class RegistryRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        if urllib.parse.urlsplit(url).scheme != 'https':
            raise ValueError('HTTPS image download required')
        redirected = super().redirect_request(request, response, code, message, headers, url)
        if urllib.parse.urlsplit(url).netloc != 'ghcr.io':
            redirected.remove_header('Authorization')
        return redirected


def verify(reference, expected_digest):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', reference):
        raise ValueError('Invalid image tag')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', expected_digest):
        raise ValueError('Exact expected registry digest required')
    repository = 'reefyai/reefy-iprouter'
    parameters = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': 'repository:' + repository + ':pull'})
    opener = urllib.request.build_opener(RegistryRedirect())
    # No GitHub login, Docker configuration or account credential is read.
    with opener.open('https://ghcr.io/token?' + parameters, timeout=30) as response:
        token = json.load(response)['token']
    headers = {'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'}
    root = 'https://ghcr.io/v2/' + repository
    request = urllib.request.Request(root + '/manifests/' + reference, headers=headers)
    with opener.open(request, timeout=30) as response:
        manifest_bytes = response.read(1024 * 1024)
    assert 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest() == expected_digest
    manifest = json.loads(manifest_bytes)
    assert manifest['schemaVersion'] == 2 and 'config' in manifest and 'layers' in manifest
    total = 0
    for descriptor in [manifest['config'], *manifest['layers']]:
        digest = descriptor['digest']
        assert re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
        request = urllib.request.Request(root + '/blobs/' + digest, headers=headers)
        checksum = hashlib.sha256()
        size = 0
        config = bytearray()
        with opener.open(request, timeout=60) as response:
            while block := response.read(1024 * 1024):
                checksum.update(block)
                size += len(block)
                assert size <= descriptor['size']
                if descriptor is manifest['config']:
                    assert size < 1024 * 1024
                    config.extend(block)
        assert size == descriptor['size'] and 'sha256:' + checksum.hexdigest() == digest
        if descriptor is manifest['config']:
            metadata = json.loads(config)
            assert metadata['architecture'] == 'amd64' and metadata['os'] == 'linux'
        total += size
    return {'passed': True, 'anonymous': True, 'reference': repository + ':' + reference,
        'digest': expected_digest, 'platform': 'linux/amd64',
        'layer_count': len(manifest['layers']), 'verified_blob_bytes': total}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tag', required=True)
    parser.add_argument('--digest', required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    result = verify(arguments.tag, arguments.digest)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, indent=2) + '\n')
