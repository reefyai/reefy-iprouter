"""Version/import compatibility is separate from this app's new release gate."""
from datetime import date
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_check', ROOT / 'tools/check_release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_actual_package_uses_first_party_reefy_version():
    release.validate(ROOT)


@pytest.fixture
def package(tmp_path):
    (tmp_path / 'reefy').mkdir()
    version = 'v2031.04.20-00'
    (tmp_path / 'VERSION').write_text(version)
    (tmp_path / 'reefy/app.json').write_text(json.dumps({
        'version': version, 'image': 'ghcr.io/reefyai/reefy-iprouter:' + version}))
    (tmp_path/'Dockerfile').write_text('LABEL org.opencontainers.image.version=\"'+version+'\"')
    return tmp_path


def test_release_tag_keeps_leading_v_and_uses_publication_date(package):
    assert release.validate(package, 'v2031.04.20-00', date(2031, 4, 20)) == 'v2031.04.20-00'
    with pytest.raises(ValueError, match='Git release tag'):
        release.validate(package, '2031.04.20-00')
    with pytest.raises(ValueError, match='UTC publication date'):
        release.validate(package, 'v2031.04.20-00', date(2031, 4, 21))


@pytest.mark.parametrize('version', ['0.1.0', 'v0.1.0-reefy.2031-04-20-00', 'v2031.4.20-0', 'v2031.02.30-00'])
def test_new_first_party_release_rejects_wrong_or_invalid_date_format(package, version):
    (package / 'VERSION').write_text(version)
    with pytest.raises(ValueError):
        release.validate(package)


def test_image_tag_cannot_drift_from_manifest(package):
    path = package / 'reefy/app.json'
    value = json.loads(path.read_text())
    value['image'] = 'ghcr.io/reefyai/reefy-iprouter:latest'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='Image tag'):
        release.validate(package)


def test_icon_is_catalog_sized_png():
    import struct
    data = (ROOT/'reefy/icon.png').read_bytes()
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    assert struct.unpack('>II', data[16:24]) == (512, 512)
