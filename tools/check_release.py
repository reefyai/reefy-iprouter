"""Internal release guard for the existing first-party Reefy version convention."""
import argparse
from datetime import date, datetime, timezone
import json
from pathlib import Path
import re


def validate(root, tag=None, publication_date=None):
    version = (root / 'VERSION').read_text().strip()
    match = re.fullmatch(r'v(\d{4})\.(\d{2})\.(\d{2})-(\d{2})', version)
    if not match:
        raise ValueError('First-party Reefy version must use vYYYY.MM.DD-NN')
    day = date(*map(int, match.groups()[:3]))
    manifest = json.loads((root / 'reefy/app.json').read_text())
    if manifest['version'] != version:
        raise ValueError('Manifest version must match VERSION')
    if manifest['image'] != 'ghcr.io/reefyai/reefy-iprouter:' + version:
        raise ValueError('Image tag must match VERSION')
    if 'org.opencontainers.image.version=\"' + version + '\"' not in (root/'Dockerfile').read_text():
        raise ValueError('Docker OCI version must match VERSION')
    if tag is not None and tag != version:
        raise ValueError('Git release tag must match VERSION exactly')
    if publication_date is not None and day != publication_date:
        raise ValueError('Use the UTC publication date for a new release')
    return version


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tag')
    args = parser.parse_args()
    validate(Path(__file__).resolve().parents[1], args.tag,
             datetime.now(timezone.utc).date() if args.tag else None)
