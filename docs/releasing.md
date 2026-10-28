# IP Router releases

First-party Reefy versions use vYYYY.MM.DD-NN with the UTC publication date
and a daily two-digit counter. VERSION, reefy/app.json, Docker OCI version,
Git release tag and container version tag must agree. Never reuse a published
version. The app retains its router slug for compatibility; its display name
is IP Router and the public repository/image are reefy-iprouter.

Branch and pull request CI run unit/HTTP tests, release guards, a Linux amd64
image build with restricted HTTP smoke, and disposable network namespace E2E.
Tag publication requires both jobs and restores the exact tested image.
Only version tags publish. The image includes no account or deployment data.

Runtime requires the capabilities and host mounts in reefy/app.json. Read the
README before installing. Build smoke grants none of those host privileges.
Starting the UI does not apply routing; Apply and start is explicit.

Catalog import uses the repository's reefy folder and icon.png. The icon is a
512-pixel PNG master; Reefy creates the smaller WebP catalog asset. Full-size
generated drafts stay outside Git. The built-in image tool generated the icon:
friendly coral-red octopus as a router hub with large arrow-shaped tentacles,
dark midnight teal rounded tile, simple readable shapes, no ports or text.

After publication verify anonymous layer download using:

```sh
python tools/verify_public_image.py --tag VERSION --digest sha256:EXPECTED --output results/anonymous.json
```

GHCR package visibility is separate from repository visibility. Confirm the
package is public and anonymously downloadable before catalog publication.
Keep all results and registry digests as workflow artifacts. Actual whole-device
reboot acceptance is separate from namespace app restart coverage.
