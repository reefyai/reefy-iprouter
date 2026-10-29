# Reefy IP Router

Use synthetic fixtures only. Never commit credentials, device identifiers,
deployment configuration or account data. Never use em-dashes.

Keep the existing /data volume and settings compatible across releases.
Retain host-service isolation outside the selected downstream subnet and IPv6
isolation when upstream LAN protection is off. Downstream host access follows
the explicit allow_downstream checkbox independently.
Use disposable Linux namespaces for kernel network tests, never fleet hosts.
Run unit, packaged HTTP smoke and real-network CI before tagging a release.

Read docs/releasing.md before publication. Match VERSION, manifest version,
Git tag, image version tag and Docker OCI version. Never mutate release tags.
