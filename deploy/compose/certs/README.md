# Certificates

Put certificate files here; the server sees them in `/etc/altiward/certs` and Caddy in
`/certs`. For example, the internal CA of your SIEM or identity provider as
`internal-ca.pem` with `ALTIWARD_TRUSTED_CAS_FILE=/etc/altiward/certs/internal-ca.pem` in
`.env`, or your own TLS
certificate and key for Caddy (`docs/install.md`, "Your own certificates or load
balancer"). Make CA files readable by everyone (`chmod 644`): the server runs as an
unprivileged user. Upgrades never change this directory.
