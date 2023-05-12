# gpn - 'guard Private Network

(More [documentation ...](docs/))

## Introduction

A daemon to manage WireGuard keys, firewall rules and routing table.

WireGuard peers are given an x509 certificate from a certification
agency of your choice which allows them access an HTTPS endpoint with
mTLS. From there the user can authenticate via an OIDC provider
(tested with Microsoft Azure AD and Keycloak) and, dependent on the
claims returned in the access token, the device is added to the
appropriate firewall rules via ipset(8).

If the token can not be refreshed (eg. because the user has been
disabled) then the firewall rules are withdrawn. If the claims in the
user's token have changed then these will cause the firewall to be
updated appropriately. OCSP support is yet to be added, but that could
also lead to access being withdrawn if a certificate is revoked.

Multiple instances can be run as a cluster (currently using Corosync)
and placed behind a load balancer to create a redunant service - use
BIRD or Quagga to advertise each peer's /32 address (or an aggregate
prefix) into your organisation's routing table.

Corosync currently needs to be installed and running - there's no need
to have multiple instances, but being able to contact the local
corosync closed process group daemon is a requirement. This will
requirement will be removed soon as the code evolves.

Whilst the standard WireGuard client can be used to access the VPN, it
would be nice to have a tailored client which can query the
/api/... endpoints that the daemon provides. This could be used for
automatic configuration of the VPN client, notification to the user of
OIDC authentication state, etc.

A truly awful proof-of-concept for macOS can be found at:

https://github.com/davidcoles/wgvpn

Currently the devices database is stored as a YAML file and converted
to JSON, but this could be generated from a database, stored in LDAP,
etc.  Devices can be added, removed, keys chenged, etc., by
regenerating the JSON file, deploying to instances if necessary, and
sending a SIGQUIT to daemon (this should probably be changed to SIGUSR2).

You will need to create your own firewall rules - the daemon will just
update ipsets which you should define and incorporate into your
ruleset.

