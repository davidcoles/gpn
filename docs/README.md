# Documentation

far from complete ...

## Installation

### Building

Currently the code makes use of Corosync's closed process groups
functionality through CGO, so the shared library and header files need
to be available. Installing `libcpg-dev` on Ubuntu 20.04 should satisfy this
requirement.

Go version 1.18 is recommended (`golang-1.18` on Ubuntu 20.04).

Once these are present then: `go build gpn.go`

`libyaml-perl` and `libjson-perl` may also be needed to run Perl
configuration scripts.

### Configuration

A number of supporting configuration files are needed:

* A certificate for the Certification Authority used to sign client device certificates
* A certificate to present on the HTTPS web interface - with chain and private key appended in a PEM file
* A JSON inventory of devices and their corresponding WireGuard public keys
* The main JSON configuration file

#### Devices 

A simple YAML file (example [devices.yaml](../devices.yaml)) can be
processed by the [devices.pl](../devices.pl) script to generate a JSON
inventory of authorised devices.

Each device needs a unique non-zero integer which is used to determine
the (static) IP address that the device gets in the VPN address
space. The device's WireGuard public key should also be specified, or
use the string "none" to explicitly indicate that the public key has not
yet been generated.

Also see [here](#further-development)

### Main configuration file

A YAML file (example [config.yaml](../config.yaml)) is processed by
[config.pl](../config.pl) to produce a JSON file which can be read by
the daemon.

Various parameters including the location of the device inventory and
TLS certificates are included. The name of the VPN's WireGuard
interface, canonical DNS address of the service, WireGuard public key,
listen port, etc., are used to enroll devices as peers and generate
WireGuard config files as needed.

Details for the OIDC/OAuth2 Identity Provider (IDP) are also required. The
roles for the authenticated user are used to configure firewall access
rules. Perhaps not everyone needs this and it could be optional,
replying solely on the WireGuard key, but it's handy to be able to
curtain VPN access by disabling the user at the IDP.

## Operation

If no key is set yet for a device then, upon authenticating via mTLS,
it may download a WireGuard configuration file with a dynamically
generated private key. The server immediately forgets the private key
but retains the corresponding public key which allows access for the
client temporarily. The public key is communicated to the
administrator via a Slack/Teams webhook (or look in the logs).

The public key should be then added to the device inventory at the
earliest possible opportunity and re-deployed.

The *.conf file which the device downloaded can be imported to
the standard WireGuard application on the device and when the tunnel
is activated the device will be active on the VPN. The conf file
should then be deleted as soon as possible as it contains the private key.


## Further development

### Devices

Currently the inventory of devices is stored as a YAML/JSON
file. There is no reason of course that you can't use an alternative
to YAML, either a different markup, or a database or LDAP
backend. Just have a script to generate the JSON file from your data
store and deploy that to the servers.

The JSON file which is deployed to the server has a serial number a
bit like a DNS zone file. When a node reads it, if the serial number
is greater than the current version then it is relayed to all of the
nodes in the cluster so that they have single consistent view.

Rather than storing as a local file this could be deployed to an HTTPS
endpoint which the nodes periodically poll (some signature mechanism
would be advisable - JWT/JWS perhaps) which could allow for immutable
server images. Or synced from an AWS S3 bucket, or stored in ZooKeeper
hierachy, etc., etc..


### Cluster

ZooKeeper (or etcd, Consul, etc.) may be good alternatives to Corosync
for cluster management. I chose Corosync because I'm familiar with it
and it tends to Just Work(TM) so seemed convenient.
