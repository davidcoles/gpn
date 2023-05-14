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

### Execution

Run the compiled binary as: `gpn </path/to/config.json>`

To reload an updated inventory file, send a SIGQUIT (should update to
SIGUSR2) to the process.

The daemon listen on port 443 for the HTTPS frontend/API, port 80 for
redirects to HTTPS and load-balancer healthchecks, and port 8443 for
beacon requests from the web frontend JavaScript.

An internal address (eg. 10.123.0.0/16) should be set as a VIP on the
loopback interface and the beacon DNS address in the config file set
to resolve to this. Devices will thus only be able to reach the beacon
address when the VPN is fully working, allowing the web interface to
detect that everything is fully operational. Make sure that any
firewall you set up allows for this.

### Devices

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

When traffic is observed coming in from a device then a route to the
devices's IP address via the WireGuard interface. If no traffic is
observed for two minutes then the route is removed. If the device is
active then it should be sending a persistent keepalive to prevent the
route being withdrawn.

When a route is added by the node, it alerts other nodes to this via a
message to the cluster. Other nodes will withdraw the route if they
currently have it, so preventing packets from being blackholed by
stale routes. This allows devices to be redirected to different node
by a load-balancer with the minimum amount of disruption.

### Cluster

Currently gpn uses the Corosync cluster engine. This will need to be
configured separately to gpn. Other nodes can be discoverable via
multicast or listed explicitly with unicast udp. No other cluster
config for gpn is required; it communicates with Corosync over a unix
domain socket and learns about other nodes from the cluster engine.

In addition to pruning stale routes from nodes, cluster communication
is used to distribute access tokens for logged in users. One node, the
cluster leader, works to keep tokens updated as necessary and
communicates refreshed tokens to the cluster.

When the device inventory is loaded by a node it is sent out to the
cluster. When receiving the update, each node checks the serial number
of the inventory, and if greater than the one it currently holds then the
inventory is updated locally. This allows the cluster to have a single
consistent view of the inventory.

When a node joins the cluster, all nodes send out their current
inventory and acces tokens, so the newly joined node quicky comes up
to date.

### Network

In the simplest case, the VPN could be hosted on a single server, with
HTTP/HTTPS and WireGuard ports forwarded and an iptables MASQUERADE
rule to NAT all devices to appear to be the address of the server.

Allocating a subnet within your address space and adding a static
route to the server, or running a routing protocol on the server to
advertise the prefix to your routers would avoid the need for NAT.

You could run a cluster of servers, load-balance the incoming
HTTP(S)/WireGuard connections, run a mesh network of tunnels between
the servers and advertise the subnet prefix or individual /32
addresses to your network.

If it's easier to host a cluster in the cloud (load-balancers and VMs
are easily defined by infrastructure-as-code tools) then a couple of
point-of-presence servers inside your infrastructure could open
outgoing WireGuard tunnels to the cloudy VMs and run an eBGP setup to
make the VPN subnet accessible.

All of this is beyond the scope of the this software, of course. gpn
will put routes for your devices into the routing table (probably good
to use a alternate table, specified in the config file) and you can
advertise these with a routing daemon of your choice (I use BIRD).

### Firewall

gpn makes no assumptions about the state of your firewall. If you
define DNS servers in the client configuration which are inside your
network then you should make sure that these are reachable without the
user being logged in. When a user logs in, the claims in the token can
be used to the user's IP to an ipset(1), or sets, reflecting the user's
roles.

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
