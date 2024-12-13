# gpnc

A proof-of-concept macOS client for the gpn VPN service

# Compilation

When building, you should specify your gpn end-point, name of your CA
(so that the client certificate can be found in your keychain) and a
name to use to display in the menu bar. Eg.:

  `make ROOTCA=MyCorpCA NAME=MyCorpVPN DOMAIN=vpn.mycorpdomain.com`

## Usage

Needs the wireguard-tools/wireguard-go packages from Homebrew:

* `brew install wireguard-go wireguard-tools`

Two processes need to be run.

* A WireGuard management process (needs root): `sudo ./gpnc -w`
* A menu bar based client process: `./gpnc`
* Alternately if you want to use the regular WireGuard app for
  establishing the VPN then you can run `./gpnc -m` to monitor it in
  the menu bar.

You will need a TLS client certificate in your keychain (or specify a
PEM format certificate file with the -c flag) and grant access to the
application when prompted. On first run a private key will be
generated and stored along with the servers public key in a keychain
entry.

If the management process exist unexpectedly it might leave the DNS
resolvers in place. They can be cleared with:

* `networksetup -setdnsservers Wi-Fi empty`

## API endpoints

### /api/1/status

Returns key:value pairs indicating the status of the user's
connection. Can be used to indicate that the user may need to
authenticate via, eg., an OIDC flow, and verify that the correct
public key is present on the server

```
{
 "public_key":"BxMyWn+hWL8mP84SkMtuoThd+CCQduwzzkN8RcTgfj0=",
 "authenticated":true,
 "user":"user@example.com",
 "ipv4_address":"10.1.2.3",
 "device":"ONWYKHOKYED1"
}
```

### /api/1/beacon

Returns a 200 status code when the VPN is fully working. Could be
implemented as a redirect to an internal service, or another port on
the VPN server bound to a port on an internal address.

### /api/1/config

Accepts a POST of the client's public key - optionally may add
temporary access if the client does not yet have a registered
key. Returns the settings that the client should use to access the
VPN. Server's public key is stored on first use along with generated
private key and subsequently is compared with the returned value to
detect spoofing - in which case the tunnel is not brought up and the
stored keychain entry should be deleted in case of a genuine need to
re-key.

Server returns the client's public key such the the client can detect
that server has an incorrect key stored and alert the user to the need
to contact support to re-key the device.

POST:

```
{"PublicKey": "+Njc296qpzKNXtkMcdbvCYAObhhg1C0o/dU2b1fu6GI="}
```

Returns:

```
{
 "Interface": {
  "PublicKey": "+Njc296qpzKNXtkMcdbvCYAObhhg1C0o/dU2b1fu6GI=",
  "Address": "10.1.2.3",
  "MTU": 1400,
  "DNS": [
   "10.0.1.53",
   "10.0.2.53"
  ]
 },
 "Peer": {
  "PublicKey": "nEQMporDAX28HB0rTMrozOPnYSdYnbkYhmS7uG5CdQg=",
  "AllowedIPs": [
   "10.0.0.0/8",
   "172.16.0.0/12"
  ],
  "Endpoint": "vpn.example.com:51820"
 }
}
```


## Native macOS client

This is a PoC. The intention would be to build a first-class macOS
implementation in Swift with appropriate entitlements. Alas, I am not
an Apple developer.

A native client should need/implement:

* WireGuardKit / NEPacketTunnelProvider integration - Network Extensions Entitlement
* Keychain access for certificate/private key
* Access the simple API via HTTPS with client cert (mTLS)
* Ability to launch browser window for AD auth, etc. (or maybe a webview with mTLS preconfigured?)
* A Simple UI - status menu item, dropdown options
* Generate private key on first use and save along with server public key
* Check server key against stored entry when connecting - alert user of mismatch
* Post pubkey when connecting to generate notification server side in case of mismatch
* Only use VPN DNS resolvers for internal domains (matchDomains in NEDNSSettings?)

## NOTES

* https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
* https://developer.apple.com/documentation/networkextension/nednssettings
* https://developer.apple.com/documentation/networkextension/netunnelnetworksettings
* https://stackoverflow.com/questions/5677810/how-to-connect-with-client-certificate-using-a-webview-in-cocoa

## Troublesome networks

Some networks don't support arbitrary high-port UDP traffic.

* Easy to add additional translated ports on AWS
* Add an option to advertise additional ports to client
* Support a tranport over websockets

## Websockets

* Each server side websocket opens a UDP socket to WireGuard via loopback
* On the client a UDP listener forwards packets from local wg
* Maybe no need to wrap wg packets unless some keepalive is needed?

