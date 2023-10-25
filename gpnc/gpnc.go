/*
 * gpn client - Copyright (C) 2023-present David Coles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/davidcoles/certstore"

	"github.com/caseymrm/menuet"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/curve25519"
)

const DIRECTORY = "/var/run/wireguard/"
const SOCKET = DIRECTORY + "gpnc"
const VPNURL = "http://localhost/up"

var ROOTCA = "MyCA"
var NAME = "MyVPN"
var DOMAIN = "vpn.example.com"
var ACTIVE = "login"
var CONFIG = "api/1/config"
var BEACON = "api/1/beacon"
var STATUS = "api/1/status"

var CLIENT = &http.Client{
	Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", SOCKET)
		},
	},
}

const (
	I_SLEEPING   = "💤"
	I_TICK       = "✅"
	I_DOWN_ARROW = "⬇️"
	I_WARNING    = "⚠️"
	I_PROHIBITED = "🚫"
	I_PASSPORT   = "🛂"
	I_CROSS_MARK = "❌"
	I_SOS        = "🆘"
	I_WTF        = "⁉️"
	I_NO_ENTRY   = "⛔️"
)

var monitor = flag.Bool("m", false, "monitor vpn status (for use with woreguard app)")
var manage = flag.Bool("w", false, "manage wireguard device (to be run with sudo)")
var name = flag.String("n", NAME, "app name")
var rootca = flag.String("r", ROOTCA, "cn of the root ca so search for")
var domain = flag.String("d", DOMAIN, "domain name")
var certfile = flag.String("c", "", "client certfile pem file")
var fallback = flag.String("f", "", "fallback private key")

func main() {

	flag.Parse()

	if *manage {
		wgtool()
		return
	}

	if *monitor {
		go app2(*name, *domain, *rootca, *certfile)
	} else {
		go app(*name, *domain, *rootca, *certfile)
	}

	menuet.App().Name = *name
	menuet.App().Label = *domain
	menuet.App().RunApplication()
}

type Private [32]byte
type Public [32]byte

func (p *Private) Decode(s string) error {
	k, err := base64.StdEncoding.DecodeString(s)

	if err != nil {
		return err
	}

	if len(k) != 32 {
		return errors.New("Incorrect key length")
	}

	copy((*p)[:], k[:])
	return nil
}

func (p *Private) Public() (public Public) {

	pub, err := curve25519.X25519(p[:], curve25519.Basepoint)

	if err != nil || len(pub) != 32 {
		panic("curve25519.X25519: " + err.Error())
	}

	copy(public[:], pub[:])

	return
}

func (p Private) Encode() string {
	return base64.StdEncoding.EncodeToString(p[:])
}

func (p Public) Encode() string {
	return base64.StdEncoding.EncodeToString(p[:])
}

type WireGuard struct {
	Interface Interface
	Peer      Peer
}

type Interface struct {
	PrivateKey Private
	PublicKey  string
	Address    string
	MTU        uint16
	DNS        []string
}

type Peer struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   string
}

type APIClient struct {
	C       chan bool
	client  *http.Client
	name    string
	account string
	domain  string
	auth    bool
	conn    bool
	state   uint8
}

func (a *APIClient) event() {
	select {
	case a.C <- true:
	default:
	}
}

const (
	V_UNREACHABLE = iota
	V_NOT_AUTHENTICATED
	V_AUTHENTICATED
	V_REACHABLE
)

func (a *APIClient) bg() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		var state uint8 = V_UNREACHABLE

		var err error

		a.auth, err = a.status()

		fmt.Println(">>>", a.auth, err)

		if err == nil {

			if a.auth {
				state = V_AUTHENTICATED

				a.conn, err = a.beacon()

				if err == nil {
					state = V_REACHABLE
				}
			} else {
				state = V_NOT_AUTHENTICATED
			}
		}

		a.state = state

		a.event()

		select {
		case <-ticker.C:
		}
	}
}
func APIClientFromFile(name, domain, file string) (*APIClient, error) {

	var account string

	certificate, err := tls.LoadX509KeyPair(file, file)

	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	tlsConfig.BuildNameToCertificate()

	for k, _ := range tlsConfig.NameToCertificate {
		account = k
	}

	if account == "" {
		return nil, errors.New("No account name")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			TLSHandshakeTimeout: 4 * time.Second,
		},
		Timeout: 6 * time.Second,
	}

	a := &APIClient{client: client, name: name, account: account, domain: domain, C: make(chan bool)}
	go a.bg()
	return a, nil
}

func APIClientFromKeychain(name, domain, rootca string) (*APIClient, error) {

	client, account, err := getclient(rootca)

	if err != nil {
		return nil, err
	}

	a := &APIClient{client: client, name: name, account: account, domain: domain, C: make(chan bool)}
	go a.bg()
	return a, nil
}

func (a *APIClient) StoreKeys(key Private, peer string) error {

	return storekey(a.name+": "+a.domain, a.account, key.Encode()+":"+peer)
}

func (f *APIClient) RetrieveKeys() (Private, string, error) {
	var pri Private

	keypeer, err := keyring.Get(f.name+": "+f.domain, f.account)

	if err != nil {
		return pri, "", err
	}

	if err != nil {
		return pri, "", err
	}

	kp := strings.Split(keypeer, ":")

	if len(kp) != 2 {
		return pri, "", errors.New("Bad keychain entry")
	}

	err = pri.Decode(kp[0])

	if err != nil {
		return pri, "", err
	}

	return pri, kp[1], nil
}

func (f *APIClient) Upload(key Public) (*WireGuard, error) {

	url := "https://" + f.domain + "/" + CONFIG

	type message struct{ PublicKey string }

	m := message{PublicKey: key.Encode()}

	j, err := json.Marshal(&m)

	if err != nil {
		return nil, err
	}

	resp, err := f.client.Post(url, "application/json", bytes.NewReader(j))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	js, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Please contact support to ensure that your device is enroled")
	}

	var wg WireGuard

	err = json.Unmarshal(js, &wg)

	if err != nil {
		return nil, err
	}

	return &wg, nil
}

func (f *APIClient) Config() (*WireGuard, error) {

	url := "https://" + f.domain + "/" + CONFIG

	resp, err := f.client.Get(url)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	js, err := ioutil.ReadAll(resp.Body)

	if err != err {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("resp.StatusCode != http.StatusOK")
	}

	var wg WireGuard

	err = json.Unmarshal(js, &wg)

	if err != nil {
		return nil, err
	}

	return &wg, nil
}

type VPNClient struct {
	C       chan bool
	api     *APIClient
	key     Private
	peer    string
	state   bool
	cancel  context.CancelFunc
	mutex   sync.Mutex
	connect sync.Mutex
}

func (f *APIClient) status() (bool, error) {
	url := "https://" + f.domain + "/" + STATUS
	res, err := f.client.Get(url)

	if err != nil {
		return false, err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false, err
	}

	type baz struct {
		Public_key    string `json:"public_key"`
		User          string `json:"user"`
		Authenticated bool   `json:"authenticated"`
		Ipv4_address  string `json:"ipv4_address"`
		Device        string `json:"device"`
	}

	js, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return false, err
	}

	var b baz

	err = json.Unmarshal(js, &b)

	if err != nil {
		return false, err
	}

	return b.Authenticated, nil
}

func (a *APIClient) BaseUrl() string {
	return "https://" + a.domain
}

func (a *APIClient) LoginUrl() string {
	return "https://" + a.domain + "/" + ACTIVE
}

func (f *APIClient) beacon() (bool, error) {
	url := "https://" + f.domain + "/" + BEACON
	res, err := f.client.Get(url)

	if err != nil {
		return false, err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false, err
	}

	type baz struct {
		Beacon bool `json:"beacon"`
	}

	js, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return false, err
	}

	var b baz

	err = json.Unmarshal(js, &b)

	if err != nil {
		return false, err
	}

	return b.Beacon, nil
}

func (b *VPNClient) event() {
	select {
	case b.C <- true:
	default:
	}
}

func NewVPNClient(api *APIClient, key Private, peer string) (*VPNClient, error) {
	v := &VPNClient{api: api, key: key, peer: peer, C: make(chan bool)}
	//go v.bg()
	return v, nil
}

func (b *VPNClient) State() bool {
	return b.state
}

func (b *VPNClient) Disconnect() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.cancel == nil {
		return errors.New("Not connected")
	}

	b.cancel()
	b.cancel = nil
	return nil
}

func (b *VPNClient) Connect() error {

	if !b.connect.TryLock() {
		return errors.New("Busy")
	}

	b.state = true

	wg, err := b.api.Config()

	if err != nil {
		return err
	}

	if wg.Interface.PublicKey == "" {
		b.state = false
		b.connect.Unlock()
		return errors.New("Key on server has not been configured yet - please contact support")
	}

	if wg.Peer.PublicKey != b.peer || wg.Interface.PublicKey != b.key.Public().Encode() {
		b.state = false
		b.connect.Unlock()
		return errors.New("Key on server does not match - please contact support")
	}

	wg.Interface.PrivateKey = b.key

	js, err := json.MarshalIndent(wg, "", "  ")

	if err != nil {
		b.state = false
		b.connect.Unlock()
		return err
	}

	ctx, cancel := context.WithCancel(context.TODO()) // I don't really understand contexts 😬

	req, err := http.NewRequestWithContext(ctx, "POST", VPNURL, bytes.NewBuffer(js))

	if err != nil {
		b.state = false
		b.connect.Unlock()
		return err
	}

	b.cancel = cancel

	req.Header.Add("Content-Type", "application/json")

	res, err := CLIENT.Do(req)
	if err != nil {
		b.state = false
		b.connect.Unlock()
		return err
	}

	if res.StatusCode != 200 {
		b.state = false
		b.connect.Unlock()
		res.Body.Close()
		return errors.New("Not 200")
	}

	b.event()

	go func() {
		defer res.Body.Close()
		defer b.connect.Unlock()

		//ioutil.ReadAll(res.Body)
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			//fmt.Println(scanner.Text())
		}

		b.mutex.Lock()
		defer b.mutex.Unlock()

		b.state = false
		b.cancel = nil

		b.event()
	}()

	return nil
}

func app2(name, domain, rootca, file string) {

	icon := I_SLEEPING
	title := name + icon

	menuet.App().SetMenuState(&menuet.MenuState{Title: title})
	menuet.App().MenuChanged()

	alert := menuet.Alert{Buttons: []string{"OK"}}

	var api *APIClient
	var err error

	if file != "" {
		api, err = APIClientFromFile(name, domain, file)
	} else {
		api, err = APIClientFromKeychain(name, domain, rootca)
	}

	if err != nil {
		alert.MessageText = "Couldn't obtain client certificate"
		alert.InformativeText = err.Error()
		menuet.App().Alert(alert)
		log.Fatal(err)
	}

	menuet.App().Children = func() []menuet.MenuItem {
		var items []menuet.MenuItem

		status := "foo"
		help := "bar"
		link := api.BaseUrl()

		items = append(items, menuet.MenuItem{
			Type: menuet.Regular,
			Text: "Status: " + status + " (" + help + ")",
			Clicked: func() {
				exec.Command("/usr/bin/open", link).Output()
			},
		})

		return items
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		}

		auth, _ := api.status()
		conn, _ := api.beacon()

		icon = I_CROSS_MARK

		if auth && conn {
			icon = I_TICK
		}

		title = name + icon

		menuet.App().SetMenuState(&menuet.MenuState{Title: title})
		menuet.App().MenuChanged()

	}
}

func app(name, domain, rootca, file string) {

	icon := I_SLEEPING
	title := name + icon

	menuet.App().SetMenuState(&menuet.MenuState{Title: title})
	menuet.App().MenuChanged()

	alert := menuet.Alert{Buttons: []string{"OK"}}

	var api *APIClient
	var err error

	if file != "" {
		api, err = APIClientFromFile(name, domain, file)
	} else {
		api, err = APIClientFromKeychain(name, domain, rootca)
	}

	if err != nil {
		alert.MessageText = "Couldn't obtain client certificate"
		alert.InformativeText = err.Error()
		menuet.App().Alert(alert)
		log.Fatal(err)
	}

	pri, peer, err := api.RetrieveKeys()

	if err == keyring.ErrNotFound {

		key, err := genkey()

		if *fallback != "" {
			err = key.Decode(*fallback)
		}

		if err != nil {
			alert.MessageText = "Couldn't generate key"
			alert.InformativeText = err.Error()
			menuet.App().Alert(alert)
			log.Fatal(err)
		}

		wg, err := api.Upload(key.Public())

		if err != nil {
			alert.MessageText = "Couldn't register with service"
			alert.InformativeText = err.Error()
			menuet.App().Alert(alert)
			log.Fatal(err)
		}

		if wg.Interface.PublicKey != key.Public().Encode() {
			alert.MessageText = "Key generation problem"
			alert.InformativeText = "An existing key is already present on the server - please contact support"
			menuet.App().Alert(alert)
			log.Fatal("Key mismatch")
		}

		err = api.StoreKeys(key, wg.Peer.PublicKey)

		if err != nil {
			alert.MessageText = "Couldn't store new key"
			alert.InformativeText = err.Error()
			menuet.App().Alert(alert)
			log.Fatal(err)
		}

		pri = key
		peer = wg.Peer.PublicKey

		alert.MessageText = "Successfully registered with service"
		alert.InformativeText = "You may need to contact support for them to approve your registration before using the VPN"
		menuet.App().Alert(alert)

	} else if err != nil {
		if err != nil {
			alert.MessageText = "Couldn't retrieve key"
			alert.InformativeText = err.Error()
			menuet.App().Alert(alert)
			log.Fatal(err)
		}
	}

	vpn, err := NewVPNClient(api, pri, peer)

	if err != nil {
		alert.MessageText = "Couldn't get a vpn client"
		alert.InformativeText = err.Error()
		menuet.App().Alert(alert)
		log.Fatal(err)
	}

	menuet.App().Children = func() []menuet.MenuItem {
		var items []menuet.MenuItem

		active := vpn.State()

		legend := "Activate"
		status := "Inactive"
		link := api.BaseUrl()
		help := "click to open portal️"

		if active {
			legend = "Deactivate"
			status = "Active"
		}

		if !api.auth {
			link = api.LoginUrl()
			help = "click to login to portal️"
			status += "/Unauthenticated"
		}

		if api.auth || active {
			items = append(items, menuet.MenuItem{
				Type:  menuet.Regular,
				Text:  legend,
				State: active,
				Clicked: func() {

					var err error

					if active {
						err = vpn.Disconnect()
					} else {
						err = vpn.Connect()
					}

					if err != nil {
						alert.MessageText = "Oops"
						alert.InformativeText = err.Error()
						menuet.App().Alert(alert)
					}
				},
			})

			items = append(items, menuet.MenuItem{Type: menuet.Separator})
		}

		items = append(items, menuet.MenuItem{
			Type: menuet.Regular,
			Text: "Status: " + status + " (" + help + ")",
			Clicked: func() {
				exec.Command("/usr/bin/open", link).Output()
			},
		})

		items = append(items, menuet.MenuItem{
			Type: menuet.Regular,
			Text: "Show keys",
			Clicked: func() {
				alert := menuet.Alert{Buttons: []string{"OK", "Private key"}}
				alert.MessageText = "Public Keys"
				alert.InformativeText = "Public key: " + pri.Public().Encode() + "\nServer key: " + peer
				ret := menuet.App().Alert(alert)

				if ret.Button == 1 {
					alert := menuet.Alert{Buttons: []string{"OK"}}
					alert.MessageText = "Private key"
					alert.InformativeText = pri.Encode()
					menuet.App().Alert(alert)
				}

				return
			},
		})

		return items
	}

	for {
		select {
		case <-api.C:
		case <-vpn.C:
		}

		icon = I_SOS

		if vpn.State() {

			switch api.state {
			case V_NOT_AUTHENTICATED:
				icon = I_WARNING
			case V_AUTHENTICATED:
				icon = I_PROHIBITED
			case V_REACHABLE:
				icon = I_TICK
			}

		} else {

			switch api.state {
			case V_NOT_AUTHENTICATED:
				icon = I_PASSPORT
			case V_AUTHENTICATED:
				icon = I_DOWN_ARROW
			case V_REACHABLE:
				icon = I_TICK
			}
		}

		title = name + icon

		menuet.App().SetMenuState(&menuet.MenuState{Title: title})
		menuet.App().MenuChanged()

	}
}

func tsf(x uint64) string {
	n := float64(x)

	suffix := []string{"", "K", "M", "G", "T", "P", "E", "Z", "Y"}

	if n < 1000 {
		return fmt.Sprint(n)
	}

	for n > 1000 && len(suffix) > 1 {
		n /= 1000
		suffix = suffix[1:]
	}

	if n > 100 {
		return fmt.Sprintf("%.0f%s", n, suffix[0])
	}

	if n > 10 {
		return fmt.Sprintf("%.1f%s", n, suffix[0])
	}

	return fmt.Sprintf("%.2f%s", n, suffix[0])
}

func getclient(sn string) (*http.Client, string, error) {

	id, cn, err := identity(sn)

	if err != nil {
		//return nil, errors.New("Couldn't find my identity")
		return nil, cn, err
	}

	// Get a crypto.Signer for the identity.
	signer, err := id.Signer()
	if err != nil {
		return nil, cn, err
	}

	crt, err := id.Certificate()
	if err != nil {
		return nil, cn, err
	}

	tlsCrt := tls.Certificate{
		Certificate: [][]byte{crt.Raw},
		PrivateKey:  signer,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCrt},
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 3 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	return client, cn, nil
}

func identity(cn string) (certstore.Identity, string, error) {

	// Open the certificate store for use. This must be Close()'ed once you're
	// finished with the store and any identities it contains.
	store, err := certstore.Open()
	if err != nil {
		return nil, "", err
	}
	defer store.Close()

	// Get an Identity slice, containing every identity in the store. Each of
	// these must be Close()'ed when you're done with them.
	idents, err := store.Identities()
	if err != nil {
		return nil, "", err
	}

	// Iterate through the identities, looking for the one we want.
	for _, ident := range idents {

		crt, err := ident.Certificate()

		if err == nil && crt.Issuer.CommonName == cn {
			return ident, crt.Subject.CommonName, nil
		}

		ident.Close()
	}

	return nil, "", errors.New("Couldn't find my identity")
}

func storekey(service, account, password string) error {
	// set password
	return keyring.Set(service, account, password)
}

func genkey() (Private, error) {
	var key [32]byte

	n, err := rand.Read(key[:])

	if err != nil {
		return key, err
	}

	if n != 32 {
		return key, errors.New("Failed to read 32 bytes fron random source")
	}

	// https://cr.yp.to/ecdh.html

	key[0] &= 248
	key[30] &= 127
	key[31] |= 64

	return key, nil
}

/**********************************************************************/

func setconf(wg WireGuard) string {
	conf := []string{"[Interface]"}
	conf = append(conf, "PrivateKey = "+wg.Interface.PrivateKey.Encode())
	conf = append(conf, "[Peer]")
	conf = append(conf, "PublicKey = "+wg.Peer.PublicKey)
	conf = append(conf, "Endpoint = "+wg.Peer.Endpoint)
	conf = append(conf, "AllowedIPs = "+strings.Join(wg.Peer.AllowedIPs, ","))
	conf = append(conf, "")
	return strings.Join(conf, "\n")
}

type req struct {
	wg      WireGuard
	control bool
	success bool
	handled chan bool
	monitor chan bool
	exited  chan bool
}

func wgtool() {

	var mutex sync.Mutex

	exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty").Output()
	exec.Command("/bin/sh", "-c", "cd "+DIRECTORY+" && rm utun?.sock wg?.name").Output()

	os.Remove(SOCKET)
	exec.Command("mkdir", DIRECTORY).Output()

	s, err := net.Listen("unix", SOCKET)
	if err != nil {
		log.Fatal(err)
	}

	exec.Command("chown", "root:staff", SOCKET).Output()
	exec.Command("chmod", "660", SOCKET).Output()

	http.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		b, err := ioutil.ReadAll(r.Body)

		var wg WireGuard

		err = json.Unmarshal(b, &wg)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if wg.Peer.Endpoint == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !mutex.TryLock() {
			w.WriteHeader(http.StatusConflict)
			return
		}

		defer mutex.Unlock()

		f := &req{wg: wg, control: true, monitor: make(chan bool, 10), handled: make(chan bool), exited: make(chan bool)}

		defer close(f.exited)

		go tunnel(f)

		<-f.handled

		if !f.success {
			w.WriteHeader(http.StatusConflict)
			return
		}

		w.WriteHeader(http.StatusOK)

		for {
			select {
			case <-r.Context().Done():
				return
			case b, ok := <-f.monitor:
				if !ok {
					return
				}

				_, err := w.Write([]byte(fmt.Sprintln(b)))

				if err != nil {
					return
				}

				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}

			}
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := http.Server{}
	log.Fatal(server.Serve(s))
}

func tunnel(f *req) {
	ticker := time.NewTicker(3 * time.Second)
	defer func() {
		ticker.Stop()
		close(f.monitor)
	}()

	dev, done := session(f.wg, f.exited)

	if dev == "" {
		fmt.Println("failed")
		close(f.handled)
		return
	}

	f.success = true
	close(f.handled)

	defer func() {
		exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty").Output()
	}()

	fmt.Println(dev, done)

	for {
		select {
		case <-ticker.C:
			select {
			case f.monitor <- true:
			default:
				return
			}
		case <-done:
			fmt.Println("down")
			return
		}
	}
}

func session(wg WireGuard, quit chan bool) (string, chan bool) {

	utun, done := wireguard_go(quit)

	if utun == "" {
		return "", nil
	}

	exec.Command("ifconfig", utun, "inet", wg.Interface.Address+"/32", wg.Interface.Address, "alias").Output()
	exec.Command("ifconfig", utun, "mtu", fmt.Sprint(wg.Interface.MTU)).Output()
	exec.Command("ifconfig", utun, "up").Output()

	for _, route := range wg.Peer.AllowedIPs {
		fmt.Println(">>>>", route)
		exec.Command("route", "-q", "-n", "add", "-inet", route, "-interface", utun).Output()
	}

	conf := setconf(wg)

	cmd := exec.Command("wg", "setconf", utun, "/dev/stdin")

	stdin, err := cmd.StdinPipe()

	if err != nil {
		log.Fatal(err)
	}

	err = cmd.Start()

	if err != nil {
		log.Fatal(err)
	}

	stdin.Write([]byte(conf))

	stdin.Close()

	networksetup := []string{"-setdnsservers", "Wi-Fi"}
	networksetup = append(networksetup, wg.Interface.DNS[:]...)
	log.Println(">>>>>", networksetup)
	exec.Command("networksetup", networksetup[:]...).Output()

	err = cmd.Wait()

	if err != nil {
		log.Fatal(err)
	}

	return utun, done
}

func wireguard_go(quit chan bool) (string, chan bool) {

	name := DIRECTORY + "/gpnc.name"
	done := make(chan bool)

	go func() {
		cmd := "WG_TUN_NAME_FILE=" + name + " /opt/homebrew/bin/wireguard-go -f utun"
		exec.Command("/bin/sh", "-c", cmd).Output()
		os.Remove(name)
		close(done)
	}()

again:
	timer := time.NewTimer(1 * time.Second)

	select {
	case <-done:
		return "", done
	case <-timer.C:
	}

	f, err := os.Open(name)

	if err != nil {
		fmt.Println(err)
		goto again
	}

	bytes, err := ioutil.ReadAll(f)

	utun := string(bytes[0 : len(bytes)-1])

	sock := DIRECTORY + "/" + utun + ".sock"

	go func() {
		select {
		case <-done:
		case <-quit:
			os.Remove(sock)
		}
	}()

	return utun, done
}
