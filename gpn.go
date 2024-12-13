/*
 * gpn - Copyright (C) 2023-present David Coles
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
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gpn/devices"
	"gpn/logger"
	"gpn/oauth2"
	"gpn/wireguard"
)

// api functionality
// firewall

//go:embed static
var STATIC embed.FS
var Logger *logger.Logger

const FACILITY = "main"

type Config struct {
	CACert      string   `json:"cacert"`
	CACerts     []string `json:"cacerts"`
	Cert        string   `json:"cert"`
	Address     string   `json:"address"`
	Beacon      string   `json:"beacon"`
	Devices     string   `json:"devices"`
	Database    string   `json:"database"`
	Slack       string   `json:"slack"`
	Sentry      string   `json:"sentry"`
	Healthcheck string   `json:"healthcheck"`
	LogLevel    uint8    `json:"loglevel"`
	Signature   string   `json:"signature"`
	Command     []string `json:"command"`

	Wireguard Wireguard     `json:"wireguard"`
	Oauth2    oauth2.Oauth2 `json:"oauth2"`
	Roles     oauth2.Roles  `json:"roles"`
}

type Wireguard struct {
	Prefix_             string   `json:"prefix"`
	Table               string   `json:"table"`
	Interface           string   `json:"interface"`
	Address             string   `json:"address"`
	Port                uint16   `json:"port"`
	PublicKey           string   `json:"publickey"`
	AllowedIPs          []string `json:"allowedips"`
	DNS                 []string `json:"dns"`
	MTU_                uint16   `json:"mtu"`
	PersistentKeepalive uint16   `json:"keepalive"`
}

func (w *Wireguard) Prefix() ([2]byte, error) {
	var ret [2]byte

	ip, _, err := net.ParseCIDR(w.Prefix_)

	if err != nil {
		return ret, err
	}

	ip4 := ip.To4()

	if len(ip4) != 4 {
		return ret, errors.New("Not an IPv4 address")
	}

	ret[0] = ip4[0]
	ret[1] = ip4[1]

	return ret, nil
}

func (w *Wireguard) MTU() uint16 {
	if w.MTU_ > 0 {
		return w.MTU_
	}
	return 1400
}

func main() {
	var pause = flag.Uint("p", 60, "pause on exit")
	var level = flag.Uint("l", 0, "log level")

	flag.Parse()
	args := flag.Args()

	file := args[0]

	config, err := loadConfig(file)

	if err != nil {
		log.Fatal(err)
	}

	if config.Oauth2.Address == "" {
		config.Oauth2.Address = config.Address
	}

	if config.Wireguard.Address == "" {
		config.Wireguard.Address = config.Address
	}

	if config.Beacon == "" {
		config.Beacon = "beacon." + config.Address
	}

	//Logger = &logger.Logger{Level: 0}
	Logger = logger.NewLogger(config.Sentry)
	devices.Logger = Logger
	wireguard.Logger = Logger

	Logger.NOTICE("config", "Config loading - starting application")

	prefix, err := config.Wireguard.Prefix()

	if err != nil {
		//log.Fatal(err)
		Logger.Fatal(err)
	}

	Logger.Level = config.LogLevel

	if *level > 0 {
		Logger.Level = uint8(*level)
	}

	exec.Command("wg-quick", "up", config.Wireguard.Interface).Output()

	auth, err := oauth2.Init(config.Oauth2, config.Roles)

	if err != nil {
		log.Fatal(err)
	}

	m, _ := loaddb(config.Database)

	persist := tokens(config.Database)

	dm, err := devices.Init(config.Devices, auth, config.Wireguard.Interface, config.Wireguard.Table, persist, prefix, config.Command)

	if err != nil {
		log.Fatal(err, dm)
	}

	time.Sleep(2 * time.Second)

	for k, v := range m {
		dm.Inject(k, v)
	}

	server, err := tlsServer(&config)

	if err != nil {
		log.Fatal(err)
	}

	var down bool

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, syscall.SIGQUIT, syscall.SIGINT)
	//signal.Notify(sig) // ALLLLL the signals!

	go func() {
		for {
			s := <-sig
			switch s {
			case syscall.SIGURG:
			case syscall.SIGCHLD:
			case syscall.SIGWINCH:
			default:
				down = true
				log.Println("SHUTTING DOWN")
				if false {
					time.Sleep(time.Duration(*pause) * time.Second) // wait for LB to drain
				}
				dm.Close()
				time.Sleep(1 * time.Second)
				exec.Command("wg-quick", "down", config.Wireguard.Interface).Output()
				log.Fatal("EXITING")

			case syscall.SIGQUIT:
				log.Println("RELOAD")
				dm.LoadDevices(config.Devices)
			}
		}

	}()

	handler := http.FileServer(http.FS(STATIC))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var sign bool

		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		if r.TLS == nil {
			http.Redirect(w, r, "https://"+config.Address, 302)
			return
		}

		cn, sn, ok := tlsInfo(r)

		if !ok {
			fmt.Println(cn, sn, ok)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		state := dm.State(cn)

		if state == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Unregistered device. Call support."))
			return
		}

		switch r.URL.Path {

		case "/login":
			http.Redirect(w, r, auth.AuthCodeURL(cn), http.StatusFound)

		case "/logout":
			if state != nil {
				Logger.NOTICE(FACILITY, "Logout triggered on device", cn, "by", state.User)
			}
			dm.Void(cn)
			http.Redirect(w, r, "/", http.StatusFound)

		case "/callback":

			if r.FormValue("state") != cn {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("Doesn't match cert"))
				return
			}

			token, err := auth.Exchange(r.URL.Query().Get("code"))

			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(fmt.Sprintln(err)))
				return
			}

			Logger.NOTICE(FACILITY, "Login triggered on device", cn, "by", token.Username())

			dm.Auth(cn, token)

			http.Redirect(w, r, "/", http.StatusFound)

		case "/template":
			wg := config.wgconfig("<YOUR-PRIVATE-KEY-HERE>", state.Address)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write(wg.File())

		case "/config":

			if state.PublicKey != "" {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("A key for this device already exists - please contact support.\n"))
				return
			}

			if !state.Authenticated {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("Please authenticate to set up device\n"))
				return
			}

			key, err := wireguard.Genkey()

			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintln(err)))
				return
			}

			wg := config.wgconfig(key.Encode(), state.Address)

			p, err := key.Pubkey()

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintln(err)))
				return
			}

			pub := p.Encode()

			message := fmt.Sprintf("User %s generated key for %s: %s", state.User, cn, pub)

			if !config.slack(message) {
				Logger.INFO("Failed to send keygen slack for", cn)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			dm.TemporaryKey(cn, pub)

			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", "attachment; filename="+config.Wireguard.Address+".conf")
			w.WriteHeader(http.StatusOK)
			w.Write(wg.File())

		case "/api/1/beacon":
			http.Redirect(w, r, "https://"+config.Beacon+":8443/beacon", 302)

		case "/api/1/status":

			js, err := json.Marshal(state)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(js)

		case "/api/1/jws":
			sign = true
			fallthrough
		case "/api/1/config":

			if r.Method == "POST" {

				b, err := ioutil.ReadAll(r.Body)
				log.Println("POST", string(b), err)

				if err == nil {

					type message struct {
						PublicKey string
					}

					var m message
					err := json.Unmarshal(b, &m)
					_, ok := wireguard.Decode(m.PublicKey)

					if err == nil && ok {

						if state.PublicKey == "" {

							if config.slack(fmt.Sprintf("Device generated key for %s: %s", cn, m.PublicKey)) {
								dm.TemporaryKey(cn, m.PublicKey)
								state.PublicKey = m.PublicKey
							} else {
								Logger.ERR("Webhook failed", cn, m.PublicKey)
							}

						} else {

							if state.PublicKey != m.PublicKey {
								if !config.slack(fmt.Sprintf("Device used incorrect key for %s: %s, should be %s", cn, m.PublicKey, state.PublicKey)) {
									Logger.ERR("Webhook failed", cn, state.PublicKey, "user tried", m.PublicKey)
								}
							}
						}
					}
				}
			}

			wg := config.wgconfig("", state.Address)
			wg.Interface.PublicKey = state.PublicKey

			js, _ := json.MarshalIndent(wg, "", " ")

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if sign {
				jwt, err := signature(config.Signature, js)

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(jwt))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(js)

		default:
			r.URL.Path = "static" + r.URL.Path
			handler.ServeHTTP(w, r)
		}
	})

	/**********************************************************************/
	// Plain HTTP alive/beacon/redirect to HTTPS
	/**********************************************************************/

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		if config.Address != "" {
			http.Redirect(w, r, "https://"+config.Address, 302)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		return
	})

	mux.HandleFunc("/beacon", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"beacon":true}` + "\n"))
	})

	mux.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		if config.Healthcheck != "" {

			_, err := os.Stat(config.Healthcheck)

			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}

		if down {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	fmt.Println("Started")

	go alive(mux)
	go beacon(mux, config.Cert)

	log.Fatal(server.ListenAndServeTLS(config.Cert, config.Cert))
}

func alive(mux http.Handler) {
	for {
		go http.ListenAndServe(":80", mux)
		time.Sleep(5 * time.Second)
	}
}

func beacon(mux http.Handler, cert string) {
	for {
		http.ListenAndServeTLS(":8443", cert, cert, mux)
		time.Sleep(5 * time.Second)
	}
}

func loadConfig(file string) (Config, error) {
	var config Config

	f, err := os.Open(file)
	if err != nil {
		return config, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(b, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}

func tlsServer(config *Config) (*http.Server, error) {

	caCertPool := x509.NewCertPool()

	if config.CACert != "" {
		caCert, err := ioutil.ReadFile(config.CACert)

		if err != nil {
			return nil, err
		}

		caCertPool.AppendCertsFromPEM(caCert)
	}

	for _, f := range config.CACerts {
		caCert, err := ioutil.ReadFile(f)

		if err != nil {
			return nil, err
		}

		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,

		// https://blog.cloudflare.com/exposing-go-on-the-internet/

		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,

		// Only use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},

		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	tlsConfig.BuildNameToCertificate()

	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,

		Addr:      ":443",
		TLSConfig: tlsConfig,
	}, nil
}

func tlsInfo(r *http.Request) (string, string, bool) {

	hexify := func(b big.Int) string {
		d := big.NewInt(256)
		var s []string
		for n := 0; n < 16; n++ {
			m := big.NewInt(0)
			b.DivMod(&b, d, m)
			s = append([]string{fmt.Sprintf("%02x", m.Int64())}, s...)
		}
		return strings.Join(s, ":")
	}

	if len(r.TLS.PeerCertificates) < 1 {
		return "", "", false
	}

	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	sn := r.TLS.PeerCertificates[0].SerialNumber
	tx, err := sn.MarshalText()
	if err != nil {
		return "", "", false
	}
	var bi big.Int
	err = bi.UnmarshalText(tx)
	if err != nil {
		return "", "", false
	}
	hx := hexify(bi)
	return cn, hx, true
}

func (c *Config) wgconfig(key, addr string) *WireGuard {
	var wg WireGuard

	wg.Interface.PrivateKey = key
	wg.Interface.Address = addr
	wg.Interface.DNS = c.Wireguard.DNS
	wg.Interface.MTU = c.Wireguard.MTU()
	wg.Peer.PublicKey = c.Wireguard.PublicKey
	wg.Peer.AllowedIPs = c.Wireguard.AllowedIPs
	wg.Peer.Endpoint = fmt.Sprintf("%s:%d", c.Wireguard.Address, c.Wireguard.Port)
	wg.Peer.PersistentKeepalive = c.Wireguard.PersistentKeepalive

	return &wg
}

type WireGuard struct {
	Interface Interface
	Peer      Peer
}

type Interface struct {
	PrivateKey string   `json:",omitempty"`
	PublicKey  string   `json:",omitempty"`
	Address    string   `json:",omitempty"`
	MTU        uint16   `json:",omitempty"`
	DNS        []string `json:",omitempty"`
}

type Peer struct {
	PublicKey           string   `json:",omitempty"`
	AllowedIPs          []string `json:",omitempty"`
	Endpoint            string   `json:",omitempty"`
	PersistentKeepalive uint16   `json:",omitempty"`
}

func (w *WireGuard) File() []byte {
	var conf []string

	conf = append(conf, "[Interface]")
	conf = append(conf, "PrivateKey = "+w.Interface.PrivateKey)
	conf = append(conf, `Address = `+w.Interface.Address+`/32`)
	conf = append(conf, `MTU = `+fmt.Sprint(w.Interface.MTU))
	conf = append(conf, `DNS = `+strings.Join(w.Interface.DNS, ", "))
	conf = append(conf, ``)
	conf = append(conf, `[Peer]`)
	conf = append(conf, `PublicKey = `+w.Peer.PublicKey)
	conf = append(conf, `AllowedIPs = `+strings.Join(w.Peer.AllowedIPs, ", "))
	conf = append(conf, `Endpoint = `+w.Peer.Endpoint)
	if w.Peer.PersistentKeepalive > 0 {
		conf = append(conf, `PersistentKeepalive = `+fmt.Sprint(w.Peer.PersistentKeepalive))
	}

	return []byte(strings.Join(conf, "\n") + "\n")
}

func (c *Config) slack(text string) bool {

	if c.Slack == "" {
		return true
	}

	type slack struct {
		Text string `json:"text"`
	}

	js, err := json.Marshal(&slack{Text: text})

	resp, err := http.Post(c.Slack, "application/json", bytes.NewReader(js))

	if err != nil {
		return false
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}

	return true
}

func tokens(file string) chan devices.Persist {
	c := make(chan devices.Persist)

	go func() {
		m := map[string]string{}

		for p := range c {

			if p.T == "" {
				delete(m, p.I)
			} else {
				m[p.I] = p.T
			}

			savedb(file, m)
		}

	}()

	return c
}

func savedb(file string, m map[string]string) {
	if file == "" {
		return
	}
	js, _ := json.MarshalIndent(&m, "", " ")
	_ = ioutil.WriteFile(file, js, 0644)
}

func loaddb(file string) (map[string]string, error) {
	m := map[string]string{}

	if file == "" {
		return m, nil
	}

	f, err := os.Open(file)

	if err != nil {
		return m, err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return m, err
	}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return m, err
	}

	return m, nil
}

func signature(key string, payload []byte) (string, error) {
	// https://curity.io/resources/learn/jwt-signatures/

	if len(key) != 44 {
		return "", errors.New("Wrong key length")
	}

	seed, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		return "", err
	}

	if len(seed) != 32 {
		return "", errors.New("Wrong key length")
	}

	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(ed25519.PublicKey)

	if !ok {
		return "", errors.New("Not an ed25519 key")
	}

	x := base64.StdEncoding.EncodeToString(pub[:])

	header := []byte(`{"kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"` + x + `"}`)
	signature := ed25519.Sign(priv, payload)

	return fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(header),
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(signature),
	), nil
}
