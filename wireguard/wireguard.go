/*
 * wgvpn client - Copyright (C) 2023-present David Coles
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

package wireguard

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"

	"gpn/logger"

	"golang.org/x/crypto/curve25519"
)

const EXPIRE_ROUTE_MINUTES = 2
const FACILITY = "wireguard"

var Logger *logger.Logger

var MUTEX sync.Mutex

// assume this only ever gets called when something changes (or at least infrequently)
func WGUpdate(wg, key, ip, old string) {

	MUTEX.Lock()
	defer MUTEX.Unlock()

	if key != old && old != "" {
		// remove existing key
		exec.Command("wg", "set", wg, "peer", old, "remove").Output()
	}

	if key != "" {
		exec.Command("wg", "set", wg, "peer", key, "allowed-ips", ip).Output()
	}

}

func addRoute(ip, wg, table string) {
	if table == "" {
		table = "main"
	}

	Logger.INFO(FACILITY, "ADDING ROUTE FOR", ip)
	exec.Command("ip", "-4", "route", "add", ip, "dev", wg, "table", table).Output()
}

func delRoute(ip, wg, table string) {
	if table == "" {
		table = "main"
	}
	Logger.INFO(FACILITY, "DELETING ROUTE FOR", ip)
	exec.Command("ip", "-4", "route", "del", ip, "dev", wg, "table", table).Output()
}

type rec struct {
	rx uint64
	at time.Time
	up bool
}

func Routing(wg, table string, takeover func(string)) chan string {
	// public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive.
	re := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)/32\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)$`)

	withdraw := make(chan string)

	go func() {

		recs := map[string]rec{}

		ticker := time.NewTicker(2 * time.Second)

		defer func() {
			ticker.Stop()

			for ip, r := range recs {
				if r.up {
					delRoute(ip, wg, table)
				}
			}
		}()

		for {
			select {
			case ip, ok := <-withdraw:
				if !ok {
					return
				}

				if r, ok := recs[ip]; ok && r.up {
					delRoute(ip, wg, table)
				}

			case <-ticker.C:

				recs = wgdump(wg, table, takeover, re, recs)

			}
		}

	}()

	return withdraw
}

// monitor wg show
// if there is traffic to IP listed in dump, but not active, then:
// - add to routing table
// - note active
// - send message to cluster
// if there is traffic to IP listed in dump and is active, then:
// - update timestamp and value
// if there is no traffic to IP and is active then:
// - meh

func wgdump(wg, table string, takeover func(string), re *regexp.Regexp, old map[string]rec) (new map[string]rec) {

	now := time.Now()

	MUTEX.Lock()

	defer func() {
		MUTEX.Unlock()

		// on exit any IPs not now in wg should have routes removed if active
		for ip, r := range old {
			Logger.DEBUG(FACILITY, "REMOVING", ip)
			if r.up {
				delRoute(ip, wg, table)
			}
		}

		Logger.DEBUG(FACILITY, "WG DUMP", len(new), "ENTRIES, TOOK", time.Now().Sub(now))
	}()

	new = make(map[string]rec, len(old))

	cmd := exec.Command("wg", "show", wg, "dump")
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		return
	}

	s := bufio.NewScanner(stdout)

	for s.Scan() {
		line := s.Text()
		match := re.FindStringSubmatch(line)

		if len(match) == 9 {

			// match[0] is the whole match, submatches are ...
			// 1        2       3         4            5                 6            7            8
			// pub-key, ps-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive

			if rx, err := strconv.ParseUint(match[6], 10, 64); err == nil {

				ip := match[4]
				r, ok := old[ip]

				if ok {

					if r.rx != rx {

						// if the entry was not active then add route
						if !r.up {
							addRoute(ip, wg, table)

							// TODO send update to cluster to clear other entries ...
							takeover(ip)
						}

						// the rx figure has changed (and therefore the ip is active) - update record
						r = rec{rx: rx, at: now, up: true}
					} else {
						if r.up && now.Sub(r.at) > (time.Minute*time.Duration(EXPIRE_ROUTE_MINUTES)) {
							delRoute(ip, wg, table)
							r.up = false
						}
					}

					// remove from old list - any remaining in old on exit will be cleaned up
					delete(old, ip)

				} else {
					// didnt' exist - populate record
					r = rec{rx: rx, at: now, up: false}

				}

				new[ip] = r
			}
		}
	}
	cmd.Wait()

	return new
}

func Encode(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func (k Key) Encode() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func Decode(s string) (key [32]byte, b bool) {
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 {
		copy(key[:], k[:])
		b = true
	}
	return
}

type Key [32]byte

func Genkey() (Key, error) {
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

func Pubkey(private [32]byte) ([32]byte, error) {

	var public [32]byte

	curve25519.ScalarBaseMult(&public, &private)

	x, err := curve25519.X25519(private[:], curve25519.Basepoint)

	if err != nil {
		return public, err
	}

	if len(x) != 32 {
		return public, errors.New("Key is not 32 bytes long")
	}

	copy(public[:], x[:])

	return public, nil
}

func (p Key) Pubkey() (Key, error) {
	return Pubkey(p)
}
