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

package devices2

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	LOAD = iota
	TOKEN
	IP
	DELETE
)

type message struct {
	kind  int
	token Token
	ip    string
	done  chan bool
}

type Cluster interface {
	Token(Token)
	Leader() bool
}

type Token interface {
	Refresh() bool
	Serialise() string
	Roles() []string
	Valid() bool
	Expiry() int64
}

type IDP interface {
}

type token struct {
}

func (t *token) Refresh() {
}

type db struct {
	Devices map[string]Device `json:"devices,omitempty"`
	Serial  uint64            `json:"serial,omitempty"`
}

type Device struct {
	Number    uint16 `json:"index,omitempty"`
	PublicKey string `json:"pubkey,omitempty"`
	Admin     bool   `json:"admin,omitempty"`
	session   *Session
}

func (d *Device) modify(foo Device) {
	//fmt.Println(*d, foo)

	// update firewall?

	if d.Number != foo.Number || d.PublicKey != foo.PublicKey {
		// update wireguard entry
	}
}

func (d *Device) Init(id string, c Cluster) {
	d.session = sesh(id, c)
	fmt.Println("INIT", *d)

}

func (d *Device) Close() {
	d.session.Close()
}

/********************************************************************************/

type Manager struct {
	Load    func([]string) []byte
	Command []string
	Cluster Cluster
	//WireGuard *WireGuard
	devices map[string]*Device
	c       chan *message
}

func (m *Manager) load() bool {
	var d db

	j := m.Load(m.Command)

	if j == nil {
		return false
	}

	err := json.Unmarshal(j, &d)

	if err != nil {
		return false
	}

	for k, v := range d.Devices {
		if v.Admin {
			delete(d.Devices, k)
		}
	}

	// delete no longer existing
	for k, v := range m.devices {
		_, ok := d.Devices[k]
		if !ok {
			fmt.Println("---", k)
			v.Close()
			delete(m.devices, k)
		}
	}

	for k, v := range d.Devices {

		x, ok := m.devices[k]

		if !ok {
			fmt.Println("+++", k)
			x := v               // copy by value
			x.Init(k, m.Cluster) // start empty session
			m.devices[k] = &x
		} else {
			//fmt.Println("===", k)
			x.modify(v)
		}
	}

	return true
}

func (m *Manager) clean() {
	for _, v := range m.devices {
		v.Close()
	}
}

func (m *Manager) message(msg *message) {
	switch msg.kind {
	case LOAD:
	case TOKEN:
	}
}

func (m *Manager) Init() {
	m.devices = map[string]*Device{}

	m.c = make(chan *message)

	m.load()

	go func() {

		ticker := time.NewTicker(7 * time.Second)

		defer ticker.Stop()
		defer m.clean()

		for {
			select {
			case msg, ok := <-m.c:

				if !ok {
					return
				}

				m.message(msg)

			case <-ticker.C:
				fmt.Println("???")
				m.load()
			}
		}

	}()
}

func (m *Manager) Close() {
	close(m.c)
}

func (m *Manager) Send() {
	m.c <- &message{}
}

/**********************************************************************/

func add(ip, group string) {}
func del(ip, group string) {}

func firewall(ip string, old, roles []string) (string, []string) {
	n := map[string]bool{}

	for _, r := range roles {
		n[r] = true
	}

	for _, r := range old {
		if _, ok := n[r]; !ok {
			del(ip, r)
		}
	}

	for _, r := range roles {
		add(ip, r)
	}

	return ip, roles
}

/**********************************************************************/

type Session struct {
	id      string
	ip      string
	token   Token
	cluster Cluster
	c       chan bool
	roles   []string
}

func sesh(id string, c Cluster) *Session {
	s := &Session{id: id, cluster: c}
	s.Init()
	return s
}

func (s *Session) message(m *message) {
	switch m.kind {
	case TOKEN:
		if s.token == nil || s.token.Expiry() < m.token.Expiry() {
			s.token = m.token
			_, s.roles = firewall(m.ip, s.roles, s.token.Roles())
		}
	case DELETE:
		_, s.roles = firewall(s.ip, s.roles, nil)
		s.token = nil
	case IP:
		firewall(s.ip, s.roles, nil)
		s.ip, s.roles = firewall(m.ip, nil, s.roles)
	}
}

func (s *Session) Init( /* token */ ) {

	s.c = make(chan bool)

	go func() {

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		defer s.clean()

		for {
			select {
			case <-ticker.C:
				s.Refresh()
			case _, ok := <-s.c:
				if !ok {
					// clean up
					fmt.Println("CLOSED", s.id)
					return
				}
			}
		}
	}()
}

func (s *Session) clean() {
	firewall(s.ip, s.roles, nil)
}

func (s *Session) Close() {
	close(s.c)
}

func (s *Session) Refresh() {

	if s.token == nil {
		return
	}

	if s.cluster.Leader() && s.token.Refresh() {
		s.cluster.Token(s.token)
	}

	if s.token.Valid() {
		_, s.roles = firewall(s.ip, s.roles, s.token.Roles())
		return
	}

	s.token = nil
}
