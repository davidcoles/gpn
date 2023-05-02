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

package devices

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	//"log"
	"os"
	"os/exec"
	"time"

	"gpn/cluster"
	"gpn/logger"
	"gpn/oauth2"
	"gpn/wireguard"
)

const GROUP = "gpn"
const FACILITY = "devices"

var LEADER bool
var Logger *logger.Logger

const (
	M_INVENTORY     = iota // sourced by start up or a group change event - causes M_CONFIGURATION & M_AUTH to be broadcast
	M_CONFIGURATION        // key/value for all device IDs/index+port
	M_AUTH                 // broadcast by token auth event - update token
	M_STATE                // local request for device status
	M_VOID                 // delete ticket
	M_TAKEOVER
	M_TEMP
)

type device struct {
	Index     uint16 `json:"index"`
	PublicKey string `json:"pubkey"`
	c         chan *message
}

type Devices struct {
	Serial  uint64            `json:"serial"`
	Devices map[string]device `json:"devices"`
}

type message struct {
	Type    uint8
	Devices Devices
	Token   string
	ID      string
	IP      string
	Device  device
	Auth    bool
	User    string
	Key     string
	OK      bool
	cluster *cluster.Cluster
	done    chan bool
}

type State struct {
	OK            bool   `json:"-"`
	Index         uint16 `json:"-"`
	PublicKey     string `json:"public_key,omitempty"`
	Authenticated bool   `json:"authenticated"`
	//Auth      bool   `json:"auth"`
	//Active    bool   `json:"active"`
	User    string `json:"user,omitempty"`
	Address string `json:"ipv4_address,omitempty"`
	Device  string `json:"device,omitempty"`
}

func (dm *DeviceManager) State(id string) *State {
	m := &message{Type: M_STATE, ID: id, done: make(chan bool)}
	dm.Message(m)
	<-m.done

	if !m.OK {
		return nil
	}

	return &State{OK: m.OK, Index: m.Device.Index, PublicKey: m.Device.PublicKey, Authenticated: m.Auth, User: m.User, Address: dm.IP(m.Device.Index), Device: id}
}

type Persist struct {
	I string
	T string
}

type DeviceManager struct {
	prefix    [2]byte
	devices   chan Devices
	messages  chan *message
	cluster   *cluster.Cluster
	routing   chan string
	auth      *oauth2.Auth
	wireguard string
	persist   chan Persist
}

func (dm *DeviceManager) Close() {
	close(dm.devices)
}

func (dm *DeviceManager) ReloadDevices(d Devices) {
	dm.devices <- d
}

func (dm *DeviceManager) Message(m *message) {
	dm.messages <- m
}

func (dm *DeviceManager) Auth(id string, token *oauth2.Token) {
	Logger.INFO(FACILITY, "SENDING AUTH")
	dm.send(&message{Type: M_AUTH, ID: id, Token: token.Pickle()})
}

func (dm *DeviceManager) Inject(id string, token string) {
	Logger.INFO(FACILITY, "INJECTING AUTH", id)
	dm.send(&message{Type: M_AUTH, ID: id, Token: token})
}

func (dm *DeviceManager) TemporaryKey(id, key string) {
	Logger.INFO(FACILITY, "SENDING TEMP KEY", id, key)
	dm.send(&message{Type: M_TEMP, ID: id, Key: key})
}

func (dm *DeviceManager) Void(id string) {
	Logger.INFO(FACILITY, "SENDING VOID", id)
	dm.send(&message{Type: M_VOID, ID: id})
}

func (dm *DeviceManager) IP(idx uint16) string {
	return fmt.Sprintf("%d.%d.%d.%d", dm.prefix[0], dm.prefix[1], idx>>8, idx&0xff)
}

func (dm *DeviceManager) manage() {
	var serial uint64
	devices := map[string]device{}

	for {
		select {
		case d, ok := <-dm.devices:
			if !ok {
				return
			}

			dm.send(&message{Type: M_CONFIGURATION, Devices: d})

		case m, _ := <-dm.messages:
			Logger.DEBUG(FACILITY, "MESSAGE", m.Type, m.Devices.Serial)
			switch m.Type {

			case M_TAKEOVER:
				Logger.INFO(FACILITY, "M_TAKEOVER", m.IP)

				dm.routing <- m.IP

			case M_INVENTORY:
				dm.send(&message{Type: M_CONFIGURATION, Devices: Devices{Devices: devices, Serial: serial}})
				for _, v := range devices {
					v.c <- m
				}

			case M_CONFIGURATION:

				Logger.INFO(FACILITY, "M_CONFIGURATION", m.Devices.Serial)

				if m.Devices.Serial > serial {

					//fmt.Println("Applying configuration")

					serial = m.Devices.Serial

					for k, v := range m.Devices.Devices {
						//fmt.Printf("%15s: %3d %s\n", k, v.Index, v.PublicKey)

						if x, ok := devices[k]; ok {
							v.c = x.c
						} else {
							v.c = dm.go_device(k, v)
						}

						v.c <- &message{Type: M_CONFIGURATION, Device: v}
						devices[k] = v

					}

					for k, v := range devices {
						if _, ok := m.Devices.Devices[k]; !ok {
							close(v.c)
							delete(devices, k)
						}
					}
				}

			case M_TEMP:
				if d, ok := devices[m.ID]; m.ID != "" && ok {
					d.PublicKey = m.Key
					devices[m.ID] = d
					d.c <- m
				}

			default: // send to device
				if d, ok := devices[m.ID]; m.ID != "" && ok {
					m.OK = true
					d.c <- m
				} else {
					m.OK = false
					if m.done != nil {
						close(m.done)
					}
				}
			}
		}
	}
}

func (dm *DeviceManager) go_device(id string, dev device) chan *message {
	c := make(chan *message)

	go func() {

		var roles []string
		var token *oauth2.Token

		wireguard.WGUpdate(dm.wireguard, dev.PublicKey, dm.IP(dev.Index), "")

		defer func() {
			wireguard.WGUpdate(dm.wireguard, "", "", dev.PublicKey) //delete key
		}()

		t := time.NewTicker(time.Second * 60)
		defer t.Stop()

		ip := dm.IP(dev.Index)

		for {
			select {
			case <-t.C:
				if LEADER && token != nil {
					Logger.DEBUG(FACILITY, "Checking token", id, token.Expiry())

					if token.Refresh() {
						Logger.DEBUG(FACILITY, "Token changed - sending!", id)
						dm.Auth(id, token)
					}
				}

				if token != nil {
					if token.Valid() {
						ipset(id, ip, roles, nil) //update firewall
					} else {
						Logger.INFO(FACILITY, "Token no longer valid", id)
						ipset(id, ip, nil, roles) // withdraw roles
						token = nil
						roles = nil
					}
				}

			case m, ok := <-c:
				if !ok {
					return
				}

				switch m.Type {
				case M_INVENTORY:
					if token != nil {
						dm.Auth(id, token)
					}

				case M_TEMP:
					m.Device.Index = dev.Index
					m.Device.PublicKey = m.Key
					fallthrough
				case M_CONFIGURATION:
					Logger.INFO(FACILITY, "UPDATING", id, dev, "TO", m.Device)
					wireguard.WGUpdate(dm.wireguard, m.Device.PublicKey, dm.IP(m.Device.Index), dev.PublicKey)
					dev = m.Device

				case M_AUTH:
					t := dm.auth.Unpickle(m.Token)
					if t != nil {

						var updated bool

						if token != nil {
							if t.Expiry().After(token.Expiry()) {
								Logger.INFO(FACILITY, "Updated token", id)
								token = t
								updated = true
							}
						} else {
							Logger.INFO(FACILITY, "New token and none existing", id)
							token = t
							updated = true
						}

						if updated {
							dm.persist <- Persist{id, m.Token}
							var old []string
							roles, old = diff(token.Roles(), roles)
							ipset(id, ip, roles, old)
						}

					}

				case M_VOID:
					Logger.INFO(FACILITY, "Voiding token", id)
					ipset(id, ip, nil, roles) // withdraw roles
					token = nil
					roles = nil
					dm.persist <- Persist{id, ""}

				case M_STATE:
					// write info to message ....
					m.Device = dev
					m.Auth = (token != nil && token.Valid())
					if token != nil {
						c, err := token.Info()
						if err != nil {
							Logger.DEBUG(FACILITY, id, err)
						} else {
							m.User = c.Username
						}
					}

				default:
					Logger.INFO(FACILITY, "Unrecognised message type", id, m.Type)
				}

				if m.done != nil {
					close(m.done)
				}
			}
		}
	}()

	return c
}

func NewDeviceManager(m chan *message, c *cluster.Cluster, a *oauth2.Auth, wg, table string, persist chan Persist, prefix [2]byte) *DeviceManager {
	dm := &DeviceManager{messages: m, cluster: c, auth: a, devices: make(chan Devices), wireguard: wg, persist: persist, prefix: prefix}
	go dm.manage()

	takeover := func(ip string) {
		dm.send(&message{Type: M_TAKEOVER, IP: ip})
	}

	dm.routing = wireguard.Routing(wg, table, takeover)

	return dm
}

func Init(file string, auth *oauth2.Auth, wg, table string, persist chan Persist, prefix [2]byte) (*DeviceManager, error) {
	messages := make(chan *message)

	deliver := func(c *cluster.Cluster, j []byte, me bool) {
		var m message
		err := json.Unmarshal(j, &m)

		if err != nil {
			//log.Println(err)
			return
		}

		m.cluster = c

		switch m.Type {
		case M_TAKEOVER:
			Logger.INFO(FACILITY, "M_TAKEOVER!", m.IP, me)
			if !me {
				messages <- &m
			}

		case M_CONFIGURATION:
			fallthrough
		case M_TEMP:
			fallthrough
		case M_VOID:
			fallthrough
		case M_AUTH:
			messages <- &m
		}
	}

	changed := func(c *cluster.Cluster, joiner bool) { // joiner true if a node joined the cluster
		LEADER = c.Leader()
		Logger.INFO(FACILITY, "Leader?: ", LEADER, joiner)
		if joiner {
			messages <- &message{Type: M_INVENTORY, cluster: c}
		}
	}

	c, err := cluster.New(GROUP, deliver, changed)

	if err != nil {
		return nil, err
	}

	dm := NewDeviceManager(messages, c, auth, wg, table, persist, prefix)

	dm.LoadDevices(file)

	return dm, nil
}

func (dm *DeviceManager) send(m *message) {

	js, err := json.Marshal(m)

	if err == nil {
		dm.cluster.Send(js)
	}
}

func (dm *DeviceManager) LoadDevices(file string) {

	if file == "" {
		return
	}

	d, err := loadDevices(file)

	if err != nil {
		//log.Println(err)
		return
	}

	//dm.SendConf(d)
	dm.devices <- d
}

func loadDevices(file string) (Devices, error) {
	var d Devices

	f, err := os.Open(file)
	if err != nil {
		return d, err
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return d, err
	}

	err = json.Unmarshal(b, &d)
	if err != nil {
		return d, err
	}

	users := map[uint16]string{}
	keys := map[string]string{}

	for k, v := range d.Devices {
		if v.Index == 0 {
			return d, errors.New("Device " + k + " has no index")
		}

		x, ok := users[v.Index]
		if ok {
			return d, errors.New("Device " + k + " has duplicated index with " + x)
		}
		users[v.Index] = k

		if v.PublicKey != "" {
			x, ok = keys[v.PublicKey]
			if ok {
				return d, errors.New("Device " + k + " has duplicated pubkey with " + x)
			}
			keys[v.PublicKey] = k
		}
	}

	return d, nil
}

func diff(current, old []string) ([]string, []string) {
	var r []string

	o := map[string]bool{}

	for _, v := range current {
		o[v] = false
	}

	for _, v := range old {
		if _, ok := o[v]; !ok {
			r = append(r, v)
		}
	}

	return current, r
}

func ipset(id, ip string, add []string, del []string) {
	timeout := "300"

	if ip != "" {

		var ok bool = true

		for _, role := range del {
			_, err := exec.Command("ipset", "del", role, ip).Output()
			if err != nil {
				ok = false
			}
		}

		for _, role := range add {
			_, err := exec.Command("ipset", "-exist", "add", role, ip, "timeout", timeout).Output()
			if err != nil {
				ok = false
			}
		}

		Logger.INFO(FACILITY, "FIREWALL", id, ip, add, del, ok)
	}
}
