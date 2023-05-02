package cluster

import (
	"errors"
	"fmt"

	"github.com/davidcoles/cpg"
)

type Cluster struct {
	group   string
	handle  uint64
	address cpg.Address
	leader  bool
}

type Address struct {
	node uint32
	pid  uint32
}

func (c *Cluster) Leader() bool {
	return c.leader
}

func (c *Cluster) Group() string {
	return c.group
}

func id(a cpg.Address) uint64 {
	return uint64(a.Nodeid)<<32 | uint64(a.Pid)
}

func (c *Cluster) ID() uint64 {
	return id(c.address)
}

func (c *Cluster) Send(m []byte) error {
	err := cpg.McastJoined(c.handle, m)

	if err != cpg.CS_OK {
		return errors.New(fmt.Sprint(err))
	}

	return nil
}

func New(group string, deliver func(*Cluster, []byte, bool), changed func(*Cluster, bool)) (*Cluster, error) {

	c := &Cluster{group: group}

	deliver_fn := func(h uint64, x []byte, n uint32, p uint32, m []byte) {
		//fmt.Println(h, x, n, p, m)

		if string(x) != c.group {
			panic(string(x) + " != " + c.group)
		}

		sender := uint64(n)<<32 | uint64(p)

		deliver(c, m, sender == c.ID())
	}

	confchg_fn := func(h uint64, x []byte, m []cpg.Address, l []cpg.Address, j []cpg.Address) {
		fmt.Println("m/l/j", h, m, l, j, len(j))

		if string(x) != c.group {
			panic(string(x) + " != " + c.group)
		}

		var leader bool = true

		me := c.ID()

		for _, v := range m {
			if id(v) < me {
				leader = false
			}
		}

		c.leader = leader

		changed(c, len(j) > 0)
	}

	h, err := cpg.Initialize(deliver_fn, confchg_fn)

	if err != cpg.CS_OK {
		return nil, errors.New(fmt.Sprint(err))
	}

	c.handle = h

	a, err := cpg.LocalGet(h)

	if err != cpg.CS_OK {
		return nil, errors.New(fmt.Sprint(err))
	}

	c.address = a

	err = cpg.Join(h, []byte(group))

	if err != cpg.CS_OK {
		return nil, errors.New(fmt.Sprint(err))
	}

	go cpg.Dispatch(h, cpg.CS_DISPATCH_BLOCKING)

	return c, nil
}
