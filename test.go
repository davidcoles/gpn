package main

import (
	"fmt"
	"gpn/devices2"
	//"io/ioutil"
	"io"
	"os"
	"os/exec"
	"time"
)

func main() {
	script := os.Args[1]

	m := devices2.Manager{
		Load:    load,
		Command: []string{script},
	}

	m.Init()

	time.Sleep(60 * time.Second)

	m.Close()

	time.Sleep(3 * time.Second)

}

func load(cmd []string) []byte {
	//cmd := []string{"/usr/local/bin/snow2.pl"}

	fmt.Println("RUNNING", cmd)

	b, _ := dev_command(cmd)

	return b
}

func dev_command(c []string) ([]byte, string) {

	cmd := exec.Command(c[0], c[1:]...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Sprint(err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Sprint(err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Sprint(err)
	}

	sout, _ := io.ReadAll(stdout)
	serr, _ := io.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Sprint(err)
	}

	return sout, fmt.Sprint(serr)
}
