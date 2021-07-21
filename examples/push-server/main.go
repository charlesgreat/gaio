package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/charlesgreat/gaio"
)

func main() {
	// by simply replace net.Listen with reuseport.Listen, everything is the same as in push-server
	// ln, err := reuseport.Listen("tcp", "localhost:0")
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("pushing server listening on", ln.Addr(), ", use telnet to receive push")

	// create a watcher
	w, err := gaio.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	// channel
	ticker := time.NewTicker(time.Second)
	chConn := make(chan net.Conn)
	chIO := make(chan gaio.OpResult)

	// watcher.WaitIO goroutine
	go func() {
		for {
			results, err := w.WaitIO()
			if err != nil {
				log.Println(err)
				return
			}

			for _, res := range results {
				chIO <- res
			}
		}
	}()

	// main logic loop, like your program core loop.
	go func() {
		var conns []net.Conn
		for {
			select {
			case res := <-chIO: // receive IO events from watcher
				if res.Error != nil {
					continue
				}
				conns = append(conns, res.Conn)
			case t := <-ticker.C: // receive ticker events
				push := []byte(fmt.Sprintf("%s\n", t))
				// all conn will receive the same 'push' content
				for _, conn := range conns {
					w.Write(nil, conn, push)
				}
				conns = nil
			case conn := <-chConn: // receive new connection events
				conns = append(conns, conn)
			}
		}
	}()

	// this loop keeps on accepting connections and send to main loop
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		chConn <- conn
	}
}
