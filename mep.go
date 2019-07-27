package main

import (
	"github.com/diiyw/gli"
	"github.com/diiyw/mep/socks"
)

func main() {
	gli.Gli{
		Name:    "Mep",
		Version: "0.1beta",
		Sketch:  "Simple proxy for GWF",
		Author:  "cheuk <zhuohong@live.com>",
		Commands: gli.Commands{
			gli.Command{
				Name: "start",
				Options: []gli.Option{
					{"-addr", "0.0.0.0:1080", "specified listen ip"},
				},
				Sketch: "Start socks4(a)/5 proxy server",
				Action: func(cok gli.Cok) error {
					addr := cok.Get("addr")
					socks.ListenSocks(addr)
					return nil
				},
			},
		},
	}.Run()
}
