package stream

import (
	"io"
)

func Copy(rw1 io.ReadWriter, rw2 io.ReadWriter) error {
	err := make(chan error)
	go func() {
		_, er := io.Copy(rw1, rw2)
		if er != nil {
			err <- er
		}
	}()
	go func() {
		_, er := io.Copy(rw2, rw1)
		if er != nil {
			err <- er
		}
	}()
	return <-err
}
