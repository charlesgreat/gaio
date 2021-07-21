// +build darwin netbsd freebsd openbsd dragonfly

package gaio

/*
#cgo LDFLAGS: -L ${SRCDIR}/cfile/staticlib/darwin -l ssl -l crypto

*/
import "C"

const (
	ErrAgain = 0x23
	ErrIntr  = 0x4
)

