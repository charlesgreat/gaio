// +build linux

package gaio

/*
#cgo LDFLAGS: -L ${SRCDIR}/cfile/staticlib/linux -l ssl -l crypto
*/
import "C"

const (
	ErrAgain = 0xb
	ErrIntr  = 0x4
)


