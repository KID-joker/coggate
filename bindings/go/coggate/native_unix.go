//go:build !windows

package coggate

/*
#cgo LDFLAGS: -lcoggate_ffi
*/
import "C"

func initializeNativeLibrary(_ string) error { return nil }
