//go:build !windows

package agentgate

/*
#cgo LDFLAGS: -lagentgate_ffi
*/
import "C"

func initializeNativeLibrary(_ string) error { return nil }
