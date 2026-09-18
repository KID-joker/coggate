//go:build windows && amd64

package coggate

/*
#cgo CFLAGS: -I${SRCDIR}/../../../packages/ffi/include
#include "native_bridge.h"
*/
import "C"

import (
	"os"
	"unicode/utf16"
	"unsafe"
)

var windowsNativeLibraryInitialization = nativeLibraryInitializer{load: loadWindowsNativeLibrary}

func initializeNativeLibrary(explicitPath string) error {
	return windowsNativeLibraryInitialization.initialize(explicitPath)
}

func loadWindowsNativeLibrary(explicitPath string) error {
	path, includeDLLDirectory, err := resolveWindowsNativeLibraryRequest(
		explicitPath, os.Getenv("COGGATE_LIBRARY_PATH"),
	)
	if err != nil {
		return err
	}
	encoded := utf16.Encode([]rune(path + "\x00"))
	status := C.ag_go_windows_init((*C.uint16_t)(unsafe.Pointer(&encoded[0])), C.int(boolInt(includeDLLDirectory)))
	if status != C.AG_STATUS_OK {
		return errorForStatus(int32(status))
	}
	return nil
}
