//go:build windows && amd64

package agentgate

/*
#cgo CFLAGS: -I${SRCDIR}/../../../packages/ffi/include
#include "native_bridge.h"
*/
import "C"

import (
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"
)

func initializeNativeLibrary(explicitPath string) error {
	path := explicitPath
	includeDLLDirectory := path != ""
	if path == "" {
		path = os.Getenv("AGENTGATE_LIBRARY_PATH")
		includeDLLDirectory = path != ""
	}
	if path == "" {
		path = "agentgate_ffi.dll"
	} else if !filepath.IsAbs(path) {
		return errorForStatus(int32(C.AG_STATUS_INVALID_ARGUMENT))
	}
	if strings.IndexByte(path, 0) >= 0 {
		return errorForStatus(int32(C.AG_STATUS_INVALID_ARGUMENT))
	}
	encoded := utf16.Encode([]rune(path + "\x00"))
	status := C.ag_go_windows_init((*C.uint16_t)(unsafe.Pointer(&encoded[0])), C.int(boolInt(includeDLLDirectory)))
	if status != C.AG_STATUS_OK {
		return errorForStatus(int32(status))
	}
	return nil
}
