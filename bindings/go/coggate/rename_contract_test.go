package coggate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModuleAndPackageUseCogGateName(t *testing.T) {
	module, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(module), "module github.com/KID-joker/coggate/bindings/go\n") {
		t.Fatalf("unexpected module declaration: %s", module)
	}
	legacy := "agent" + "gate"
	if _, err := os.Stat(filepath.Join("..", legacy)); !os.IsNotExist(err) {
		t.Fatalf("legacy package directory still exists: %v", err)
	}
}
