package coggate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func firstModuleLine(module []byte) string {
	return strings.TrimSuffix(strings.SplitN(string(module), "\n", 2)[0], "\r")
}

func TestModuleAndPackageUseCogGateName(t *testing.T) {
	module, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	moduleDeclaration := firstModuleLine(module)
	if moduleDeclaration != "module github.com/KID-joker/coggate/bindings/go" {
		t.Fatalf("unexpected module declaration: %s", module)
	}
	legacy := "agent" + "gate"
	if _, err := os.Stat(filepath.Join("..", legacy)); !os.IsNotExist(err) {
		t.Fatalf("legacy package directory still exists: %v", err)
	}
}

func TestModuleDeclarationAcceptsNativeLineEndings(t *testing.T) {
	want := "module github.com/KID-joker/coggate/bindings/go"
	for _, ending := range []string{"\n", "\r\n"} {
		if got := firstModuleLine([]byte(want + ending + "go 1.24")); got != want {
			t.Fatalf("module declaration with %q ending = %q, want %q", ending, got, want)
		}
	}
}
