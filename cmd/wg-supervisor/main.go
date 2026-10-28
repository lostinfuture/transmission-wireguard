// Command wg-supervisor is PID 1 for the transmission-wireguard image.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/lostinfuture/transmission-wireguard/internal/supervisor"
)

var (
	version      = "dev"
	transmission = "4.1.4"
)

func main() {
	os.Exit(run(os.Args[1:], os.Environ()))
}

func run(args, env []string) int {
	cmd := "run"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version":
		if err := printVersions(); err != nil {
			fmt.Fprintf(os.Stderr, "version: %v\n", err)
			return 1
		}
		return 0
	case "run":
		cfg, err := supervisor.LoadFrom(env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			return 1
		}
		supervisor.NoteRustnet(cfg.Rustnet)
		fmt.Fprintln(os.Stderr, "wireguard is not implemented")
		return 1
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		return 2
	}
}

func printVersions() error {
	fmt.Printf("wg-supervisor %s\n", version)
	if err := requireVersion("transmission-daemon", []string{"--version"}, "transmission-daemon "+transmission); err != nil {
		return err
	}
	out, err := exec.Command("wg", "--version").CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		return fmt.Errorf("wg: %w", err)
	}
	fmt.Println("rustnet absent")
	return nil
}

func requireVersion(bin string, args []string, needle string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		return fmt.Errorf("%s: %w", bin, err)
	}
	if !strings.Contains(string(out), needle) {
		return fmt.Errorf("%s output %q does not contain %q", bin, strings.TrimSpace(string(out)), needle)
	}
	return nil
}
