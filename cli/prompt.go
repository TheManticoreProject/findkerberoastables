package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ResolvePassword prompts when no password or other secret was provided.
func ResolvePassword(domain, username string, password *string, noPass bool, otherSecrets ...string) error {
	if *password != "" || noPass {
		return nil
	}
	for _, secret := range otherSecrets {
		if secret != "" {
			return nil
		}
	}
	secret, err := PromptForPassword(domain, username)
	if err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("no password provided; pass --no-pass to bind without one")
	}
	*password = secret
	return nil
}

// PromptForPassword reads a password without echo when stdin is a terminal.
func PromptForPassword(domain, username string) (string, error) {
	identity := username
	if domain != "" {
		identity = domain + "\\" + username
	}
	if _, err := fmt.Fprintf(os.Stderr, "  | Password for '%s': ", identity); err != nil {
		return "", err
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(secret), err
	}
	fmt.Fprintln(os.Stderr)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no password on stdin")
	}
	return strings.TrimRight(scanner.Text(), "\r\n"), nil
}
