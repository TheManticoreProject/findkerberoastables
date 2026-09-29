package mode_request

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/TheManticoreProject/FindKerberoastables/core"
	kerberos "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
)

type fakeRequester struct {
	calls []string
}

func (f *fakeRequester) Kerberoast(spn string) (*kerberos.KerberoastResult, error) {
	f.calls = append(f.calls, spn)
	if strings.HasPrefix(spn, "bad/") {
		return nil, errors.New("ticket unavailable")
	}
	return &kerberos.KerberoastResult{
		SPN: spn, Realm: "EXAMPLE.LOCAL", EType: 23,
		Cipher: bytes.Repeat([]byte{0xab}, 32),
	}, nil
}

func TestRequestTicketsFallsBackAndWritesHashcatLines(t *testing.T) {
	client := &fakeRequester{}
	targets := []core.RequestTarget{
		{Account: "sqlservice", SPNs: []string{"bad/sql", "MSSQLSvc/sql"}},
		{Account: "broken", SPNs: []string{"bad/only"}},
	}
	var output bytes.Buffer
	var warnings []string
	successes, failures, err := requestTickets(client, targets, &output, func(s string) { warnings = append(warnings, s) })
	if err != nil {
		t.Fatal(err)
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes, failures = %d, %d; want 1, 1", successes, failures)
	}
	if got := client.calls; strings.Join(got, ",") != "bad/sql,MSSQLSvc/sql,bad/only" {
		t.Fatalf("requested SPNs = %v", got)
	}
	want := "$krb5tgs$23$*sqlservice$EXAMPLE.LOCAL$MSSQLSvc/sql*$" + strings.Repeat("ab", 16) + "$" + strings.Repeat("ab", 16) + "\n"
	if output.String() != want {
		t.Fatalf("hash output = %q, want %q", output.String(), want)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v, want 2", warnings)
	}
}

type aesRequester struct{}

func (aesRequester) Kerberoast(spn string) (*kerberos.KerberoastResult, error) {
	return &kerberos.KerberoastResult{
		SPN: spn, Realm: "EXAMPLE.LOCAL", EType: 18,
		Cipher: bytes.Repeat([]byte{0xcd}, 28),
	}, nil
}

func TestRequestTicketsUsesAccountNameForAESHash(t *testing.T) {
	targets := []core.RequestTarget{{Account: "sqlservice", SPNs: []string{"MSSQLSvc/sql.example.local"}}}
	var output bytes.Buffer
	successes, failures, err := requestTickets(aesRequester{}, targets, &output, func(string) {})
	if err != nil || successes != 1 || failures != 0 {
		t.Fatalf("requestTickets() = %d, %d, %v", successes, failures, err)
	}
	want := "$krb5tgs$18$sqlservice$EXAMPLE.LOCAL$" + strings.Repeat("cd", 12) + "$" + strings.Repeat("cd", 16) + "\n"
	if output.String() != want {
		t.Fatalf("AES hash output = %q, want %q", output.String(), want)
	}
}
