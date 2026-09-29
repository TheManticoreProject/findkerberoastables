package mode_request

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/TheManticoreProject/FindKerberoastables/core"
	kerberos "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	goldap "github.com/go-ldap/ldap/v3"
)

// TestLiveRequestTicket uses an existing SPN to exercise the KDC request path.
// A computer SPN tests ticket acquisition, but its hash is not a valid
// user-account roasting result because the account name ends in '$'.
func TestLiveRequestTicket(t *testing.T) {
	host, domain, spn, passwordFile := os.Getenv("FK_LIVE_HOST"), os.Getenv("FK_LIVE_DOMAIN"), os.Getenv("FK_LIVE_SPN"), os.Getenv("FK_LIVE_PASSWORD_FILE")
	if host == "" || domain == "" || spn == "" || passwordFile == "" {
		t.Skip("live test environment is not configured")
	}
	raw, err := os.ReadFile(passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSpace(string(raw))
	creds, err := credentials.NewCredentials(domain, "Administrator", password, "")
	if err != nil {
		t.Fatal(err)
	}
	ldaps := os.Getenv("FK_LIVE_LDAPS") == "1"
	port := 389
	if ldaps {
		port = 636
	}
	session, err := ldap.NewSession(host, port, creds, ldaps, false)
	if err != nil {
		t.Fatal(err)
	}
	connected, err := session.Connect()
	if !connected {
		t.Fatalf("LDAP connect: %v", err)
	}
	defer session.Close()
	entries, err := session.QueryWholeSubtree("", fmt.Sprintf("(servicePrincipalName=%s)", goldap.EscapeFilter(spn)), []string{"sAMAccountName"})
	if err != nil || len(entries) != 1 {
		t.Fatalf("LDAP SPN lookup: %d entries, %v", len(entries), err)
	}
	account := entries[0].GetAttributeValue("sAMAccountName")
	if account == "" {
		t.Fatal("SPN owner has no sAMAccountName")
	}
	client := kerberos.NewClient("Administrator", strings.ToUpper(domain), host).WithPassword(password)
	defer client.Destroy()
	if err := client.GetTGT(); err != nil {
		t.Fatalf("GetTGT: %v", err)
	}
	var out bytes.Buffer
	successes, failures, err := requestTickets(client, []core.RequestTarget{{Account: account, SPNs: []string{spn}}}, &out, func(message string) { t.Log(message) })
	if err != nil || successes != 1 || failures != 0 {
		t.Fatalf("requestTickets: successes=%d failures=%d err=%v", successes, failures, err)
	}
	line := strings.TrimSpace(out.String())
	if !strings.HasPrefix(line, "$krb5tgs$") || strings.Count(out.String(), "\n") != 1 {
		t.Fatal("ticket was not formatted as one hashcat TGS line")
	}
	t.Logf("ticket formatted: enctype=%s, hash_bytes=%d", strings.Split(line, "$")[2], len(line))
}
