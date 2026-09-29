package core

import (
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestRequestTargetsFromEntries(t *testing.T) {
	entries := []*ldap.Entry{
		ldap.NewEntry("CN=SQL,DC=example,DC=local", map[string][]string{
			"sAMAccountName":       {"sqlservice"},
			"servicePrincipalName": {"MSSQLSvc/sql.example.local:1433", "mssqlsvc/sql.example.local:1433", "HTTP/sql.example.local", ""},
		}),
		ldap.NewEntry("CN=Invalid,DC=example,DC=local", map[string][]string{
			"servicePrincipalName": {"HTTP/invalid.example.local"},
		}),
	}
	got := requestTargetsFromEntries(entries)
	want := []RequestTarget{{
		DN:      "CN=SQL,DC=example,DC=local",
		Account: "sqlservice",
		SPNs:    []string{"HTTP/sql.example.local", "MSSQLSvc/sql.example.local:1433"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requestTargetsFromEntries() = %#v, want %#v", got, want)
	}
}
