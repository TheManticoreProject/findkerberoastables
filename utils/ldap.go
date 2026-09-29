package utils

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// OpenLDAP connects to the target domain controller using shared CLI settings.
func OpenLDAP(host string, port int, creds *credentials.Credentials, useLdaps, useKerberos bool) (*ldap.Session, error) {
	session, err := ldap.NewSession(host, port, creds, useLdaps, useKerberos)
	if err != nil {
		return nil, fmt.Errorf("creating LDAP session: %w", err)
	}
	ok, err := session.Connect()
	if !ok {
		session.Close()
		if err == nil {
			return nil, fmt.Errorf("LDAP connection failed")
		}
		return nil, fmt.Errorf("connecting to LDAP: %w", err)
	}
	return session, nil
}
