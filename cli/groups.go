package cli

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
)

// RegisterCommonGroups attaches shared authentication and LDAP options to a mode.
func RegisterCommonGroups(p *parser.ArgumentsParser, debug *bool, domainController *string, ldapPort *int, useLdaps *bool, useKerberos *bool, authDomain *string, authUsername *string, authPassword *string, authHashes *string, authNoPass *bool) {
	config, err := p.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating configuration options: %s", err))
		return
	}
	config.NewBoolArgument(debug, "", "--debug", false, "Debug mode.")

	ldapGroup, err := p.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating LDAP options: %s", err))
		return
	}
	ldapGroup.NewStringArgument(domainController, "-dc", "--dc-ip", "", true, "Domain controller hostname or IP address, also used as the KDC.")
	ldapGroup.NewTcpPortArgument(ldapPort, "-lp", "--ldap-port", 389, false, "LDAP port.")
	ldapGroup.NewBoolArgument(useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
	ldapGroup.NewBoolArgument(useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM for LDAP authentication.")

	auth, err := p.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating authentication options: %s", err))
		return
	}
	auth.NewStringArgument(authDomain, "-d", "--domain", "", true, "Active Directory domain.")
	auth.NewStringArgument(authUsername, "-u", "--username", "", true, "User to authenticate as.")
	auth.NewStringArgument(authPassword, "-p", "--password", "", false, "Password. Prompted for when no secret is supplied.")
	auth.NewStringArgument(authHashes, "-H", "--hashes", "", false, "Authentication hashes in LMhash:NThash format.")
	auth.NewBoolArgument(authNoPass, "", "--no-pass", false, "Do not prompt for a password (find mode only).")
}
