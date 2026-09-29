package mode_find

import (
	"fmt"
	"sort"

	"github.com/TheManticoreProject/FindKerberoastables/core"
	"github.com/TheManticoreProject/FindKerberoastables/utils"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Run lists LDAP accounts with SPNs and optionally prints the SPNs.
func Run(host string, port int, creds *credentials.Credentials, useLdaps, useKerberos, printSPNs, debug bool) error {
	session, err := utils.OpenLDAP(host, port, creds, useLdaps, useKerberos)
	if err != nil {
		return err
	}
	defer session.Close()

	accounts, err := core.GetKerberoastables(session, creds.Domain)
	if err != nil {
		return err
	}
	if debug {
		logger.Debug(fmt.Sprintf("Found %d accounts with SPNs.", len(accounts)))
	}
	dns := make([]string, 0, len(accounts))
	for dn := range accounts {
		dns = append(dns, dn)
	}
	sort.Strings(dns)
	logger.Print(fmt.Sprintf("[>] Accounts with SPNs (\x1b[93m%d\x1b[0m):", len(dns)))
	for i, dn := range dns {
		prefix, childIndent := "  ├── ", "  │   "
		if i == len(dns)-1 {
			prefix, childIndent = "  └── ", "      "
		}
		logger.Print(fmt.Sprintf("%s\x1b[94m%s\x1b[0m", prefix, dn))
		if !printSPNs {
			continue
		}
		spns := append([]string(nil), accounts[dn]...)
		sort.Strings(spns)
		for j, spn := range spns {
			spnPrefix := "├── "
			if j == len(spns)-1 {
				spnPrefix = "└── "
			}
			logger.Print(childIndent + spnPrefix + spn)
		}
	}
	return nil
}
