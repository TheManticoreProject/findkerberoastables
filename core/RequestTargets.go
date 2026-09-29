package core

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)

// RequestTarget identifies a user account and its registered service principals.
type RequestTarget struct {
	DN      string
	Account string
	SPNs    []string
}

// GetRequestTargets finds enabled user accounts with SPNs. Computer accounts and
// krbtgt are excluded because request mode is aimed at service user credentials.
func GetRequestTargets(session *ldap.Session, domain string) ([]RequestTarget, error) {
	const filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(sAMAccountName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	entries, err := session.QueryWholeSubtree(domainToDN(domain), filter, []string{"sAMAccountName", "servicePrincipalName"})
	if err != nil {
		return nil, fmt.Errorf("querying service accounts: %w", err)
	}
	return requestTargetsFromEntries(entries), nil
}

func requestTargetsFromEntries(entries []*goldap.Entry) []RequestTarget {
	targets := make([]RequestTarget, 0, len(entries))
	for _, entry := range entries {
		account := strings.TrimSpace(entry.GetAttributeValue("sAMAccountName"))
		if account == "" {
			continue
		}
		seen := make(map[string]bool)
		var spns []string
		for _, spn := range entry.GetAttributeValues("servicePrincipalName") {
			spn = strings.TrimSpace(spn)
			key := strings.ToLower(spn)
			if spn != "" && !seen[key] {
				seen[key] = true
				spns = append(spns, spn)
			}
		}
		if len(spns) == 0 {
			continue
		}
		sort.Strings(spns)
		targets = append(targets, RequestTarget{DN: entry.DN, Account: account, SPNs: spns})
	}
	sort.Slice(targets, func(i, j int) bool {
		return strings.ToLower(targets[i].DN) < strings.ToLower(targets[j].DN)
	})
	return targets
}
