package main

import (
	"fmt"
	"os"

	"github.com/TheManticoreProject/FindKerberoastables/cli"
	"github.com/TheManticoreProject/FindKerberoastables/modes/mode_find"
	"github.com/TheManticoreProject/FindKerberoastables/modes/mode_request"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
)

var (
	mode             string
	debug            bool
	printSPNs        bool
	authDomain       string
	authUsername     string
	authPassword     string
	authHashes       string
	authNoPass       bool
	domainController string
	ldapPort         int
	useLdaps         bool
	useKerberos      bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "FindKerberoastables - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.1.0"}
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(false)
	ap.SetupSubParsing("mode", &mode, true)

	find := ap.AddSubParser("find", "List accounts with service principal names over LDAP.")
	cli.RegisterCommonGroups(find, &debug, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass)
	if group, err := find.NewArgumentGroup("Find options"); err == nil {
		group.NewBoolArgument(&printSPNs, "-s", "--print-spns", false, "Print SPNs for each account.")
	} else {
		logger.Warn(fmt.Sprintf("Error creating find options: %s", err))
	}

	request := ap.AddSubParser("request", "Request service tickets and print hashcat TGS hashes.")
	cli.RegisterCommonGroups(request, &debug, &domainController, &ldapPort, &useLdaps, &useKerberos, &authDomain, &authUsername, &authPassword, &authHashes, &authNoPass)
	ap.Parse()
}

func run() error {
	parseArgs()
	if mode == "request" && authNoPass && authPassword == "" && authHashes == "" {
		return fmt.Errorf("request mode requires a password or NT hash")
	}
	if err := cli.ResolvePassword(authDomain, authUsername, &authPassword, authNoPass, authHashes); err != nil {
		return err
	}
	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		return fmt.Errorf("creating credentials: %w", err)
	}
	if useLdaps && ldapPort == 389 {
		ldapPort = 636
	}
	switch mode {
	case "find":
		return mode_find.Run(domainController, ldapPort, creds, useLdaps, useKerberos, printSPNs, debug)
	case "request":
		return mode_request.Run(domainController, ldapPort, creds, useLdaps, useKerberos, debug)
	default:
		return fmt.Errorf("invalid mode %q", mode)
	}
}

func main() {
	if err := run(); err != nil {
		logger.Warn(err.Error())
		os.Exit(1)
	}
}
