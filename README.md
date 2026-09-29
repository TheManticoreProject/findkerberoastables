![](./.github/banner.png)

<p align="center">
  A tool to find accounts with service principal names over LDAP and request their Kerberos service tickets as hashcat-compatible hashes.
  <br>
  <a href="https://github.com/TheManticoreProject/FindKerberoastables/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/FindKerberoastables/actions/workflows/release.yaml/badge.svg"></a>
  <a href="https://github.com/TheManticoreProject/FindKerberoastables/releases"><img alt="GitHub release" src="https://img.shields.io/github/v/release/TheManticoreProject/FindKerberoastables"></a>
  <a href="https://goreportcard.com/report/github.com/TheManticoreProject/FindKerberoastables"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/FindKerberoastables"></a>
</p>

## Modes

- `find` lists accounts with SPNs. Add `-s` to print each SPN.
- `request` finds enabled user accounts with SPNs, requests one service ticket per account, and prints hashcat-compatible TGS hashes. Computer accounts and `krbtgt` are excluded.

Run `FindKerberoastables -h` to list modes, or `FindKerberoastables find -h` and `FindKerberoastables request -h` for mode options.

## Usage

Find accounts and SPNs:

```sh
./FindKerberoastables find -d EXAMPLE.local -u analyst -dc 10.0.0.1 -s
```

Request service tickets and save the resulting hashes:

```sh
./FindKerberoastables request -d EXAMPLE.local -u analyst -dc 10.0.0.1 > tgs.hashes
```

Both modes prompt for a password when no secret is supplied. To supply an NT hash for authentication, use `-H LMhash:NThash`; `-p` also accepts a password directly. The `--no-pass` flag suppresses prompting for `find`, which can be used with a directory that permits an unauthenticated bind. `request` requires a password or NT hash to obtain a TGT.

The `-L` flag selects LDAPS (port 636 by default). The `-k` flag selects Kerberos authentication for the LDAP bind; ticket requests in `request` mode always use Kerberos. The domain controller given with `-dc` is also used as the KDC.

The `request` mode writes only hash lines to stdout. Progress and per-SPN errors go to stderr. If one SPN fails, it tries another SPN for the same account; if an account cannot produce a hash, the command exits with a failure status after processing the remaining accounts. Hash formatting is provided by the Manticore Kerberos library for supported RC4 and AES ticket types.

## Example output

```text
$ ./FindKerberoastables find -d EXAMPLE.local -u analyst -dc 10.0.0.1 -s
[>] Accounts with SPNs (2):
  ├── CN=SQL Service,CN=Users,DC=EXAMPLE,DC=local
  │   └── MSSQLSvc/sql.example.local:1433
  └── CN=WEB-SERVER,CN=Computers,DC=EXAMPLE,DC=local
      └── HTTP/web.example.local
```

`request` produces one `$krb5tgs$...` line per successfully requested user account. These lines can be used with the matching hashcat Kerberos TGS mode for their encryption type.

## Contributing

Pull requests are welcome.

## Credits

- [Remi GASCOU (Podalirius)](https://github.com/Podalirius) for creating FindKerberoastables.
