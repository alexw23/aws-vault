package cli

import (
	"fmt"
	"log"

	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin/v2"
)

type CopyCommandInput struct {
	SourceBackend      string
	DestinationBackend string
}

func ConfigureCopyCommand(app *kingpin.Application, a *AwsVault) {
	input := CopyCommandInput{}

	cmd := app.Command("copy", "Copy credentials from one backend to another")

	cmd.Arg("src", "Name of the backend to move credentials from").
		Required().
		EnumVar(&input.SourceBackend, a.AvailableBackends()...)

	cmd.Arg("destination", "Name of the backend to move credentials to").
		Required().
		EnumVar(&input.DestinationBackend, a.AvailableBackends()...)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		src := &AwsVault{KeyringBackend: input.SourceBackend, KeyringConfig: a.KeyringConfig, Debug: a.Debug}
		dest := &AwsVault{KeyringBackend: input.DestinationBackend, KeyringConfig: a.KeyringConfig, Debug: a.Debug}

		srcKeyring, err := src.Keyring()
		if err != nil {
			return err
		}

		destKeyring, err := dest.Keyring()
		if err != nil {
			return err
		}

		fmt.Printf("Copying credentials from %s to %s\n", input.SourceBackend, input.DestinationBackend)

		err = CopyCommand(input, srcKeyring, destKeyring)
		app.FatalIfError(err, "Copy")
		return nil
	})
}

func CopyCommand(input CopyCommandInput, srcKeyring keyring.Keyring, destKeyring keyring.Keyring) error {
	srcCredentialKeyring := &vault.CredentialKeyring{Keyring: srcKeyring}
	srcOidcTokenKeyring := &vault.OIDCTokenKeyring{Keyring: srcCredentialKeyring.Keyring}
	srcSessionKeyring := &vault.SessionKeyring{Keyring: srcCredentialKeyring.Keyring}
	destCredentialKeyring := &vault.CredentialKeyring{Keyring: destKeyring}
	destOidcTokenKeyring := &vault.OIDCTokenKeyring{Keyring: destCredentialKeyring.Keyring}
	destSessionKeyring := &vault.SessionKeyring{Keyring: destCredentialKeyring.Keyring}

	srcCredentialNames, err := srcCredentialKeyring.Keys()
	if err != nil {
		return err
	}

	srcOidcTokenNames, err := srcOidcTokenKeyring.Keys()
	if err != nil {
		return err
	}

	srcSessionNames, err := srcSessionKeyring.Keys()
	if err != nil {
		return err
	}

	log.Printf("Found %d credentials to copy", len(srcCredentialNames))
	log.Printf("Found %d OIDC tokens to copy", len(srcOidcTokenNames))
	log.Printf("Found %d sessions to copy", len(srcSessionNames))

	for _, credentialName := range srcCredentialNames {
		creds, err := srcCredentialKeyring.Get(credentialName)
		if err != nil {
			return err
		}

		log.Printf("Copying %s", credentialName)

		err = destCredentialKeyring.Set(credentialName, creds)
		if err != nil {
			return err
		}
	}

	for _, oidcTokenName := range srcOidcTokenNames {
		oidcToken, err := srcOidcTokenKeyring.Get(oidcTokenName)
		if err != nil {
			return err
		}

		log.Printf("Copying %s", oidcTokenName)

		err = destOidcTokenKeyring.Set(oidcTokenName, oidcToken)
		if err != nil {
			log.Printf("Error copying %s: %s", oidcTokenName, err)
			return err
		}
	}

	for _, sessionName := range srcSessionNames {
		session, err := srcSessionKeyring.Get(sessionName)
		if err != nil {
			return err
		}

		log.Printf("Copying %s", sessionName)

		err = destSessionKeyring.Set(sessionName, session)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Copied %d credentials, %d OIDC tokens, and %d sessions.\n", len(srcCredentialNames), len(srcOidcTokenNames), len(srcSessionNames))

	return nil
}
