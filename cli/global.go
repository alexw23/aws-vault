package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/99designs/aws-vault/v7/prompt"
	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin/v2"
	isatty "github.com/mattn/go-isatty"
	"golang.org/x/term"
)

var keyringConfigDefaults = keyring.Config{
	ServiceName:              "aws-vault",
	FilePasswordFunc:         fileKeyringPassphrasePrompt,
	LibSecretCollectionName:  "awsvault",
	KWalletAppID:             "aws-vault",
	KWalletFolder:            "aws-vault",
	KeychainTrustApplication: true,
	WinCredPrefix:            "aws-vault",
}

type AwsVault struct {
	Debug          bool
	KeyringConfig  keyring.Config
	KeyringBackend string
	promptDriver   string
	accessControl  string

	keyringImpl   keyring.Keyring
	awsConfigFile *vault.ConfigFile
}

var accessControlOptions = []string{"UserPresence", "BiometryCurrentSet", "BiometryAnySet", "DevicePasscode", "Watch", "ApplicationPassword"}
var accessConstraintOptions = []string{"", "AccessibleWhenUnlocked", "AccessibleAfterFirstUnlock", "AccessibleAfterFirstUnlockThisDeviceOnly", "AccessibleWhenPasscodeSetThisDeviceOnly", "AccessibleWhenUnlockedThisDeviceOnly"}

func isATerminal() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func (a *AwsVault) PromptDriver(avoidTerminalPrompt bool) string {
	if a.promptDriver == "" {
		a.promptDriver = "terminal"

		if !isATerminal() || avoidTerminalPrompt {
			for _, driver := range prompt.Available() {
				a.promptDriver = driver
				if driver != "terminal" {
					break
				}
			}
		}
	}

	log.Println("Using prompt driver: " + a.promptDriver)

	return a.promptDriver
}

func (a *AwsVault) Keyring() (keyring.Keyring, error) {
	if a.keyringImpl == nil {
		if a.KeyringBackend != "" {
			a.KeyringConfig.AllowedBackends = []keyring.BackendType{keyring.BackendType(a.KeyringBackend)}
		}
		var err error
		a.keyringImpl, err = keyring.Open(a.KeyringConfig)
		if err != nil {
			return nil, err
		}
	}

	return a.keyringImpl, nil
}

func (a *AwsVault) AwsConfigFile() (*vault.ConfigFile, error) {
	if a.awsConfigFile == nil {
		var err error
		a.awsConfigFile, err = vault.LoadConfigFromEnv()
		if err != nil {
			return nil, err
		}
	}

	return a.awsConfigFile, nil
}

func (a *AwsVault) MustGetProfileNames() []string {
	config, err := a.AwsConfigFile()
	if err != nil {
		log.Fatalf("Error loading AWS config: %s", err.Error())
	}
	return config.ProfileNames()
}

// Get available backends
func (a *AwsVault) AvailableBackends() []string {
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}
	return backendsAvailable
}

func ConfigureGlobals(app *kingpin.Application) *AwsVault {
	a := &AwsVault{
		KeyringConfig: keyringConfigDefaults,
	}

	backendsAvailable := a.AvailableBackends()
	promptsAvailable := prompt.Available()

	app.Flag("debug", "Show debugging output").
		BoolVar(&a.Debug)

	app.Flag("backend", fmt.Sprintf("Secret backend to use %v", backendsAvailable)).
		Default(backendsAvailable[0]).
		Envar("AWS_VAULT_BACKEND").
		EnumVar(&a.KeyringBackend, backendsAvailable...)

	app.Flag("prompt", fmt.Sprintf("Prompt driver to use %v", promptsAvailable)).
		Envar("AWS_VAULT_PROMPT").
		StringVar(&a.promptDriver)

	app.Validate(func(app *kingpin.Application) error {
		if a.promptDriver == "" {
			return nil
		}
		if a.promptDriver == "pass" {
			kingpin.Fatalf("--prompt=pass (or AWS_VAULT_PROMPT=pass) has been removed from aws-vault as using TOTPs without " +
				"a dedicated device goes against security best practices. If you wish to continue using pass, " +
				"add `mfa_process = pass otp <your mfa_serial>` to profiles in your ~/.aws/config file.")
		}
		for _, v := range promptsAvailable {
			if v == a.promptDriver {
				return nil
			}
		}
		return fmt.Errorf("--prompt value must be one of %s, got '%s'", strings.Join(promptsAvailable, ","), a.promptDriver)
	})

	app.Flag("keychain", "Name of macOS keychain to use, if it doesn't exist it will be created").
		Default("aws-vault").
		Envar("AWS_VAULT_KEYCHAIN_NAME").
		StringVar(&a.KeyringConfig.KeychainName)

	app.Flag("secret-service-collection", "Name of secret-service collection to use, if it doesn't exist it will be created").
		Default("awsvault").
		Envar("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME").
		StringVar(&a.KeyringConfig.LibSecretCollectionName)

	app.Flag("pass-dir", "Pass password store directory").
		Envar("AWS_VAULT_PASS_PASSWORD_STORE_DIR").
		StringVar(&a.KeyringConfig.PassDir)

	app.Flag("pass-cmd", "Name of the pass executable").
		Envar("AWS_VAULT_PASS_CMD").
		StringVar(&a.KeyringConfig.PassCmd)

	app.Flag("pass-prefix", "Prefix to prepend to the item path stored in pass").
		Envar("AWS_VAULT_PASS_PREFIX").
		StringVar(&a.KeyringConfig.PassPrefix)

	app.Flag("file-dir", "Directory for the \"file\" password store").
		Default("~/.awsvault/keys/").
		Envar("AWS_VAULT_FILE_DIR").
		StringVar(&a.KeyringConfig.FileDir)

	app.Flag("access-control", "Access Control Settings for the Data Protection Keychain \"dp-keychain\" backend").
		Default("UserPresence").
		Envar("AWS_VAULT_ACCESS_CONTROL").
		StringVar(&a.accessControl)

	app.Flag("access-constraint", "Access Control Settings for the Data Protection Keychain \"dp-keychain\" backend").
		Default("").
		Envar("AWS_VAULT_ACCESS_CONSTRAINT").
		EnumVar(&a.KeyringConfig.KeychainAccessConstraint, accessConstraintOptions...)

	app.Validate(func(app *kingpin.Application) error {
		// Ensure that current keyring backend is supported
		if a.KeyringBackend != "dp-keychain" && a.KeyringConfig.KeychainAccessConstraint != "" {
			return fmt.Errorf("--access-control is not supported with the backend '%s', only 'dp-keychain' is supported", a.KeyringBackend)
		}

		if a.KeyringBackend != "dp-keychain" && a.accessControl != "UserPresence" {
			return fmt.Errorf("--access-control is not supported with the backend '%s', only 'dp-keychain' is supported", a.KeyringBackend)
		}

		log.Printf("Using keyring backend: %s", a.KeyringBackend)
		log.Printf("Using access control: %s", a.accessControl)

		if a.KeyringConfig.KeychainAccessConstraint != "" {
			log.Printf("Using access constraint: %s", a.KeyringConfig.KeychainAccessConstraint)
		}

		terms, err := validateAccessControls(a)
		if err != nil {
			return err
		}

		a.KeyringConfig.KeychainAccessControl = terms

		return nil
	})

	app.PreAction(func(c *kingpin.ParseContext) error {
		if !a.Debug {
			log.SetOutput(io.Discard)
		}
		keyring.Debug = a.Debug
		log.Printf("aws-vault %s", app.Model().Version)
		return nil
	})

	return a
}

func validateAccessControls(a *AwsVault) ([]string, error) {
	validTerms := accessControlOptions
	validTermsPattern := strings.Join(validTerms, "|")

	// Regex for checking structure
	pattern := fmt.Sprintf(`^(%s)(?:\s*(And|Or)\s*(%s))*$`, validTermsPattern, validTermsPattern)
	regex := regexp.MustCompile(pattern)

	if !regex.MatchString(a.accessControl) {
		return nil, fmt.Errorf("invalid access control setting: '%s'", a.accessControl)
	}

	// Split the string by 'And' or 'Or' to check for repeats
	splitRegex := regexp.MustCompile(`\s*(And|Or)\s*`)
	terms := splitRegex.Split(a.accessControl, -1)

	// Map to track occurrences of terms
	seen := make(map[string]bool)
	for _, term := range terms {
		normalizedTerm := strings.TrimSpace(term)
		if seen[normalizedTerm] {
			return nil, fmt.Errorf("repeated access control term: '%s'", normalizedTerm)
		}
		seen[normalizedTerm] = true
	}

	return terms, nil
}

func StringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password, ok := os.LookupEnv("AWS_VAULT_FILE_PASSPHRASE"); ok {
		return password, nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}
