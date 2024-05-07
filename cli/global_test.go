package cli

import (
	"github.com/alecthomas/kingpin/v2"
	"testing"
)

// Assuming ConfigureGlobals is a function that configures global flags and returns some struct
// containing global variables or configuration settings.
func setupCLI() *kingpin.Application {
	app := kingpin.New("aws-vault", "A tool for securely managing AWS keys")
	// Here you would set up your flags, commands, and any validation hooks
	ConfigureGlobals(app) // Assuming this function sets up your flags and validation
	return app
}

func TestCheckAccessControlValidation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"ValidInput", []string{"--backend", "dp-keychain", "--access-control", "UserPresenceAndBiometryAnySet"}, false},
		{"InvalidKeyringBackend", []string{"--backend", "keychain", "--access-control", "UserPresence"}, false},
		{"InvalidAccessControl", []string{"--backend", "dp-keychain", "--access-control", "UserPresenceAndInvalid"}, true},
		{"ConjunctionAtStart", []string{"--backend", "dp-keychain", "--access-control", "AndUserPresence"}, true},
		{"ConjunctionAtEnd", []string{"--backend", "dp-keychain", "--access-control", "AndUserPresence"}, true},
		{"InvalidCasing", []string{"--backend", "dp-keychain", "--access-control", "userpresence"}, true},
		{"InvalidConjunctions", []string{"--backend", "dp-keychain", "--access-control", "UserPresence,Watch"}, true},
		{"RepeatTerms", []string{"--backend", "dp-keychain", "--access-control", "UserPresenceAndUserPresence"}, true},
		{"RepeatConjunctions", []string{"--backend", "dp-keychain", "--access-control", "UserPresenceAndAndWatch"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := kingpin.New("aws-vault", "A tool for securely managing AWS keys")
			ConfigureGlobals(app)
			_, err := app.Parse(tc.args)
			if (tc.wantErr && err == nil) || (!tc.wantErr && err != nil) {
				t.Errorf("CheckAccessControlValidation() for %s: unexpected error status: %v", tc.name, err)
			}
		})
	}
}
