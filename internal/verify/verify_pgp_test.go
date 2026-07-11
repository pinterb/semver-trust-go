// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/pgp/pgptest"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// Pipeline-level GPG coverage: verifyWith over a hermetic in-test fixture
// repository whose single commit is genuinely GPG-signed (per-run key, no
// gpg binary, no network), with the keyring injected through the
// --gpg-keyring seam (Options.GPGKeyringPath). The signature-abort fixture
// tests keep proving that WITHOUT a keyring the GPG family fails closed
// (TestVerifySignatureAborts gpg-signed) — the conformance contract.

// buildGPGFixture returns a GPG-signed single-commit repository, the signed
// commit's SHA, and the signer's armored public keyring written to disk.
func buildGPGFixture(t *testing.T) (repo, sha, keyringPath string) {
	t.Helper()
	signer, err := pgptest.NewSigner("Test Signer", "gpg-signer@semver-trust.test", pinnedEpoch, 0)
	if err != nil {
		t.Fatalf("generating entity: %v", err)
	}
	repo = t.TempDir()
	sha, err = pgptest.NewRepoWithSignedCommit(repo, signer, pinnedEpoch, "feat: gpg change\n\nProvenance: human\n")
	if err != nil {
		t.Fatalf("building GPG fixture repo: %v", err)
	}
	armored, err := pgptest.ArmoredKeyring(signer)
	if err != nil {
		t.Fatalf("armoring keyring: %v", err)
	}
	keyringPath = filepath.Join(t.TempDir(), "keyring.asc")
	if err := os.WriteFile(keyringPath, armored, 0o600); err != nil {
		t.Fatalf("writing keyring: %v", err)
	}
	return repo, sha, keyringPath
}

// An enrolled GPG key verifies through the whole pipeline: principal
// reported, human identity class, T2 level — the same path an SSH signer
// takes. No allowed-signers registry is given: a pure-GPG run needs none.
func TestVerifyGPGKeyringSucceeds(t *testing.T) {
	repo, sha, keyringPath := buildGPGFixture(t)

	report, err := verifyWith(Options{
		RepoPath:       repo,
		To:             sha,
		GPGKeyringPath: keyringPath,
		VerifyTime:     pinnedEpoch,
	}, minimalPolicy(t))
	if err != nil {
		t.Fatalf("verifyWith: %v", err)
	}
	if len(report.Commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(report.Commits))
	}
	c := report.Commits[0]
	if c.Signer != "gpg-signer@semver-trust.test" {
		t.Errorf("signer = %q, want gpg-signer@semver-trust.test", c.Signer)
	}
	if c.Fingerprint == "" {
		t.Error("fingerprint is empty")
	}
	assertCommit(t, c, "T2", "human", "none")
}

// The same fixture WITHOUT the keyring aborts at step 3 as an unsupported
// key family: injecting GPG material is the only thing that activates the
// GPG arm, so the SSH-only conformance contract is preserved.
func TestVerifyGPGWithoutKeyringFailsClosed(t *testing.T) {
	repo, sha, _ := buildGPGFixture(t)

	_, err := verifyWith(Options{
		RepoPath:           repo,
		To:                 sha,
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	}, minimalPolicy(t))
	assertAbortStep(t, err, stepSignature)
	if !errors.Is(err, vcs.ErrUnsupportedKeyFamily) {
		t.Errorf("error = %v, want ErrUnsupportedKeyFamily", err)
	}
}

// A GPG principal listed in policy identity.agent.bot_accounts classifies as
// an agent identity — the same §9 rule as SSH principals.
func TestVerifyGPGBotAccountClassifiesAgent(t *testing.T) {
	repo, sha, keyringPath := buildGPGFixture(t)

	pol := minimalPolicy(t)
	pol.Identity.Agent.BotAccounts = []string{"gpg-signer@semver-trust.test"}

	report, err := verifyWith(Options{
		RepoPath:       repo,
		To:             sha,
		GPGKeyringPath: keyringPath,
		VerifyTime:     pinnedEpoch,
	}, pol)
	if err != nil {
		t.Fatalf("verifyWith: %v", err)
	}
	if len(report.Commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(report.Commits))
	}
	// Bot-account signer: agent identity. The human Provenance trailer under
	// an agent signer is a mismatch that trust.Classify resolves; the level
	// must not be the human T2.
	if report.Commits[0].Level == "T2" {
		t.Errorf("level = T2 under a bot-account signer, want an agent-class level")
	}
}

// An unreadable or garbage keyring aborts at step 1: trust material that
// cannot be loaded is an abort, never an empty grant.
func TestVerifyGPGKeyringLoadFailures(t *testing.T) {
	repo, sha, _ := buildGPGFixture(t)

	garbage := filepath.Join(t.TempDir(), "garbage.asc")
	if err := os.WriteFile(garbage, []byte("not a keyring"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "absent.asc"),
		"garbage": garbage,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := verifyWith(Options{
				RepoPath:       repo,
				To:             sha,
				GPGKeyringPath: path,
				VerifyTime:     pinnedEpoch,
			}, minimalPolicy(t))
			assertAbortStep(t, err, stepLoadPolicy)
		})
	}
}
