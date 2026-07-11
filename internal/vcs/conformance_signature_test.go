// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// Consumes the SSH signature-verification vectors from the ADR-021 vendored
// copy (conformance/vendor/crypto/). The fixture repositories are built at
// test time by the vendored deterministic script; commits are addressed by
// role tag AND pinned SHA (dual assertion, fixture plan §5) so a recipe
// drift is diagnosed as such rather than read as a verification bug.

type sigVectorFile struct {
	SpecVersion      string      `json:"spec_version"`
	VerificationTime string      `json:"verification_time"`
	AllowedSigners   string      `json:"allowed_signers"`
	Vectors          []sigVector `json:"vectors"`
}

type sigVector struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Inputs struct {
		Repo           string `json:"repo"`
		Role           string `json:"role"`
		SHA            string `json:"sha"`
		StripSignature bool   `json:"strip_signature"`
	} `json:"inputs"`
	Expected struct {
		Outcome   string `json:"outcome"`
		Principal string `json:"principal"`
		Reason    string `json:"reason"`
	} `json:"expected"`
}

// reasonErrs maps vector failure reasons to the verifier's sentinel errors.
var reasonErrs = map[string]error{
	"unsigned":               ErrUnsigned,
	"unsupported_key_family": ErrUnsupportedKeyFamily,
	"unknown_signer":         ErrUnknownSigner,
	"revoked_signer":         ErrRevokedSigner,
	"invalid_signature":      ErrInvalidSignature,
}

func cryptoVendorDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "vendor", "crypto")
}

func loadSigVectors(t *testing.T) (sigVectorFile, string) {
	t.Helper()
	dir := cryptoVendorDir(t)
	path := os.Getenv("SEMVER_TRUST_SIGNATURE_VECTORS")
	if path == "" {
		path = filepath.Join(dir, "signature-vectors.json")
		dir = filepath.Dir(path)
	} else {
		dir = filepath.Dir(path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("signature vectors missing (refresh via scripts/sync-conformance.py): %v", err)
	}
	var vf sigVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return vf, dir
}

// buildCryptoFixtures runs the vendored deterministic builder once per test
// run directory. Hermetic: local repositories, no network.
func buildCryptoFixtures(t *testing.T, cryptoDir string) string {
	t.Helper()
	dest := t.TempDir()
	script := filepath.Join(cryptoDir, "build-fixture-repos.sh")
	cmd := exec.Command("bash", script, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-fixture-repos.sh failed: %v\n%s", err, out)
	}
	return dest
}

func TestConformanceSSHSignatures(t *testing.T) {
	vf, cryptoDir := loadSigVectors(t)

	at, err := time.Parse(time.RFC3339, vf.VerificationTime)
	if err != nil {
		t.Fatalf("verification_time: %v", err)
	}
	signersData, err := os.ReadFile(filepath.Join(cryptoDir, vf.AllowedSigners))
	if err != nil {
		t.Fatalf("allowed_signers: %v", err)
	}
	signers, err := ParseAllowedSigners(signersData)
	if err != nil {
		t.Fatalf("ParseAllowedSigners: %v", err)
	}

	fixtures := buildCryptoFixtures(t, cryptoDir)

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "ssh_signature" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			repo := filepath.Join(fixtures, vec.Inputs.Repo)
			rev := "role/" + vec.Inputs.Role

			// Dual assertion (fixture plan §5): the built SHA must match the
			// pinned one; a mismatch is recipe drift, not a verifier bug.
			built := resolveSHA(t, repo, rev)
			if built != vec.Inputs.SHA {
				t.Fatalf(
					"fixture build recipe drifted — expected %s for role %q, got %s; the recipe or its inputs changed",
					vec.Inputs.SHA, vec.Inputs.Role, built,
				)
			}
			if vec.Inputs.StripSignature {
				rev = stripSignature(t, repo, rev)
			}

			// No PGP keyring is injected: the gpg-family vector asserts the
			// SSH-only conformance contract's fail-closed rider holds.
			got, err := VerifyCommitSignature(repo, rev, TrustedSigners{AllowedSigners: signers}, at)

			if vec.Expected.Outcome == "verified" {
				if err != nil {
					t.Fatalf("VerifyCommitSignature: %v, want verified as %s", err, vec.Expected.Principal)
				}
				if got.Principal != vec.Expected.Principal {
					t.Errorf("principal = %q, want %q", got.Principal, vec.Expected.Principal)
				}
				return
			}

			want, ok := reasonErrs[vec.Expected.Reason]
			if !ok {
				t.Fatalf("vector carries unknown reason %q", vec.Expected.Reason)
			}
			if err == nil {
				t.Fatalf("verification succeeded (%+v), want abort: %s — unverifiable is never T0 (§5.2)", got, vec.Expected.Reason)
			}
			if !errors.Is(err, want) {
				t.Errorf("error = %v, want %v", err, want)
			}
		})
	}
	if seen == 0 {
		t.Error("no ssh_signature vectors found")
	}
}

func resolveSHA(t *testing.T, repoPath, rev string) string {
	t.Helper()
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := r.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		t.Fatalf("resolving %s: %v", rev, err)
	}
	return hash.String()
}

// stripSignature stores a copy of the commit at rev with its signature
// removed and returns the new commit's hash — the synthetic unsigned case.
func stripSignature(t *testing.T, repoPath, rev string) string {
	t.Helper()
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := r.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := r.CommitObject(*hash)
	if err != nil {
		t.Fatal(err)
	}

	obj := r.Storer.NewEncodedObject()
	if err := commit.EncodeWithoutSignature(obj); err != nil {
		t.Fatal(err)
	}
	stripped, err := r.Storer.SetEncodedObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	return stripped.String()
}
