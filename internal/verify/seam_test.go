// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// TestLoadTrustMaterial exercises the P0 trust-material seam directly: on the
// signed-history fixture it resolves the vendored allowed-signers registry into
// a TrustedSigners set that verifies a real commit — the same material verifyWith
// loads, now callable by internal/preflight (doctor).
func TestLoadTrustMaterial(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "signed-history")
	opts := Options{
		RepoPath:           repo,
		To:                 "main",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	}

	trusted, _, err := LoadTrustMaterial(opts, minimalPolicy(t), repo)
	if err != nil {
		t.Fatalf("LoadTrustMaterial: %v", err)
	}
	if len(trusted.AllowedSigners) == 0 {
		t.Fatal("trusted.AllowedSigners is empty; want the vendored registry loaded")
	}

	commits, err := vcs.Range(repo, "", "main")
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(commits) == 0 {
		t.Fatal("no commits enumerated")
	}
	// The loaded material must actually verify a real commit (not just parse).
	if _, err := vcs.VerifyCommitSignature(repo, commits[len(commits)-1].Hash, trusted, pinnedEpoch); err != nil {
		t.Errorf("VerifyCommitSignature with loaded material: %v", err)
	}
}

// TestClassifyCommit exercises the P0 single-commit seam directly. The abort
// fixtures (same set as TestVerifySignatureAborts) must abort at §10 step 3 with
// their signature sentinel when classified; the signed-history fixture must
// classify every commit cleanly, with the report row and the trust.Commit in
// agreement on the level.
func TestClassifyCommit(t *testing.T) {
	fixtures := buildFixtures(t)
	pol := minimalPolicy(t)

	t.Run("aborts", func(t *testing.T) {
		cases := []struct {
			repo     string
			sentinel error
		}{
			{"unknown-signer", vcs.ErrUnknownSigner},
			{"tampered", vcs.ErrInvalidSignature},
			{"gpg-signed", vcs.ErrUnsupportedKeyFamily},
		}
		for _, tc := range cases {
			t.Run(tc.repo, func(t *testing.T) {
				repo := filepath.Join(fixtures, tc.repo)
				opts := Options{RepoPath: repo, To: "main", AllowedSignersPath: allowedSignersPath(t), VerifyTime: pinnedEpoch}
				trusted, av, err := LoadTrustMaterial(opts, pol, repo)
				if err != nil {
					t.Fatalf("LoadTrustMaterial: %v", err)
				}
				commits, err := vcs.Range(repo, "", "main")
				if err != nil {
					t.Fatalf("Range: %v", err)
				}
				// Classify in order; the first non-nil error is the abort, exactly
				// as verifyWith's loop stops on the first unverifiable commit.
				var got error
				for _, c := range commits {
					if _, _, e := ClassifyCommit(repo, c, trusted, av, pol, pinnedEpoch); e != nil {
						got = e
						break
					}
				}
				assertAbortStep(t, got, stepSignature)
				if !errors.Is(got, tc.sentinel) {
					t.Errorf("error = %v, want sentinel %v", got, tc.sentinel)
				}
			})
		}
	})

	t.Run("signed-history", func(t *testing.T) {
		repo := filepath.Join(fixtures, "signed-history")
		opts := Options{RepoPath: repo, To: "main", AllowedSignersPath: allowedSignersPath(t), VerifyTime: pinnedEpoch}
		trusted, av, err := LoadTrustMaterial(opts, pol, repo)
		if err != nil {
			t.Fatalf("LoadTrustMaterial: %v", err)
		}
		commits, err := vcs.Range(repo, "", "main")
		if err != nil {
			t.Fatalf("Range: %v", err)
		}
		if len(commits) == 0 {
			t.Fatal("no commits enumerated")
		}
		for _, c := range commits {
			row, tc, err := ClassifyCommit(repo, c, trusted, av, pol, pinnedEpoch)
			if err != nil {
				t.Fatalf("ClassifyCommit(%s): %v", c.Hash, err)
			}
			if row.SHA != c.Hash {
				t.Errorf("row.SHA = %s, want %s", row.SHA, c.Hash)
			}
			if row.Level != tc.Level.String() {
				t.Errorf("row.Level %q != trust.Commit level %q", row.Level, tc.Level.String())
			}
		}
	})
}
