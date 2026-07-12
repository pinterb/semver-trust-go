// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

const releaseEpoch = "2026-01-01T00:00:00Z"

// releaseResultJSON mirrors the release --json output shape.
type releaseResultJSON struct {
	DryRun        bool            `json:"dry_run"`
	Channel       string          `json:"channel"`
	Version       string          `json:"version"`
	Tag           string          `json:"tag"`
	ToCommit      string          `json:"to_commit"`
	Bump          string          `json:"bump"`
	Effective     string          `json:"effective"`
	Own           string          `json:"own"`
	SemanticFloor string          `json:"semantic_floor"`
	StoredRefs    []string        `json:"stored_refs"`
	Statement     json.RawMessage `json:"statement"`
	Report        *verify.Report  `json:"report"`
}

// releasePayloadJSON is the subset of the §8.1 payload the tests assert on.
type releasePayloadJSON struct {
	Type          string `json:"_type"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		Component string `json:"component"`
		Range     struct {
			From                   *string `json:"from"`
			To                     string  `json:"to"`
			FromIsAdoptionBoundary bool    `json:"from_is_adoption_boundary"`
		} `json:"range"`
		Trust struct {
			Effective          string           `json:"effective"`
			Own                string           `json:"own"`
			FloorSource        *json.RawMessage `json:"floor_source"`
			DependenciesPinned []any            `json:"dependencies_pinned"`
		} `json:"trust"`
		Commits []struct {
			SHA        string `json:"sha"`
			Level      string `json:"level"`
			Authorship struct {
				Class    string            `json:"class"`
				Identity string            `json:"identity"`
				Trailers map[string]string `json:"trailers"`
			} `json:"authorship"`
			Review struct {
				Class       string `json:"class"`
				Identity    string `json:"identity"`
				Attestation string `json:"attestation"`
			} `json:"review"`
		} `json:"commits"`
		Evidence struct {
			Compat *struct {
				Provider string `json:"provider"`
				Result   string `json:"result"`
			} `json:"compat"`
			BlastRadius struct {
				Files  int            `json:"files"`
				Score  string         `json:"score"`
				Inputs map[string]any `json:"inputs"`
			} `json:"blast_radius"`
		} `json:"evidence"`
		Decision struct {
			ClaimedBump   string `json:"claimed_bump"`
			SemanticFloor string `json:"semantic_floor"`
			Strategy      string `json:"strategy"`
			Channel       string `json:"channel"`
			Policy        struct {
				Path   string `json:"path"`
				Digest string `json:"digest"`
			} `json:"policy"`
			Supersedes *string `json:"supersedes"`
		} `json:"decision"`
		Timestamp string `json:"timestamp"`
	} `json:"predicate"`
}

// emitBobReviewOverRoot runs `attest review` over root..main of the release
// fixture — the post-hoc review lift (#46 pattern, Appendix A step 3).
func emitBobReviewOverRoot(t *testing.T, repo string) {
	t.Helper()
	_, err := runCommand(t, "attest", "review",
		"--repo", repo,
		"--to", "main",
		"--reviewer", "bob@semver-trust.test",
		"--pr", "https://forge.semver-trust.test/release/pull/3",
		"--key", bobKeyPath(t),
		"--timestamp", releaseEpoch)
	if err != nil {
		t.Fatalf("attest review: %v", err)
	}
}

// attestationRefs lists every ref under refs/attestations/ via the git CLI —
// the write-nothing assertions key off it.
func attestationRefs(t *testing.T, repo string) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "for-each-ref", "--format=%(refname)", "refs/attestations").Output()
	if err != nil {
		t.Fatalf("for-each-ref: %v", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	return fields
}

// verifyTagWithGit runs `git tag -v` against an injected allowed-signers
// registry — git's own acceptance of the SSHSIG-signed tag.
func verifyTagWithGit(t *testing.T, repo, tag string) {
	t.Helper()
	cmd := exec.Command("git", "-C", repo,
		"-c", "gpg.ssh.allowedSignersFile="+allowedSignersPath(t),
		"tag", "-v", tag)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("git tag -v %s rejected the tag: %v\n%s", tag, err, out)
	}
}

// validateReleasePayload asserts the payload independently against the
// vendored release-v0.1.json — not through the emitter or verifier that
// produced it.
func validateReleasePayload(t *testing.T, payload []byte) {
	t.Helper()
	schemaBytes, err := conformance.Vector("schemas/release-v0.1.json")
	if err != nil {
		t.Fatal(err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("release-v0.1.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("release-v0.1.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("payload does not validate against release-v0.1.json: %v", err)
	}
}

// envelopePayload decodes a DSSE envelope's payload bytes.
func envelopePayload(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var env attest.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// The acceptance e2e (spec §10 steps 8-9): on the deterministic release
// fixture WITH bob's post-hoc review attestations, `release --claimed-bump
// patch --blast low` from v0.1.0 decides honestly — alice lifts to T3,
// ci-bot to T2, own floor T2, adapter none so effective T2, blast low is the
// §6.4 clean cell with no differ condition, declared-intent floor over two
// fix: commits is patch — and emits the clean v0.1.1: a signed annotated tag
// git itself verifies, plus a release attestation that validates against
// release-v0.1.json and is retrievable for BOTH subjects.
func TestReleaseCleanAfterReview(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	emitBobReviewOverRoot(t, repo)

	out, err := runCommand(t, "release",
		"--repo", repo,
		"--from", "v0.1.0",
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--claimed-bump", "patch",
		"--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "bob",
		"--tagger-email", "bob@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("release: %v", err)
	}

	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("release --json output does not parse: %v\n%s", err, out)
	}
	if result.Channel != "clean" || result.Version != "v0.1.1" || result.Tag != "v0.1.1" {
		t.Errorf("decision = channel %s, version %s, tag %s; want clean v0.1.1", result.Channel, result.Version, result.Tag)
	}
	if result.Effective != "T2" || result.Own != "T2" || result.Bump != "patch" || result.SemanticFloor != "patch" {
		t.Errorf("decision inputs = effective %s, own %s, bump %s, floor %s; want T2/T2/patch/patch",
			result.Effective, result.Own, result.Bump, result.SemanticFloor)
	}
	if len(result.StoredRefs) != 2 {
		t.Fatalf("stored refs = %v, want one per subject (TO commit + tag)", result.StoredRefs)
	}

	// The signed tag exists at TO and verifies — through git itself.
	toSHA, err := vcs.ResolveCommit(repo, "v0.1.1")
	if err != nil {
		t.Fatalf("tag v0.1.1 does not resolve: %v", err)
	}
	if toSHA != result.ToCommit {
		t.Errorf("tag points at %s, want TO %s", toSHA, result.ToCommit)
	}
	verifyTagWithGit(t, repo, "v0.1.1")

	// The stored envelope is retrievable via List for BOTH subjects and is
	// the same envelope.
	store := attest.GitRefStore{Path: repo}
	bySHA, err := store.List(result.ToCommit)
	if err != nil {
		t.Fatal(err)
	}
	byTag, err := store.List("v0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	// The TO commit also carries bob's review attestation; find the release
	// envelope by predicate.
	var releaseEnvelopes [][]byte
	for _, env := range bySHA {
		if strings.Contains(string(envelopePayload(t, env)), attest.PredicateRelease) {
			releaseEnvelopes = append(releaseEnvelopes, env)
		}
	}
	if len(releaseEnvelopes) != 1 || len(byTag) != 1 {
		t.Fatalf("release envelopes: %d under TO, %d under tag; want 1 and 1", len(releaseEnvelopes), len(byTag))
	}
	if !bytes.Equal(releaseEnvelopes[0], byTag[0]) {
		t.Error("subjects reference different envelopes")
	}

	// Independent schema validation (the emitter guarantees it; assert anyway).
	payload := envelopePayload(t, byTag[0])
	validateReleasePayload(t, payload)

	// The payload carries the §8.1 shape: provenance vector with consumed
	// review refs, self-floored trust as null, operator-recorded blast, the
	// pinned policy digest, and a null supersedes.
	var stmt releasePayloadJSON
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatal(err)
	}
	p := stmt.Predicate
	if stmt.Subject[0].Name != "v0.1.1" || stmt.Subject[0].Digest["gitCommit"] != result.ToCommit {
		t.Errorf("subject = %+v", stmt.Subject)
	}
	if p.Component != "default" {
		t.Errorf("component = %q, want the implicit default scope", p.Component)
	}
	if p.Range.From == nil || *p.Range.From != "v0.1.0" || p.Range.To != result.ToCommit || p.Range.FromIsAdoptionBoundary {
		t.Errorf("range = %+v", p.Range)
	}
	if p.Trust.Effective != "T2" || p.Trust.Own != "T2" {
		t.Errorf("trust = %+v", p.Trust)
	}
	if p.Trust.FloorSource != nil && string(*p.Trust.FloorSource) != "null" {
		t.Errorf("floor_source = %s, want null (self-floored maps to the schema's null)", *p.Trust.FloorSource)
	}
	if p.Trust.DependenciesPinned == nil || len(p.Trust.DependenciesPinned) != 0 {
		t.Errorf("dependencies_pinned = %v, want present and empty (adapter none)", p.Trust.DependenciesPinned)
	}
	if len(p.Commits) != 2 {
		t.Fatalf("provenance vector = %d commits, want 2", len(p.Commits))
	}
	for _, c := range p.Commits {
		if c.Review.Class != "human" || c.Review.Identity != "bob@semver-trust.test" || c.Review.Attestation == "" {
			t.Errorf("commit %s review = %+v, want bob's consumed attestation referenced", c.SHA[:7], c.Review)
		}
		if c.Authorship.Trailers["Provenance"] == "" {
			t.Errorf("commit %s trailers missing Provenance", c.SHA[:7])
		}
	}
	if p.Evidence.Compat != nil {
		t.Errorf("compat = %+v, want absent (no differ configured — absence, never fabrication)", p.Evidence.Compat)
	}
	if p.Evidence.BlastRadius.Score != "low" || p.Evidence.BlastRadius.Inputs["source"] != "operator" {
		t.Errorf("blast_radius = %+v, want the operator-supplied score recorded as such", p.Evidence.BlastRadius)
	}
	if p.Decision.Channel != "clean" || p.Decision.ClaimedBump != "patch" || p.Decision.Strategy != "demote" {
		t.Errorf("decision = %+v", p.Decision)
	}
	if !strings.HasPrefix(p.Decision.Policy.Digest, "sha256:") {
		t.Errorf("policy digest = %q, want alg-prefixed", p.Decision.Policy.Digest)
	}
	if p.Decision.Supersedes != nil {
		t.Errorf("supersedes = %v, want null (promotion out of scope for v1)", p.Decision.Supersedes)
	}
}

// The refusal acceptance: the same fixture WITHOUT review attestations fails
// §5.4 over root..main (the policy's own history cannot be trusted), and
// release refuses outright — no tag created, nothing stored.
func TestReleaseRefusesMetaPathFailure(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	tagsBefore, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runCommand(t, "release",
		"--repo", repo,
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--claimed-bump", "patch",
		"--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "bob",
		"--tagger-email", "bob@semver-trust.test")
	if err == nil {
		t.Fatal("release succeeded on a history whose policy fails §5.4 meta-path trust")
	}
	for _, want := range []string{"release refused", "§5.4"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}

	tagsAfter, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(tagsAfter) != len(tagsBefore) {
		t.Errorf("tags changed on refusal: before %v, after %v", tagsBefore, tagsAfter)
	}
	if refs := attestationRefs(t, repo); len(refs) != 0 {
		t.Errorf("attestation store not empty on refusal: %v", refs)
	}
}

// --dry-run evaluates and decides, prints the would-be tag and attestation,
// and writes nothing: no tag ref, no attestation ref.
func TestReleaseDryRunWritesNothing(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	emitBobReviewOverRoot(t, repo)
	tagsBefore, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	refsBefore := attestationRefs(t, repo)

	out, err := runCommand(t, "release",
		"--repo", repo,
		"--from", "v0.1.0",
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--claimed-bump", "patch",
		"--blast", "low",
		"--verify-time", releaseEpoch,
		"--dry-run",
		"--json")
	if err != nil {
		t.Fatalf("release --dry-run: %v", err)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	if !result.DryRun || result.Tag != "v0.1.1" || result.Channel != "clean" {
		t.Errorf("dry-run result = %+v", result)
	}
	if len(result.Statement) == 0 {
		t.Error("dry-run did not print the would-be statement")
	}
	validateReleasePayload(t, result.Statement)

	tagsAfter, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(tagsAfter) != len(tagsBefore) {
		t.Errorf("dry-run created a tag: before %v, after %v", tagsBefore, tagsAfter)
	}
	if refsAfter := attestationRefs(t, repo); len(refsAfter) != len(refsBefore) {
		t.Errorf("dry-run stored something: before %v, after %v", refsBefore, refsAfter)
	}
}

// A decision whose tag already exists refuses (§7.2: a re-cut is a new
// iteration, never a moved ref) — the fixture already carries v0.1.1-t0.1 on
// exactly the demoted decision this unreviewed range produces — and the same
// release at --iteration 2 cuts v0.1.1-t0.2 on the pre-release channel.
func TestReleaseRefusesExistingTagThenIterates(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")

	args := func(iteration string) []string {
		return []string{"release",
			"--repo", repo,
			"--from", "v0.1.0",
			"--to", "main",
			"--allowed-signers", allowedSignersPath(t),
			"--claimed-bump", "patch",
			"--blast", "low",
			"--verify-time", releaseEpoch,
			"--tag-key", bobKeyPath(t),
			"--attest-key", bobKeyPath(t),
			"--tagger-name", "bob",
			"--tagger-email", "bob@semver-trust.test",
			"--iteration", iteration,
			"--json",
		}
	}

	// Unreviewed: own floor T0 → effective T0 → pre-release v0.1.1-t0.1,
	// which the fixture already tagged.
	_, err := runCommand(t, args("1")...)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("release = %v, want the existing-tag refusal", err)
	}
	if refs := attestationRefs(t, repo); len(refs) != 0 {
		t.Errorf("attestation store not empty after refusal: %v", refs)
	}

	out, err := runCommand(t, args("2")...)
	if err != nil {
		t.Fatalf("release --iteration 2: %v", err)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Channel != "prerelease" || result.Tag != "v0.1.1-t0.2" {
		t.Errorf("re-cut = channel %s, tag %s; want prerelease v0.1.1-t0.2", result.Channel, result.Tag)
	}
	verifyTagWithGit(t, repo, "v0.1.1-t0.2")
}

// An adoption-boundary release (ADR-026): the policy declares the boundary,
// a first release anchors there, and the attestation discloses it —
// range.from is the boundary and from_is_adoption_boundary is true.
func TestReleaseAdoptionBoundaryDisclosed(t *testing.T) {
	repo := buildBoundaryReleaseRepo(t)

	out, err := runCommand(t, "release",
		"--repo", repo,
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--claimed-bump", "patch",
		"--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "alice",
		"--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	// One post-boundary feat: commit at T2 → declared floor minor governs
	// over the patch claim; T2 × low is clean; first release from the
	// v0.0.0 baseline → v0.1.0.
	if result.Channel != "clean" || result.Tag != "v0.1.0" {
		t.Errorf("decision = channel %s, tag %s; want clean v0.1.0", result.Channel, result.Tag)
	}

	byTag, err := attest.GitRefStore{Path: repo}.List("v0.1.0")
	if err != nil || len(byTag) != 1 {
		t.Fatalf("stored envelopes under tag = %d (%v), want 1", len(byTag), err)
	}
	payload := envelopePayload(t, byTag[0])
	validateReleasePayload(t, payload)
	var stmt releasePayloadJSON
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatal(err)
	}
	if stmt.Predicate.Range.From == nil || *stmt.Predicate.Range.From != "v0-import" {
		t.Errorf("range.from = %v, want the declared boundary", stmt.Predicate.Range.From)
	}
	if !stmt.Predicate.Range.FromIsAdoptionBoundary {
		t.Error("from_is_adoption_boundary = false, want true (ADR-026: the two claims must never be conflated)")
	}
}

// buildBoundaryReleaseRepo constructs the ADR-026 shape in-test (the
// boundary_test.go pattern): an unverifiable pre-scheme commit tagged
// v0-import, then alice adopting the scheme with the boundary declared.
func buildBoundaryReleaseRepo(t *testing.T) string {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo := t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	policy := `# semver-trust TEST POLICY - in-test adoption-boundary release repo (ADR-026)
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
adoption_boundary = "v0-import"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
`
	commitSignedCLI(t, repo, keys, "unknown-mallory", "mallory@semver-trust.test",
		"pre.txt", "pre-scheme content\n", "feat: pre-scheme change\n\nProvenance: human")
	gitCLI(t, repo, "tag", "v0-import")
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		".semver-trust/policy.toml", policy, "feat: adopt semver-trust (ADR-026)\n\nProvenance: human")
	return repo
}

// stageVendoredKeys copies the vendored test keys into a private 0600
// staging dir: ssh-keygen -Y sign refuses group/other-readable private keys.
func stageVendoredKeys(t *testing.T) string {
	t.Helper()
	src := filepath.Join(cryptoVendorDir(t), "keys")
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o600)
		if strings.HasSuffix(e.Name(), ".pub") {
			mode = 0o644
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func gitCLI(t *testing.T, repo string, args ...string) {
	t.Helper()
	if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// commitSignedCLI writes file and commits it SSH-signed by the staged key,
// with configuration pinned per-invocation.
func commitSignedCLI(t *testing.T, repo, keys, key, identity, file, content, message string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, file)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCLI(t, repo, "add", file)
	gitCLI(t, repo,
		"-c", "user.name="+strings.SplitN(identity, "@", 2)[0],
		"-c", "user.email="+identity,
		"-c", "gpg.format=ssh",
		"-c", "user.signingkey="+filepath.Join(keys, key),
		"-c", "commit.gpgsign=true",
		"commit", "--quiet", "-m", message)
}
