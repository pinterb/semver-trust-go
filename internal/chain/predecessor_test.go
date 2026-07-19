// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

var chainEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func oid(c byte) string { return strings.Repeat(string(c), 40) }

func chainTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func chainVerifier(t *testing.T, signer ssh.Signer) *attest.Verifier {
	t.Helper()
	schema, err := conformance.Vector("schemas/release-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewVerifier([]sshsig.AllowedSigner{{
		Principals: []string{"releaser@semver-trust.test"},
		Namespaces: []string{attest.Namespace},
		Key:        signer.PublicKey(),
	}}, map[string][]byte{attest.PredicateReleaseV02: schema})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func releaseSchema(t *testing.T) []byte {
	t.Helper()
	schema, err := conformance.Vector("schemas/release-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func gitCmd(t *testing.T, repo string, args ...string) string {
	t.Helper()
	full := append([]string{
		"-C", repo,
		"-c", "user.name=Test", "-c", "user.email=test@semver-trust.test",
		"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
	}, args...)
	out, err := exec.Command("git", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return repo
}

func mkCommit(t *testing.T, repo, msg string) string {
	t.Helper()
	gitCmd(t, repo, "commit", "--allow-empty", "-m", msg)
	return gitCmd(t, repo, "rev-parse", "HEAD")
}

// mkTag creates an annotated tag at commit and returns its real raw ref OID (the
// tag object) and peeled commit OID, read back through vcs.TagRefs — the same path
// the reader uses.
func mkTag(t *testing.T, repo, name, commit string) (rawRefOID, peeledCommitOID string) {
	t.Helper()
	gitCmd(t, repo, "tag", "-a", name, commit, "-m", name)
	refs, err := vcs.TagRefs(repo)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := refs[name]
	if !ok {
		t.Fatalf("tag %q not found after creation", name)
	}
	return r.RefOID, r.CommitOID
}

// releaseSpec describes one release to synthesize into a chain. The resulting
// state's digest is computed here (the same way the emitter's caller does), so a
// stored release is internally consistent unless forceDigest overrides it.
type releaseSpec struct {
	repoID      string
	component   string
	tagPrefix   string
	to          string
	rawRefOID   string
	emittedTag  string
	genesis     bool
	predecessor *version.Binding // nil at genesis
	priorDigest *string          // "sha256:<hex>", nil at genesis
	state       version.VersionState
	forceDigest string // override resulting_state.digest (bare hex) to synthesize tampering
}

// emitAndStore builds, signs, and stores a release/v0.2 for spec and returns its
// resulting_state.digest (bare hex).
func emitAndStore(t *testing.T, repoPath string, signer ssh.Signer, schema []byte, spec releaseSpec) string {
	t.Helper()
	digest, err := version.StateDigest(version.CanonicalStateMap(spec.component, spec.tagPrefix, spec.state, spec.priorDigest))
	if err != nil {
		t.Fatal(err)
	}
	wireDigest := digest
	if spec.forceDigest != "" {
		wireDigest = spec.forceDigest
	}

	var predTag *attest.ReleaseTagIdentity
	if spec.predecessor != nil {
		predTag = &attest.ReleaseTagIdentity{Name: spec.predecessor.Tag, RawRefOID: spec.predecessor.RefOID, PeeledCommitOID: spec.predecessor.CommitOID}
	}
	var priorState *attest.ReleaseStateIdentity
	if spec.priorDigest != nil {
		priorState = &attest.ReleaseStateIdentity{
			ID:     "version-state:prior",
			Digest: map[string]string{"sha256": strings.TrimPrefix(*spec.priorDigest, "sha256:")},
		}
	}
	lineage := make([]attest.ReleaseObjectRef, 0, len(spec.state.TargetIntervals))
	for _, id := range spec.state.TargetIntervals {
		lineage = append(lineage, attest.ReleaseObjectRef{ID: id})
	}
	mode := "recurring"
	if spec.genesis {
		mode = "inception"
	}

	in := attest.ReleaseV02Input{
		TagName:    spec.emittedTag,
		CommitSHA:  spec.to,
		Repository: attest.ReleaseV02Repository{ID: spec.repoID, Digest: map[string]string{"sha256": oid('a') + oid('a')}},
		Component:  attest.ReleaseComponent{Name: spec.component, TagPrefix: spec.tagPrefix},
		Interval: attest.ReleaseInterval{
			Mode:           mode,
			To:             attest.ReleaseObjectRef{ID: "commit:" + spec.to},
			SourceIdentity: map[string]string{"gitCommit": spec.to},
		},
		PolicyState: attest.ReleasePolicyState{
			ActivePolicy: attest.ReleaseDigestDescriptor{Path: ".semver-trust/policy.toml", Digest: map[string]string{"sha256": oid('b') + oid('b')}},
			ActiveTrustRoots: []attest.ReleaseDigestDescriptor{
				{Path: ".semver-trust/allowed_signers", Digest: map[string]string{"sha256": oid('d') + oid('d')}},
			},
			CandidateTrustRoots: []attest.ReleaseDigestDescriptor{},
			MandatoryWorkflows: []attest.ReleaseDigestDescriptor{
				{Path: ".github/workflows/release.yml", Digest: map[string]string{"sha256": oid('e') + oid('e')}},
			},
			Authority:         "bootstrap",
			AuthorityIdentity: attest.ReleaseDigestDescriptor{URI: "bootstrap:" + spec.component, Digest: map[string]string{"sha256": oid('f') + oid('f')}},
		},
		VersionState: attest.ReleaseVersionState{
			Action:         "advance",
			Genesis:        spec.genesis,
			Predecessor:    predTag,
			PriorState:     priorState,
			ResultingState: attest.ReleaseStateIdentity{ID: "version-state:" + spec.component + ":" + spec.emittedTag, Digest: map[string]string{"sha256": wireDigest}},
			TargetCore:     spec.state.TargetCore,
			TargetBump:     spec.state.TargetBump,
			Emission: attest.ReleaseTagEmission{
				Kind: "tag",
				Tag:  &attest.ReleaseTagIdentity{Name: spec.emittedTag, RawRefOID: spec.rawRefOID, PeeledCommitOID: spec.to},
			},
			TargetLineage:          lineage,
			PendingCorrectiveFloor: spec.state.CorrectiveFloor,
		},
		Trust: attest.ReleaseTrust{Effective: "T2", Own: "T2", FloorSources: []attest.ReleaseObjectRef{}},
		Provenance: []attest.ReleaseProvenanceCommit{{
			SHA:        spec.to,
			Level:      "T2",
			Authorship: attest.ReleaseAuthorship{Class: "human", CredentialIdentity: "alice@semver-trust.test"},
			Review:     attest.ReleaseReviewRef{Class: "none"},
		}},
		Evidence: attest.ReleaseEvidence{BlastRadius: attest.ReleaseObjectRef{ID: "blast:low"}},
		Decision: attest.ReleaseV02Decision{ClaimedBump: "minor", SemanticFloor: "minor", Threshold: "T2", Strategy: "demote", Channel: "clean"},
		Timestamp: chainEpoch,
	}

	emitter, err := attest.NewReleaseV02Emitter(signer, schema)
	if err != nil {
		t.Fatal(err)
	}
	emission, err := emitter.Emit(in)
	if err != nil {
		t.Fatalf("emit %s: %v", spec.emittedTag, err)
	}
	if _, err := attest.StoreForSubjects(attest.GitRefStore{Path: repoPath}, []string{spec.to, spec.emittedTag}, emission.Envelope); err != nil {
		t.Fatal(err)
	}
	return digest
}

func genesisSpec(commit, rawRef string) releaseSpec {
	return releaseSpec{
		repoID: "repo:test/auth", component: "auth", tagPrefix: "auth/",
		to: commit, rawRefOID: rawRef, emittedTag: "auth/v0.1.0", genesis: true,
		state: version.VersionState{
			BaselineCore: "0.0.0", TargetCore: "0.1.0", TargetBump: "minor", CleanAccepted: true,
			TargetIntervals: []string{version.GenesisIntervalID("auth", "inception")},
			Iterations:      map[string]int{},
		},
	}
}

func advanceSpec(genCommit, genRawRef, advCommit, advRawRef, genesisDigest string) releaseSpec {
	prior := "sha256:" + genesisDigest
	baseline := &version.Binding{Tag: "auth/v0.1.0", RefOID: genRawRef, CommitOID: genCommit}
	return releaseSpec{
		repoID: "repo:test/auth", component: "auth", tagPrefix: "auth/",
		to: advCommit, rawRefOID: advRawRef, emittedTag: "auth/v0.2.0", genesis: false,
		predecessor: baseline,
		priorDigest: &prior,
		state: version.VersionState{
			Baseline:     baseline,
			BaselineCore: "0.1.0", TargetCore: "0.2.0", TargetBump: "minor", CleanAccepted: true,
			TargetIntervals: []string{"interval:auth:recurring:2"},
			Iterations:      map[string]int{},
		},
	}
}

// TestAcceptedChainHeadAdvance is the happy path over a REAL repo: a genesis→advance
// chain (real commits + annotated tags) is discovered, the head selected, the
// complete chain and the head tag verified, and the recurring authority
// projections produced.
func TestAcceptedChainHeadAdvance(t *testing.T) {
	repo := initGitRepo(t)
	signer := chainTestSigner(t)
	schema := releaseSchema(t)

	c1 := mkCommit(t, repo, "genesis")
	rawG, _ := mkTag(t, repo, "auth/v0.1.0", c1)
	gd := emitAndStore(t, repo, signer, schema, genesisSpec(c1, rawG))

	c2 := mkCommit(t, repo, "advance")
	rawS, _ := mkTag(t, repo, "auth/v0.2.0", c2)
	advDigest := emitAndStore(t, repo, signer, schema, advanceSpec(c1, rawG, c2, rawS, gd))

	pred, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
	if err != nil {
		t.Fatalf("AcceptedChainHead: %v", err)
	}
	if pred == nil {
		t.Fatal("AcceptedChainHead = nil, want the advance release as head")
	}

	if pred.To() != c2 || pred.Tag() != "auth/v0.2.0" {
		t.Errorf("head = %s@%s, want auth/v0.2.0@%s", pred.Tag(), pred.To()[:7], c2[:7])
	}
	if pred.ResultingStateDigest() != "sha256:"+advDigest {
		t.Errorf("ResultingStateDigest = %s, want sha256:%s", pred.ResultingStateDigest(), advDigest)
	}

	vs := pred.VersionSelected()
	if !vs.Accepted || !vs.ChainHead || vs.SourceSuccessorExists {
		t.Errorf("VersionSelected flags = accepted=%v chainHead=%v successor=%v, want true/true/false", vs.Accepted, vs.ChainHead, vs.SourceSuccessorExists)
	}
	if vs.To != c2 || len(vs.CanonicalTags) != 1 || vs.CanonicalTags[0].Tag != "auth/v0.2.0" || vs.CanonicalTags[0].CommitOID != c2 || vs.CanonicalTags[0].RefOID != rawS {
		t.Errorf("VersionSelected To/CanonicalTags = %s/%+v", vs.To, vs.CanonicalTags)
	}
	if vs.State.TargetCore != "0.2.0" || vs.State.BaselineCore != "0.1.0" || vs.State.Baseline == nil || vs.State.Baseline.Tag != "auth/v0.1.0" {
		t.Errorf("head State = %+v, want target 0.2.0 baseline auth/v0.1.0@0.1.0", vs.State)
	}

	iv := pred.IntervalDescriptor()
	if !iv.Accepted || !iv.ChainHead || iv.Repository != "repo:test/auth" || iv.Component != "auth" || iv.To != c2 || iv.TagTarget != c2 {
		t.Errorf("IntervalDescriptor = %+v, want accepted head, To=TagTarget=%s", iv, c2[:7])
	}

	pins := pred.PolicyPins()
	if pins.PolicyPath != ".semver-trust/policy.toml" || pins.PolicyDigest != "sha256:"+oid('b')+oid('b') {
		t.Errorf("policy pins = %+v, want the pinned active policy", pins)
	}
	if pins.TrustMaterial[".semver-trust/allowed_signers"] != "sha256:"+oid('d')+oid('d') {
		t.Errorf("trust-material pins = %+v", pins.TrustMaterial)
	}
	if len(pins.MandatoryMetaPaths) != 1 || pins.MandatoryMetaPaths[0] != ".github/workflows/release.yml" {
		t.Errorf("mandatory meta paths = %+v", pins.MandatoryMetaPaths)
	}
}

// A lone genesis release (real commit + tag) is itself the head.
func TestAcceptedChainHeadGenesisOnlyIsHead(t *testing.T) {
	repo := initGitRepo(t)
	signer := chainTestSigner(t)
	schema := releaseSchema(t)

	c1 := mkCommit(t, repo, "genesis")
	rawG, _ := mkTag(t, repo, "auth/v0.1.0", c1)
	emitAndStore(t, repo, signer, schema, genesisSpec(c1, rawG))

	pred, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
	if err != nil || pred == nil {
		t.Fatalf("AcceptedChainHead = %v, %v; want the genesis release as head", pred, err)
	}
	if pred.Tag() != "auth/v0.1.0" || pred.VersionSelected().State.TargetCore != "0.1.0" {
		t.Errorf("genesis head = %s, want auth/v0.1.0 @ 0.1.0", pred.Tag())
	}
}

// The head's emitted tag MUST still resolve to the signed binding (§5.2/ADR-027):
// a missing tag, a moved tag (peels elsewhere), and a recreated tag (raw ref OID
// differs) each abort — an attestation without its live tag cannot become the
// chain head the next recurring release builds on (PR #107 no-orphan discipline).
func TestAcceptedChainHeadRequiresLiveHeadTag(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		repo := initGitRepo(t)
		signer := chainTestSigner(t)
		schema := releaseSchema(t)
		c1 := mkCommit(t, repo, "genesis")
		// No tag created — emit with a placeholder raw ref.
		emitAndStore(t, repo, signer, schema, genesisSpec(c1, oid('7')))
		_, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
		if err == nil || !strings.Contains(err.Error(), "absent from the repository") {
			t.Errorf("missing-tag error = %v, want an absent-tag abort", err)
		}
	})

	t.Run("moved", func(t *testing.T) {
		repo := initGitRepo(t)
		signer := chainTestSigner(t)
		schema := releaseSchema(t)
		c1 := mkCommit(t, repo, "genesis")
		rawG, _ := mkTag(t, repo, "auth/v0.1.0", c1)
		emitAndStore(t, repo, signer, schema, genesisSpec(c1, rawG))
		// Move the tag to a different commit after the attestation was signed.
		c2 := mkCommit(t, repo, "later")
		gitCmd(t, repo, "tag", "-f", "-a", "auth/v0.1.0", c2, "-m", "moved")
		_, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
		if err == nil || !strings.Contains(err.Error(), "ref has moved") {
			t.Errorf("moved-tag error = %v, want a moved-ref abort", err)
		}
	})

	t.Run("recreated", func(t *testing.T) {
		repo := initGitRepo(t)
		signer := chainTestSigner(t)
		schema := releaseSchema(t)
		c1 := mkCommit(t, repo, "genesis")
		mkTag(t, repo, "auth/v0.1.0", c1) // real tag, but the emission pins a different raw ref
		// Sign with a raw_ref_oid that is NOT the live tag object (peels correct).
		emitAndStore(t, repo, signer, schema, genesisSpec(c1, oid('9')))
		_, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
		if err == nil || !strings.Contains(err.Error(), "recreated") {
			t.Errorf("recreated-tag error = %v, want a recreated-tag abort", err)
		}
	})
}

// No stored release for the component → genesis (nil): the caller stays on the
// descriptor authority. A release for a different component is not selected.
func TestAcceptedChainHeadNoneIsGenesis(t *testing.T) {
	repo := initGitRepo(t)
	signer := chainTestSigner(t)
	schema := releaseSchema(t)

	other := genesisSpec(oid('1'), oid('7'))
	other.component = "other"
	other.tagPrefix = "other/"
	other.emittedTag = "other/v0.1.0"
	other.state.TargetIntervals = []string{version.GenesisIntervalID("other", "inception")}
	emitAndStore(t, repo, signer, schema, other)

	pred, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
	if err != nil {
		t.Fatalf("AcceptedChainHead: %v", err)
	}
	if pred != nil {
		t.Errorf("AcceptedChainHead = %+v, want nil (no head for this component)", pred)
	}
}

// Two releases both advancing from genesis → a fork → abort (before tag
// resolution, so synthetic OIDs suffice).
func TestAcceptedChainHeadForkAborts(t *testing.T) {
	repo := initGitRepo(t)
	signer := chainTestSigner(t)
	schema := releaseSchema(t)

	gd := emitAndStore(t, repo, signer, schema, genesisSpec(oid('1'), oid('7')))
	emitAndStore(t, repo, signer, schema, advanceSpec(oid('1'), oid('7'), oid('2'), oid('8'), gd))
	fork := advanceSpec(oid('1'), oid('7'), oid('3'), oid('5'), gd) // second successor off the same genesis
	fork.emittedTag = "auth/v0.2.0-t1.1"
	fork.state.TargetCore = "0.2.0"
	fork.state.CleanAccepted = false
	fork.state.Iterations = map[string]int{"T1": 1}
	fork.state.TargetIntervals = []string{"interval:auth:recurring:2b"}
	emitAndStore(t, repo, signer, schema, fork)

	_, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
	if err == nil || !strings.Contains(err.Error(), "conflicting chain heads") {
		t.Errorf("fork error = %v, want a conflicting-heads abort", err)
	}
}

// A successor whose predecessor's attestation is absent → a broken chain → abort.
func TestAcceptedChainHeadBrokenLinkAborts(t *testing.T) {
	repo := initGitRepo(t)
	signer := chainTestSigner(t)
	schema := releaseSchema(t)

	gd, err := version.StateDigest(version.CanonicalStateMap("auth", "auth/", genesisSpec(oid('1'), oid('7')).state, nil))
	if err != nil {
		t.Fatal(err)
	}
	emitAndStore(t, repo, signer, schema, advanceSpec(oid('1'), oid('7'), oid('2'), oid('8'), gd)) // successor only

	_, err = AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
	if err == nil || !strings.Contains(err.Error(), "chain is broken") {
		t.Errorf("broken-link error = %v, want a broken-chain abort", err)
	}
}

// A successor that binds a FORGED predecessor raw ref OID — one consistent with
// its own reproduced state digest, but not the genesis's real emitted tag object —
// must still be rejected. ADR-036 excludes emission from resulting_state.digest, so
// a self-consistent forged predecessor raw ref reproduces the successor's digest;
// the full predecessor-tag-identity linkage check is the only place it is caught.
func TestAcceptedChainHeadForgedPredecessorRawRefAborts(t *testing.T) {
	repo := initGitRepo(t)
	signer := chainTestSigner(t)
	schema := releaseSchema(t)

	// genesis emits with raw ref oid('7').
	gd := emitAndStore(t, repo, signer, schema, genesisSpec(oid('1'), oid('7')))
	// The successor's predecessor binding (wire + canonicalized baseline) uses a
	// DIFFERENT raw ref oid('0') — internally consistent, so its own digest still
	// reproduces, but the tag object it binds is not the genesis's.
	emitAndStore(t, repo, signer, schema, advanceSpec(oid('1'), oid('0'), oid('2'), oid('8'), gd))

	_, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
	if err == nil || !strings.Contains(err.Error(), "does not match the linked release's emitted tag") {
		t.Errorf("forged-raw-ref error = %v, want a predecessor-tag-identity mismatch abort", err)
	}
}

// A release whose signed resulting_state.digest does not reproduce from its
// version_state → tampered → abort.
func TestAcceptedChainHeadTamperedDigestAborts(t *testing.T) {
	repo := initGitRepo(t)
	signer := chainTestSigner(t)
	schema := releaseSchema(t)

	g := genesisSpec(oid('1'), oid('7'))
	g.forceDigest = oid('9') + oid('9') // a signed-but-wrong resulting_state.digest
	emitAndStore(t, repo, signer, schema, g)

	_, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, signer), chainEpoch)
	if err == nil || !strings.Contains(err.Error(), "does not reproduce") {
		t.Errorf("tampered-digest error = %v, want a digest-reproduction abort", err)
	}
}

// A release signed by a key the verifier does not enroll is not a trustworthy
// chain member: it is skipped, so a component with only an unverifiable release
// reads as genesis (nil).
func TestAcceptedChainHeadSkipsUnverifiable(t *testing.T) {
	repo := initGitRepo(t)
	realSigner := chainTestSigner(t)
	strangerSigner := chainTestSigner(t)
	schema := releaseSchema(t)

	emitAndStore(t, repo, strangerSigner, schema, genesisSpec(oid('1'), oid('7')))

	pred, err := AcceptedChainHead(repo, "repo:test/auth", "auth", chainVerifier(t, realSigner), chainEpoch)
	if err != nil {
		t.Fatalf("AcceptedChainHead: %v", err)
	}
	if pred != nil {
		t.Errorf("AcceptedChainHead = %+v, want nil (the only release is unverifiable)", pred)
	}
}
