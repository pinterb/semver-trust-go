// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"regexp"
	"strings"
)

// Trailer keys with spec-defined meaning (§4.1). Trailers are self-asserted
// and advisory: they refine classification but never override the verified
// signer identity class.
const (
	TrailerProvenance      = "Provenance"
	TrailerProvenanceAgent = "Provenance-Agent"
	TrailerProvenanceModel = "Provenance-Model"
	TrailerCoAuthoredBy    = "Co-authored-by"
)

// Trailer is one "Key: value" line of a commit's trailer block.
type Trailer struct {
	Key   string
	Value string
}

// Trailers is a commit's trailer block, in message order. Keys may repeat
// (Co-authored-by commonly does); lookups are case-insensitive, matching
// git-interpret-trailers.
type Trailers []Trailer

// Get returns the value of the last trailer with the given key — later
// trailers override earlier ones, as in git — and whether one exists.
func (t Trailers) Get(key string) (string, bool) {
	for i := len(t) - 1; i >= 0; i-- {
		if strings.EqualFold(t[i].Key, key) {
			return t[i].Value, true
		}
	}
	return "", false
}

// Values returns every value carried by the given key, in message order.
func (t Trailers) Values(key string) []string {
	var values []string
	for _, tr := range t {
		if strings.EqualFold(tr.Key, key) {
			values = append(values, tr.Value)
		}
	}
	return values
}

// Provenance returns the Provenance trailer value, or "" when absent — the
// shape trust classification consumes (§4.1).
func (t Trailers) Provenance() string {
	v, _ := t.Get(TrailerProvenance)
	return v
}

// trailerLine matches one "Key: value" line. Keys follow the conventional
// git-trailer shape: alphanumeric tokens separated by single dashes.
var trailerLine = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)[ \t]*:[ \t]*(\S.*?)[ \t]*$`)

// ParseTrailers extracts the trailer block from a commit message: the final
// paragraph, when every line in it is a trailer or a whitespace-indented
// continuation of the previous one, and it is not the message's only
// paragraph (a subject line is never a trailer block). Anything else yields
// no trailers — trailers are advisory, so a malformed block reads as absent
// rather than guessed at (§4.1: unverifiable claims are treated as absent).
func ParseTrailers(message string) Trailers {
	paragraphs := splitParagraphs(message)
	if len(paragraphs) < 2 {
		return nil
	}

	var trailers Trailers
	for _, line := range paragraphs[len(paragraphs)-1] {
		switch {
		case trailerLine.MatchString(line):
			m := trailerLine.FindStringSubmatch(line)
			trailers = append(trailers, Trailer{Key: m[1], Value: m[2]})
		case len(trailers) > 0 && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")):
			// Folded continuation line: appended to the previous value.
			trailers[len(trailers)-1].Value += " " + strings.TrimSpace(line)
		default:
			return nil
		}
	}
	return trailers
}

// splitParagraphs splits a message into blank-line-separated paragraphs of
// lines, ignoring trailing whitespace-only lines.
func splitParagraphs(message string) [][]string {
	var paragraphs [][]string
	var current []string
	for _, line := range strings.Split(message, "\n") {
		if strings.TrimSpace(line) == "" {
			if len(current) > 0 {
				paragraphs = append(paragraphs, current)
				current = nil
			}
			continue
		}
		current = append(current, line)
	}
	if len(current) > 0 {
		paragraphs = append(paragraphs, current)
	}
	return paragraphs
}
