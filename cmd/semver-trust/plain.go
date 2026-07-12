// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/semver-trust/semver-trust-go/internal/plain"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

// The plain-mode command group (GO-041): list, latest, next, tag — the
// go-semver donor surface, working with zero configuration. These commands
// never read a policy file; they enumerate raw git tags and operate on the
// lenient-valid set version.ParseLenient admits (out-of-grammar tags are
// tolerated for display parity, trust shapes fail closed — maintainer
// decision 2026-07-07).

// plainTags enumerates the repository's raw tags.
func plainTags(repoPath string) ([]string, error) {
	return vcs.Tags(repoPath)
}

// warnRejected surfaces the invalid-tag count on stderr — lenient filtering
// is allowed in plain mode, silent dropping is not (audit §5.2).
func warnRejected(cmd *cobra.Command, rejected int) error {
	if rejected == 0 {
		return nil
	}
	_, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d invalid tag(s) ignored\n", rejected)
	return err
}

// incrementFlags registers the donor's increment flag set on cmd. The bare
// forms `-i` and `-d` take the donor's defaults (patch, 0.0.0); values attach
// with `=` (e.g. -i=preminor), exactly as the donor parsed them.
func incrementFlags(cmd *cobra.Command, incr, preid, defv *string) {
	f := cmd.Flags()
	f.StringVarP(incr, "increment", "i", "patch",
		"increment level: major, minor, patch, premajor, preminor, prepatch, or prerelease (use -i=level)")
	cmd.Flag("increment").NoOptDefVal = "patch"
	f.StringVar(preid, "preid", "",
		"identifier prefixing premajor, preminor, prepatch, or prerelease increments")
	f.StringVarP(defv, "default", "d", "",
		"seed version to add as a candidate when set (bare -d seeds 0.0.0)")
	cmd.Flag("default").NoOptDefVal = "0.0.0"
}

// plainCandidates builds the lenient-valid candidate set for latest/next: the
// repository's tags plus the --default seed when one was given (the donor
// seeded the default into the list, so it participates in precedence rather
// than only backstopping an empty repository).
func plainCandidates(repoPath, defv string) (valid []version.Lenient, rejected int, err error) {
	tags, err := plainTags(repoPath)
	if err != nil {
		return nil, 0, err
	}
	valid, rejected = plain.Valid(tags)
	if defv != "" {
		seed, err := version.ParseLenient(defv)
		if err != nil {
			return nil, 0, fmt.Errorf("--default %q: %w", defv, err)
		}
		valid = append(valid, seed)
	}
	return valid, rejected, nil
}

func newListCmd() *cobra.Command {
	var repoPath string
	var strict bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the repository's tags as versions (zero configuration)",
		Long: `list enumerates the repository's git tags and prints each with its parsed
form, sorted ascending by SemVer precedence. The default view is lenient
(donor parity): short and v-less forms are coerced (2.1 -> 2.1.0), build
metadata is tolerated and flagged as out of grammar (§7.1), and invalid tags —
including malformed trust shapes, which fail closed — are listed with their
reason rather than silently dropped. --strict shows only §7.1-valid tags.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tags, err := plainTags(repoPath)
			if err != nil {
				return err
			}
			entries := plain.Classify(tags)
			plain.SortEntries(entries)

			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 0, 2, ' ', 0)
			et := &errWriter{w: tw}

			if strict {
				rejected := 0
				for _, e := range entries {
					if e.Err != nil || e.Val.Coerced {
						rejected++
						continue
					}
					et.printf("%s\t%s\n", e.Val.Version, e.Val.Version.Kind())
				}
				if et.err != nil {
					return et.err
				}
				if err := tw.Flush(); err != nil {
					return err
				}
				return warnRejected(cmd, rejected)
			}

			for _, e := range entries {
				et.printf("%s\n", strings.Join(listRow(e), "\t"))
			}
			if et.err != nil {
				return et.err
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", ".", "repository whose tags to list")
	cmd.Flags().BoolVar(&strict, "strict", false, "only §7.1-valid tags, in canonical tag form")
	return cmd
}

// listRow renders one classified tag: parsed form, raw tag, and a note
// flagging coercion, out-of-grammar build metadata, or invalidity.
func listRow(e plain.Entry) []string {
	if e.Err != nil {
		reason := e.Err.Error()
		var pe *version.ParseError
		if errors.As(e.Err, &pe) {
			reason = pe.Reason // the raw tag already has its own column
		}
		return []string{"-", e.Raw, "invalid: " + reason}
	}
	switch {
	case len(e.Val.Build) > 0:
		return []string{e.Val.Canonical(), e.Raw, "coerced (build metadata, out of grammar §7.1)"}
	case e.Val.Coerced:
		return []string{e.Val.Canonical(), e.Raw, "coerced"}
	default:
		return []string{e.Val.Canonical(), e.Raw}
	}
}

func newLatestCmd() *cobra.Command {
	var repoPath string
	cmd := &cobra.Command{
		Use:   "latest",
		Short: "Print the highest version among the repository's tags (zero configuration)",
		Long: `latest picks the SemVer-precedence maximum of the lenient-valid tag set the
donor accepted. Trust-suffixed tags participate in the selection (a trust
pre-release above every clean tag IS the repository's newest release); invalid
tags are ignored with a count on stderr, never silently.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			valid, rejected, err := plainCandidates(repoPath, "")
			if err != nil {
				return err
			}
			if err := warnRejected(cmd, rejected); err != nil {
				return err
			}
			latest, err := plain.Latest(valid)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), latest.Canonical())
			return err
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", ".", "repository whose tags to inspect")
	return cmd
}

func newNextCmd() *cobra.Command {
	var repoPath, incr, preid, defv string
	cmd := &cobra.Command{
		Use:   "next",
		Short: "Print the version that follows the latest tag (zero configuration)",
		Long: `next increments the latest lenient-valid version by the given level with
node-semver semantics (the donor's increment). A repository with no valid
tags bootstraps from 0.0.0, so a fresh repo's first patch bump is 0.0.1;
--default seeds a different candidate. A trust-suffixed latest is refused
with guidance — a trust re-cut is a release operation (§7.2), not a bump.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			next, err := computeNext(cmd, repoPath, incr, preid, defv)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), version.Lenient{Version: next}.Canonical())
			return err
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", ".", "repository whose tags to inspect")
	incrementFlags(cmd, &incr, &preid, &defv)
	return cmd
}

// computeNext runs the shared next-version pipeline for `next` and `tag`.
func computeNext(cmd *cobra.Command, repoPath, incr, preid, defv string) (version.Version, error) {
	rt, err := version.ToReleaseType(incr)
	if err != nil {
		return version.Version{}, fmt.Errorf("--increment %q: %w", incr, err)
	}
	valid, rejected, err := plainCandidates(repoPath, defv)
	if err != nil {
		return version.Version{}, err
	}
	if err := warnRejected(cmd, rejected); err != nil {
		return version.Version{}, err
	}
	return plain.Next(valid, rt, preid)
}

func newTagCmd() *cobra.Command {
	var repoPath, incr, preid, defv, message, taggerName, taggerEmail string
	cmd := &cobra.Command{
		Use:   "tag [name]",
		Short: "Create an annotated tag at HEAD: the given name or the computed next version",
		Long: `tag creates an annotated tag at HEAD (zero configuration; unsigned — signed
release tags are the release command's job). With a name argument the
tag is created verbatim after validation: §7.1-valid tags and the lenient
plain forms the donor accepted are allowed; malformed trust shapes and other
invalid names are refused (§7.1 fails closed). Without a name the next
version is computed exactly like ` + "`next`" + ` and written in canonical §7.1 form
(v-prefixed). The tagger comes from git config unless overridden.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var name string
			if len(args) == 1 {
				name = args[0]
				if _, err := version.ParseLenient(name); err != nil {
					return fmt.Errorf("refusing to create tag: %w", err)
				}
			} else {
				next, err := computeNext(cmd, repoPath, incr, preid, defv)
				if err != nil {
					return err
				}
				name = next.String()
			}

			tn, te := taggerName, taggerEmail
			if tn == "" || te == "" {
				gn, ge, err := vcs.Tagger(repoPath)
				if err != nil {
					return err
				}
				if tn == "" {
					tn = gn
				}
				if te == "" {
					te = ge
				}
			}
			msg := message
			if msg == "" {
				msg = name
			}

			// The clock is read once, here at the process boundary, and
			// injected (ADR-018 keeps internal/* free of time.Now).
			if err := vcs.CreateTagAtHead(repoPath, name, tn, te, msg, time.Now()); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), name)
			return err
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", ".", "repository to tag")
	cmd.Flags().StringVarP(&message, "message", "m", "", "annotation message (default: the tag name)")
	cmd.Flags().StringVar(&taggerName, "tagger-name", "", "tagger name (default: git config user.name)")
	cmd.Flags().StringVar(&taggerEmail, "tagger-email", "", "tagger email (default: git config user.email)")
	incrementFlags(cmd, &incr, &preid, &defv)
	return cmd
}
