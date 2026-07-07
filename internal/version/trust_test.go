// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestNextIteration(t *testing.T) {
	v := mustParse(t, "auth/v1.4.0-t1.1")
	got, err := v.NextIteration()
	if err != nil {
		t.Fatalf("NextIteration: %v", err)
	}
	if s := got.String(); s != "auth/v1.4.0-t1.2" {
		t.Errorf("NextIteration = %q, want auth/v1.4.0-t1.2", s)
	}
	// The receiver is unchanged (values are immutable after Parse).
	if s := v.String(); s != "auth/v1.4.0-t1.1" {
		t.Errorf("receiver mutated: %q", s)
	}
}

func TestNextIterationRequiresTrust(t *testing.T) {
	v := mustParse(t, "v1.4.0")
	if _, err := v.NextIteration(); err == nil {
		t.Error("NextIteration on clean version: want error, got nil")
	}
}

func TestWithLevel(t *testing.T) {
	// §7.2 worked example: -t0.1, fixes reviewed, re-cut at a new level → -t2.1.
	v := mustParse(t, "v1.4.0-t0.1")
	got, err := v.WithLevel(2)
	if err != nil {
		t.Fatalf("WithLevel: %v", err)
	}
	if s := got.String(); s != "v1.4.0-t2.1" {
		t.Errorf("WithLevel(2) = %q, want v1.4.0-t2.1", s)
	}
}

func TestWithLevelFromClean(t *testing.T) {
	v := mustParse(t, "pkg/common/v0.9.0")
	got, err := v.WithLevel(3)
	if err != nil {
		t.Fatalf("WithLevel: %v", err)
	}
	if s := got.String(); s != "pkg/common/v0.9.0-t3.1" {
		t.Errorf("WithLevel(3) = %q, want pkg/common/v0.9.0-t3.1", s)
	}
}

func TestWithLevelClearsPlainPrerelease(t *testing.T) {
	v := mustParse(t, "v1.4.0-rc.1")
	got, err := v.WithLevel(1)
	if err != nil {
		t.Fatalf("WithLevel: %v", err)
	}
	if s := got.String(); s != "v1.4.0-t1.1" {
		t.Errorf("WithLevel(1) = %q, want v1.4.0-t1.1", s)
	}
}

func TestWithLevelOutOfRange(t *testing.T) {
	v := mustParse(t, "v1.4.0")
	if _, err := v.WithLevel(4); err == nil {
		t.Error("WithLevel(4): want error, got nil")
	}
}
