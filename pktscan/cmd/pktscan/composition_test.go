package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-services/pktscan/packetwalk"
)

func assertRefused(t *testing.T, d, p, base string, want error) {
	t.Helper()
	got, e := scan(d, p, base)
	if e != want || got != (result{}) {
		t.Fatal("refusal contract failed")
	}
	var out, diag bytes.Buffer
	args := []string{d, "--patterns", p}
	if base != "" {
		args = append(args, "--known-base", base)
	}
	if run(args, &out, &diag) != 1 || out.Len() != 0 || diag.String() != "pktscan: "+want.Error()+"\n" {
		t.Fatal("refusal disclosed input or partial counts")
	}
	if _, e = os.Lstat(filepath.Join(d, outputDir)); !os.IsNotExist(e) {
		t.Fatal("refusal left output")
	}
}

func TestComposedNestedSecretsAndPositiveNeighbor(t *testing.T) {
	for _, outer := range []string{"zip", "tgz"} {
		for _, data := range []string{`{"nested":{"token":"SYNTHETIC"}}`, `{"nested":{"token":""},"note":"TOKEN"}`, `{"nested":`, `{"token":null} trailing`, "gh" + "p_" + strings.Repeat("0", 36), "SYNTHETIC\x00"} {
			d, p := setup(t)
			inner := makeArchive(t, "tgz", []member{{name: "note.json", data: data}})
			put(t, filepath.Join(d, "packet."+outer), makeArchive(t, outer, []member{{name: "inner.tgz", data: string(inner)}}))
			base := filepath.Join(d, "known")
			put(t, base, []byte("packet."+outer+"/inner.tgz/note.json\x00"))
			if data == `{"nested":{"token":""},"note":"TOKEN"}` {
				r, e := scan(d, p, base)
				if e != nil || r.Known.Files != 1 || r.Known.HitLines != 1 || r.New.Files != 0 || r.Traversal.Containers != 2 || r.Secrets.Blocking() {
					t.Fatal("valid nested neighbor failed")
				}
				continue
			}
			want := errClassify
			if strings.Contains(data, "SYNTHETIC\x00") {
				want = errInput
			} else if strings.Contains(data, "SYNTHETIC") {
				want = errSecret
			}
			assertRefused(t, d, p, base, want)
		}
	}
}

func TestSecretShapesIgnorePatchAndKnownBaseExemptions(t *testing.T) {
	d, p := setup(t)
	marker := "gh" + "p_" + strings.Repeat("0", 36)
	put(t, filepath.Join(d, "change.patch"), []byte("--- "+marker+"\n+++ clean\n@@ -1 +1 @@\n-"+marker+"\n+clean\n"))
	base := filepath.Join(d, "known")
	put(t, base, []byte("change.patch\x00"))
	assertRefused(t, d, p, base, errSecret)
}

func TestSecretPathsAndControlAliases(t *testing.T) {
	marker := "gh" + "p_" + strings.Repeat("0", 36)
	for _, which := range []string{"empty-directory", "empty-archive", "archive-directory", "pattern-alias", "known-list", "jsonl", "binary", "malformed-json"} {
		d, p := setup(t)
		base := ""
		switch which {
		case "empty-directory":
			if os.Mkdir(filepath.Join(d, marker), 0700) != nil {
				t.Fatal("fixture failed")
			}
		case "empty-archive":
			put(t, filepath.Join(d, marker+".zip"), makeArchive(t, "zip", nil))
		case "archive-directory":
			put(t, filepath.Join(d, "packet.zip"), makeArchive(t, "zip", []member{{name: marker + "/", mode: os.ModeDir | 0700}}))
		case "pattern-alias":
			put(t, p, []byte(marker+"\n"))
			if os.Link(p, filepath.Join(d, "alias")) != nil {
				t.Fatal("fixture failed")
			}
		case "known-list":
			base = filepath.Join(d, "known")
			put(t, base, []byte(marker+"\x00"))
		case "jsonl":
			put(t, filepath.Join(d, "note.jsonl"), []byte("{}\n{}\n"))
		case "binary":
			put(t, filepath.Join(d, "note"), []byte{0xff})
		case "malformed-json":
			put(t, filepath.Join(d, "note.json"), []byte("false trailing"))
		}
		want := errSecret
		if which == "jsonl" || which == "malformed-json" {
			want = errClassify
		}
		if which == "binary" {
			want = errInput
		}
		assertRefused(t, d, p, base, want)
	}
	// A control outside the packet is excluded from packet classification.
	d, p := setup(t)
	outside := filepath.Join(t.TempDir(), "patterns")
	put(t, outside, []byte(marker+"\n"))
	os.Remove(p)
	put(t, filepath.Join(d, "note"), []byte("safe"))
	if _, e := scan(d, outside, ""); e != nil {
		t.Fatal("external control incorrectly classified as packet")
	}
}

func TestCumulativeCLICapsAndNoPartialOutput(t *testing.T) {
	inner := makeArchive(t, "tgz", []member{{name: "leaf", data: "TOKEN\n"}})
	packet := makeArchive(t, "zip", []member{{name: "one.tgz", data: string(inner)}, {name: "two.tgz", data: string(inner)}})
	for _, flags := range [][]string{{"--max-depth", "1"}, {"--max-containers", "2"}, {"--max-files", "3"}, {"--max-entries", "3"}, {"--max-compressed-bytes", "1"}, {"--max-expanded-bytes", "1"}, {"--max-stream-bytes", "1"}, {"--timeout", "1ns"}} {
		d, p := setup(t)
		put(t, filepath.Join(d, "packet.zip"), packet)
		for attempt := 0; attempt < 2; attempt++ {
			var out, diag bytes.Buffer
			args := append([]string{d, "--patterns", p}, flags...)
			if run(args, &out, &diag) != 1 || out.Len() != 0 || diag.String() != "pktscan: limit exceeded\n" {
				t.Fatal("cumulative cap not deterministic")
			}
			if _, e := os.Lstat(filepath.Join(d, outputDir)); !os.IsNotExist(e) {
				t.Fatal("limit left output")
			}
		}
	}
}

func TestArchiveMetadataSecretAndOpaqueRefusals(t *testing.T) {
	marker := "gh" + "p_" + strings.Repeat("0", 36)
	for _, which := range []string{"gzip-name", "gzip-extra", "zip-extra", "tar-padding"} {
		d, p := setup(t)
		var packet []byte
		name := "packet.tgz"
		want := errArchive
		switch which {
		case "gzip-name", "gzip-extra":
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			if which == "gzip-name" {
				gz.Name = marker
				want = errSecret
			} else {
				gz.Extra = []byte("SYNTHETIC")
			}
			gz.Write(makeArchive(t, "tar", []member{{name: "note", data: "safe"}}))
			gz.Close()
			packet = b.Bytes()
		case "zip-extra":
			name = "packet.zip"
			var b bytes.Buffer
			z := zip.NewWriter(&b)
			w, e := z.CreateHeader(&zip.FileHeader{Name: "note", Extra: []byte{1, 0, 1, 0, 'x'}})
			if e != nil {
				t.Fatal("fixture failed")
			}
			w.Write([]byte("safe"))
			z.Close()
			packet = b.Bytes()
		case "tar-padding":
			name = "packet.tar"
			packet = makeArchive(t, "tar", []member{{name: "note", data: "safe"}})
			packet[512+4] = 'x'
		}
		put(t, filepath.Join(d, name), packet)
		assertRefused(t, d, p, "", want)
	}
}

func fixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("/usr/bin/git", args...)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z"}
	out, e := cmd.Output()
	if e != nil {
		t.Fatal("synthetic git fixture failed")
	}
	return strings.TrimSpace(string(out))
}
func fixtureCommit(t *testing.T, dir, name, body string) string {
	t.Helper()
	put(t, filepath.Join(dir, name), []byte(body))
	fixtureGit(t, dir, "add", "--all")
	fixtureGit(t, dir, "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "synthetic")
	return fixtureGit(t, dir, "rev-parse", "HEAD")
}
func fixtureBundle(t *testing.T, repo, dest string, revs ...string) {
	t.Helper()
	fixtureGit(t, repo, append([]string{"bundle", "create", "--version=2", dest}, revs...)...)
}

func TestCLINestedBundleDeltaScopeAndSecretCrossing(t *testing.T) {
	for _, which := range []string{"valid-delta", "secret-delta", "malformed-json", "jsonl", "nested-secret", "nested-safe", "missing-base", "missing-current", "wrong-scope", "command-limit", "output-limit", "baseline-in-packet"} {
		t.Run(which, func(t *testing.T) {
			repo := t.TempDir()
			fixtureGit(t, repo, "init", "--template=", ".")
			// Explicit baseline scope excludes this old blob; it is never declared safe.
			base := fixtureCommit(t, repo, "old.json", `{"secret":"SYNTHETIC"}`)
			control := t.TempDir()
			baseline := filepath.Join(control, "base.bundle")
			fixtureBundle(t, repo, baseline, "HEAD")
			body := "TOKEN\n"
			name := "next.txt"
			switch which {
			case "secret-delta":
				name = "next.json"
				body = `{"secret":"SYNTHETIC-current"}`
			case "malformed-json":
				name = "next.json"
				body = "false trailing"
			case "jsonl":
				name = "next.jsonl"
				body = "{}\n{}\n"
			case "nested-secret":
				name = "nested.zip"
				body = string(makeArchive(t, "zip", []member{{name: "note.json", data: `{"token":"SYNTHETIC"}`}}))
			case "nested-safe":
				name = "nested.zip"
				body = string(makeArchive(t, "zip", []member{{name: "note.json", data: `{"token":"","note":"TOKEN"}`}}))
			}
			current := fixtureCommit(t, repo, name, body)
			thin := filepath.Join(control, "thin.bundle")
			fixtureBundle(t, repo, thin, "HEAD", "^"+base)
			raw, e := os.ReadFile(thin)
			if e != nil {
				t.Fatal("fixture failed")
			}
			d, p := setup(t)
			put(t, filepath.Join(d, "packet.zip"), makeArchive(t, "zip", []member{{name: "delta.bundle", data: string(raw)}}))
			args := []string{d, "--patterns", p, "--bundle-path", "packet.zip/delta.bundle", "--current", current, "--base", base, "--base-bundle", baseline}
			switch which {
			case "missing-base":
				args = args[:len(args)-4]
			case "missing-current":
				args = []string{d, "--patterns", p}
			case "wrong-scope":
				args[4] = "other.bundle"
			case "command-limit":
				args = append(args, "--max-commands", "1")
			case "output-limit":
				args = append(args, "--max-command-bytes", "1")
			case "baseline-in-packet":
				raw, e = os.ReadFile(baseline)
				if e != nil {
					t.Fatal("fixture failed")
				}
				baseline = filepath.Join(d, "base.bundle")
				put(t, baseline, raw)
				args[len(args)-1] = baseline
			}
			var out, diag bytes.Buffer
			code := run(args, &out, &diag)
			if which == "valid-delta" || which == "nested-safe" {
				var r result
				if code != 0 || diag.Len() != 0 || json.Unmarshal(out.Bytes(), &r) != nil || r.Objects.Files != 1 || r.Objects.HitFiles != 1 || r.New.Files != 0 || r.Traversal.GitBaseObjects == 0 || r.Traversal.GitDeltaObjects == 0 {
					t.Fatal("CLI bundle positive contract failed")
				}
			} else {
				if code != 1 || out.Len() != 0 || !strings.HasPrefix(diag.String(), "pktscan: ") || strings.Contains(diag.String(), "SYNTHETIC") {
					t.Fatal("CLI bundle refusal contract failed")
				}
				if _, e := os.Lstat(filepath.Join(d, outputDir)); !os.IsNotExist(e) {
					t.Fatal("bundle refusal left output")
				}
			}
		})
	}
}

func TestSandboxAndDependencyContract(t *testing.T) {
	if _, e := os.Stat("/home"); !os.IsNotExist(e) {
		t.Fatal("host home exposed")
	}
	if os.Getenv("SSH_AUTH_SOCK") != "" || os.Getenv("GOPROXY") != "off" || os.Getenv("GOTOOLCHAIN") != "local" {
		t.Fatal("unsafe environment")
	}
	for _, key := range []string{"HOME", "TMPDIR", "XDG_CACHE_HOME", "GOMODCACHE"} {
		p := os.Getenv(key)
		i, e := os.Stat(p)
		if !filepath.IsAbs(p) || e != nil || !i.IsDir() || i.Mode().Perm() != 0700 {
			t.Fatal("private directory contract failed")
		}
	}
	if packetwalk.DefaultLimits().Duration <= 0 {
		t.Fatal("missing invocation bound")
	}
}

func TestEmptyKnownControlUsesDeclaredNULFormat(t *testing.T) {
	d, p := setup(t)
	base := filepath.Join(d, "control.json")
	put(t, base, nil)
	put(t, filepath.Join(d, "note"), []byte("TOKEN"))
	if os.Link(base, filepath.Join(d, "control-alias")) != nil {
		t.Fatal("fixture failed")
	}
	r, e := scan(d, p, base)
	if e != nil || r.New.Files != 1 || r.New.HitLines != 1 {
		t.Fatal("empty NUL-list control format lost")
	}
}

func TestBundlePolicyMustBeConsumedAndTmpOutsidePacket(t *testing.T) {
	d, p := setup(t)
	put(t, filepath.Join(d, "note"), []byte("TOKEN"))
	var out, diag bytes.Buffer
	args := []string{d, "--patterns", p, "--bundle-path", "missing.bundle", "--current", strings.Repeat("0", 40)}
	if run(args, &out, &diag) != 1 || out.Len() != 0 || diag.String() != "pktscan: bundle refused\n" {
		t.Fatal("unused bundle policy accepted")
	}
	t.Setenv("TMPDIR", d)
	assertRefused(t, d, p, "", errOutput)
}

func TestExactNestedBudgetsAndInvalidFlags(t *testing.T) {
	inner := makeArchive(t, "tgz", []member{{name: "leaf", data: "TOKEN\n"}})
	packet := makeArchive(t, "zip", []member{{name: "one.tgz", data: string(inner)}, {name: "two.tgz", data: string(inner)}})
	d, p := setup(t)
	put(t, filepath.Join(d, "packet.zip"), packet)
	args := []string{d, "--patterns", p, "--max-depth", "2", "--max-files", "5", "--max-entries", "6", "--max-containers", "3"}
	var out, diag bytes.Buffer
	if run(args, &out, &diag) != 0 || diag.Len() != 0 {
		t.Fatal("exact valid cap neighbor refused")
	}
	var r result
	if json.Unmarshal(out.Bytes(), &r) != nil || r.New.Files != 2 || r.New.HitLines != 2 || r.Traversal.Containers != 3 || r.Traversal.Files != 5 || r.Traversal.Entries != 6 {
		t.Fatal("nested cumulative accounting changed")
	}
	for _, flags := range [][]string{{"--max-depth", "0"}, {"--max-files", "-1"}, {"--max-file-bytes", "16777217"}, {"--max-entries", "131073"}, {"--max-containers", "1025"}, {"--max-commands", "65537"}, {"--max-expanded-bytes", "1073741825"}, {"--timeout", "6m"}} {
		out.Reset()
		diag.Reset()
		if run(append([]string{d, "--patterns", p}, flags...), &out, &diag) != 2 || out.Len() != 0 || diag.String() != "pktscan: invalid arguments\n" {
			t.Fatal("invalid cap accepted or disclosed")
		}
	}
}

func TestCLIFullBundleBlockingAndDeltaExclusion(t *testing.T) {
	for _, blocking := range []bool{false, true} {
		repo := t.TempDir()
		fixtureGit(t, repo, "init", "--template=", ".")
		data := `{"token":"","note":"TOKEN"}`
		if blocking {
			data = `{"token":"SYNTHETIC"}`
		}
		current := fixtureCommit(t, repo, "note.json", data)
		bundle := filepath.Join(t.TempDir(), "full.bundle")
		fixtureBundle(t, repo, bundle, "HEAD")
		raw, e := os.ReadFile(bundle)
		if e != nil {
			t.Fatal("fixture failed")
		}
		d, p := setup(t)
		put(t, filepath.Join(d, "source.bundle"), raw)
		var out, diag bytes.Buffer
		code := run([]string{d, "--patterns", p, "--bundle-path", "source.bundle", "--current", current}, &out, &diag)
		if blocking {
			if code != 1 || out.Len() != 0 || diag.String() != "pktscan: blocking secret class refused\n" {
				t.Fatal("full closure secret missed")
			}
		} else {
			var r result
			if code != 0 || diag.Len() != 0 || json.Unmarshal(out.Bytes(), &r) != nil || r.Objects.Files != 1 || r.Objects.HitLines != 1 || r.BaselineExcluded || r.Traversal.GitBaseObjects != 0 {
				t.Fatal("full closure positive contract failed")
			}
		}
	}
}
