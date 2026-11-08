package gate

import (
	"context"
	"testing"
)

func TestGenericLocalAndTemporaryHygiene(t *testing.T) {
	p := policy{ctx: context.Background(), exceptions: map[string]bool{}}
	for _, s := range []string{
		"machine" + ".local",
		"author Someone <member@machine" + ".local> 0 +0000",
		"/var/" + "folders/ab/synthetic/T/file",
		"/private/" + "tmp/member-1234/file",
		"/tmp/" + "member-1234/file",
		"/tmp/" + "user/1234/file",
		"time." + "Local",
		"t.In(time." + "Local)",
		"threading." + "local()",
		"this." + "local = x",
		"cp .env.example .env." + "local",
	} {
		for _, kind := range []string{"line", "message", "header"} {
			r := Report{}
			if p.match(kind, []byte(s), &r) != nil || r.HygieneHits != 1 {
				t.Fatal("generic hygiene shape missed")
			}
		}
	}
	for _, s := range []string{"local", "localization", "machine.locality", "machine.local.example", "machine.local-data", "member@example.test", "/var/tmp/shared", "/var/folders", "/private/tmp/shared", "/private/tmp/member-id/file", "/private/tmp/member-1234x/file", "/tmp/shared", "/tmp/member-id/file", "/tmp/member-1234x/file", "/tmp/user/id/file", "/tmp/user/1234x/file", "time.Locality", "threading.localized()"} {
		r := Report{}
		if p.match("header", []byte(s), &r) != nil || r.HygieneHits != 0 {
			t.Fatal("neutral neighboring shape refused")
		}
	}
}

func TestGenericLocalEmailHeaderScan(t *testing.T) {
	f := newFixture(t)
	f.candidate = signedExtraHeader(t, f, "x-fixture Someone <member@machine"+".local>")
	r, code := run(f.config())
	require(t, code == 1 && r.HygieneHits == 1 && r.Completed == 1 && r.PrivateHits == 0, r, code)
}
