package signingaudit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestProcessChild runs only in a test-owned subprocess with explicit synthetic
// paths. Its signer stages real bytes after durable intent and then stalls.
func TestProcessChild(t *testing.T) {
	if os.Getenv("SIGNINGAUDIT_CHILD") != "1" {
		return
	}
	dir, stage := os.Getenv("SIGNINGAUDIT_DIR"), os.Getenv("SIGNINGAUDIT_STAGE")
	p := &faultProfile{}
	trust := &fakeTrust{}
	effects := &fakeEffects{t: t, dir: stage, journal: dir, profile: p}
	staller := &stallSigner{effects: effects}
	a, err := Open(dir, Options{Durability: p, MaxBytes: 1 << 20}, trust, staller, effects)
	if err != nil {
		t.Fatal(err)
	}
	op, err := a.Accept(request(), inputs())
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Run(context.Background(), op.ID)
	t.Fatalf("child unexpectedly resumed: %v", err)
}

type stallSigner struct{ effects *fakeEffects }

func (s *stallSigner) Sign(ctx context.Context, op Operation) (Signed, error) {
	signed, err := s.effects.Sign(ctx, op)
	if err != nil {
		return Signed{}, err
	}
	fmt.Fprintln(os.Stdout, "staged")
	// A timer keeps the helper bounded even without the parent's kill control.
	select {
	case <-ctx.Done():
		return Signed{}, ctx.Err()
	case <-time.After(8 * time.Second):
		return signed, errFixture
	}
}

func TestProcessKillRetainsIntentAndRecoversWithoutSigning(t *testing.T) {
	f := newFixture(t)
	closeFixture(t, f)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestProcessChild$", "-test.timeout=10s")
	cmd.Env = []string{"SIGNINGAUDIT_CHILD=1", "SIGNINGAUDIT_DIR=" + f.dir, "SIGNINGAUDIT_STAGE=" + f.effects.dir, "TMPDIR=" + os.TempDir()}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "staged\n" {
		t.Fatalf("child did not reach real staging: %q %v", line, err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("kill returned success")
	}
	if ctx.Err() != nil {
		t.Fatal("subprocess control timed out")
	}
	f.reopen(t)
	op, err := f.a.Inspect(request().Caller, request().RequestID)
	if err != nil || op.State != Uncertain {
		t.Fatalf("lost interrupted operation: %+v %v", op, err)
	}
	if _, err = os.Stat(filepath.Join(f.effects.dir, op.ID)); err != nil {
		t.Fatal("child did not stage", err)
	}
	retry, err := f.a.Accept(request(), inputs())
	if err != nil || retry.ID != op.ID || retry.State != Uncertain {
		t.Fatal("retry lost interrupted operation")
	}
	_, err = f.a.Run(context.Background(), op.ID)
	wantErr(t, err, ErrUncertain)
	recovered, err := f.a.Reconcile(context.Background(), op.ID, f.effects)
	if err != nil || recovered.State != Succeeded {
		t.Fatal("reconcile failed", err)
	}
	if err = f.a.Fetch(context.Background(), op.Request.Caller, op.ID); err != nil {
		t.Fatal(err)
	}
	if f.effects.signs.Load() != 0 || f.effects.releases.Load() != 1 {
		t.Fatal("restart signed again")
	}
}
