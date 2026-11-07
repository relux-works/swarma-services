package keylessexecutor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/keyvaultinput"
)

// stepRunner is private controller plumbing, not a caller-provided native
// qualification. Its sole current implementation lives in offline controls.
// An eventual native implementation must independently admit the whole process
// domain (including synchronous Prepare/PlanInput), CPU/RSS/process enforcement,
// actual protected source qualification, tool closure and readonly mounts.
// No production path constructs a runner in this source-only slice.
type stepRunner interface {
	run(context.Context, string, int, *state, keyvaultinput.Command) ([]byte, error)
}
type controller struct {
	slot   chan struct{}
	limits Limits
}

func newController() *controller {
	return &controller{slot: make(chan struct{}, 1), limits: ProposedLimits()}
}

type outcome struct {
	SHA256      string
	Bytes       uint64
	CleanBuilds int
	Synthetic   bool
}

// exercise runs the source lifecycle using a private source-control runner.
// Every error joins cleanup failure; equality is reported only after cleanup.
// The containing worker owns the whole-job process limit, including preparation.
func (c *controller) exercise(ctx context.Context, parent string, p *Plan, r stepRunner) (out outcome, err error) {
	if c == nil || p == nil || r == nil {
		return out, ErrInput
	}
	select {
	case c.slot <- struct{}{}:
		defer func() { <-c.slot }()
	default:
		return out, ErrLimit
	}
	// Reserve termination/cleanup inside the original whole-job budget.
	// The supervisor starts that budget before synchronous input verification.
	if c.limits.WholeJob <= c.limits.Termination {
		return out, ErrLimit
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.WholeJob-c.limits.Termination)
	defer cancel()
	var artifact []byte
	var logTotal uint64
	out.Synthetic = true
	for n := 0; n < 2; n++ {
		if err = ctx.Err(); err != nil {
			return outcome{}, err
		}
		// One absolute deadline covers allocation, graph and compilation together.
		buildCtx, stop := context.WithTimeout(ctx, c.limits.EachBuild)
		s, e := materialize(buildCtx, parent, p)
		if e != nil {
			stop()
			return outcome{}, e
		}
		runErr := func() error {
			graph, e := r.run(buildCtx, "graph", n, s, p.GraphCommand())
			if e != nil {
				return e
			}
			if uint64(len(graph)) > c.limits.LogBytes-logTotal {
				return ErrLimit
			}
			logTotal += uint64(len(graph))
			if e = CheckGraph(graph); e != nil {
				return e
			}
			if e = buildCtx.Err(); e != nil {
				return e
			}
			log, e := r.run(buildCtx, "build", n, s, p.BuildCommand())
			if e != nil {
				return e
			}
			if uint64(len(log)) > c.limits.LogBytes-logTotal {
				return ErrLimit
			}
			logTotal += uint64(len(log))
			if e = buildCtx.Err(); e != nil {
				return e
			}
			name := filepath.Join(s.root, "out", "mac-keyvault")
			li, e := os.Lstat(name)
			if e != nil || !li.Mode().IsRegular() {
				return ErrWorker
			}
			f, e := openArtifact(name)
			if e != nil {
				return ErrWorker
			}
			defer f.Close()
			i, e := f.Stat()
			if e != nil || !i.Mode().IsRegular() || i.Size() <= 0 || uint64(i.Size()) > c.limits.ArtifactBytes {
				return ErrLimit
			}
			// Lstat rejects a symlink even if its destination is a regular file.
			li, e = os.Lstat(name)
			if e != nil || !li.Mode().IsRegular() || !os.SameFile(i, li) {
				return ErrWorker
			}
			b, e := io.ReadAll(io.LimitReader(f, int64(c.limits.ArtifactBytes)+1))
			if e != nil {
				return ErrWorker
			}
			if len(b) == 0 || uint64(len(b)) > c.limits.ArtifactBytes {
				return ErrLimit
			}
			if n == 0 {
				artifact = b
			} else if !bytes.Equal(artifact, b) {
				return ErrUnequal
			}
			return buildCtx.Err()
		}()
		stop()
		cleanupErr := s.cleanup()
		if runErr != nil || cleanupErr != nil {
			return outcome{}, errors.Join(runErr, cleanupErr)
		}
		out.CleanBuilds++
	}
	if err = ctx.Err(); err != nil {
		return outcome{}, err
	}
	out.SHA256 = sum(artifact)
	out.Bytes = uint64(len(artifact))
	return out, nil
}

// WholeJobDeadline is the original finite job budget, never a renewable lease.
// A supervisor starts it before synchronous input verification in its child.
func WholeJobDeadline(accepted time.Time) time.Time { return accepted.Add(ProposedLimits().WholeJob) }
