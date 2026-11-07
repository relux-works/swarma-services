// durability-check exercises the real journal with one explicit native profile
// and synthetic effect callbacks. It never builds, signs or releases artifacts.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-services/signer/internal/nativedurability"
	"github.com/relux-works/swarma-services/signer/internal/signingaudit"
)

var (
	errOmitted   = errors.New("injected_sync_omission")
	errCleanup   = errors.New("injected_cleanup_unknown")
	errClose     = errors.New("injected_close_failure")
	errRelease   = errors.New("injected_partial_release")
	errInvariant = errors.New("control_invariant_failed")
)

var controls = []string{"baseline", "open-file-error", "open-directory-error", "directory-omit", "accepted-error", "accepted-omit", "intent-error", "intent-omit", "outcome-error", "outcome-omit", "unsupported", "cleanup-refusal", "ambiguous-release", "close-error"}

type event struct {
	Boundary  string `json:"boundary"`
	Attempted bool   `json:"profile_call_attempted"`
	Completed bool   `json:"completed"`
	Error     string `json:"error,omitempty"`
	Errno     uint64 `json:"errno,omitempty"`
}

type result struct {
	Control         string                    `json:"control"`
	StartedAt       string                    `json:"started_at"`
	FinishedAt      string                    `json:"finished_at"`
	Fixture         string                    `json:"retained_fixture,omitempty"`
	Profile         string                    `json:"profile"`
	ProfileSelected bool                      `json:"profile_selected"`
	Target          *nativedurability.Binding `json:"observed_target,omitempty"`
	State           signingaudit.State        `json:"state,omitempty"`
	Signs           int                       `json:"synthetic_sign_entries"`
	Releases        int                       `json:"synthetic_release_entries"`
	Events          []event                   `json:"boundaries"`
	Error           string                    `json:"operation_error,omitempty"`
	CleanupError    string                    `json:"cleanup_error,omitempty"`
	EffectError     string                    `json:"synthetic_effect_error,omitempty"`
	ControlVerified bool                      `json:"control_verified"`
	Failures        []failure                 `json:"failures,omitempty"`
}

type failure struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
	Errno uint64 `json:"errno,omitempty"`
}

type profileFactory func(*os.File, uint64) (signingaudit.Durability, error)

func main() {
	root := flag.String("root", "", "existing protected absolute 0700 fixture root on the intended APFS volume")
	device := flag.Uint64("device", 0, "explicit actual st_dev pin from the planned native sitting")
	control := flag.String("control", "", "suite or an explicit control (see native durability documentation)")
	flag.Parse()
	if flag.NArg() != 0 || !validConfig(*root, *device, *control) {
		fmt.Fprintln(os.Stderr, "invalid explicit root/device/control")
		os.Exit(2)
	}
	// A context cannot cancel a blocked filesystem syscall. Process exit bounds
	// this source runner; a watchdog exit leaves cleanup UNKNOWN, not qualified.
	timer := time.AfterFunc(120*time.Second, func() {
		fmt.Fprintln(os.Stderr, `{"status":"watchdog_expired","cleanup":"unknown","native_powerloss_proved":false}`)
		os.Exit(124)
	})
	factory := func(f *os.File, d uint64) (signingaudit.Durability, error) { return nativedurability.New(f, d) }
	selected := []string{*control}
	if *control == "suite" {
		selected = controls
	}
	results := make([]result, 0, len(selected))
	passed := true
	for _, c := range selected {
		r := runCase(*root, *device, c, factory)
		results = append(results, r)
		if !r.ControlVerified {
			passed = false
			break
		}
	}
	timer.Stop()
	out := struct {
		Schema                string   `json:"schema"`
		SyntheticEffects      bool     `json:"synthetic_effects"`
		NativePowerlossProved bool     `json:"native_powerloss_proved"`
		ProductionAdmitted    bool     `json:"production_admitted"`
		Results               []result `json:"results"`
	}{"native-durability-check/1", true, false, false, results}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(1)
	}
	if !passed {
		os.Exit(1)
	}
}

func validConfig(root string, device uint64, control string) bool {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || device == 0 {
		return false
	}
	if control == "suite" {
		return true
	}
	for _, c := range controls {
		if c == control {
			return true
		}
	}
	return false
}

// All fixture bytes are retained, including after failure. Cleanup closes
// descriptors/locks only; it never prunes audit, artifacts or idempotency state.
func runCase(root string, device uint64, control string, factory profileFactory) (r result) {
	r.Control, r.Profile = control, nativedurability.ProfileName
	r.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	var a *signingaudit.Audit
	var parent *os.File
	var opErr error
	var cleanupErr error
	defer func() {
		if a != nil {
			cleanupErr = errors.Join(cleanupErr, a.Close())
		}
		if parent != nil {
			cleanupErr = errors.Join(cleanupErr, parent.Close())
		}
		actualCleanupErr := cleanupErr
		if control == "close-error" && a != nil {
			cleanupErr = errors.Join(cleanupErr, errClose)
		}
		r.Error, r.CleanupError = code(opErr), code(cleanupErr)
		r.Failures = appendFailures(r.Failures, "operation", opErr)
		r.Failures = appendFailures(r.Failures, "cleanup", cleanupErr)
		r.ControlVerified = matchesExpectedError(control, opErr) && cleanupErr == nil
		if control == "close-error" {
			r.ControlVerified = opErr == nil && actualCleanupErr == nil && errors.Is(cleanupErr, errClose)
		}
		if strings.HasPrefix(control, "intent-") || strings.HasPrefix(control, "accepted-") || strings.HasPrefix(control, "open-") || control == "directory-omit" || control == "unsupported" {
			r.ControlVerified = r.ControlVerified && r.Signs == 0 && r.Releases == 0
		}
		if control == "outcome-error" || control == "outcome-omit" || control == "cleanup-refusal" {
			r.ControlVerified = r.ControlVerified && r.Signs == 1 && r.Releases == 0 && r.State == signingaudit.Uncertain
		}
		if control == "baseline" || control == "ambiguous-release" || control == "close-error" {
			r.ControlVerified = r.ControlVerified && r.Signs == 1 && r.Releases == 1 && r.State == signingaudit.Succeeded
		}
		r.ControlVerified = r.ControlVerified && verifyBoundaries(control, r.Events)
		r.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}()
	before, err := os.Lstat(root)
	if err != nil {
		opErr = err
		return
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || before.Mode() != os.ModeDir|0700 {
		opErr = nativedurability.ErrDescriptor
		return
	}
	parent, err = os.Open(root)
	if err != nil {
		opErr = err
		return
	}
	after, err := parent.Stat()
	if err != nil || !os.SameFile(before, after) {
		opErr = nativedurability.ErrDescriptor
		return
	}
	base, err := factory(parent, device)
	if err != nil {
		opErr = err
		return
	}
	r.Profile = base.Name()
	r.ProfileSelected = true
	if bound, ok := base.(interface {
		Binding() nativedurability.Binding
	}); ok {
		binding := bound.Binding()
		r.Target = &binding
	}
	// Parent path ancestry remains an installed custody requirement. Recheck the
	// root before and after creation; this is not a hostile-parent sandbox.
	dir, err := os.MkdirTemp(root, "durability-")
	if err != nil {
		opErr = err
		return
	}
	r.Fixture = filepath.Base(dir)
	current, err := os.Lstat(root)
	if err != nil || !os.SameFile(after, current) {
		opErr = nativedurability.ErrDescriptor
		return
	}
	if err = base.Directory(parent); err != nil {
		opErr = err
		var errno syscall.Errno
		errors.As(err, &errno)
		r.Events = append(r.Events, event{Boundary: "fixture-parent", Attempted: true, Error: code(err), Errno: uint64(errno)})
		return
	}
	p := &observedProfile{base: base, control: control, result: &r, stage: "open"}
	effects := &syntheticEffects{profile: p, result: &r}
	a, opErr = signingaudit.Open(dir, signingaudit.Options{Durability: p, MaxBytes: 1 << 20}, effects, effects, effects)
	if opErr != nil {
		return
	}
	p.stage = "accepted"
	req, in := syntheticInput()
	op, err := a.Accept(req, in)
	if err != nil {
		opErr = err
		return
	}
	p.stage, p.runFiles = "run", 0
	op, opErr = a.Run(context.Background(), op.ID)
	r.State = op.State
	if control == "cleanup-refusal" {
		if !errors.Is(opErr, signingaudit.ErrUncertain) {
			opErr = errInvariant
			return
		}
		_, opErr = a.Reconcile(context.Background(), op.ID, effects)
		if !errors.Is(opErr, signingaudit.ErrUncertain) {
			opErr = errInvariant
			return
		}
		if _, err = a.Run(context.Background(), op.ID); !errors.Is(err, signingaudit.ErrUncertain) {
			opErr = errInvariant
			return
		}
		if err = a.Fetch(context.Background(), req.Caller, op.ID); !errors.Is(err, signingaudit.ErrUncertain) {
			opErr = errInvariant
		}
		next := req
		next.RequestID = "two"
		if _, err = a.Accept(next, in); !errors.Is(err, signingaudit.ErrBusy) {
			opErr = errInvariant
		}
		return
	}
	if opErr != nil {
		// Poisoning must prevent both release and a second signer entry.
		if _, err = a.Run(context.Background(), op.ID); !errors.Is(err, signingaudit.ErrAudit) {
			opErr = errInvariant
			return
		}
		if err = a.Fetch(context.Background(), req.Caller, op.ID); !errors.Is(err, signingaudit.ErrAudit) {
			opErr = errInvariant
		}
		return
	}
	opErr = a.Fetch(context.Background(), req.Caller, op.ID)
	if control == "ambiguous-release" {
		historical, err := a.Inspect(req.Caller, req.RequestID)
		if err != nil || historical.State != signingaudit.Succeeded || historical.Receipt != op.Receipt {
			opErr = errInvariant
		}
		if _, err = a.Run(context.Background(), op.ID); !errors.Is(err, signingaudit.ErrUncertain) {
			opErr = errInvariant
		}
	}
	return
}

type observedProfile struct {
	base            signingaudit.Durability
	control, stage  string
	runFiles        int
	intent, outcome bool
	result          *result
}

func (p *observedProfile) Name() string               { return p.base.Name() }
func (p *observedProfile) File(f *os.File) error      { return p.call(f, false) }
func (p *observedProfile) Directory(f *os.File) error { return p.call(f, true) }
func (p *observedProfile) call(f *os.File, directory bool) error {
	boundary := p.stage + "-file"
	if directory {
		boundary = p.stage + "-directory"
	}
	if !directory && p.stage == "run" {
		p.runFiles++
		if p.runFiles == 1 {
			boundary = "intent"
		} else if p.runFiles == 2 {
			boundary = "outcome"
		} else {
			return errInvariant
		}
	}
	e := event{Boundary: boundary}
	var err error
	switch {
	case p.control == "unsupported" && boundary == "open-file":
		err = syscall.ENOTSUP
	case p.control == boundary+"-error" || p.control == "accepted-error" && boundary == "accepted-file":
		err = syscall.EIO
	case p.control == boundary+"-omit" || p.control == "directory-omit" && boundary == "open-directory" || p.control == "accepted-omit" && boundary == "accepted-file":
		err = errOmitted
	default:
		e.Attempted = true
		if directory {
			err = p.base.Directory(f)
		} else {
			err = p.base.File(f)
		}
	}
	e.Completed = err == nil
	e.Error = code(err)
	var errno syscall.Errno
	if errors.As(err, &errno) {
		e.Errno = uint64(errno)
	}
	if len(p.result.Events) >= 16 {
		return errInvariant
	}
	p.result.Events = append(p.result.Events, e)
	if err == nil && boundary == "intent" {
		p.intent = true
	}
	if err == nil && boundary == "outcome" {
		p.outcome = true
	}
	return err
}

type syntheticEffects struct {
	profile *observedProfile
	result  *result
}

func (*syntheticEffects) Check(context.Context, signingaudit.Phase, signingaudit.Operation) error {
	return nil
}
func (e *syntheticEffects) Sign(_ context.Context, op signingaudit.Operation) (signingaudit.Signed, error) {
	e.result.Signs++
	if !e.profile.intent {
		return signingaudit.Signed{}, errInvariant
	}
	if e.result.Control == "cleanup-refusal" {
		e.result.EffectError = code(errCleanup)
		return signingaudit.Signed{}, errCleanup
	}
	return signingaudit.Signed{SHA256: hash("synthetic-signed"), Bytes: 1, CertificateSHA256: op.Inputs.CertificateSHA256, RequirementSHA256: op.Inputs.RequirementSHA256}, nil
}
func (*syntheticEffects) Reconcile(context.Context, signingaudit.Operation) (signingaudit.Signed, error) {
	return signingaudit.Signed{}, errCleanup
}
func (e *syntheticEffects) Verify(context.Context, signingaudit.Operation) error {
	if !e.profile.outcome {
		return errInvariant
	}
	return nil
}
func (e *syntheticEffects) Release(context.Context, signingaudit.Operation) error {
	e.result.Releases++
	if !e.profile.outcome {
		return errInvariant
	}
	if e.result.Control == "ambiguous-release" {
		e.result.EffectError = code(errRelease)
		return errRelease
	}
	return nil
}

func expectedError(control string) error {
	switch control {
	case "open-file-error", "open-directory-error", "directory-omit", "accepted-error", "accepted-omit", "intent-error", "intent-omit", "outcome-error", "outcome-omit", "unsupported":
		return signingaudit.ErrAudit
	case "cleanup-refusal":
		return signingaudit.ErrUncertain
	case "ambiguous-release":
		return errRelease
	default:
		return nil
	}
}

func matchesExpectedError(control string, err error) bool {
	want := expectedError(control)
	if want == nil {
		return err == nil
	}
	if !errors.Is(err, want) {
		return false
	}
	leaves := appendFailures(nil, "operation", err)
	if want != signingaudit.ErrAudit {
		return len(leaves) == 1
	}
	var cause error = syscall.EIO
	if control == "unsupported" {
		cause = syscall.ENOTSUP
	}
	if strings.HasSuffix(control, "-omit") {
		cause = errOmitted
	}
	// An injected boundary failure must not hide a separate cleanup/I/O failure.
	return len(leaves) == 2 && errors.Is(err, cause)
}
func code(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, os.ErrClosed) {
		return "descriptor_closed"
	}
	for _, known := range []error{errInvariant, errOmitted, errCleanup, errClose, errRelease, nativedurability.ErrUnavailable, nativedurability.ErrVolume, nativedurability.ErrDescriptor, signingaudit.ErrAudit, signingaudit.ErrUncertain} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("errno_%d", errno)
	}
	return "io_error"
}

// Keep every joined failure code/errno without exporting paths or raw OS text.
func appendFailures(out []failure, stage string, err error) []failure {
	if err == nil {
		return out
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			out = appendFailures(out, stage, cause)
		}
		return out
	}
	var errno syscall.Errno
	errors.As(err, &errno)
	return append(out, failure{Stage: stage, Code: code(err), Errno: uint64(errno)})
}

func verifyBoundaries(control string, events []event) bool {
	want := []string{"open-file", "open-directory", "open-file", "open-directory", "accepted-file", "intent", "outcome"}
	count := len(want)
	switch control {
	case "open-file-error", "unsupported":
		count = 1
	case "open-directory-error", "directory-omit":
		count = 2
	case "accepted-error", "accepted-omit":
		count = 5
	case "intent-error", "intent-omit", "cleanup-refusal":
		count = 6
	}
	if len(events) != count {
		return false
	}
	for n, e := range events {
		if e.Boundary != want[n] {
			return false
		}
		negative := n == count-1 && expectedError(control) == signingaudit.ErrAudit
		if negative {
			if e.Error == "" || e.Attempted || e.Completed {
				return false
			}
		} else if e.Error != "" || !e.Attempted || !e.Completed {
			return false
		}
	}
	return true
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func syntheticInput() (signingaudit.Request, signingaudit.Inputs) {
	req := signingaudit.Request{Caller: "durability-fixture", Version: 1, RequestID: "one", ProductID: "fixture", Repository: "fixture", Commit: strings.Repeat("a", 40)}
	in := signingaudit.Inputs{Tree: strings.Repeat("b", 40), PolicySHA256: hash("policy"), RecipeSHA256: hash("recipe"), ToolchainSHA256: hash("toolchain"), InputSHA256: hash("input"), JobSHA256: hash("job"), AuthoritySHA256: hash("authority"), UnsignedSHA256: hash("unsigned"), UnsignedBytes: 1, CertificateSHA256: hash("public-certificate-fixture"), RequirementSHA256: hash("requirement-fixture"), Target: "darwin/arm64"}
	return req, in
}
