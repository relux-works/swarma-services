// Package nativedurability supplies an explicitly selected, unqualified native
// journal profile. Successful calls report API completion, not power-loss proof.
package nativedurability

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const ProfileName = "darwin-apfs-fullfsync-strict-v1"

var (
	ErrUnavailable = errors.New("native_durability_unavailable")
	ErrVolume      = errors.New("native_durability_volume_refused")
	ErrDescriptor  = errors.New("native_durability_descriptor_refused")
)

type volume struct {
	device     uint64
	fsid       [2]int32
	local      bool
	writable   bool
	filesystem string
}

// Binding is a copy of the observed target facts. It carries no path or device
// serial and is not an admission or a persistent identity across host restarts.
type Binding struct {
	Device       uint64   `json:"device"`
	FilesystemID [2]int32 `json:"filesystem_id"`
	Filesystem   string   `json:"filesystem"`
	Local        bool     `json:"local"`
	Writable     bool     `json:"writable"`
}

// Profile has no fixture fallback, retry or caller-selectable weaker primitive.
// Its zero value refuses. Construct it with New for one explicitly pinned volume.
// Concurrent descriptor closure/replacement is outside this profile's custody.
type Profile struct {
	volume   volume
	inspect  func(*os.File) (volume, error)
	fullSync func(*os.File) error
}

// New checks an already-open private target directory against the native device
// number supplied by the sitting's protected configuration. It does not qualify
// a volume, provision it, or flush it. Non-Darwin/non-cgo builds refuse.
func New(target *os.File, expectedDevice uint64) (*Profile, error) {
	if expectedDevice == 0 {
		return nil, ErrVolume
	}
	if target == nil {
		return nil, ErrDescriptor
	}
	st, err := target.Stat()
	if err != nil || !st.IsDir() || st.Mode() != os.ModeDir|0700 {
		return nil, ErrDescriptor
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, ErrDescriptor
	}
	v, err := nativeVolume(target)
	if err != nil {
		return nil, err
	}
	if v.device != expectedDevice || !v.local || !v.writable || v.filesystem != "apfs" {
		return nil, ErrVolume
	}
	return &Profile{volume: v, inspect: nativeVolume, fullSync: nativeFullSync}, nil
}

func (*Profile) Name() string { return ProfileName }

func (p *Profile) Binding() Binding {
	return Binding{p.volume.device, p.volume.fsid, p.volume.filesystem, p.volume.local, p.volume.writable}
}

func (p *Profile) File(f *os.File) error      { return p.sync(f, false) }
func (p *Profile) Directory(f *os.File) error { return p.sync(f, true) }

func (p *Profile) sync(f *os.File, directory bool) error {
	if p == nil || p.inspect == nil || p.fullSync == nil {
		return ErrUnavailable
	}
	if f == nil {
		return ErrDescriptor
	}
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("descriptor stat: %w", err)
	}
	if directory && !st.IsDir() || !directory && !st.Mode().IsRegular() {
		return ErrDescriptor
	}
	v, err := p.inspect(f)
	if err != nil {
		return fmt.Errorf("volume inspection: %w", err)
	}
	if v != p.volume || !v.local || !v.writable || v.filesystem != "apfs" {
		return ErrVolume
	}
	// F_FULLFSYNC includes fsync's data/metadata synchronization, then asks
	// the device to flush its cache. Use it on the directory descriptor too;
	// an unsupported directory or filesystem is a hard error, never fsync-only.
	if err := p.fullSync(f); err != nil {
		return fmt.Errorf("F_FULLFSYNC: %w", err)
	}
	return nil
}
