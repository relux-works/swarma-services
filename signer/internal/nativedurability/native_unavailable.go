//go:build !darwin || !cgo

package nativedurability

import "os"

func nativeVolume(*os.File) (volume, error) { return volume{}, ErrUnavailable }
func nativeFullSync(*os.File) error         { return ErrUnavailable }
