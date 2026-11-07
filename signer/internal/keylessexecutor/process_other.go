//go:build !linux && !darwin

package keylessexecutor

import "os"

func openArtifact(string) (*os.File, error) { return nil, ErrWorker }

// No worker or native backend is installed on this platform. The pure planning
// and explicit RunNative refusal remain available.
