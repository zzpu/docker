// +build !windows

package distribution

import (
	"github.com/docker/distribution"
	"github.com/docker/distribution/context"
)

func (ld *v2LayerDescriptor) open(ctx context.Context) (distribution.ReadSeekCloser, error) {
	// Blobs returns a reference to this repository's blob service.
	//在/docker/distribution/registry/client/repository.go中实现
	blobs := ld.repo.Blobs(ctx)
	return blobs.Open(ctx, ld.digest)
}
