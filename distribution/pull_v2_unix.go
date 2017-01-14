// +build !windows

package distribution

import (
	"github.com/docker/distribution"
	"github.com/docker/distribution/context"
)

func (ld *v2LayerDescriptor) open(ctx context.Context) (distribution.ReadSeekCloser, error) {
	// Blobs returns a reference to this repository's blob service.
	//实现在docker\vendor\src\github.com\docker\distribution\registry\client\repository.go
	//得到的是httpReadSeeker对象，实现在docker\vendor\src\github.com\docker\distribution\registry\client\transport\http_reader.go
	blobs := ld.repo.Blobs(ctx)
	return blobs.Open(ctx, ld.digest)
}
