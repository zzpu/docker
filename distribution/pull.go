package distribution

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/digest"
	"github.com/docker/docker/api"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/distribution/metadata"
	"github.com/docker/docker/distribution/xfer"
	"github.com/docker/docker/image"
	"github.com/docker/docker/pkg/progress"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
	"golang.org/x/net/context"

)

// ImagePullConfig stores pull configuration.
type ImagePullConfig struct {
	// MetaHeaders stores HTTP headers with metadata about the image
	MetaHeaders map[string][]string
	// AuthConfig holds authentication credentials for authenticating with
	// the registry.
	AuthConfig *types.AuthConfig
	// ProgressOutput is the interface for showing the status of the pull
	// operation.
	ProgressOutput progress.Output
	// RegistryService is the registry service to use for TLS configuration
	// and endpoint lookup.
	RegistryService registry.Service
	// ImageEventLogger notifies events for a given image
	ImageEventLogger func(id, name, action string)
	// MetadataStore is the storage backend for distribution-specific
	// metadata.
	MetadataStore metadata.Store
	// ImageStore manages images.
	ImageStore image.Store
	// ReferenceStore manages tags.
	ReferenceStore reference.Store
	// DownloadManager manages concurrent pulls.
	DownloadManager *xfer.LayerDownloadManager
}

// Puller is an interface that abstracts pulling for different API versions.
type Puller interface {
	// Pull tries to pull the image referenced by `tag`
	// Pull returns an error if any, as well as a boolean that determines whether to retry Pull on the next configured endpoint.
	//
	Pull(ctx context.Context, ref reference.Named) error
}

// newPuller returns a Puller interface that will pull from either a v1 or v2
// registry. The endpoint argument contains a Version field that determines
// whether a v1 or v2 puller will be created. The other parameters are passed
// through to the underlying puller implementation for use during the actual
// pull operation.

//关于imagePullConfig看docker\daemon\image_pull.go的pullImageWithReference
func newPuller(endpoint registry.APIEndpoint, repoInfo *registry.RepositoryInfo, imagePullConfig *ImagePullConfig) (Puller, error) {
	switch endpoint.Version {
	case registry.APIVersion2:
		return &v2Puller{
			V2MetadataService: metadata.NewV2MetadataService(imagePullConfig.MetadataStore),
			endpoint:          endpoint,
			config:            imagePullConfig,
			repoInfo:          repoInfo,
		}, nil
	case registry.APIVersion1:
		return &v1Puller{
			v1IDService: metadata.NewV1IDService(imagePullConfig.MetadataStore),
			endpoint:    endpoint,
			config:      imagePullConfig,
			repoInfo:    repoInfo,
		}, nil
	}
	return nil, fmt.Errorf("unknown version %d for registry %s", endpoint.Version, endpoint.URL)
}

// Pull initiates a pull operation. image is the repository name to pull, and
// tag may be either empty, or indicate a specific tag to pull.
//关于imagePullConfig看docker\daemon\image_pull.go的pullImageWithReference
func Pull(ctx context.Context, ref reference.Named, imagePullConfig *ImagePullConfig) error {
	// Resolve the Repository name from fqn to RepositoryInfo

	//在/docker/registry/config.go的 newServiceConfig初始化仓库地址和仓库镜像地址，其中有官方的和通过选项insecure-registry自定义的私有仓库,实质是通过IndexName找到IndexInfo，有用的也只有IndexName
	//这里的imagePullConfig.RegistryService为daemon.RegistryService，也即是docker\registry\service.go的DefaultService
	//初始化时,会将insecure-registry选项和registry-mirrors存入ServiceOptions,在NewService函数被调用时,作为参入传入

	//repoInfo为RepositoryInfo对象,其实是对reference.Named对象的封装,添加了镜像成员和官方标示
	//RepositoryInfo包含了一个Named对象,Index对象和一个Official标志
	repoInfo, err := imagePullConfig.RegistryService.ResolveRepository(ref)
	if err != nil {
		return err
	}

	// makes sure name is not empty or `scratch`
	//为了确保不为空或?
	if err := ValidateRepoName(repoInfo.Name()); err != nil {
		return err
	}
	// APIEndpoint represents a remote API endpoint
	// /docker/cmd/dockerddaemon.go----大约125 和 248
	//如果没有镜像仓库服务器地址，默认使用V2仓库地址registry-1.docker.io
	//Hostname()函数来源于Named

	//实质上如果Hostname()返回的是官方仓库地址,则endpoint的URL将是registry-1.docker.io,如果有镜像则会添加镜像作为endpoint
	// 否则就是私有地址的两种类型:http和https

	//V2的接口具体代码在docker\registry\service_v2.go的函数lookupV2Endpoints
	// endpoints其实就是对hostname的一个封装,并没有加什么特别的东西
	//{
	//	URL: &url.URL{
	//		Scheme: "https",
	//		Host:   hostname,
	//	},
	//		Version:      APIVersion2,
	//	TrimHostname: true,
	//	TLSConfig:    tlsConfig,
	//},
	logrus.Debugf("Get endpoint from:%s", repoInfo.Hostname())
	endpoints, err := imagePullConfig.RegistryService.LookupPullEndpoints(repoInfo.Hostname())
	if err != nil {
		return err
	}

	var (
		lastErr error

		// discardNoSupportErrors is used to track whether an endpoint encountered an error of type registry.ErrNoSupport
		// By default it is false, which means that if an ErrNoSupport error is encountered, it will be saved in lastErr.
		// As soon as another kind of error is encountered, discardNoSupportErrors is set to true, avoiding the saving of
		// any subsequent ErrNoSupport errors in lastErr.
		// It's needed for pull-by-digest on v1 endpoints: if there are only v1 endpoints configured, the error should be
		// returned and displayed, but if there was a v2 endpoint which supports pull-by-digest, then the last relevant
		// error is the ones from v2 endpoints not v1.
		discardNoSupportErrors bool

		// confirmedV2 is set to true if a pull attempt managed to
		// confirm that it was talking to a v2 registry. This will
		// prevent fallback to the v1 protocol.
		confirmedV2 bool

		// confirmedTLSRegistries is a map indicating which registries
		// are known to be using TLS. There should never be a plaintext
		// retry for any of these.
		confirmedTLSRegistries = make(map[string]struct{})
	)
	//如果设置了镜像服务器地址,且使用了官方默认的镜像仓库,则endpoints包含官方仓库地址:registry-1.docker.io和镜像服务器地址,否则就是私有仓库地址的http和https形式
	for _, endpoint := range endpoints {
		logrus.Debugf("Endpoint API version:%d", endpoint.Version)
		if confirmedV2 && endpoint.Version == registry.APIVersion1 {
			logrus.Debugf("Skipping v1 endpoint %s because v2 registry was detected", endpoint.URL)
			continue
		}

		if endpoint.URL.Scheme != "https" {
			if _, confirmedTLS := confirmedTLSRegistries[endpoint.URL.Host]; confirmedTLS {
				logrus.Debugf("Skipping non-TLS endpoint %s for host/port that appears to use TLS", endpoint.URL)
				continue
			}
		}

		logrus.Debugf("Trying to pull %s from %s %s", repoInfo.Name(), endpoint.URL, endpoint.Version)
		//针对每一个endpoint，建立一个Puller,newPuller会根据endpoint的形式（endpoint应该遵循restful api的设计，url中含有版本号），决定采用version1还是version2版本
		//imagePullConfig是个很重要的对象,包含了很多镜像操作相关的对象
		puller, err := newPuller(endpoint, repoInfo, imagePullConfig)
		if err != nil {
			lastErr = err
			continue
		}
		//如果是v2,实现在docker\distribution\pull_v2.go
		if err := puller.Pull(ctx, ref); err != nil {
			// Was this pull cancelled? If so, don't try to fall
			// back.
			fallback := false
			select {
			case <-ctx.Done():
			default:
				if fallbackErr, ok := err.(fallbackError); ok {
					fallback = true
					confirmedV2 = confirmedV2 || fallbackErr.confirmedV2
					if fallbackErr.transportOK && endpoint.URL.Scheme == "https" {
						confirmedTLSRegistries[endpoint.URL.Host] = struct{}{}
					}
					err = fallbackErr.err
				}
			}
			if fallback {
				if _, ok := err.(ErrNoSupport); !ok {
					// Because we found an error that's not ErrNoSupport, discard all subsequent ErrNoSupport errors.
					discardNoSupportErrors = true
					// append subsequent errors
					lastErr = err
				} else if !discardNoSupportErrors {
					// Save the ErrNoSupport error, because it's either the first error or all encountered errors
					// were also ErrNoSupport errors.
					// append subsequent errors
					lastErr = err
				}
				logrus.Errorf("Attempting next endpoint for pull after error: %v", err)
				continue
			}
			logrus.Errorf("Not continuing with pull after error: %v", err)
			return err
		}

		imagePullConfig.ImageEventLogger(ref.String(), repoInfo.Name(), "pull")
		return nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoints found for %s", ref.String())
	}

	return lastErr
}

// writeStatus writes a status message to out. If layersDownloaded is true, the
// status message indicates that a newer image was downloaded. Otherwise, it
// indicates that the image is up to date. requestedTag is the tag the message
// will refer to.
func writeStatus(requestedTag string, out progress.Output, layersDownloaded bool) {
	if layersDownloaded {
		progress.Message(out, "", "Status: Downloaded newer image for "+requestedTag)
	} else {
		progress.Message(out, "", "Status: Image is up to date for "+requestedTag)
	}
}

// ValidateRepoName validates the name of a repository.
func ValidateRepoName(name string) error {
	if name == "" {
		return fmt.Errorf("Repository name can't be empty")
	}
	if name == api.NoBaseImageSpecifier {
		return fmt.Errorf("'%s' is a reserved name", api.NoBaseImageSpecifier)
	}
	return nil
}

func addDigestReference(store reference.Store, ref reference.Named, dgst digest.Digest, id digest.Digest) error {
	dgstRef, err := reference.WithDigest(ref, dgst)
	if err != nil {
		return err
	}

	if oldTagID, err := store.Get(dgstRef); err == nil {
		if oldTagID != id {
			// Updating digests not supported by reference store
			logrus.Errorf("Image ID for digest %s changed from %s to %s, cannot update", dgst.String(), oldTagID, id)
		}
		return nil
	} else if err != reference.ErrDoesNotExist {
		return err
	}

	return store.AddDigest(dgstRef, id, true)
}
