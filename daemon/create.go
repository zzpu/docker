package daemon

import (
	"fmt"
	"net"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/errors"
	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/container"
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/docker/runconfig"
	volumestore "github.com/docker/docker/volume/store"
	"github.com/opencontainers/runc/libcontainer/label"
)

// CreateManagedContainer creates a container that is managed by a Service
func (daemon *Daemon) CreateManagedContainer(params types.ContainerCreateConfig, validateHostname bool) (types.ContainerCreateResponse, error) {
	return daemon.containerCreate(params, true, validateHostname)
}

// ContainerCreate creates a regular container
func (daemon *Daemon) ContainerCreate(params types.ContainerCreateConfig, validateHostname bool) (types.ContainerCreateResponse, error) {
	return daemon.containerCreate(params, false, validateHostname)
}

func (daemon *Daemon) containerCreate(params types.ContainerCreateConfig, managed bool, validateHostname bool) (types.ContainerCreateResponse, error) {
	if params.Config == nil {
		return types.ContainerCreateResponse{}, fmt.Errorf("Config cannot be empty in order to create a container")
	}

        //
	warnings, err := daemon.verifyContainerSettings(params.HostConfig, params.Config, false, validateHostname)
	if err != nil {
		return types.ContainerCreateResponse{Warnings: warnings}, err
	}

	//
	err = daemon.verifyNetworkingConfig(params.NetworkingConfig)
	if err != nil {
		return types.ContainerCreateResponse{Warnings: warnings}, err
	}

	if params.HostConfig == nil {
		params.HostConfig = &containertypes.HostConfig{}
	}

	//
	err = daemon.adaptContainerSettings(params.HostConfig, params.AdjustCPUShares)
	if err != nil {
		return types.ContainerCreateResponse{Warnings: warnings}, err
	}

	// Create creates a new container from the given configuration with a given name.
	container, err := daemon.create(params, managed)
	if err != nil {
		return types.ContainerCreateResponse{Warnings: warnings}, daemon.imageNotExistToErrcode(err)
	}

	return types.ContainerCreateResponse{ID: container.ID, Warnings: warnings}, nil
}

// Create creates a new container from the given configuration with a given name.
//返回Container只是为了得到ID?
func (daemon *Daemon) create(params types.ContainerCreateConfig, managed bool) (retC *container.Container, retErr error) {
	var (
		container *container.Container
		img       *image.Image
		imgID     image.ID
		err       error
	)

	if params.Config.Image != "" {
		//获得镜像的描述信息结构
		img, err = daemon.GetImage(params.Config.Image)
		if err != nil {
			return nil, err
		}
		imgID = img.ID()
	}

	if err := daemon.mergeAndVerifyConfig(params.Config, img); err != nil {
		return nil, err
	}

	if err := daemon.mergeAndVerifyLogConfig(&params.HostConfig.LogConfig); err != nil {
		return nil, err
	}
	// NewBaseContainer creates a new container with its
	// basic configuration.
	//type Container struct {
	//	CommonContainer
	//
	//	// Fields below here are platform specific.
	//	AppArmorProfile string
	//	HostnamePath    string
	//	HostsPath       string
	//	ShmPath         string
	//	ResolvConfPath  string
	//	SeccompProfile  string
	//	NoNewPrivileges bool
	//}
	//基本配置的容器
	//docker\container\container_unix.go
	if container, err = daemon.newContainer(params.Name, params.Config, imgID, managed); err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if err := daemon.cleanupContainer(container, true, true); err != nil {
				logrus.Errorf("failed to cleanup container on create error: %v", err)
			}
		}
	}()

	if err := daemon.setSecurityOptions(container, params.HostConfig); err != nil {
		return nil, err
	}

	container.HostConfig.StorageOpt = params.HostConfig.StorageOpt

	// Set RWLayer for container after mount labels have been set
	//这里是建读写层目录和init目录
	if err := daemon.setRWLayer(container); err != nil {
		return nil, err
	}
	logrus.Debugf("container.Root: %s", container.Root)
	rootUID, rootGID, err := idtools.GetRootUIDGID(daemon.uidMaps, daemon.gidMaps)
	if err != nil {
		return nil, err
	}
	if err := idtools.MkdirAs(container.Root, 0700, rootUID, rootGID); err != nil {
		return nil, err
	}
	if err := idtools.MkdirAs(container.CheckpointDir(), 0700, rootUID, rootGID); err != nil {
		return nil, err
	}

	if err := daemon.setHostConfig(container, params.HostConfig); err != nil {
		return nil, err
	}
        //这里挂载一次不知挂载什么
	//对卷的处理
	if err := daemon.createContainerPlatformSpecificSettings(container, params.Config, params.HostConfig); err != nil {
		return nil, err
	}

	var endpointsConfigs map[string]*networktypes.EndpointSettings
	if params.NetworkingConfig != nil {
		endpointsConfigs = params.NetworkingConfig.EndpointsConfig
	}
	// Make sure NetworkMode has an acceptable value. We do this to ensure
	// backwards API compatibility.
	container.HostConfig = runconfig.SetDefaultNetModeIfBlank(container.HostConfig)

	if err := daemon.updateContainerNetworkSettings(container, endpointsConfigs); err != nil {
		return nil, err
	}

	if err := container.ToDisk(); err != nil {
		logrus.Errorf("Error saving new container to disk: %v", err)
		return nil, err
	}
	//实际上是添加到一个内存Map中,以ID为key
	if err := daemon.Register(container); err != nil {
		return nil, err
	}
	daemon.LogContainerEvent(container, "create")
	return container, nil
}

func (daemon *Daemon) generateSecurityOpt(ipcMode containertypes.IpcMode, pidMode containertypes.PidMode, privileged bool) ([]string, error) {
	if ipcMode.IsHost() || pidMode.IsHost() || privileged {
		return label.DisableSecOpt(), nil
	}

	var ipcLabel []string
	var pidLabel []string
	ipcContainer := ipcMode.Container()
	pidContainer := pidMode.Container()
	if ipcContainer != "" {
		c, err := daemon.GetContainer(ipcContainer)
		if err != nil {
			return nil, err
		}
		ipcLabel = label.DupSecOpt(c.ProcessLabel)
		if pidContainer == "" {
			return ipcLabel, err
		}
	}
	if pidContainer != "" {
		c, err := daemon.GetContainer(pidContainer)
		if err != nil {
			return nil, err
		}

		pidLabel = label.DupSecOpt(c.ProcessLabel)
		if ipcContainer == "" {
			return pidLabel, err
		}
	}

	if pidLabel != nil && ipcLabel != nil {
		for i := 0; i < len(pidLabel); i++ {
			if pidLabel[i] != ipcLabel[i] {
				return nil, fmt.Errorf("--ipc and --pid containers SELinux labels aren't the same")
			}
		}
		return pidLabel, nil
	}
	return nil, nil
}

func (daemon *Daemon) setRWLayer(container *container.Container) error {
	var layerID layer.ChainID
	if container.ImageID != "" {
		img, err := daemon.imageStore.Get(container.ImageID)
		if err != nil {
			return err
		}
		layerID = img.RootFS.ChainID()
	}
	// RWLayer represents a layer which is
	// read and writable
	//返回RWLayer,实际上是mountedLayer,实现在docker\layer\mounted_layer.go
	//layerStore实现在docker/layer/layer_store.go
	//建读写的目录和init目录
	rwLayer, err := daemon.layerStore.CreateRWLayer(container.ID, layerID, container.MountLabel, daemon.getLayerInit(), container.HostConfig.StorageOpt)

	if err != nil {
		return err
	}
	container.RWLayer = rwLayer

	return nil
}

// VolumeCreate creates a volume with the specified name, driver, and opts
// This is called directly from the remote API
func (daemon *Daemon) VolumeCreate(name, driverName string, opts, labels map[string]string) (*types.Volume, error) {
	if name == "" {
		name = stringid.GenerateNonCryptoID()
	}

	v, err := daemon.volumes.Create(name, driverName, opts, labels)
	if err != nil {
		if volumestore.IsNameConflict(err) {
			return nil, fmt.Errorf("A volume named %s already exists. Choose a different volume name.", name)
		}
		return nil, err
	}

	daemon.LogVolumeEvent(v.Name(), "create", map[string]string{"driver": v.DriverName()})
	apiV := volumeToAPIType(v)
	apiV.Mountpoint = v.Path()
	return apiV, nil
}

func (daemon *Daemon) mergeAndVerifyConfig(config *containertypes.Config, img *image.Image) error {
	if img != nil && img.Config != nil {
		if err := merge(config, img.Config); err != nil {
			return err
		}
	}
	// Reset the Entrypoint if it is [""]
	if len(config.Entrypoint) == 1 && config.Entrypoint[0] == "" {
		config.Entrypoint = nil
	}
	if len(config.Entrypoint) == 0 && len(config.Cmd) == 0 {
		return fmt.Errorf("No command specified")
	}
	return nil
}

// Checks if the client set configurations for more than one network while creating a container
// Also checks if the IPAMConfig is valid
func (daemon *Daemon) verifyNetworkingConfig(nwConfig *networktypes.NetworkingConfig) error {
	if nwConfig == nil || len(nwConfig.EndpointsConfig) == 0 {
		return nil
	}
	if len(nwConfig.EndpointsConfig) == 1 {
		for _, v := range nwConfig.EndpointsConfig {
			if v != nil && v.IPAMConfig != nil {
				if v.IPAMConfig.IPv4Address != "" && net.ParseIP(v.IPAMConfig.IPv4Address).To4() == nil {
					return errors.NewBadRequestError(fmt.Errorf("invalid IPv4 address: %s", v.IPAMConfig.IPv4Address))
				}
				if v.IPAMConfig.IPv6Address != "" {
					n := net.ParseIP(v.IPAMConfig.IPv6Address)
					// if the address is an invalid network address (ParseIP == nil) or if it is
					// an IPv4 address (To4() != nil), then it is an invalid IPv6 address
					if n == nil || n.To4() != nil {
						return errors.NewBadRequestError(fmt.Errorf("invalid IPv6 address: %s", v.IPAMConfig.IPv6Address))
					}
				}
			}
		}
		return nil
	}
	l := make([]string, 0, len(nwConfig.EndpointsConfig))
	for k := range nwConfig.EndpointsConfig {
		l = append(l, k)
	}
	err := fmt.Errorf("Container cannot be connected to network endpoints: %s", strings.Join(l, ", "))
	return errors.NewBadRequestError(err)
}
