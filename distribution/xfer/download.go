package xfer

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution"
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/pkg/progress"
	"golang.org/x/net/context"
)

const maxDownloadAttempts = 5

// LayerDownloadManager figures out which layers need to be downloaded, then
// registers and downloads those, taking into account dependencies between
// layers.
type LayerDownloadManager struct {
	layerStore layer.Store
	tm         TransferManager
}

// SetConcurrency set the max concurrent downloads for each pull
func (ldm *LayerDownloadManager) SetConcurrency(concurrency int) {
	ldm.tm.SetConcurrency(concurrency)
}

// NewLayerDownloadManager returns a new LayerDownloadManager.
func NewLayerDownloadManager(layerStore layer.Store, concurrencyLimit int) *LayerDownloadManager {
	return &LayerDownloadManager{
		layerStore: layerStore,
		tm:         NewTransferManager(concurrencyLimit),
	}
}

type downloadTransfer struct {
	Transfer

	layerStore layer.Store
	layer      layer.Layer
	err        error
}

// result returns the layer resulting from the download, if the download
// and registration were successful.
func (d *downloadTransfer) result() (layer.Layer, error) {
	return d.layer, d.err
}

// A DownloadDescriptor references a layer that may need to be downloaded.
type DownloadDescriptor interface {
	// Key returns the key used to deduplicate downloads.
	Key() string
	// ID returns the ID for display purposes.
	ID() string
	// DiffID should return the DiffID for this layer, or an error
	// if it is unknown (for example, if it has not been downloaded
	// before).
	DiffID() (layer.DiffID, error)
	// Download is called to perform the download.
	Download(ctx context.Context, progressOutput progress.Output) (io.ReadCloser, int64, error)
	// Close is called when the download manager is finished with this
	// descriptor and will not call Download again or read from the reader
	// that Download returned.
	Close()
}

// DownloadDescriptorWithRegistered is a DownloadDescriptor that has an
// additional Registered method which gets called after a downloaded layer is
// registered. This allows the user of the download manager to know the DiffID
// of each registered layer. This method is called if a cast to
// DownloadDescriptorWithRegistered is successful.
type DownloadDescriptorWithRegistered interface {
	DownloadDescriptor
	Registered(diffID layer.DiffID)
}

// Download is a blocking function which ensures the requested layers are
// present in the layer store. It uses the string returned by the Key method to
// deduplicate downloads. If a given layer is not already known to present in
// the layer store, and the key is not used by an in-progress download, the
// Download method is called to get the layer tar data. Layers are then
// registered in the appropriate order.  The caller must call the returned
// release function once it is is done with the returned RootFS object.
//数据会在这里解压
func (ldm *LayerDownloadManager) Download(ctx context.Context, initialRootFS image.RootFS, layers []DownloadDescriptor, progressOutput progress.Output) (image.RootFS, func(), error) {
	var (
		topLayer       layer.Layer
		topDownload    *downloadTransfer
		watcher        *Watcher
		missingLayer   bool
		transferKey    = ""
		downloadsByKey = make(map[string]*downloadTransfer)
	)
        //一个新的镜像有一个rootfs
	rootFS := initialRootFS
	for _, descriptor := range layers {
		//防止重复下载
		key := descriptor.Key()

		transferKey += key
                 //missingLayer默认是false,所以一定会进入
		//而且进入后会置为true,确保只进入一次
		if !missingLayer {
			missingLayer = true
			diffID, err := descriptor.DiffID()
			//如果镜像层存在，则可以找到DiffID
			if err == nil {
				logrus.Debugf("Layer DiffID: %s", diffID)
				getRootFS := rootFS
				getRootFS.Append(diffID)
				//// ChainID is the content-addressable ID of a layer.
				// chain is made up of DiffID of top layer and all of its parents.

				//ImageStore在docker\daemon\daemon.go初始化,实现在docker\image\store.go
				//实际读入 "/var/lib/docker/image/imagedb/content/sha265/xxx"中对应的镜像信息json文件
				l, err := ldm.layerStore.Get(getRootFS.ChainID())
				//不出错，说明，该镜像层已经存在
				if err == nil {
					// Layer already exists.
					logrus.Debugf("Layer already exists: %s", descriptor.ID())
					progress.Update(progressOutput, descriptor.ID(), "Already exists")
					if topLayer != nil {
						layer.ReleaseAndLog(ldm.layerStore, topLayer)
					}
					topLayer = l
					missingLayer = false
					rootFS.Append(diffID)
					//不出错，说明，该镜像层已经存在,无需重新下载,直接添加ID即可
					continue
				}

			}
			logrus.Debugf("Layer with key: %s didn't download before" , key)
		}

		// Does this layer have the same data as a previous layer in
		// the stack? If so, avoid downloading it more than once.
		var topDownloadUncasted Transfer
		if existingDownload, ok := downloadsByKey[key]; ok {
			//下载函数,最终会调用descriptor的download函数
			xferFunc := ldm.makeDownloadFuncFromDownload(descriptor, existingDownload, topDownload)
			defer topDownload.Transfer.Release(watcher)
			//实现在docker\distribution\xfer\transfer.go
			//
			topDownloadUncasted, watcher = ldm.tm.Transfer(transferKey, xferFunc, progressOutput)
			topDownload = topDownloadUncasted.(*downloadTransfer)
			continue
		}

		// Layer is not known to exist - download and register it.
		progress.Update(progressOutput, descriptor.ID(), "Pulling fs layer")

		var xferFunc DoFunc
		if topDownload != nil {
			xferFunc = ldm.makeDownloadFunc(descriptor, "", topDownload)
			defer topDownload.Transfer.Release(watcher)
		} else {
			//下载函数,最终会调用descriptor的download函数
			//下载完后会在该函数进行解压
			//解压动作函数,同时镜像层也会在这里注册到系统中
			xferFunc = ldm.makeDownloadFunc(descriptor, rootFS.ChainID(), nil)
		}
		//实现在docker\distribution\xfer\transfer.go
		topDownloadUncasted, watcher = ldm.tm.Transfer(transferKey, xferFunc, progressOutput)
		topDownload = topDownloadUncasted.(*downloadTransfer)
		downloadsByKey[key] = topDownload
	}

	if topDownload == nil {
		return rootFS, func() {
			if topLayer != nil {
				layer.ReleaseAndLog(ldm.layerStore, topLayer)
			}
		}, nil
	}

	// Won't be using the list built up so far - will generate it
	// from downloaded layers instead.
	rootFS.DiffIDs = []layer.DiffID{}

	defer func() {
		if topLayer != nil {
			layer.ReleaseAndLog(ldm.layerStore, topLayer)
		}
	}()

	select {
	case <-ctx.Done():
		topDownload.Transfer.Release(watcher)
		return rootFS, func() {}, ctx.Err()
	case <-topDownload.Done():
		break
	}

	l, err := topDownload.result()
	if err != nil {
		topDownload.Transfer.Release(watcher)
		return rootFS, func() {}, err
	}

	// Must do this exactly len(layers) times, so we don't include the
	// base layer on Windows.
	for range layers {
		if l == nil {
			topDownload.Transfer.Release(watcher)
			return rootFS, func() {}, errors.New("internal error: too few parent layers")
		}
		rootFS.DiffIDs = append([]layer.DiffID{l.DiffID()}, rootFS.DiffIDs...)
		l = l.Parent()
	}
	return rootFS, func() { topDownload.Transfer.Release(watcher) }, err
}

// makeDownloadFunc returns a function that performs the layer download and
// registration. If parentDownload is non-nil, it waits for that download to
// complete before the registration step, and registers the downloaded data
// on top of parentDownload's resulting layer. Otherwise, it registers the
// layer on top of the ChainID given by parentLayer.
//镜像层会在这里注册到系统中
func (ldm *LayerDownloadManager) makeDownloadFunc(descriptor DownloadDescriptor, parentLayer layer.ChainID, parentDownload *downloadTransfer) DoFunc {
	return func(progressChan chan<- progress.Progress, start <-chan struct{}, inactive chan<- struct{}) Transfer {
		d := &downloadTransfer{
			Transfer:   NewTransfer(),
			layerStore: ldm.layerStore,
		}

		go func() {
			defer func() {
				close(progressChan)
			}()

			progressOutput := progress.ChanOutput(progressChan)

			select {
			case <-start:
			default:
				progress.Update(progressOutput, descriptor.ID(), "Waiting")
				<-start
			}

			if parentDownload != nil {
				// Did the parent download already fail or get
				// cancelled?
				select {
				case <-parentDownload.Done():
					_, err := parentDownload.result()
					if err != nil {
						d.err = err
						return
					}
				default:
				}
			}

			var (
				downloadReader io.ReadCloser
				size           int64
				err            error
				retries        int
			)

			defer descriptor.Close()

			for {
				//使用descriptor的Download函数
				//downloadReader是io.ReadCloser对象
				// 其实是临时镜像文件/var/lib/docker/tmp/GetImageBlobxxxx读取出来的
				downloadReader, size, err = descriptor.Download(d.Transfer.Context(), progressOutput)
				if err == nil {
					break
				}

				// If an error was returned because the context
				// was cancelled, we shouldn't retry.
				select {
				case <-d.Transfer.Context().Done():
					d.err = err
					return
				default:
				}

				retries++
				if _, isDNR := err.(DoNotRetry); isDNR || retries == maxDownloadAttempts {
					logrus.Errorf("Download failed: %v", err)
					d.err = err
					return
				}

				logrus.Errorf("Download failed, retrying: %v", err)
				delay := retries * 5
				ticker := time.NewTicker(time.Second)

			selectLoop:
				for {
					progress.Updatef(progressOutput, descriptor.ID(), "Retrying in %d second%s", delay, (map[bool]string{true: "s"})[delay != 1])
					select {
					case <-ticker.C:
						delay--
						if delay == 0 {
							ticker.Stop()
							break selectLoop
						}
					case <-d.Transfer.Context().Done():
						ticker.Stop()
						d.err = errors.New("download cancelled during retry delay")
						return
					}

				}
			}

			close(inactive)

			if parentDownload != nil {
				select {
				case <-d.Transfer.Context().Done():
					d.err = errors.New("layer registration cancelled")
					downloadReader.Close()
					return
				case <-parentDownload.Done():
				}

				l, err := parentDownload.result()
				if err != nil {
					d.err = err
					downloadReader.Close()
					return
				}
				// chain is made up of DiffID of top layer and all of its parents.
				parentLayer = l.ChainID()
			}
			// Reader is a Reader with progress bar.

			reader := progress.NewProgressReader(ioutils.NewCancelReadCloser(d.Transfer.Context(), downloadReader), progressOutput, size, descriptor.ID(), "Extracting")
			defer reader.Close()
                        //解压出镜像数据，会调用reader的read函数，所以会打印Extracting...
			inflatedLayerData, err := archive.DecompressStream(reader)
			if err != nil {
				d.err = fmt.Errorf("could not get decompression stream: %v", err)
				return
			}

			var src distribution.Descriptor
			if fs, ok := descriptor.(distribution.Describable); ok {
				src = fs.Descriptor()
			}
			//解压完了之后，写到文件系统中
			//实现在docker/layer/layer_store.go
			//没有实现RegisterWithDescriptor接口，会走else分支
			if ds, ok := d.layerStore.(layer.DescribableStore); ok {
				d.layer, err = ds.RegisterWithDescriptor(inflatedLayerData, parentLayer, src)
			} else {
                                //注册镜像层
				d.layer, err = d.layerStore.Register(inflatedLayerData, parentLayer)
			}
			if err != nil {
				select {
				case <-d.Transfer.Context().Done():
					d.err = errors.New("layer registration cancelled")
				default:
					d.err = fmt.Errorf("failed to register layer: %v", err)
				}
				return
			}

			progress.Update(progressOutput, descriptor.ID(), "Pull complete")
			withRegistered, hasRegistered := descriptor.(DownloadDescriptorWithRegistered)
			if hasRegistered {
				withRegistered.Registered(d.layer.DiffID())
			}

			// Doesn't actually need to be its own goroutine, but
			// done like this so we can defer close(c).
			go func() {
				<-d.Transfer.Released()
				if d.layer != nil {
					layer.ReleaseAndLog(d.layerStore, d.layer)
				}
			}()
		}()

		return d
	}
}

// makeDownloadFuncFromDownload returns a function that performs the layer
// registration when the layer data is coming from an existing download. It
// waits for sourceDownload and parentDownload to complete, and then
// reregisters the data from sourceDownload's top layer on top of
// parentDownload. This function does not log progress output because it would
// interfere with the progress reporting for sourceDownload, which has the same
// Key.
func (ldm *LayerDownloadManager) makeDownloadFuncFromDownload(descriptor DownloadDescriptor, sourceDownload *downloadTransfer, parentDownload *downloadTransfer) DoFunc {
	return func(progressChan chan<- progress.Progress, start <-chan struct{}, inactive chan<- struct{}) Transfer {
		d := &downloadTransfer{
			Transfer:   NewTransfer(),
			layerStore: ldm.layerStore,
		}

		go func() {
			defer func() {
				close(progressChan)
			}()

			<-start

			close(inactive)

			select {
			case <-d.Transfer.Context().Done():
				d.err = errors.New("layer registration cancelled")
				return
			case <-parentDownload.Done():
			}

			l, err := parentDownload.result()
			if err != nil {
				d.err = err
				return
			}
			parentLayer := l.ChainID()

			// sourceDownload should have already finished if
			// parentDownload finished, but wait for it explicitly
			// to be sure.
			select {
			case <-d.Transfer.Context().Done():
				d.err = errors.New("layer registration cancelled")
				return
			case <-sourceDownload.Done():
			}

			l, err = sourceDownload.result()
			if err != nil {
				d.err = err
				return
			}

			layerReader, err := l.TarStream()
			if err != nil {
				d.err = err
				return
			}
			defer layerReader.Close()

			var src distribution.Descriptor
			if fs, ok := l.(distribution.Describable); ok {
				src = fs.Descriptor()
			}
			if ds, ok := d.layerStore.(layer.DescribableStore); ok {
				d.layer, err = ds.RegisterWithDescriptor(layerReader, parentLayer, src)
			} else {
				d.layer, err = d.layerStore.Register(layerReader, parentLayer)
			}
			if err != nil {
				d.err = fmt.Errorf("failed to register layer: %v", err)
				return
			}

			withRegistered, hasRegistered := descriptor.(DownloadDescriptorWithRegistered)
			if hasRegistered {
				withRegistered.Registered(d.layer.DiffID())
			}

			// Doesn't actually need to be its own goroutine, but
			// done like this so we can defer close(c).
			go func() {
				<-d.Transfer.Released()
				if d.layer != nil {
					layer.ReleaseAndLog(d.layerStore, d.layer)
				}
			}()
		}()

		return d
	}
}
