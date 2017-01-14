//+build !windows

package chrootarchive

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/reexec"
	"github.com/docker/docker/pkg/system"
	rsystem "github.com/opencontainers/runc/libcontainer/system"
)

type applyLayerResponse struct {
	LayerSize int64 `json:"layerSize"`
}

// applyLayer is the entry-point for docker-applylayer on re-exec. This is not
// used on Windows as it does not support chroot, hence no point sandboxing
// through chroot and rexec.
func applyLayer() {

	var (
		tmpDir  = ""
		err     error
		options *archive.TarOptions
	)
	runtime.LockOSThread()
	flag.Parse()

	inUserns := rsystem.RunningInUserNS()
	//更换根目录到dest
	//dest其实是镜像层目录下的一个名为tmproot的目录
	if err := chroot(flag.Arg(0)); err != nil {
		fatal(err)
	}

	// We need to be able to set any perms
	oldmask, err := system.Umask(0)
	defer system.Umask(oldmask)
	if err != nil {
		fatal(err)
	}

	if err := json.Unmarshal([]byte(os.Getenv("OPT")), &options); err != nil {
		fatal(err)
	}

	if inUserns {
		options.InUserNS = true
	}

	if tmpDir, err = ioutil.TempDir("/", "temp-docker-extract"); err != nil {
		fatal(err)
	}

	os.Setenv("TMPDIR", tmpDir)
	//解压到镜像层的根目录
	size, err := archive.UnpackLayer("/", os.Stdin, options)
	os.RemoveAll(tmpDir)
	if err != nil {
		fatal(err)
	}

	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(applyLayerResponse{size}); err != nil {
		fatal(fmt.Errorf("unable to encode layerSize JSON: %s", err))
	}

	if _, err := flush(os.Stdin); err != nil {
		fatal(err)
	}

	os.Exit(0)
}

// applyLayerHandler parses a diff in the standard layer format from `layer`, and
// applies it to the directory `dest`. Returns the size in bytes of the
// contents of the layer.
func applyLayerHandler(dest string, layer archive.Reader, options *archive.TarOptions, decompress bool) (size int64, err error) {
	//dest其实是镜像层目录下的一个名为tmproot的目录
	dest = filepath.Clean(dest)
	//直接实现为ApplyUncompressedLayer，false，不用解压，之前已经做了
	if decompress {
		decompressed, err := archive.DecompressStream(layer)
		if err != nil {
			return 0, err
		}
		defer decompressed.Close()

		layer = decompressed
	}
	if options == nil {
		options = &archive.TarOptions{}
		if rsystem.RunningInUserNS() {
			options.InUserNS = true
		}
	}
	if options.ExcludePatterns == nil {
		options.ExcludePatterns = []string{}
	}

	data, err := json.Marshal(options)
	if err != nil {
		return 0, fmt.Errorf("ApplyLayer json encode: %v", err)
	}
        //命令在docker/pkg/chrootarchive/init_unix.go注册
	cmd := reexec.Command("docker-applyLayer", dest)
	cmd.Stdin = layer
	cmd.Env = append(cmd.Env, fmt.Sprintf("OPT=%s", data))

	outBuf, errBuf := new(bytes.Buffer), new(bytes.Buffer)
	cmd.Stdout, cmd.Stderr = outBuf, errBuf
	logrus.Debugf("Apply running...with opt:%s",data)
	if err = cmd.Run(); err != nil {
		return 0, fmt.Errorf("ApplyLayer %s stdout: %s stderr: %s", err, outBuf, errBuf)
	}

	// Stdout should be a valid JSON struct representing an applyLayerResponse.
	response := applyLayerResponse{}
	decoder := json.NewDecoder(outBuf)
	if err = decoder.Decode(&response); err != nil {
		return 0, fmt.Errorf("unable to decode ApplyLayer JSON response: %s", err)
	}

	return response.LayerSize, nil
}
