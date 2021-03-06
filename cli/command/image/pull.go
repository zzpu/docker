package image

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/context"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
	"github.com/spf13/cobra"
)

type pullOptions struct {
	remote string
	all    bool
}

// NewPullCommand creates a new `docker pull` command
func NewPullCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts pullOptions

	cmd := &cobra.Command{
		Use:   "pull [OPTIONS] NAME[:TAG|@DIGEST]",
		Short: "Pull an image or a repository from a registry",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]
			return runPull(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.all, "all-tags", "a", false, "Download all tagged images in the repository")
	command.AddTrustedFlags(flags, true)

	return cmd
}

func runPull(dockerCli *command.DockerCli, opts pullOptions) error {
	distributionRef, err := reference.ParseNamed(opts.remote)
	if err != nil {
		return err
	}
	// -a, --all-tags                Download all tagged images in the repository
	//如果使用了all选项，但是又不是只有镜像名（包含tag），则报错处理
	if opts.all && !reference.IsNameOnly(distributionRef) {
		return errors.New("tag can't be used with --all-tags/-a")
	}
	//如果没有使用all选项，且只有镜像名，则添加一个默认的tag（latest）
	if !opts.all && reference.IsNameOnly(distributionRef) {
		distributionRef = reference.WithDefaultTag(distributionRef)
		fmt.Fprintf(dockerCli.Out(), "Using default tag: %s\n", reference.DefaultTag)
	}

	var tag string
	switch x := distributionRef.(type) {
	//标准的
	case reference.Canonical:
		tag = x.Digest().String()
	//name:tag形式
	case reference.NamedTagged:
		tag = x.Tag()
	}

	registryRef := registry.ParseReference(tag)

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(distributionRef)
	if err != nil {
		return err
	}

	ctx := context.Background()

	authConfig := command.ResolveAuthConfig(ctx, dockerCli, repoInfo.Index)
	requestPrivilege := command.RegistryAuthenticationPrivilegedFunc(dockerCli, repoInfo.Index, "pull")
        //如果没有添加禁止信任镜像内容选项disable-content-trust,而且没有附带数字摘要,则不对镜像进行校验
	if command.IsTrusted() && !registryRef.HasDigest() {
		// Check if tag is digest
		err = trustedPull(ctx, dockerCli, repoInfo, registryRef, authConfig, requestPrivilege)
	} else {
		err = imagePullPrivileged(ctx, dockerCli, authConfig, distributionRef.String(), requestPrivilege, opts.all)
	}
	if err != nil {
		if strings.Contains(err.Error(), "target is a plugin") {
			return errors.New(err.Error() + " - Use `docker plugin install`")
		}
		return err
	}

	return nil
}
