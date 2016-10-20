package main

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cli"
	cliflags "github.com/docker/docker/cli/flags"
	"github.com/docker/docker/daemon"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/pkg/reexec"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type daemonOptions struct {
	version      bool
	configFile   string
	daemonConfig *daemon.Config
	common       *cliflags.CommonOptions
	flags        *pflag.FlagSet
}

func newDaemonCommand() *cobra.Command {
	opts := daemonOptions{
		daemonConfig: daemon.NewConfig(),
		common:       cliflags.NewCommonOptions(),//comm 选项空白对象
	}
        //根命令
	cmd := &cobra.Command{
		Use:           "dockerd [OPTIONS]",
		Short:         "A self-sufficient runtime for containers.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cli.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.flags = cmd.Flags()
			//根命令回调函数
			return runDaemon(opts)
		},
	}
	cli.SetupRootCommand(cmd)

	flags := cmd.Flags()
	flags.BoolVarP(&opts.version, "version", "v", false, "Print version information and quit")
	//默认配置文件"/etc/docker/daemon.json"
	flags.StringVar(&opts.configFile, flagDaemonConfigFile, defaultDaemonConfigFile, "Daemon configuration file")

	//通过install，从flag获取选项值，并将相应值传到各个模块
	opts.common.InstallFlags(flags)
	opts.daemonConfig.InstallFlags(flags)
	//在linux下执行空白函数
	installServiceFlags(flags)

	return cmd
}

func runDaemon(opts daemonOptions) error {
	if opts.version {
		showVersion()
		return nil
	}
        //空的命令行终端
	daemonCli := NewDaemonCli()

	// On Windows, this may be launching as a service or with an option to
	// register the service.
	//在linux下不会执行
	stop, err := initService(daemonCli)
	if err != nil {
		logrus.Fatal(err)
	}

	if stop {
		return nil
	}
       //启动一个server
	err = daemonCli.start(opts)
	notifyShutdown(err)
	return err
}

func showVersion() {
	if utils.ExperimentalBuild() {
		fmt.Printf("Docker version %s, build %s, experimental\n", dockerversion.Version, dockerversion.GitCommit)
	} else {
		fmt.Printf("Docker version %s, build %s\n", dockerversion.Version, dockerversion.GitCommit)
	}
}

func main() {
	if reexec.Init() {
		return
	}

	// Set terminal emulation based on platform as required.
	_, stdout, stderr := term.StdStreams()
	logrus.SetOutput(stderr)

	cmd := newDaemonCommand()
	cmd.SetOutput(stdout)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		os.Exit(1)
	}
}
