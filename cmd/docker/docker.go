package main

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/cli/command/commands"
	cliflags "github.com/docker/docker/cli/flags"
	"github.com/docker/docker/cliconfig"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newDockerCommand(dockerCli *command.DockerCli) *cobra.Command {
	//选项结构对象，之后通过传入的选项选项参数进行填充
	opts := cliflags.NewClientOptions()
	//选项集合
	var flags *pflag.FlagSet
       //定义主命令
	cmd := &cobra.Command{
		Use:              "docker [OPTIONS] COMMAND [arg...]",
		Short:            "A self-sufficient runtime for containers.",
		SilenceUsage:     true,
		SilenceErrors:    true,
		TraverseChildren: true,
		Args:             noArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Version {
				showVersion()
				return nil
			}
			fmt.Fprintf(dockerCli.Err(), "\n"+cmd.UsageString())
			return nil
		},
		//在run之前执行
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// flags must be the top-level command flags, not cmd.Flags()
			opts.Common.SetDefaultOptions(flags)
			dockerPreRun(opts)
			//初始化一个client
			return dockerCli.Initialize(opts)
		},
	}
	
	//设置默认的处理方式
	cli.SetupRootCommand(cmd)
        //为主命令添加选项
	flags = cmd.Flags()
	flags.BoolVarP(&opts.Version, "version", "v", false, "Print version information and quit")
	flags.StringVar(&opts.ConfigDir, "config", cliconfig.ConfigDir(), "Location of client config files")
	//为主命令添加公共选项
	opts.Common.InstallFlags(flags)
        //设置命令的输入
	cmd.SetOutput(dockerCli.Out())
	//添加daemon选项，其实已经作废了，应为新代码已经将客户端和服务端守护进程命令分开了，不需要这个选项区分启动客户端还是服务端
	cmd.AddCommand(newDaemonCommand())
	// AddCommands adds all the commands from cli/command to the root command
	//添加子命令及子命令的选项
	commands.AddCommands(cmd, dockerCli)

	return cmd
}

func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf(
		"docker: '%s' is not a docker command.\nSee 'docker --help'%s", args[0], ".")
}

func main() {
	// Set terminal emulation based on platform as required.
	stdin, stdout, stderr := term.StdStreams()
	logrus.SetOutput(stderr)

	dockerCli := command.NewDockerCli(stdin, stdout, stderr)
	//主命令
	cmd := newDockerCommand(dockerCli)
       //执行命令
	if err := cmd.Execute(); err != nil {
		if sterr, ok := err.(cli.StatusError); ok {
			if sterr.Status != "" {
				fmt.Fprintln(stderr, sterr.Status)
			}
			// StatusError should only be used for errors, and all errors should
			// have a non-zero exit status, so never exit with 0
			if sterr.StatusCode == 0 {
				os.Exit(1)
			}
			os.Exit(sterr.StatusCode)
		}
		fmt.Fprintln(stderr, err)
		os.Exit(1)
	}
}

func showVersion() {
	if utils.ExperimentalBuild() {
		fmt.Printf("Docker version %s, build %s, experimental\n", dockerversion.Version, dockerversion.GitCommit)
	} else {
		fmt.Printf("Docker version %s, build %s\n", dockerversion.Version, dockerversion.GitCommit)
	}
}

func dockerPreRun(opts *cliflags.ClientOptions) {
	cliflags.SetDaemonLogLevel(opts.Common.LogLevel)

	if opts.ConfigDir != "" {
		cliconfig.SetConfigDir(opts.ConfigDir)
	}
        // 调试选项
	if opts.Common.Debug {
		utils.EnableDebug()
	}
}
