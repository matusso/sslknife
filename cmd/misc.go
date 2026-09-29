package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/matusso/sslknife/internal/buildinfo"
	"github.com/matusso/sslknife/internal/config"
	"github.com/matusso/sslknife/internal/database"
)

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := buildinfo.Get()
			return a.out.Emit(info, func(w io.Writer) error {
				fmt.Fprintf(w, "SSLKnife %s\ncommit: %s\nbuilt: %s\ngo: %s\nos/arch: %s/%s\n",
					info.Version, info.Commit, info.Built, info.GoVersion, info.OS, info.Arch)
				return nil
			})
		},
	}
}

func newConfigCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or create the configuration file",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if a.out.Machine() {
				return a.out.Emit(a.cfg, nil)
			}
			data, err := a.cfg.Marshal()
			if err != nil {
				return err
			}
			_, err = a.stdout.Write(data)
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print the config, database and key file locations",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			cfgPath := a.flags.configPath
			if cfgPath == "" {
				cfgPath, _ = config.DefaultConfigPath()
			}
			v := map[string]string{"config": cfgPath, "database": a.cfg.Database.Path, "key_file": database.KeyFilePath(a.cfg.Database.Path)}
			return a.out.Emit(v, func(w io.Writer) error {
				fmt.Fprintf(w, "config:   %s\ndatabase: %s\nkey file: %s\n", v["config"], v["database"], v["key_file"])
				return nil
			})
		},
	})
	var force bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a config file with the default settings",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			path := a.flags.configPath
			if path == "" {
				var err error
				if path, err = config.DefaultConfigPath(); err != nil {
					return err
				}
			}
			def, err := config.Default()
			if err != nil {
				return err
			}
			data, err := def.Marshal()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := writeNewFile(path, data, 0o600, force); err != nil {
				return err
			}
			a.out.Infof("Wrote %s", path)
			return nil
		},
	}
	initCmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	cmd.AddCommand(initCmd)
	return cmd
}

// newDocsCmd generates the Markdown command reference (docs/commands).
func newDocsCmd(root *cobra.Command) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:    "docs",
		Short:  "Generate the Markdown command reference",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return err
			}
			root.DisableAutoGenTag = true
			return doc.GenMarkdownTree(root, dir)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "docs/commands", "output directory")
	return cmd
}
