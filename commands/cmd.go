/*
 * Copyright © 2022 Docker, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/docker/cli/cli/command"
	"github.com/docker/index-cli-plugin/query"
	"github.com/docker/index-cli-plugin/sbom"
	"github.com/docker/index-cli-plugin/types"
	"github.com/docker/index-cli-plugin/util"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/term"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewRootCmd(name string, isPlugin bool, dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Short: "Docker Index",
		Long:  `Index Docker images, create SBOMs and detect CVEs`,
		Use:   name,
	}
	if isPlugin {
		cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			return plugin.PersistentPreRunE(cmd, args)
		}
	} else {
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.TraverseChildren = true
		cmd.DisableFlagsInUseLine = true
		cli.DisableFlagsInUseLine(cmd)
	}

	skill.Log.SetOutput(os.Stderr)
	if dockerCli.Out().IsTerminal() {
		skill.Log.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp:       true,
			DisableLevelTruncation: true,
		})
	} else {
		skill.Log.SetFormatter(&logrus.JSONFormatter{})
	}

	config := dockerCli.ConfigFile()

	var (
		output, ociDir, image, workspace    string
		apiKeyStdin, includeCves, remediate bool
	)

	logoutCommand := &cobra.Command{
		Use:   "logout",
		Short: "Remove Atomist workspace authentication",
		RunE: func(cmd *cobra.Command, _ []string) error {
			config.SetPluginConfig("index", "workspace", "")
			config.SetPluginConfig("index", "api-key", "")
			return config.Save()
		},
	}

	loginCommand := &cobra.Command{
		Use:   "login WORKSPACE",
		Short: "Authenticate with Atomist workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			workspace, err := readWorkspace(args, dockerCli)
			if err != nil {
				return err
			}
			apiKey, err := readApiKey(apiKeyStdin, dockerCli)
			if err != nil {
				return err
			}
			if valid, err := query.CheckAuth(workspace, apiKey); err == nil && valid {
				fmt.Println("Login successful")
				config.SetPluginConfig("index", "workspace", workspace)
				config.SetPluginConfig("index", "api-key", apiKey)
				return config.Save()
			} else {
				return errors.New("Login failed")
			}
		},
	}
	loginCommandFlags := loginCommand.Flags()
	loginCommandFlags.BoolVar(&apiKeyStdin, "api-key-stdin", false, "Atomist API key")

	sbomCommand := &cobra.Command{
		Use:   "sbom [OPTIONS]",
		Short: "Write SBOM file",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var sb *types.Sbom

			if ociDir == "" {
				sb, _, err = sbom.IndexImage(image, dockerCli)
			} else {
				sb, _, err = sbom.IndexPath(ociDir, image, dockerCli)
			}
			if err != nil {
				return err
			}
			if includeCves {
				workspace, _ := config.PluginConfig("index", "workspace")
				apiKey, _ := config.PluginConfig("index", "api-key")
				cves, err := query.QueryCves(sb, "", workspace, apiKey)
				if err != nil {
					return err
				}
				sb.Vulnerabilities = *cves
			}

			js, err := json.MarshalIndent(sb, "", "  ")
			if err != nil {
				return err
			}
			if output != "" {
				_ = os.WriteFile(output, js, 0644)
				skill.Log.Infof("SBOM written to %s", output)
			} else {
				fmt.Println(string(js))
			}
			return nil
		},
	}
	sbomCommandFlags := sbomCommand.Flags()
	sbomCommandFlags.StringVarP(&output, "output", "o", "", "Location path to write SBOM to")
	sbomCommandFlags.StringVarP(&image, "image", "i", "", "Image reference to index")
	sbomCommandFlags.StringVarP(&ociDir, "oci-dir", "d", "", "Path to image in OCI format")
	sbomCommandFlags.BoolVarP(&includeCves, "include-cves", "c", false, "Include package CVEs")

	uploadCommand := &cobra.Command{
		Use:   "upload [OPTIONS]",
		Short: "Upload SBOM",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			if workspace == "" {
				workspace, _ = config.PluginConfig("index", "workspace")
				if workspace == "" {
					workspace, err = readWorkspace(args, dockerCli)
					if err != nil {
						return err
					}
				}
			}

			apiKey, _ := config.PluginConfig("index", "api-key")
			if apiKey == "" {
				apiKey, err = readApiKey(apiKeyStdin, dockerCli)
				if err != nil {
					return err
				}
			}

			var sb *types.Sbom
			var img *v1.Image
			if ociDir == "" {
				sb, img, err = sbom.IndexImage(image, dockerCli)
			} else {
				sb, img, err = sbom.IndexPath(ociDir, image, dockerCli)
			}
			if err != nil {
				return err
			}
			err = sbom.UploadSbom(sb, img, workspace, apiKey)

			return nil
		},
	}
	uploadCommandFlags := uploadCommand.Flags()
	uploadCommandFlags.StringVar(&image, "image", "", "Image reference to index")
	uploadCommandFlags.StringVar(&ociDir, "oci-dir", "", "Path to image in OCI format")
	uploadCommandFlags.StringVar(&workspace, "workspace", "", "Atomist workspace")
	uploadCommandFlags.BoolVar(&apiKeyStdin, "api-key-stdin", false, "Atomist API key")

	cveCommand := &cobra.Command{
		Use:   "cve [OPTIONS] CVE_ID",
		Short: "Check if image is vulnerable to given CVE",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf(`"docker index cve" requires exactly 1 argument`)
			}
			cve := args[0]
			var err error
			var sb *types.Sbom
			var img *v1.Image

			if ociDir == "" {
				sb, img, err = sbom.IndexImage(image, dockerCli)
			} else {
				sb, img, err = sbom.IndexPath(ociDir, image, dockerCli)
			}
			if err != nil {
				return err
			}
			workspace, _ := config.PluginConfig("index", "workspace")
			apiKey, _ := config.PluginConfig("index", "api-key")
			cves, err := query.QueryCves(sb, cve, workspace, apiKey)
			if err != nil {
				return err
			}

			if len(*cves) > 0 {
				for _, c := range *cves {
					types.FormatCve(sb, &c)

					if !remediate {
						continue
					}

					var remediation = make([]string, 0)
					layerIndex := -1
					for _, p := range sb.Artifacts {
						if p.Purl == c.Purl {
							loc := p.Locations[0]
							for i, l := range sb.Source.Image.Config.RootFS.DiffIDs {
								if l.String() == loc.DiffId && layerIndex < i {
									layerIndex = i
								}
							}

							if rem := types.FormatPackageRemediation(p, c); rem != "" {
								remediation = append(remediation, rem)
							}
						}
					}

					// see if the package comes in via the base image
					s := util.StartInfoSpinner("Detecting base image", dockerCli.Out().IsTerminal())
					defer s.Stop()
					baseImages, index, _ := query.Detect(img, true, workspace, apiKey)
					s.Stop()
					var baseImage *types.Image
					if layerIndex <= index && baseImages != nil && len(*baseImages) > 0 {
						baseImage = &(*baseImages)[0]

						fmt.Println("")
						fmt.Println("installed in base image")
						fmt.Println("")
						fmt.Println(types.FormatImage(baseImage))
					}

					if baseImage != nil {
						s := util.StartInfoSpinner("Finding alternative base images", dockerCli.Out().IsTerminal())
						defer s.Stop()
						aBaseImage, _ := query.ForBaseImageWithoutCve(c.SourceId, baseImage.Repository.Name, img, workspace, apiKey)
						s.Stop()
						if aBaseImage != nil && len(*aBaseImage) > 0 {
							e := []string{fmt.Sprintf("Update base image\n\nAlternative base images not vulnerable to %s", c.SourceId)}
							for _, a := range *aBaseImage {
								e = append(e, types.FormatImage(&a))
							}
							remediation = append(remediation, strings.Join(e, "\n\n"))
						}
					}

					types.FormatRemediation(remediation)
				}

				os.Exit(1)
			} else {
				fmt.Println(fmt.Sprintf("%s not detected", cve))
				os.Exit(0)
			}
			return nil
		},
	}
	cveCommandFlags := cveCommand.Flags()
	cveCommandFlags.StringVarP(&image, "image", "i", "", "Image reference to index")
	cveCommandFlags.StringVarP(&ociDir, "oci-dir", "d", "", "Path to image in OCI format")
	cveCommandFlags.BoolVarP(&remediate, "remediate", "r", false, "Include suggested remediation")

	diffCommand := &cobra.Command{
		Use:   "diff [OPTIONS]",
		Short: "Diff images",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sbom.DiffImages(args[0], args[1], dockerCli, "", "")
		},
	}

	cmd.AddCommand(loginCommand, logoutCommand, sbomCommand, cveCommand, uploadCommand, diffCommand)
	return cmd
}

func readWorkspace(args []string, cli command.Cli) (string, error) {
	var workspace string
	if len(args) == 1 {
		workspace = args[0]
	} else if v, ok := os.LookupEnv("ATOMIST_WORKSPACE"); v != "" && ok {
		workspace = v
	} else {
		fmt.Fprintf(cli.Out(), "Workspace: ")

		workspace = readInput(cli.In(), cli.Out())
		if workspace == "" {
			return "", errors.Errorf("Error: Workspace required")
		}
	}
	return workspace, nil
}

func readApiKey(apiKeyStdin bool, cli command.Cli) (string, error) {
	var apiKey string

	if apiKeyStdin {
		contents, err := io.ReadAll(cli.In())
		if err != nil {
			return "", err
		}

		apiKey = strings.TrimSuffix(string(contents), "\n")
		apiKey = strings.TrimSuffix(apiKey, "\r")
	} else if v, ok := os.LookupEnv("ATOMIST_API_KEY"); v != "" && ok {
		apiKey = v
	} else {
		oldState, err := term.SaveState(cli.In().FD())
		if err != nil {
			return "", err
		}
		fmt.Fprintf(cli.Out(), "API key: ")
		term.DisableEcho(cli.In().FD(), oldState)

		apiKey = readInput(cli.In(), cli.Out())
		fmt.Fprint(cli.Out(), "\n")
		term.RestoreTerminal(cli.In().FD(), oldState)
		if apiKey == "" {
			return "", errors.Errorf("Error: API key required")
		}
	}
	return apiKey, nil
}

func readInput(in io.Reader, out io.Writer) string {
	reader := bufio.NewReader(in)
	line, _, err := reader.ReadLine()
	if err != nil {
		fmt.Fprintln(out, err.Error())
		os.Exit(1)
	}
	return string(line)
}
