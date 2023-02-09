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

package query

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/hasura/go-graphql-client"
	"github.com/pkg/errors"
	"olympos.io/encoding/edn"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/index-cli-plugin/internal"
	"github.com/docker/index-cli-plugin/internal/ddhttp"
	"github.com/docker/index-cli-plugin/types"
)

type CveResult struct {
	Cves []types.Cve `edn:"cves"`
}

type QueryResult struct {
	Query struct {
		Data []CveResult `edn:"data"`
	} `edn:"query"`
}

//go:embed enabled_skills.edn
var enabledSkillsQuery string

//go:embed package_cves.edn
var packageCvesQuery string

//go:embed package_cve.edn
var packageCveQuery string

func CheckAuth(workspace string, apiKey string) (bool, error) {
	resp, err := query(enabledSkillsQuery, "auth_check", workspace, apiKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to check auth")
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != 200 || err != nil {
		return false, nil
	}
	return true, nil
}

func QueryCves(sb *types.Sbom, cve string, workspace string, apiKey string) (*[]types.Cve, error) {
	pkgs := make([]string, 0)
	for _, p := range sb.Artifacts {
		pkgs = append(pkgs, fmt.Sprintf(`["%s" "%s" "%s" "%s"]`, p.Purl, p.Type, p.Version, types.ToAdvisoryUrl(p)))
	}

	var q, name string
	if cve == "" {
		q = fmt.Sprintf(packageCvesQuery, strings.Join(pkgs, " "))
		name = "cves_query"
	} else {
		q = fmt.Sprintf(packageCveQuery, cve, strings.Join(pkgs, " "))
		name = "cve_query"
	}
	resp, err := query(q, name, workspace, apiKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to run query")
	}
	var result QueryResult
	defer resp.Body.Close() //nolint:errcheck
	err = edn.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal response")
	}
	if len(result.Query.Data) > 0 {
		if len(result.Query.Data[0].Cves) == 1 {
			skill.Log.Infof("Detected %d vulnerability", len(result.Query.Data[0].Cves))
		} else {
			skill.Log.Infof("Detected %d vulnerabilities", len(result.Query.Data[0].Cves))
		}
		fcves := internal.UniqueBy(result.Query.Data[0].Cves, func(cve types.Cve) string {
			if cve.Cve != nil {
				return fmt.Sprintf("%s %s", cve.Purl, cve.Cve.SourceId)
			} else {
				return fmt.Sprintf("%s %s", cve.Purl, cve.Advisory.SourceId)
			}
		})
		return &fcves, nil
	} else {
		return nil, nil
	}
}

func query(query string, name string, workspace string, apiKey string) (*http.Response, error) {
	url := fmt.Sprintf("https://api.dso.docker.com/datalog/team/%s/queries", workspace)
	if workspace == "" || apiKey == "" {
		url = "https://api.dso.docker.com/datalog/shared-vulnerability/queries"
	}
	query = fmt.Sprintf(`{:queries [{:name "query" :query %s}]}`, query)
	skill.Log.Debugf("Query %s", query)
	client := ddhttp.DefaultClient()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(query))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create http request")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Content-Type", "application/edn")
	req.Header.Set("X-Docker-Client", fmt.Sprintf("index-cli-plugin/%s", internal.FromBuild().Version))
	req.Header.Set("X-Docker-Query", name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create http client")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to run query")
	}
	skill.Log.Debugf("Query response %s", resp.Status)
	return resp, nil
}

func ForVulnerabilitiesInGraphQL(sb *types.Sbom) (*types.VulnerabilitiesByPurls, error) {
	url := "https://api.dso.docker.com/v1/graphql"
	client := graphql.NewClient(url, ddhttp.DefaultClient())

	purls := make([]string, 0)
	for _, p := range sb.Artifacts {
		purls = append(purls, p.Purl)
	}

	variables := map[string]interface{}{
		"purls": purls,
	}

	var q types.VulnerabilitiesByPurls
	err := client.Query(context.Background(), &q, variables)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to run query")
	}
	if len(q.VulnerabilitiesByPackage) > 0 {
		if len(q.VulnerabilitiesByPackage) == 1 {
			skill.Log.Infof("Detected 1 vulnerable package")
		} else {
			skill.Log.Infof("Detected %d vulnerable packages", len(q.VulnerabilitiesByPackage))
		}
	}
	return &q, nil
}
