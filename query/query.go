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
	_ "embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/atomist-skills/go-skill"
	"github.com/docker/index-cli-plugin/sbom"
	"github.com/pkg/errors"
	"olympos.io/encoding/edn"
)

type CveResult struct {
	Cves []sbom.Cve `edn:"cves"`
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

func CheckAuth(workspace string, apiKey string) (bool, error) {
	resp, err := query(enabledSkillsQuery, workspace, apiKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to check auth")
	}
	if resp.StatusCode != 200 || err != nil {
		return false, nil
	}
	return true, nil
}

func QueryCves(sb *sbom.Sbom, workspace string, apiKey string) (*[]sbom.Cve, error) {
	pkgs := make([]string, 0)
	for _, p := range sb.Artifacts {
		pkgs = append(pkgs, fmt.Sprintf(`["%s" "%s" "%s" "%s"]`, p.Purl, p.Type, p.Version, sbom.ToAdvisoryUrl(p)))
	}

	resp, err := query(fmt.Sprintf(packageCvesQuery, strings.Join(pkgs, " ")), workspace, apiKey)
	if workspace == "" || apiKey == "" {
		var result QueryResult
		err = edn.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal response")
		}
		if len(result.Query.Data) > 0 {
			skill.Log.Infof("Detected %d vulnerabilities", len(result.Query.Data[0].Cves))
			return &result.Query.Data[0].Cves, nil
		} else {
			return nil, nil
		}
	} else {
		var cves []CveResult
		err = edn.NewDecoder(resp.Body).Decode(&cves)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal response")
		}
		skill.Log.Infof("Detected %d vulnerabilities", len(cves[0].Cves))
		return &cves[0].Cves, nil
	}
}

func query(query string, workspace string, apiKey string) (*http.Response, error) {
	url := "https://api.dso.docker.com/datalog/team/" + workspace
	if workspace == "" || apiKey == "" {
		url = "https://api.dso.docker.com/datalog/shared-vulnerability/queries"
		query = fmt.Sprintf(`{:queries [{:name "query" :query %s}]}`, query)
	} else {
		query = fmt.Sprintf(`{:query %s}`, query)
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(query))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create http request")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Content-Type", "application/edn")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create http client")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to run query")
	}
	return resp, nil
}
