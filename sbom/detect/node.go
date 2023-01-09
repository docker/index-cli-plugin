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

package detect

import (
	"regexp"

	"github.com/docker/index-cli-plugin/types"
)

func nodePackageDetector() PackageDetector {
	expr := regexp.MustCompile(`node\.js/v(.*)`)
	pkg := types.Package{
		Type:        "github",
		Namespace:   "nodejs",
		Name:        "node",
		Author:      "Node.js Project",
		Description: "Node.js JavaScript runtime",
		Licenses:    []string{"MIT"},
		Url:         "https://nodejs.org",
	}
	filter := func(purl string) bool {
		pkg, _ := types.ToPackageUrl(purl)
		return pkg.Name == "nodejs" || pkg.Name == "node"
	}
	return stringsNodeDetector("node", "NODE_VERSION", expr, pkg, filter)
}
