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

package sbom

import (
	"testing"

	"github.com/docker/index-cli-plugin/types"
)

func TestMergePackages(t *testing.T) {
	pkga := types.Package{
		Purl: "pkg:maven/foo@1.0.0",
		Files: []types.Location{{
			Path:   "/bar",
			Digest: "sha256:1234",
			DiffId: "sha256:1234",
		}},
	}
	pkgb := types.Package{
		Purl: "pkg:maven/foo@1.0.0",
		Files: []types.Location{{
			Path:   "/bar",
			Digest: "sha256:1234",
			DiffId: "sha256:1234",
		}, {
			Path:   "/bla",
			Digest: "sha256:5678",
			DiffId: "sha256:5678",
		}},
	}
	packages := mergePackages(types.IndexResult{
		Status:   types.Success,
		Packages: []types.Package{pkga},
	}, types.IndexResult{
		Status:   types.Success,
		Packages: []types.Package{pkgb},
	})
	if len(packages) != 1 {
		t.Error("expected 1 package")
	}
	fpkg := packages[0]
	if len(fpkg.Files) != 2 {
		t.Error("expected 2 files")
	}
}
