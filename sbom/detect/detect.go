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
	"github.com/anchore/syft/syft/source"
	"github.com/docker/index-cli-plugin/types"
)

type PackageDetector = func(packages []types.Package, image source.Source, lm types.LayerMapping) []types.Package

var detectors []PackageDetector

func init() {
	detectors = []PackageDetector{nodePackageDetector}
}

func AdditionalPackages(packages []types.Package, image source.Source, lm types.LayerMapping) []types.Package {
	additionalPackages := make([]types.Package, 0)
	for _, d := range detectors {
		additionalPackages = append(additionalPackages, d(packages, image, lm)...)
	}
	return additionalPackages
}
