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
	"strings"

	"github.com/anchore/packageurl-go"
	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	pkg2 "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/pkg/cataloger/apkdb"
	"github.com/anchore/syft/syft/pkg/cataloger/deb"
	"github.com/anchore/syft/syft/pkg/cataloger/rpm"
	"github.com/anchore/syft/syft/source"
	"github.com/docker/index-cli-plugin/sbom/detect"
	"github.com/docker/index-cli-plugin/sbom/util"
	"github.com/docker/index-cli-plugin/types"
	"github.com/pkg/errors"
)

type packageMapping map[string]*stereoscopeimage.Layer

func syftSbom(ociPath string, lm types.LayerMapping, resultChan chan<- types.IndexResult) {
	result := types.IndexResult{
		Name:     "syft",
		Status:   types.Success,
		Packages: make([]types.Package, 0),
	}

	defer close(resultChan)

	i := source.Input{
		Scheme:      source.ImageScheme,
		ImageSource: stereoscopeimage.OciDirectorySource,
		Location:    ociPath,
	}
	src, cleanup, err := source.New(i, nil, nil)
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to create image source")
	}
	defer cleanup()

	packageCatalog, packageRelationships, distro, err := syft.CatalogPackages(src, cataloger.DefaultConfig())
	if err != nil {
		result.Status = types.Failed
		result.Error = errors.Wrap(err, "failed to index image")
	}

	d, qualifiers := osQualifiers(distro)
	result.Distro = d

	pm := make(packageMapping, 0)
	for _, layer := range src.Image.Layers {
		layerPkgs := make([]pkg2.Package, 0)
		res := util.NewSingleLayerResolver(layer)
		apkPkgs, _, err := apkdb.NewApkdbCataloger().Catalog(res)
		if err != nil {
			if err != nil {
				result.Status = types.Failed
				result.Error = errors.Wrap(err, "failed to catalog apk packages")
			}
		}
		layerPkgs = append(layerPkgs, apkPkgs...)
		debPkgs, _, err := deb.NewDpkgdbCataloger().Catalog(res)
		if err != nil {
			if err != nil {
				result.Status = types.Failed
				result.Error = errors.Wrap(err, "failed to catalog dep packages")
			}
		}
		layerPkgs = append(layerPkgs, debPkgs...)
		rpmPkgs, _, err := rpm.NewRpmdbCataloger().Catalog(res)
		if err != nil {
			if err != nil {
				result.Status = types.Failed
				result.Error = errors.Wrap(err, "failed to catalog rpm packages")
			}
		}
		layerPkgs = append(layerPkgs, rpmPkgs...)
		for _, p := range layerPkgs {
			if _, ok := pm[toKey(p)]; !ok {
				pm[toKey(p)] = layer
			}
		}
	}

	result.Packages = make([]types.Package, 0)
	packages := packageCatalog.Sorted()
	for _, p := range packages {
		pkg := toPackage(p, packageRelationships, qualifiers, lm, pm)
		result.Packages = append(result.Packages, pkg...)
	}

	result.Packages = append(result.Packages, detect.AdditionalPackages(result.Packages, *src, lm)...)
	resultChan <- result
}

type sourcePackage struct {
	name               string
	overwriteNamespace bool
	version            string
	relationship       string
}

func toPackage(p pkg2.Package, rels []artifact.Relationship, qualifiers map[string]string, lm types.LayerMapping, pm packageMapping) []types.Package {
	pkg := types.Package{
		Purl:      p.PURL,
		Licenses:  p.Licenses,
		Locations: make([]types.Location, 0),
	}

	var sourceNameAndVersion sourcePackage
	var virtualPath string

	switch p.MetadataType {
	case pkg2.AlpmMetadataType:
		md := p.Metadata.(pkg2.AlpmMetadata)
		pkg.Author = md.Packager
		pkg.Description = md.Description
		pkg.Size = md.Size
		pkg.Url = md.URL

		sourceNameAndVersion = sourcePackage{
			name:         md.BasePackage,
			version:      md.Version,
			relationship: "parent",
		}
	case pkg2.ApkMetadataType:
		md := p.Metadata.(pkg2.ApkMetadata)
		pkg.Author = md.Maintainer
		pkg.Description = md.Description
		pkg.Size = md.Size
		pkg.InstalledSize = md.InstalledSize
		pkg.Url = md.URL

		sourceNameAndVersion = sourcePackage{
			name:         md.OriginPackage,
			version:      md.Version,
			relationship: "parent",
		}
	case pkg2.DpkgMetadataType:
		md := p.Metadata.(pkg2.DpkgMetadata)
		pkg.Author = md.Maintainer
		pkg.Description = md.Description
		pkg.InstalledSize = md.InstalledSize

		sourceNameAndVersion = sourcePackage{
			name:         md.Source,
			version:      md.SourceVersion,
			relationship: "parent",
		}
	case pkg2.GolangBinMetadataType:
		md := p.Metadata.(pkg2.GolangBinMetadata)
		sourceNameAndVersion = sourcePackage{
			name:               "stdlib",
			overwriteNamespace: true,
			version:            md.GoCompiledVersion[2:],
			relationship:       "none",
		}
	case pkg2.GemMetadataType:
		md := p.Metadata.(pkg2.GemMetadata)
		pkg.Author = strings.Join(md.Authors, ", ")
	case pkg2.NpmPackageJSONMetadataType:
		md := p.Metadata.(pkg2.NpmPackageJSONMetadata)
		pkg.Author = md.Author
		pkg.Description = md.Description
		if md.Homepage != "" {
			pkg.Url = md.Homepage
		} else {
			pkg.Url = md.URL
		}
	case pkg2.RpmMetadataType:
		md := p.Metadata.(pkg2.RpmMetadata)
		pkg.Size = md.Size
	case pkg2.PythonPackageMetadataType:
		md := p.Metadata.(pkg2.PythonPackageMetadata)
		pkg.Author = md.Author
	case pkg2.PhpComposerJSONMetadataType:
		md := p.Metadata.(pkg2.PhpComposerJSONMetadata)
		pkg.Description = md.Description
		pkg.Url = md.NotificationURL
	case pkg2.PortageMetadataType:
		md := p.Metadata.(pkg2.PortageMetadata)
		pkg.Size = md.InstalledSize
	case pkg2.JavaMetadataType:
		md := p.Metadata.(pkg2.JavaMetadata)
		virtualPath = md.VirtualPath
	case pkg2.ConanLockMetadataType:
	case pkg2.CocoapodsMetadataType:
	case pkg2.KbPackageMetadataType:
	case pkg2.RustCargoPackageMetadataType:
	case pkg2.DotnetDepsMetadataType:
	case pkg2.DartPubMetadataType:
	default:
	}

	for _, rel := range rels {
		if rel.From.ID() == p.ID() {
			if rel.Type != artifact.ContainsRelationship {
				continue
			}
			if corr, ok := rel.To.(source.Coordinates); ok {
				path := corr.RealPath
				if virtualPath != "" && strings.HasPrefix(virtualPath, path) {
					path = virtualPath
				}

				pkg.Files = append(pkg.Files, types.Location{
					Path:   path,
					DiffId: corr.FileSystemID,
					Digest: lm.ByDiffId[corr.FileSystemID],
				})
			}
		}
	}

	locs := p.Locations.ToSlice()
	for _, loc := range locs {
		path := loc.VirtualPath
		if virtualPath != "" && strings.HasPrefix(virtualPath, path) {
			path = virtualPath
		}

		pkg.Locations = append(pkg.Locations, types.Location{
			Path:   path,
			DiffId: loc.FileSystemID,
			Digest: lm.ByDiffId[loc.FileSystemID],
		})
	}

	// fix up the package manager files
	for i, loc := range pkg.Locations {
		if loc.Path == "/lib/apk/db/installed" || loc.Path == "/var/lib/dpkg/status" || loc.Path == "/var/lib/rpm/Packages" {
			layer := pm[toKey(p)]
			// the stereoscope layers use diff_ids internally as their digest
			pkg.Locations[i].DiffId = layer.Metadata.Digest
			pkg.Locations[i].Digest = lm.ByDiffId[layer.Metadata.Digest]
		}
	}

	// bring qualifiers into form we understand
	purl, _ := packageurl.FromString(pkg.Purl)
	if purl.Type == "deb" || purl.Type == "rpm" || purl.Type == "alpine" {
		purl.Qualifiers = packageurl.QualifiersFromMap(qualifiers)
	}
	purl.Version = p.Version
	pkg.Purl = purl.String()

	// add package for source packages
	if sourceNameAndVersion.name != "" {
		if sourceNameAndVersion.overwriteNamespace {
			purl.Namespace = ""
		}
		purl.Name = sourceNameAndVersion.name
		if sourceNameAndVersion.version != "" {
			purl.Version = sourceNameAndVersion.version
		}
		url := purl.String()
		sourcePkg := types.Package{
			Purl:          url,
			Licenses:      pkg.Licenses,
			Author:        pkg.Author,
			Description:   pkg.Description,
			Size:          pkg.Size,
			InstalledSize: pkg.InstalledSize,
			Url:           pkg.Url,
			Locations:     pkg.Locations,
		}
		if sourceNameAndVersion.relationship == "parent" {
			pkg.Parent = url
		}
		return []types.Package{pkg, sourcePkg}
	}

	return []types.Package{pkg}
}

func osQualifiers(release *linux.Release) (types.Distro, map[string]string) {
	qualifiers := make(map[string]string, 0)
	distro := types.Distro{}
	if release == nil {
		return distro, qualifiers
	}
	if release.ID != "" {
		distro.OsName = release.ID
	} else if release.Name != "" {
		distro.OsName = release.Name
	}
	if release.Version != "" {
		distro.OsVersion = release.Version
	} else if release.VersionID != "" {
		distro.OsVersion = release.VersionID
	}

	if v, ok := types.NamespaceMapping[distro.OsName]; ok {
		distro.OsName = v
	}

	if distro.OsVersion != "" {
		// alpine: with comma
		// amazonlinux: single digit
		// debian: single digit
		// oraclelinux: single digit
		// redhatlinux: single digit
		// centos: single digit
		// ubuntu: with comma
		version := strings.Split(distro.OsVersion, " ")[0]
		parts := strings.Split(version, ".")
		if distro.OsName == "alpine" || distro.OsName == "ubuntu" {
			distro.OsVersion = strings.Join(parts[0:2], ".")
		} else {
			distro.OsVersion = parts[0]
		}
	} else if distro.OsName == "debian" {
		distro.OsVersion = "unstable"
	}

	if release.VersionCodename != "" {
		distro.OsDistro = release.VersionCodename
	}

	qualifiers["os_name"] = distro.OsName
	qualifiers["os_version"] = distro.OsVersion
	if distro.OsDistro != "" {
		qualifiers["os_distro"] = distro.OsDistro
	}
	return distro, qualifiers
}

func toKey(p pkg2.Package) string {
	purl := packageurl.PackageURL{
		Name:    p.Name,
		Type:    string(p.Type),
		Version: p.Version,
	}
	return purl.String()
}
