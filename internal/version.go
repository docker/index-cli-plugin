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

/*
Package internal contains all build time metadata (version, build time, git commit, etc).
*/
package internal

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// build-time arguments
var (
	version = "n/a"
	commit  = "n/a"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				commit = setting.Value
			}
		}
	}
}

// Version information from build time args and environment
type Version struct {
	Version   string
	Commit    string
	GoVersion string
	Compiler  string
	Platform  string

	SbomVersion string
}

// FromBuild provides all version details
func FromBuild() Version {
	return Version{
		Version:   fmt.Sprintf("v%s", version),
		Commit:    commit,
		GoVersion: runtime.Version(),
		Compiler:  runtime.Compiler,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),

		SbomVersion: "6",
	}
}
