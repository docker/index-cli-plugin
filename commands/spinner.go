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
	"fmt"
	"time"

	"github.com/briandowns/spinner"
	"github.com/gookit/color"
)

func StartInfoSpinner(text string) *spinner.Spinner {
	return StartSpinner(color.Cyan.Sprint("INFO"), text)
}

func StartSpinner(level string, text string) *spinner.Spinner {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Prefix = fmt.Sprintf("%s %s ", level, text)
	s.Color("yellow")
	s.Start()
	return s
}
