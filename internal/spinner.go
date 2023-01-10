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

package internal

import (
	"fmt"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/gookit/color"
	"github.com/sirupsen/logrus"

	"github.com/atomist-skills/go-skill"
)

type Fields map[string]interface{}

type Spinner struct {
	level      string
	spinner    *spinner.Spinner
	isTerminal bool
	fields     map[string]interface{}
}

func (s *Spinner) WithFields(fields map[string]interface{}) *Spinner {
	s.fields = fields
	return s
}

func (s *Spinner) Update(text string) {
	if s.isTerminal {
		s.spinner.Prefix = fmt.Sprintf("%s %s ", colorizeLevel(s.level), text)
	} else {
		l, _ := logrus.ParseLevel(s.level)
		skill.Log.WithFields(s.fields).Log(l, text)
	}
}

func (s *Spinner) Stop() {
	if s.isTerminal {
		s.spinner.Stop()
	}
}

func StartInfoSpinner(text string, isTerminal bool) *Spinner {
	return StartSpinner("info", text, isTerminal)
}

func StartSpinner(level string, text string, isTerminal bool) *Spinner {
	if isTerminal {
		s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		_ = s.Color("yellow")

		spinner := &Spinner{
			level:      level,
			spinner:    s,
			isTerminal: true,
		}
		spinner.Update(text)
		s.Start()
		return spinner
	} else {
		spinner := &Spinner{
			level:      level,
			isTerminal: false,
		}
		spinner.Update(text)
		return spinner
	}
}

func colorizeLevel(level string) string {
	switch s := strings.ToUpper(level); s {
	case "INFO":
		return color.Cyan.Sprint(s)
	case "DEBUG":
		return s
	default:
		return s
	}
}
