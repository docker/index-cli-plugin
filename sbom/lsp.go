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
	"github.com/docker/cli/cli/command"
	cliflags "github.com/docker/cli/cli/flags"
	"github.com/pkg/errors"
)

func Send(image string, tx chan<- string) error {
	cmd, err := command.NewDockerCli()
	if err != nil {
		return errors.Wrap(err, "failed to create docker cli")
	}
	if err := cmd.Initialize(cliflags.NewClientOptions()); err != nil {
		return errors.Wrap(err, "failed to initialize docker cli")
	}
	sbom, err := IndexImage(image, cmd)
	if err != nil {
		return errors.Wrap(err, "failed to create sbom")
	}
	err = sendSbom(sbom, tx)
	if err != nil {
		return errors.Wrap(err, "failed to send sbom")
	}
	close(tx)
	return nil
}
