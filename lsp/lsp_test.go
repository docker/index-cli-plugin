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

package lsp

import (
	"testing"
)

func TestSend(t *testing.T) {
	tx := make(chan string, 10)
	transactions := make([]string, 0)

	err := New().Send("alpine@sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c", tx)
	if err != nil {
		t.Fail()
	}
	for elem := range tx {
		transactions = append(transactions, elem)
	}
	if len(transactions) != 3 {
		t.Errorf("expected 3 transactions, instead got %d", len(transactions))
	}
}

func TestSendFileHashes(t *testing.T) {
	tx := make(chan string, 100)
	transactions := make([]string, 0)

	err := New().SendFileHashes("alpine@sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c", tx)
	if err != nil {
		t.Fail()
	}
	for elem := range tx {
		transactions = append(transactions, elem)
	}
	if len(transactions) != 88 {
		t.Errorf("expected 88 transactions, instead got %d", len(transactions))
	}
}
