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
	"crypto/sha256"
	"fmt"
	"reflect"
)

func ChunkSlice[K interface{}](slice []K, chunkSize int) [][]K {
	var chunks [][]K
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

func Hash(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func Contains[K interface{}](slice []K, value K) bool {
	for _, v := range slice {
		if reflect.DeepEqual(v, value) {
			return true
		}
	}
	return false
}

func UniqueBy[K interface{}](slice []K, by func(K) string) []K {
	values := make(map[string]K)
	for _, s := range slice {
		k := by(s)
		if _, ok := values[k]; !ok {
			values[k] = s
		}
	}

	v := make([]K, 0, len(values))
	for _, value := range values {
		v = append(v, value)
	}
	return v
}
