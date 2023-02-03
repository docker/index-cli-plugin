package registry

import (
	"testing"
)

func Test_mustParseNameAndTag(t *testing.T) {
	type testCase struct {
		description string
		input       string
		name        string
		tag         string
	}
	testCases := []testCase{
		{
			description: "library namespace",
			input:       "foo:1",
			name:        "foo",
			tag:         "1",
		},
		{
			description: "namespace",
			input:       "foo/bar:2",
			name:        "foo/bar",
			tag:         "2",
		},
		{
			description: "registry",
			input:       "registry.example.com/foo/bar:3",
			name:        "registry.example.com/foo/bar",
			tag:         "3",
		},
		{
			description: "registry with port",
			input:       "localhost:8082/foo/bar:4",
			name:        "localhost:8082/foo/bar",
			tag:         "4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			name, tag := mustParseNameAndTag(tc.input)
			if name != tc.name {
				t.Errorf("expected name to be '%s', got '%s'", tc.name, name)
			}
			if tag != tc.tag {
				t.Errorf("expected tag to be '%s', got '%s'", tc.tag, tag)
			}
		})
	}
}

func Test_mustParseNameAndDigest(t *testing.T) {
	type testCase struct {
		description string
		input       string
		name        string
		digest      string
	}
	testCases := []testCase{
		{
			description: "library namespace",
			input:       "foo@sha256:544e165df59f0effc3b4aa054712710e0a0913c050d524c44772539c515d1a43",
			name:        "foo",
			digest:      "sha256:544e165df59f0effc3b4aa054712710e0a0913c050d524c44772539c515d1a43",
		},
		{
			description: "namespace",
			input:       "foo/bar@sha256:00b8c9532fbc7894ef92b07322f1943ce23a4935ea1dd4e1a04297831d3aad45",
			name:        "foo/bar",
			digest:      "sha256:00b8c9532fbc7894ef92b07322f1943ce23a4935ea1dd4e1a04297831d3aad45",
		},
		{
			description: "registry",
			input:       "registry.example.com/foo/bar@sha256:57a2a04950c1bd45958947a1b5414558bc2bee863fee519c45da34b398d6d29e",
			name:        "registry.example.com/foo/bar",
			digest:      "sha256:57a2a04950c1bd45958947a1b5414558bc2bee863fee519c45da34b398d6d29e",
		},
		{
			description: "registry with port",
			input:       "localhost:8082/foo/bar@sha256:2adb2c6ade4b433326ea8cddd5c5aa9998d07e8ff603374e3360290807d8c14b",
			name:        "localhost:8082/foo/bar",
			digest:      "sha256:2adb2c6ade4b433326ea8cddd5c5aa9998d07e8ff603374e3360290807d8c14b",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			name, digest := mustParseNameAndDigest(tc.input)
			if name != tc.name {
				t.Errorf("expected name to be '%s', got '%s'", tc.name, name)
			}
			if digest != tc.digest {
				t.Errorf("expected digest to be '%s', got '%s'", tc.digest, digest)
			}
		})
	}
}
