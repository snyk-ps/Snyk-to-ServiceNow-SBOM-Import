package main

import (
	"io"
	"testing"
)

func TestParseCommandOptionsPreservesBuildIDPresence(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantValue    string
		wantProvided bool
	}{
		{
			name: "absent",
		},
		{
			name:         "non-empty value",
			args:         []string{"--buildid", "command-build"},
			wantValue:    "command-build",
			wantProvided: true,
		},
		{
			name:         "special characters",
			args:         []string{"--buildid=release 42/A&B"},
			wantValue:    "release 42/A&B",
			wantProvided: true,
		},
		{
			name:         "explicit empty value",
			args:         []string{"--buildid="},
			wantProvided: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseCommandOptions(test.args, io.Discard)
			if err != nil {
				t.Fatalf("parseCommandOptions() error = %v", err)
			}
			if options.buildID != test.wantValue {
				t.Errorf("buildID = %q, want %q", options.buildID, test.wantValue)
			}
			if options.buildIDProvided != test.wantProvided {
				t.Errorf(
					"buildIDProvided = %t, want %t",
					options.buildIDProvided,
					test.wantProvided,
				)
			}
		})
	}
}
