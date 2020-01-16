package traffic

import (
	"testing"

	"github.com/caddyserver/caddy"
)

func TestSetup(t *testing.T) {
	/*
		c := caddy.NewTestController("dns", `traffic grpc://bla`)
		if err := setup(c); err != nil {
			t.Fatalf("Test 1, expected no errors, but got: %q", err)
		}
	*/
}

func TestParseTraffic(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
	}{
		// fail
		{`traffic {
			id bla bla
		}`, true},
		{`traffic {
			node bla bla
		}`, true},
	}
	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		_, err := parseTraffic(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
			continue
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
			continue
		}

		if test.shouldErr {
			continue
		}
	}
}