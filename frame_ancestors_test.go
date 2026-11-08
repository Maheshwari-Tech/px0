package main

import (
	"strings"
	"testing"
)

func TestSetFrameAncestors(t *testing.T) {
	defer func() { frameAncestors = "" }()

	if cspHeader() != contentSecurityPolicy {
		t.Fatalf("default CSP changed: %q", cspHeader())
	}
	if err := setFrameAncestors("http://localhost:5190 http://127.0.0.1:5190"); err != nil {
		t.Fatalf("valid origins rejected: %v", err)
	}
	csp := cspHeader()
	if !strings.Contains(csp, "frame-ancestors http://localhost:5190 http://127.0.0.1:5190;") || strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("frame-ancestors not applied: %q", csp)
	}
	for _, bad := range []string{"*", "javascript:alert(1)", "http://x.com/path", "http://a.com; script-src *"} {
		if err := setFrameAncestors(bad); err == nil {
			t.Errorf("accepted invalid origin %q", bad)
		}
	}
}
