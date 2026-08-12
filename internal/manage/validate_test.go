package manage

import "testing"

// The destination half of a mapping is checked too, not just the port. A
// destination that is only separators names no backend at all, and the engine
// that has to dial it cannot invent one.
func TestPortSpecRejectsADestinationWithAHoleInIt(t *testing.T) {
	for _, spec := range []string{"443=|", "443=||", "443=| ", "443=a:1||b:2", "443=|a:1", "443=a:1|"} {
		if validPortSpec(spec) {
			t.Errorf("validPortSpec(%q) = true, want false", spec)
		}
	}
}

// The forms that do name backends keep working — this must not tighten into
// rejecting a real list.
func TestPortSpecStillAcceptsRealBackendLists(t *testing.T) {
	for _, spec := range []string{
		"443",
		"400-450",
		"443=1.1.1.1:443",
		"443=127.0.0.1:8443|127.0.0.1:8444",
		"127.0.0.1:41234=127.0.0.1:1080",
	} {
		if !validPortSpec(spec) {
			t.Errorf("validPortSpec(%q) = false, want true", spec)
		}
	}
}
