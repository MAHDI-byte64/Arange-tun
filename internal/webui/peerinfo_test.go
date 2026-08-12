package webui

import (
	"testing"

	"github.com/mahdi-byte64/arange-tun/internal/geo"
)

// The geo providers disagree about which halves of a location they return:
// some give a city and a country, geojs gives only a country, and an IP with
// no city gives only that. The location line has to read cleanly in every case
// — no leading ", Sweden" and no trailing "Mountain View," — which is the whole
// reason fillPeer joins instead of concatenating.
func TestFillPeerLocationFormatting(t *testing.T) {
	cases := []struct {
		name           string
		in             geo.Info
		wantLocation   string
		wantISP, wantC string
	}{
		{"city and country", geo.Info{City: "Stockholm", Country: "Sweden", Code: "SE", ISP: "Acme"}, "Stockholm, Sweden", "Acme", "SE"},
		{"country only (geojs)", geo.Info{Country: "United States", Code: "US", ISP: "Google"}, "United States", "Google", "US"},
		{"city only", geo.Info{City: "Mountain View", Code: "US"}, "Mountain View", "", "US"},
		{"nothing but a flag", geo.Info{Code: "IR"}, "", "", "IR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var info TunnelInfo
			g := tc.in
			fillPeer(&info, &g)
			if info.PeerLocation != tc.wantLocation {
				t.Errorf("PeerLocation = %q, want %q", info.PeerLocation, tc.wantLocation)
			}
			if info.PeerISP != tc.wantISP {
				t.Errorf("PeerISP = %q, want %q", info.PeerISP, tc.wantISP)
			}
			if info.PeerCountry != tc.wantC {
				t.Errorf("PeerCountry = %q, want %q", info.PeerCountry, tc.wantC)
			}
		})
	}
}
