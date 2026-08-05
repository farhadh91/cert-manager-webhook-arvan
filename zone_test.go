package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

// fakeArvan stands in for the arvan api. It hosts a fixed set of zones and
// answers 404 for any other one, the way the real api does for a domain that
// is not in the account.
type fakeArvan struct {
	server *httptest.Server
	zones  map[string][]DNSRecord // zone -> records
	nextID int
}

func newFakeArvan(zones ...string) *fakeArvan {
	f := &fakeArvan{zones: map[string][]DNSRecord{}}
	for _, zone := range zones {
		f.zones[zone] = nil
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeArvan) Close() { f.server.Close() }

// handle serves the endpoints the solver uses:
//   GET/POST /cdn/4.0/domains/{zone}/dns-records
//   DELETE   /cdn/4.0/domains/{zone}/dns-records/{id}
func (f *fakeArvan) handle(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[2] != "domains" || parts[4] != "dns-records" {
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		return
	}
	zone := parts[3]
	records, hosted := f.zones[zone]
	if !hosted {
		http.Error(w, `{"message":"Domain not found"}`, http.StatusNotFound)
		return
	}

	switch {
	case r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, DNSRecords{Data: records})

	case r.Method == http.MethodPost:
		rec := DNSRecord{}
		json.NewDecoder(r.Body).Decode(&rec)
		f.nextID++
		rec.ID = fmt.Sprintf("rec-%d", f.nextID)
		f.zones[zone] = append(f.zones[zone], rec)
		writeJSON(w, http.StatusCreated, map[string]interface{}{"data": rec})

	case r.Method == http.MethodDelete && len(parts) == 6:
		kept := []DNSRecord{}
		for _, rec := range records {
			if rec.ID != parts[5] {
				kept = append(kept, rec)
			}
		}
		f.zones[zone] = kept
		writeJSON(w, http.StatusOK, map[string]interface{}{"message": "deleted"})

	default:
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// challenge builds a ChallengeRequest pointed at the fake api.
func (f *fakeArvan) challenge(t *testing.T, fqdn, resolvedZone, key string) *v1alpha1.ChallengeRequest {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{
		"authApiKey": "test-key",
		"baseUrl":    f.server.URL,
		"ttl":        120,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &v1alpha1.ChallengeRequest{
		ResolvedFQDN: fqdn,
		ResolvedZone: resolvedZone,
		Key:          key,
		Config:       &extapi.JSON{Raw: raw},
	}
}

// recordNames returns the name of every record currently in a zone.
func (f *fakeArvan) recordNames(zone string) []string {
	out := []string{}
	for _, rec := range f.zones[zone] {
		out = append(out, rec.Name)
	}
	return out
}

// TestResolveZone is the bug itself: a delegated child zone has to win over
// its parent, while a plain sub domain still resolves to the parent.
func TestResolveZone(t *testing.T) {
	tests := []struct {
		name       string
		hosted     []string
		fqdn       string
		zone       string // ResolvedZone, as computed by cert-manager
		wantRecord string
		wantDomain string
	}{
		{
			// Case 1: api.example.com is a record inside example.com.
			name:       "sub domain of a non delegated zone",
			hosted:     []string{"example.com"},
			fqdn:       "_acme-challenge.api.example.com.",
			zone:       "example.com.",
			wantRecord: "_acme-challenge.api",
			wantDomain: "example.com",
		},
		{
			// Case 2 and 3: sub.example.com is delegated. cert-manager
			// resolves both sub.example.com and *.sub.example.com to this
			// same fqdn, so a wildcard takes the same path.
			name:       "delegated zone wins over its parent",
			hosted:     []string{"example.com", "sub.example.com"},
			fqdn:       "_acme-challenge.sub.example.com.",
			zone:       "sub.example.com.",
			wantRecord: "_acme-challenge",
			wantDomain: "sub.example.com",
		},
		{
			name:       "delegated zone without its parent in the account",
			hosted:     []string{"sub.example.com"},
			fqdn:       "_acme-challenge.sub.example.com.",
			zone:       "sub.example.com.",
			wantRecord: "_acme-challenge",
			wantDomain: "sub.example.com",
		},
		{
			name:       "sub domain of a delegated zone",
			hosted:     []string{"example.com", "sub.example.com"},
			fqdn:       "_acme-challenge.api.sub.example.com.",
			zone:       "sub.example.com.",
			wantRecord: "_acme-challenge.api",
			wantDomain: "sub.example.com",
		},
		{
			name:       "apex",
			hosted:     []string{"example.com"},
			fqdn:       "_acme-challenge.example.com.",
			zone:       "example.com.",
			wantRecord: "_acme-challenge",
			wantDomain: "example.com",
		},
		{
			// Nothing in the account matches: use the zone cert-manager
			// resolved over DNS rather than guessing.
			name:       "falls back to the resolved zone",
			hosted:     []string{"other.example.net"},
			fqdn:       "_acme-challenge.sub.example.com.",
			zone:       "sub.example.com.",
			wantRecord: "_acme-challenge",
			wantDomain: "sub.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeArvan(tt.hosted...)
			defer fake.Close()

			solver := &arvanDNSProviderSolver{}
			cfg, err := loadConfig(fake.challenge(t, tt.fqdn, tt.zone, "key").Config)
			if err != nil {
				t.Fatal(err)
			}

			record, domain := solver.resolveZone(&cfg, "test-key", tt.fqdn, tt.zone)
			if record != tt.wantRecord || domain != tt.wantDomain {
				t.Errorf("resolveZone(%q) = (%q, %q), want (%q, %q)",
					tt.fqdn, record, domain, tt.wantRecord, tt.wantDomain)
			}
		})
	}
}

// TestPresentUsesDelegatedZone: the TXT record must be created in the
// delegated zone, not in its parent.
func TestPresentUsesDelegatedZone(t *testing.T) {
	fake := newFakeArvan("example.com", "sub.example.com")
	defer fake.Close()

	solver := &arvanDNSProviderSolver{}
	ch := fake.challenge(t, "_acme-challenge.sub.example.com.", "sub.example.com.", "key-1")

	if err := solver.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}

	if got := fake.recordNames("sub.example.com"); len(got) != 1 || got[0] != "_acme-challenge" {
		t.Errorf("records in sub.example.com = %v, want [_acme-challenge]", got)
	}
	if got := fake.recordNames("example.com"); len(got) != 0 {
		t.Errorf("records in example.com = %v, want none", got)
	}
}

// TestPresentUsesParentZoneForPlainSubDomain: existing behaviour for a zone
// that is not delegated is unchanged.
func TestPresentUsesParentZoneForPlainSubDomain(t *testing.T) {
	fake := newFakeArvan("example.com")
	defer fake.Close()

	solver := &arvanDNSProviderSolver{}
	ch := fake.challenge(t, "_acme-challenge.api.example.com.", "example.com.", "key-1")

	if err := solver.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}

	if got := fake.recordNames("example.com"); len(got) != 1 || got[0] != "_acme-challenge.api" {
		t.Errorf("records in example.com = %v, want [_acme-challenge.api]", got)
	}
}

// TestCleanUpUsesSameZoneAsPresent is case 4 of the report.
func TestCleanUpUsesSameZoneAsPresent(t *testing.T) {
	fake := newFakeArvan("example.com", "sub.example.com")
	defer fake.Close()

	solver := &arvanDNSProviderSolver{}
	ch := fake.challenge(t, "_acme-challenge.sub.example.com.", "sub.example.com.", "key-1")

	if err := solver.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	if got := fake.zones["sub.example.com"]; len(got) != 0 {
		t.Errorf("records left in sub.example.com = %v, want none", got)
	}
}

// TestCleanUpWithoutRecordSucceeds: cert-manager also calls CleanUp for
// challenges that were never presented. That used to fail the challenge with
// "Domain not Found".
func TestCleanUpWithoutRecordSucceeds(t *testing.T) {
	fake := newFakeArvan("sub.example.com")
	defer fake.Close()

	solver := &arvanDNSProviderSolver{}
	ch := fake.challenge(t, "_acme-challenge.sub.example.com.", "sub.example.com.", "key-1")

	if err := solver.CleanUp(ch); err != nil {
		t.Errorf("CleanUp with no record present: %v, want nil", err)
	}
}

// TestCleanUpKeepsConcurrentChallenge: a wildcard and its base domain are
// validated through the same record name at the same time, so cleaning up one
// must leave the other's record in place.
func TestCleanUpKeepsConcurrentChallenge(t *testing.T) {
	fake := newFakeArvan("sub.example.com")
	defer fake.Close()

	solver := &arvanDNSProviderSolver{}
	wildcard := fake.challenge(t, "_acme-challenge.sub.example.com.", "sub.example.com.", "key-wildcard")
	base := fake.challenge(t, "_acme-challenge.sub.example.com.", "sub.example.com.", "key-base")

	if err := solver.Present(wildcard); err != nil {
		t.Fatalf("Present wildcard: %v", err)
	}
	if err := solver.Present(base); err != nil {
		t.Fatalf("Present base: %v", err)
	}
	if err := solver.CleanUp(wildcard); err != nil {
		t.Fatalf("CleanUp wildcard: %v", err)
	}

	left := fake.zones["sub.example.com"]
	if len(left) != 1 || left[0].Value["text"] != "key-base" {
		t.Errorf("records after cleanup = %v, want only the key-base record", left)
	}
}
