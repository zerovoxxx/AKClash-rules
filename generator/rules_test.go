package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPayloadPreservesDomainSemantics(t *testing.T) {
	got, err := parsePayload([]byte("payload:\n  - Example.COM\n  - '+.example.com'\n  - Example.COM\n"), "domain")
	if err != nil || !reflect.DeepEqual(got, []string{"+.example.com", "example.com"}) {
		t.Fatalf("payload = %v, %v", got, err)
	}
}

func TestInvalidPayloadRejected(t *testing.T) {
	for _, tc := range []struct{ name, behavior, input string }{
		{"invalid CIDR", "ipcidr", "payload: [132203]"},
		{"bare IP", "ipcidr", "payload: ['1.1.1.1']"},
		{"bad prefix", "ipcidr", "payload: ['192.168.0.0/99']"},
		{"URL in domain", "domain", "payload: ['https://example.com']"},
		{"classical in domain", "domain", "payload: ['DOMAIN,example.com']"},
		{"empty", "domain", "payload: []"},
		{"full config", "domain", "rules: ['MATCH,Proxy']"},
		{"duplicate keys", "domain", "payload: ['a.com']\npayload: ['b.com']"},
		{"multiple documents", "domain", "payload: ['a.com']\n---\npayload: ['b.com']"},
		{"unsupported behavior", "classical", "payload: ['a.com']"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePayload([]byte(tc.input), tc.behavior); err == nil {
				t.Fatal("accepted invalid payload")
			}
		})
	}
}

func TestCanonicalIPv4AndIPv6(t *testing.T) {
	got, err := parsePayload([]byte("payload: ['2001:0db8:0000::/32', '192.168.1.1/24', '192.168.1.0/24']"), "ipcidr")
	if err != nil || !reflect.DeepEqual(got, []string{"192.168.1.0/24", "2001:db8::/32"}) {
		t.Fatalf("%v, %v", got, err)
	}
}

func TestMRSRoundTripMatches(t *testing.T) {
	for _, tc := range []struct {
		behavior string
		entries  []string
		host, ip string
		want     bool
	}{
		{"domain", []string{"example.com"}, "www.example.com", "", false},
		{"domain", []string{"+.example.com"}, "www.example.com", "", true},
		{"domain", []string{"+.example.com"}, "evil-example.com", "", false},
		{"ipcidr", []string{"192.168.0.0/16", "fd00::/8"}, "", "fd01::123", true},
		{"ipcidr", []string{"192.168.0.0/16"}, "", "8.8.8.8", false},
	} {
		mrs, err := compileMRS(tc.behavior, tc.entries)
		if err != nil {
			t.Fatal(err)
		}
		again, err := compileMRS(tc.behavior, tc.entries)
		if err != nil || !bytes.Equal(mrs, again) {
			t.Fatal("non-deterministic MRS")
		}
		matcher, err := readMRS(tc.behavior, mrs)
		if err != nil {
			t.Fatal(err)
		}
		if got := matches(matcher, tc.host, tc.ip); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.behavior, got, tc.want)
		}
	}
}

func TestCorruptMRSRejected(t *testing.T) {
	valid, err := compileMRS("domain", []string{"+.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("not mrs"), valid[:len(valid)/2]} {
		if _, err := readMRS("domain", data); err == nil {
			t.Fatal("accepted corrupt MRS")
		}
	}
	if _, err := readMRS("ipcidr", valid); err == nil {
		t.Fatal("accepted wrong behavior")
	}
}

func TestOverridesDoNotMutateSource(t *testing.T) {
	input := []string{"+.kimi.ai", "+.openai.com"}
	got, err := applyPatch("domain", input, Patch{Add: []string{"+.claude.com"}, Remove: []string{"+.kimi.ai"}})
	if err != nil || !reflect.DeepEqual(got, []string{"+.claude.com", "+.openai.com"}) {
		t.Fatalf("%v, %v", got, err)
	}
	if input[0] != "+.kimi.ai" {
		t.Fatal("mutated upstream input")
	}
}

func TestManifestRejectsTamperingAndUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	data := []byte("payload: ['+.example.com']\n")
	if err := os.WriteFile(filepath.Join(dir, "sample.yaml"), data, 0644); err != nil {
		t.Fatal(err)
	}
	f := Artifact{Path: "sample.yaml", SHA256: digest(data), Bytes: int64(len(data))}
	if err := verifyFile(dir, f); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sample.yaml"), []byte("corrupt"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(dir, f); err == nil {
		t.Fatal("accepted modified artifact")
	}
	for _, path := range []string{"../sample.yaml", "/tmp/sample.yaml", "a/../../b", "https://example.com/a", "a\\b"} {
		f.Path = path
		if err := verifyFile(dir, f); err == nil {
			t.Fatalf("accepted path %q", path)
		}
	}
}

func sampleBuild(t *testing.T) (Config, map[string]Patch, Lock, map[string][]byte) {
	t.Helper()
	s := Source{ID: "ai", Repository: "MetaCubeX/meta-rules-dat", Ref: "meta", Path: "geo/geosite/test.yaml", Behavior: "domain", MinRules: 1}
	input := []byte("payload: ['+.openai.com', '+.kimi.ai']\n")
	cfg := Config{SchemaVersion: 1, Repository: "zerovoxxx/AKClash-rules", Sources: []Source{s}, Packages: []Package{
		{ID: "ai-cn-domain", Behavior: "domain"}, {ID: "ai-proxy-domain", Behavior: "domain", Sources: []string{"ai"}},
	}, Routing: []Route{{Type: "personal"}, {Type: "remote"}, {Type: "rule-set", Provider: "ai-cn-domain", Target: "DIRECT"}, {Type: "rule-set", Provider: "ai-proxy-domain", Target: "Proxy"}, {Type: "match", Target: "Proxy"}}}
	patches := map[string]Patch{"ai-cn-domain": {Add: []string{"+.kimi.ai"}}, "ai-proxy-domain": {Remove: []string{"+.kimi.ai"}}}
	lock := Lock{SchemaVersion: 1, Sources: []LockedSource{{Source: s, Revision: "3183259a6636ad3ab4623917d6b01f42ad443aaf", SHA256: digest(input), Bytes: int64(len(input))}}}
	return cfg, patches, lock, map[string][]byte{"ai": input}
}

func TestBuildReproducibleAndChecksFixtures(t *testing.T) {
	cfg, patches, lock, inputs := sampleBuild(t)
	first, err := generate(cfg, patches, lock, inputs, "generator-hash")
	if err != nil {
		t.Fatal(err)
	}
	second, err := generate(cfg, patches, lock, inputs, "generator-hash")
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("build is not reproducible")
	}
	fixtures := []Fixture{{Name: "domestic AI", Host: "api.kimi.ai", Target: "DIRECT", Provider: "ai-cn-domain"}, {Name: "overseas AI", Host: "chat.openai.com", Target: "Proxy", Provider: "ai-proxy-domain"}}
	if err = checkFixtures(first, fixtures); err != nil {
		t.Fatal(err)
	}
	fixtures[0].Target = "Proxy"
	if err = checkFixtures(first, fixtures); err == nil {
		t.Fatal("wrong routing expectation went undetected")
	}
}

func TestBuildRejectsBadInputsAndReferences(t *testing.T) {
	for _, mutation := range []string{"source hash", "empty source", "unknown provider", "unknown source", "unsafe ID", "unsupported target", "early match"} {
		t.Run(mutation, func(t *testing.T) {
			cfg, patches, lock, inputs := sampleBuild(t)
			switch mutation {
			case "source hash":
				lock.Sources[0].SHA256 = "bad"
			case "empty source":
				inputs["ai"] = []byte("payload: []")
			case "unknown provider":
				cfg.Routing[2].Provider = "missing"
			case "unknown source":
				cfg.Packages[1].Sources[0] = "missing"
			case "unsafe ID":
				cfg.Packages[0].ID = "../escape"
			case "unsupported target":
				cfg.Routing[2].Target = "REJECT"
			case "early match":
				cfg.Routing = append([]Route{{Type: "match", Target: "Proxy"}}, cfg.Routing...)
			}
			if _, err := generate(cfg, patches, lock, inputs, "generator-hash"); err == nil {
				t.Fatal("accepted invalid build")
			}
		})
	}
}

func TestRuleOrderAndExtensions(t *testing.T) {
	cfg, patches, lock, inputs := sampleBuild(t)
	b, err := generate(cfg, patches, lock, inputs, "generator-hash")
	if err != nil {
		t.Fatal(err)
	}
	cases := []Fixture{
		{Name: "personal before AI", Host: "api.kimi.ai", Personal: []string{"DOMAIN-SUFFIX,kimi.ai,Proxy"}, Target: "Proxy", Provider: "personal"},
		{Name: "remote before AI", Host: "api.openai.com", Remote: []RemoteFixture{{Behavior: "domain", Payload: []string{"+.openai.com"}, Target: "DIRECT"}}, Target: "DIRECT", Provider: "remote"},
		{Name: "default fallback", Host: "unlisted.routing-check.net", Target: "Proxy", Provider: "MATCH"},
	}
	if err = checkFixtures(b, cases); err != nil {
		t.Fatal(err)
	}
}

func TestWrittenBundleRejectsTampering(t *testing.T) {
	cfg, patches, lock, inputs := sampleBuild(t)
	b, err := generate(cfg, patches, lock, inputs, "generator-hash")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "dist")
	if err = writeBundle(dir, b); err != nil {
		t.Fatal(err)
	}
	if _, err = loadBundle(dir); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "mrs/ai-cn-domain.mrs"), []byte("bad"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadBundle(dir); err == nil {
		t.Fatal("accepted damaged release")
	}
}

func TestInvalidBuildDoesNotReplaceExistingOutput(t *testing.T) {
	cfg, patches, lock, inputs := sampleBuild(t)
	b, err := generate(cfg, patches, lock, inputs, "generator-hash")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "dist")
	if err = writeBundle(dir, b); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	b.Files["mrs/ai-cn-domain.mrs"] = []byte("bad")
	if err = writeBundle(dir, b); err == nil {
		t.Fatal("accepted corrupt build")
	}
	after, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed build replaced previous output")
	}
}

func TestDownloadRejectsErrorsAndOversizedResponses(t *testing.T) {
	for _, mode := range []string{"valid", "not-found", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "not-found":
					http.Error(w, "missing", http.StatusNotFound)
				case "oversized":
					w.Header().Set("Content-Length", "33554433")
				default:
					_, _ = w.Write([]byte("payload: ['example.com']"))
				}
			}))
			defer s.Close()
			data, err := download(s.Client(), s.URL)
			if mode == "valid" && (err != nil || len(data) == 0) {
				t.Fatalf("%s: %v", mode, err)
			}
			if mode != "valid" && err == nil {
				t.Fatal("accepted invalid download")
			}
		})
	}
}

func TestPublishValidatesBeforeCallingGitHub(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmtBool(corrupt), func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "generator"), 0755); err != nil {
				t.Fatal(err)
			}
			script, err := os.ReadFile("publish.sh")
			if err != nil {
				t.Fatal(err)
			}
			scriptPath := filepath.Join(root, "generator", "publish.sh")
			if err = os.WriteFile(scriptPath, script, 0644); err != nil {
				t.Fatal(err)
			}
			cfg, patches, lock, inputs := sampleBuild(t)
			b, err := generate(cfg, patches, lock, inputs, "generator-hash")
			if err != nil {
				t.Fatal(err)
			}
			if err = writeBundle(filepath.Join(root, "dist"), b); err != nil {
				t.Fatal(err)
			}
			if corrupt {
				if err = os.Remove(filepath.Join(root, "dist", "mrs", "ai-cn-domain.mrs")); err != nil {
					t.Fatal(err)
				}
			}
			mock := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GH_TEST_LOG\"\nif [ \"$1\" = api ]; then echo 'gh: Not Found (HTTP 404)' >&2; exit 1; fi\n"
			if err = os.WriteFile(filepath.Join(root, "gh"), []byte(mock), 0755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(root, "calls")
			cmd := exec.Command("bash", scriptPath)
			cmd.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "GH_TEST_LOG="+log, "GITHUB_REPOSITORY=zerovoxxx/AKClash-rules", "GITHUB_SHA=0123456789012345678901234567890123456789")
			output, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(log)
			if corrupt {
				if err == nil || len(calls) != 0 {
					t.Fatalf("invalid artifact reached GitHub: err=%v calls=%s output=%s", err, calls, output)
				}
			} else {
				if err != nil {
					t.Fatalf("publish: %v %s", err, output)
				}
				text := string(calls)
				create, upload, publish := strings.Index(text, "release create"), strings.Index(text, "release upload"), strings.Index(text, "release edit")
				if create < 0 || upload < create || publish < upload || !strings.Contains(text, "--draft=false --latest") {
					t.Fatalf("wrong publication order: %s", text)
				}
			}
		})
	}
}

func fmtBool(v bool) string {
	if v {
		return "corrupt"
	}
	return "valid"
}

func TestServiceCategories(t *testing.T) {
	data, err := os.ReadFile("sources.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err = decodeYAML(data, &cfg); err != nil {
		t.Fatal(err)
	}
	packages := map[string]Package{}
	for _, p := range cfg.Packages {
		packages[p.ID] = p
		if strings.HasPrefix(p.ID, "telegram") {
			t.Fatal("public categories must not use a single application's name")
		}
		if p.ID == "proxy-domain" {
			for _, s := range p.Sources {
				if s == "telegram" {
					t.Fatal("chat source duplicated in generic proxy category")
				}
			}
		}
	}
	if packages["chat-domain"].Behavior != "domain" || packages["chat-ip"].Behavior != "ipcidr" {
		t.Fatal("missing domain/IP chat categories")
	}
}
