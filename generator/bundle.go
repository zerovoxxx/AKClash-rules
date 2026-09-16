package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules"
)

type Source struct {
	ID         string `yaml:"id" json:"id"`
	Repository string `yaml:"repository" json:"repository"`
	Ref        string `yaml:"ref" json:"ref"`
	Path       string `yaml:"path" json:"path"`
	Behavior   string `yaml:"behavior" json:"behavior"`
	MinRules   int    `yaml:"min_rules" json:"min_rules"`
}

type Package struct {
	ID       string   `yaml:"id"`
	Behavior string   `yaml:"behavior"`
	Sources  []string `yaml:"sources"`
}

type Route struct {
	Type      string `yaml:"type" json:"type"`
	Provider  string `yaml:"provider,omitempty" json:"provider,omitempty"`
	Target    string `yaml:"target,omitempty" json:"target,omitempty"`
	NoResolve bool   `yaml:"no_resolve,omitempty" json:"no_resolve,omitempty"`
}

type Config struct {
	SchemaVersion int       `yaml:"schema_version"`
	Repository    string    `yaml:"repository"`
	Sources       []Source  `yaml:"sources"`
	Packages      []Package `yaml:"packages"`
	Routing       []Route   `yaml:"routing"`
}

type LockedSource struct {
	Source
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
}

type Lock struct {
	SchemaVersion int            `json:"schema_version"`
	Sources       []LockedSource `json:"sources"`
}

type Manifest struct {
	SchemaVersion   int        `json:"schema_version"`
	Version         string     `json:"version"`
	Repository      string     `json:"repository"`
	KernelRevision  string     `json:"kernel_revision"`
	GeneratorSHA256 string     `json:"generator_sha256"`
	Files           []Artifact `json:"files"`
}

type Bundle struct {
	Manifest Manifest
	Files    map[string][]byte
}

type Routing struct {
	SchemaVersion int     `json:"schema_version"`
	Rules         []Route `json:"rules"`
}

type RemoteFixture struct {
	Behavior string   `json:"behavior"`
	Payload  []string `json:"payload"`
	Target   string   `json:"target"`
}

type Fixture struct {
	Name       string          `json:"name"`
	Host       string          `json:"host,omitempty"`
	IP         string          `json:"ip,omitempty"`
	ResolvedIP string          `json:"resolved_ip,omitempty"`
	Process    string          `json:"process,omitempty"`
	Personal   []string        `json:"personal,omitempty"`
	Remote     []RemoteFixture `json:"remote,omitempty"`
	Target     string          `json:"target"`
	Provider   string          `json:"provider"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var revisionPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateConfig(cfg Config) error {
	if cfg.SchemaVersion != 1 || !repositoryName.MatchString(cfg.Repository) {
		return errors.New("unsupported schema or invalid repository")
	}
	sources := map[string]Source{}
	for _, s := range cfg.Sources {
		if !identifier.MatchString(s.ID) || !repositoryName.MatchString(s.Repository) || !safePath(s.Path) || strings.HasPrefix(s.Ref, "-") || s.Ref == "" || s.MinRules < 1 {
			return fmt.Errorf("invalid source %q", s.ID)
		}
		if s.Behavior != "domain" && s.Behavior != "ipcidr" {
			return fmt.Errorf("invalid source behavior: %s", s.ID)
		}
		if _, found := sources[s.ID]; found {
			return fmt.Errorf("duplicate source %s", s.ID)
		}
		sources[s.ID] = s
	}
	packages := map[string]Package{}
	for _, p := range cfg.Packages {
		if !identifier.MatchString(p.ID) || (p.Behavior != "domain" && p.Behavior != "ipcidr") {
			return fmt.Errorf("invalid package %q", p.ID)
		}
		if _, found := packages[p.ID]; found {
			return fmt.Errorf("duplicate package %s", p.ID)
		}
		for _, id := range p.Sources {
			if src, ok := sources[id]; !ok || src.Behavior != p.Behavior {
				return fmt.Errorf("package %s references incompatible source %s", p.ID, id)
			}
		}
		packages[p.ID] = p
	}
	return validateRouting(cfg.Routing, packages)
}

func validateRouting(routes []Route, packages map[string]Package) error {
	seen := map[string]int{}
	for i, r := range routes {
		switch r.Type {
		case "personal", "remote":
			if r.Provider != "" || r.Target != "" || r.NoResolve {
				return errors.New("extension slot must not carry an action")
			}
			seen[r.Type]++
		case "rule-set":
			p, ok := packages[r.Provider]
			if !ok || (r.NoResolve && p.Behavior != "ipcidr") {
				return fmt.Errorf("invalid provider reference %q", r.Provider)
			}
			seen["provider:"+r.Provider]++
		case "match":
			if i != len(routes)-1 || r.Target != "Proxy" || r.Provider != "" || r.NoResolve {
				return errors.New("MATCH,Proxy must appear only at the end")
			}
			seen["match"]++
		default:
			return fmt.Errorf("unsupported route type %q", r.Type)
		}
		if r.Type == "rule-set" && r.Target != "DIRECT" && r.Target != "Proxy" {
			return fmt.Errorf("unsupported target %q", r.Target)
		}
	}
	if seen["match"] != 1 || seen["personal"] != 1 || seen["remote"] != 1 {
		return errors.New("routing requires one fallback and both extension slots")
	}
	for id := range packages {
		if seen["provider:"+id] != 1 {
			return fmt.Errorf("provider %s must be referenced exactly once", id)
		}
	}
	return nil
}

func generate(cfg Config, patches map[string]Patch, lock Lock, inputs map[string][]byte, generatorHash string) (*Bundle, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if lock.SchemaVersion != 1 || len(lock.Sources) != len(cfg.Sources) {
		return nil, errors.New("source lock does not match configuration")
	}
	locked := map[string]LockedSource{}
	for _, src := range lock.Sources {
		if _, exists := locked[src.ID]; exists || !revisionPattern.MatchString(src.Revision) {
			return nil, errors.New("duplicate or invalid locked source")
		}
		locked[src.ID] = src
	}
	parsed := map[string][]string{}
	for _, src := range cfg.Sources {
		l, ok := locked[src.ID]
		data := inputs[src.ID]
		if !ok || l.Source != src || digest(data) != l.SHA256 || int64(len(data)) != l.Bytes {
			return nil, fmt.Errorf("source integrity mismatch: %s", src.ID)
		}
		entries, err := parsePayload(data, src.Behavior)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", src.ID, err)
		}
		if len(entries) < src.MinRules {
			return nil, fmt.Errorf("source %s: %d rules below minimum %d", src.ID, len(entries), src.MinRules)
		}
		parsed[src.ID] = entries
	}
	b := &Bundle{Manifest: Manifest{SchemaVersion: 1, Repository: cfg.Repository, KernelRevision: kernelRevision, GeneratorSHA256: generatorHash}, Files: map[string][]byte{}}
	known := map[string]bool{}
	for _, p := range cfg.Packages {
		known[p.ID] = true
		var all []string
		for _, src := range p.Sources {
			all = append(all, parsed[src]...)
		}
		entries, err := applyPatch(p.Behavior, all, patches[p.ID])
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", p.ID, err)
		}
		mrs, err := compileMRS(p.Behavior, entries)
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", p.ID, err)
		}
		b.add("yaml/"+p.ID+".yaml", payloadYAML(entries), p.ID, p.Behavior, "yaml", len(entries))
		b.add("mrs/"+p.ID+".mrs", mrs, p.ID, p.Behavior, "mrs", len(entries))
	}
	for id := range patches {
		if !known[id] {
			return nil, fmt.Errorf("unknown patch package %s", id)
		}
	}
	b.add("routing.json", jsonBytes(Routing{SchemaVersion: 1, Rules: cfg.Routing}), "", "", "json", 0)
	b.add("sources.lock.json", jsonBytes(lock), "", "", "json", 0)
	sort.Slice(b.Manifest.Files, func(i, j int) bool { return b.Manifest.Files[i].Path < b.Manifest.Files[j].Path })
	b.Manifest.Version = bundleVersion(b.Manifest)
	return b, nil
}

func (b *Bundle) add(name string, data []byte, id, behavior, format string, count int) {
	b.Files[name] = data
	b.Manifest.Files = append(b.Manifest.Files, Artifact{Path: name, Asset: path.Base(name), ID: id, Behavior: behavior, Format: format, Count: count, Bytes: int64(len(data)), SHA256: digest(data)})
}

func bundleVersion(m Manifest) string {
	var identity []Artifact
	for _, f := range m.Files {
		if f.Path != "sources.lock.json" {
			identity = append(identity, f)
		}
	}
	return "rules-" + digest(jsonBytes(struct {
		Schema            int
		Kernel, Generator string
		Files             []Artifact
	}{m.SchemaVersion, m.KernelRevision, m.GeneratorSHA256, identity}))[:24]
}

func checkFixtures(b *Bundle, fixtures []Fixture) error {
	var routing Routing
	if err := json.Unmarshal(b.Files["routing.json"], &routing); err != nil {
		return err
	}
	if len(fixtures) == 0 {
		return errors.New("no routing fixtures")
	}
	for _, format := range []string{"yaml", "mrs"} {
		matchers := map[string]ruleMatcher{}
		for _, f := range b.Manifest.Files {
			if f.Format != format {
				continue
			}
			var m ruleMatcher
			var err error
			if format == "mrs" {
				m, err = readMRS(f.Behavior, b.Files[f.Path])
			} else {
				var entries []string
				entries, err = parsePayload(b.Files[f.Path], f.Behavior)
				if err == nil {
					m, err = newMatcher(f.Behavior, entries)
				}
			}
			if err != nil {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
			matchers[f.ID] = m
		}
		for _, f := range fixtures {
			target, provider, err := firstMatch(routing.Rules, matchers, f)
			if err != nil {
				return fmt.Errorf("fixture %s: %w", f.Name, err)
			}
			if target != f.Target || provider != f.Provider {
				return fmt.Errorf("%s [%s]: got %s/%s, want %s/%s", f.Name, format, target, provider, f.Target, f.Provider)
			}
		}
	}
	return nil
}

func firstMatch(routes []Route, matchers map[string]ruleMatcher, f Fixture) (string, string, error) {
	m := &C.Metadata{Host: f.Host, Process: f.Process}
	if f.IP != "" {
		var err error
		m.DstIP, err = netip.ParseAddr(f.IP)
		if err != nil {
			return "", "", err
		}
	}
	helper := C.RuleMatchHelper{FindProcess: func() {}}
	if f.ResolvedIP != "" {
		ip, err := netip.ParseAddr(f.ResolvedIP)
		if err != nil {
			return "", "", err
		}
		helper.ResolveIP = func() {
			if !m.DstIP.IsValid() {
				m.DstIP = ip
			}
		}
	}
	for _, r := range routes {
		switch r.Type {
		case "rule-set":
			h := helper
			if r.NoResolve {
				h.ResolveIP = nil
			}
			matcher, ok := matchers[r.Provider]
			if !ok {
				return "", "", fmt.Errorf("missing provider %s", r.Provider)
			}
			if matcher.Match(m, h) {
				return r.Target, r.Provider, nil
			}
		case "personal":
			for _, line := range f.Personal {
				parts := strings.Split(line, ",")
				if len(parts) < 3 {
					return "", "", errors.New("invalid personal fixture")
				}
				rule, err := R.ParseRule(parts[0], parts[1], parts[2], parts[3:], nil)
				if err != nil {
					return "", "", err
				}
				if ok, _ := rule.Match(m, helper); ok {
					return rule.Adapter(), "personal", nil
				}
			}
		case "remote":
			for _, remote := range f.Remote {
				entries, err := normalize(remote.Behavior, remote.Payload)
				if err != nil {
					return "", "", err
				}
				matcher, err := newMatcher(remote.Behavior, entries)
				if err != nil {
					return "", "", err
				}
				if matcher.Match(m, helper) {
					return remote.Target, "remote", nil
				}
			}
		case "match":
			return r.Target, "MATCH", nil
		}
	}
	return "", "", errors.New("no fallback")
}
