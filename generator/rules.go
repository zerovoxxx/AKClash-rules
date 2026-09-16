package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
	"gopkg.in/yaml.v3"
)

const kernelRevision = "70f0570405c3c2c47bb113b88db95006d239b346"
const maxFileSize = 32 << 20

type Patch struct {
	Add    []string `yaml:"add"`
	Remove []string `yaml:"remove"`
}

type Artifact struct {
	Path     string `json:"path"`
	Asset    string `json:"asset"`
	ID       string `json:"id,omitempty"`
	Behavior string `json:"behavior,omitempty"`
	Format   string `json:"format"`
	Count    int    `json:"count,omitempty"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
}

type ruleMatcher interface {
	Match(*C.Metadata, C.RuleMatchHelper) bool
	Count() int
	Reset()
	Insert(string)
	FinishInsert()
}

func decodeYAML(data []byte, out any) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return errors.New("expected exactly one YAML document")
	}
	return nil
}

func parsePayload(data []byte, behavior string) ([]string, error) {
	var doc struct {
		Payload yaml.Node `yaml:"payload"`
	}
	if err := decodeYAML(data, &doc); err != nil {
		return nil, err
	}
	if doc.Payload.Kind != yaml.SequenceNode || len(doc.Payload.Content) == 0 {
		return nil, errors.New("payload must be a nonempty list")
	}
	var items []string
	for _, n := range doc.Payload.Content {
		if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
			return nil, fmt.Errorf("line %d: expected string rule", n.Line)
		}
		items = append(items, n.Value)
	}
	return normalize(behavior, items)
}

var domainLabel = regexp.MustCompile(`^[a-z0-9_-]+$`)

func normalize(behavior string, values []string) ([]string, error) {
	if behavior != "domain" && behavior != "ipcidr" {
		return nil, fmt.Errorf("unsupported behavior %q", behavior)
	}
	unique := map[string]bool{}
	for _, v := range values {
		if v == "" || strings.TrimSpace(v) != v {
			return nil, fmt.Errorf("empty or padded rule %q", v)
		}
		if behavior == "ipcidr" {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", v, err)
			}
			v = p.Masked().String()
		} else {
			v = strings.ToLower(strings.TrimSuffix(v, "."))
			domain := strings.TrimPrefix(v, "+.")
			if domain == "" || domain == "*" || len(domain) > 253 {
				return nil, fmt.Errorf("invalid domain %q", v)
			}
			for _, label := range strings.Split(domain, ".") {
				if label != "*" && (!domainLabel.MatchString(label) || len(label) > 63) {
					return nil, fmt.Errorf("invalid domain %q", v)
				}
			}
		}
		unique[v] = true
	}
	result := make([]string, 0, len(unique))
	for v := range unique {
		result = append(result, v)
	}
	sort.Strings(result)
	return result, nil
}

func applyPatch(behavior string, input []string, patch Patch) ([]string, error) {
	remove, err := normalize(behavior, patch.Remove)
	if err != nil {
		return nil, err
	}
	excluded := map[string]bool{}
	for _, s := range remove {
		excluded[s] = true
	}
	var output []string
	for _, s := range input {
		if !excluded[s] {
			output = append(output, s)
		}
	}
	output = append(output, patch.Add...)
	return normalize(behavior, output)
}

func newMatcher(behavior string, entries []string) (ruleMatcher, error) {
	var m ruleMatcher
	switch behavior {
	case "domain":
		m = RP.NewDomainStrategy()
	case "ipcidr":
		m = RP.NewIPCidrStrategy()
	default:
		return nil, fmt.Errorf("unsupported behavior %q", behavior)
	}
	m.Reset()
	for _, entry := range entries {
		before := m.Count()
		m.Insert(entry)
		if m.Count() != before+1 {
			return nil, fmt.Errorf("kernel rejected %q", entry)
		}
	}
	m.FinishInsert()
	return m, nil
}

func payloadYAML(entries []string) []byte {
	var b strings.Builder
	b.WriteString("payload:\n")
	for _, entry := range entries {
		fmt.Fprintf(&b, "  - '%s'\n", entry)
	}
	return []byte(b.String())
}

func compileMRS(behavior string, entries []string) ([]byte, error) {
	canonical, err := normalize(behavior, entries)
	if err != nil {
		return nil, err
	}
	if len(canonical) == 0 {
		return nil, errors.New("empty rule set")
	}
	if _, err = newMatcher(behavior, canonical); err != nil {
		return nil, err
	}
	b, err := P.ParseBehavior(behavior)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err = RP.ConvertToMrs(payloadYAML(canonical), b, P.YamlRule, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func readMRS(behavior string, data []byte) (ruleMatcher, error) {
	b, err := P.ParseBehavior(behavior)
	if err != nil {
		return nil, err
	}
	var plain bytes.Buffer
	if err = RP.ConvertToMrs(data, b, P.MrsRule, &plain); err != nil {
		return nil, err
	}
	entries, err := normalize(behavior, strings.Fields(plain.String()))
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("invalid or empty MRS: %v", err)
	}
	return newMatcher(behavior, entries)
}

func matches(m ruleMatcher, host, ip string) bool {
	metadata := &C.Metadata{Host: host}
	if ip != "" {
		metadata.DstIP, _ = netip.ParseAddr(ip)
	}
	return m.Match(metadata, C.RuleMatchHelper{})
}

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func jsonBytes(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func safePath(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\\:") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../")
}

func verifyFile(dir string, f Artifact) error {
	if !safePath(f.Path) {
		return fmt.Errorf("unsafe artifact path %q", f.Path)
	}
	name := filepath.Join(dir, filepath.FromSlash(f.Path))
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(abs, resolved)
	if err != nil || !safePath(filepath.ToSlash(rel)) {
		return errors.New("artifact escapes output directory")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	if int64(len(data)) != f.Bytes || digest(data) != f.SHA256 {
		return fmt.Errorf("artifact integrity mismatch: %s", f.Path)
	}
	return nil
}
