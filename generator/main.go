package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage (from generator/): go run . build|update|check")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		os.Exit(1)
	}
}

func readJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func run(command string) error {
	if command != "build" && command != "update" && command != "check" {
		return fmt.Errorf("unknown command %q", command)
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	out := filepath.Join(root, "..", "dist")
	fixtureBytes, err := os.ReadFile(filepath.Join(root, "fixtures", "routing.json"))
	if err != nil {
		return err
	}
	var fixtures []Fixture
	if err = readJSON(fixtureBytes, &fixtures); err != nil {
		return err
	}
	if command == "check" {
		b, err := loadBundle(out)
		if err != nil {
			return err
		}
		if err = checkFixtures(b, fixtures); err != nil {
			return err
		}
		fmt.Printf("PASS %s: %d artifacts; %d routing cases in YAML and MRS\n", b.Manifest.Version, len(b.Manifest.Files), len(fixtures))
		return nil
	}
	configBytes, err := os.ReadFile(filepath.Join(root, "sources.yaml"))
	if err != nil {
		return err
	}
	var cfg Config
	if err = decodeYAML(configBytes, &cfg); err != nil {
		return err
	}
	if err = validateConfig(cfg); err != nil {
		return err
	}
	patchBytes, err := os.ReadFile(filepath.Join(root, "overrides", "rules.yaml"))
	if err != nil {
		return err
	}
	var patches map[string]Patch
	if err = decodeYAML(patchBytes, &patches); err != nil {
		return err
	}
	var lock Lock
	if command == "build" {
		data, err := os.ReadFile(filepath.Join(root, "sources.lock.json"))
		if err != nil {
			return err
		}
		if err = readJSON(data, &lock); err != nil {
			return err
		}
	} else {
		lock, err = resolveSources(cfg)
		if err != nil {
			return err
		}
	}
	inputs, err := fetchSources(&lock, filepath.Join(root, ".cache"), command == "update")
	if err != nil {
		return err
	}
	fingerprint, err := generatorFingerprint(root)
	if err != nil {
		return err
	}
	b, err := generate(cfg, patches, lock, inputs, fingerprint)
	if err != nil {
		return err
	}
	licenseFiles, err := filepath.Glob(filepath.Join(root, "licenses", "*"))
	if err != nil || len(licenseFiles) == 0 {
		return errors.New("missing source license notices")
	}
	for _, name := range licenseFiles {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		b.add("licenses/"+filepath.Base(name), data, "", "", "text", 0)
	}
	sort.Slice(b.Manifest.Files, func(i, j int) bool { return b.Manifest.Files[i].Path < b.Manifest.Files[j].Path })
	b.Manifest.Version = bundleVersion(b.Manifest)
	if err = checkFixtures(b, fixtures); err != nil {
		return err
	}
	if err = writeBundle(out, b); err != nil {
		return err
	}
	if command == "update" {
		if err = atomicFile(filepath.Join(root, "sources.lock.json"), jsonBytes(lock)); err != nil {
			return err
		}
	}
	fmt.Printf("Built %s: %d artifacts; %d routing cases passed in both formats\n", b.Manifest.Version, len(b.Manifest.Files), len(fixtures))
	for _, f := range b.Manifest.Files {
		if f.Format == "mrs" {
			fmt.Printf("  %-24s %6d rules  %8d bytes\n", f.ID, f.Count, f.Bytes)
		}
	}
	return nil
}

func generatorFingerprint(root string) (string, error) {
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		return "", err
	}
	files = append(files, filepath.Join(root, "go.mod"), filepath.Join(root, "go.sum"))
	sort.Strings(files)
	var input bytes.Buffer
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&input, "%s\x00%s\n", filepath.Base(name), digest(data))
	}
	return digest(input.Bytes()), nil
}

func resolveSources(cfg Config) (Lock, error) {
	lock := Lock{SchemaVersion: 1}
	revisions := map[string]string{}
	for _, s := range cfg.Sources {
		key := s.Repository + "/" + s.Ref
		if revisions[key] == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			data, err := exec.CommandContext(ctx, "git", "ls-remote", "https://github.com/"+s.Repository+".git", "refs/heads/"+s.Ref).Output()
			cancel()
			if err != nil {
				return lock, fmt.Errorf("resolve %s: %w", key, err)
			}
			fields := strings.Fields(string(data))
			if len(fields) != 2 || !revisionPattern.MatchString(fields[0]) {
				return lock, fmt.Errorf("cannot resolve exact revision for %s", key)
			}
			revisions[key] = fields[0]
		}
		lock.Sources = append(lock.Sources, LockedSource{Source: s, Revision: revisions[key]})
	}
	return lock, nil
}

func download(client *http.Client, address string) ([]byte, error) {
	if !strings.HasPrefix(address, "https://") {
		return nil, errors.New("download requires HTTPS")
	}
	req, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AKClash-rules/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request.URL.Scheme != "https" {
		return nil, errors.New("download redirected away from HTTPS")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, address)
	}
	if resp.ContentLength > maxFileSize {
		return nil, errors.New("source exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, errors.New("source exceeds size limit")
	}
	return data, nil
}

func fetchSources(lock *Lock, cache string, update bool) (map[string][]byte, error) {
	if err := os.MkdirAll(cache, 0755); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 45 * time.Second}
	inputs := map[string][]byte{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	errorsBySource := make([]error, len(lock.Sources))
	for i := range lock.Sources {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s := &lock.Sources[i]
			if !update && !hashPattern.MatchString(s.SHA256) {
				errorsBySource[i] = errors.New("invalid locked source hash")
				return
			}
			if !repositoryName.MatchString(s.Repository) || !revisionPattern.MatchString(s.Revision) || !safePath(s.Path) {
				errorsBySource[i] = errors.New("invalid locked source address")
				return
			}
			var data []byte
			if !update && len(s.SHA256) == 64 {
				data, _ = os.ReadFile(filepath.Join(cache, s.SHA256+".yaml"))
			}
			if len(data) == 0 {
				var err error
				data, err = download(client, "https://raw.githubusercontent.com/"+s.Repository+"/"+s.Revision+"/"+s.Path)
				if err != nil {
					errorsBySource[i] = err
					return
				}
			}
			if !update && (digest(data) != s.SHA256 || int64(len(data)) != s.Bytes) {
				errorsBySource[i] = fmt.Errorf("locked hash mismatch: %s", s.ID)
				return
			}
			entries, err := parsePayload(data, s.Behavior)
			if err != nil || len(entries) < s.MinRules {
				errorsBySource[i] = fmt.Errorf("invalid source %s: %d rules, error %v", s.ID, len(entries), err)
				return
			}
			s.SHA256, s.Bytes = digest(data), int64(len(data))
			if err = atomicFile(filepath.Join(cache, s.SHA256+".yaml"), data); err != nil {
				errorsBySource[i] = err
				return
			}
			mu.Lock()
			inputs[s.ID] = data
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	for _, err := range errorsBySource {
		if err != nil {
			return nil, err
		}
	}
	return inputs, nil
}

func validateBundle(b *Bundle) error {
	m := b.Manifest
	if m.SchemaVersion != 1 || m.KernelRevision != kernelRevision || !repositoryName.MatchString(m.Repository) || m.Version != bundleVersion(m) {
		return errors.New("invalid manifest schema, compatibility or version")
	}
	seen, assets, packages, formats := map[string]bool{}, map[string]bool{}, map[string]Package{}, map[string]map[string]bool{}
	for _, f := range m.Files {
		if !safePath(f.Path) || f.Asset != filepath.Base(f.Path) || assets[f.Asset] || seen[f.Path] {
			return errors.New("unsafe or duplicate manifest artifact")
		}
		seen[f.Path], assets[f.Asset] = true, true
		data, exists := b.Files[f.Path]
		if !exists || int64(len(data)) != f.Bytes || digest(data) != f.SHA256 {
			return fmt.Errorf("artifact integrity mismatch: %s", f.Path)
		}
		if f.Format == "yaml" || f.Format == "mrs" {
			if !identifier.MatchString(f.ID) || f.Count <= 0 || f.Path != f.Format+"/"+f.ID+"."+f.Format {
				return errors.New("invalid rule artifact metadata")
			}
			if existing, ok := packages[f.ID]; ok && existing.Behavior != f.Behavior {
				return errors.New("inconsistent provider behavior")
			}
			packages[f.ID] = Package{ID: f.ID, Behavior: f.Behavior}
			if formats[f.ID] == nil {
				formats[f.ID] = map[string]bool{}
			}
			formats[f.ID][f.Format] = true
			if f.Format == "yaml" {
				entries, err := parsePayload(data, f.Behavior)
				if err != nil || len(entries) != f.Count {
					return fmt.Errorf("invalid YAML/count: %s", f.Path)
				}
			} else {
				if _, err := readMRS(f.Behavior, data); err != nil {
					return err
				}
			}
		} else if f.Format != "json" && f.Format != "text" {
			return errors.New("unsupported artifact format")
		}
	}
	if len(seen) != len(b.Files) || !seen["routing.json"] || !seen["sources.lock.json"] {
		return errors.New("missing or unlisted artifact")
	}
	for id, formats := range formats {
		if !formats["yaml"] || !formats["mrs"] {
			return fmt.Errorf("missing format for %s", id)
		}
	}
	var routing Routing
	if err := readJSON(b.Files["routing.json"], &routing); err != nil {
		return err
	}
	if routing.SchemaVersion != 1 {
		return errors.New("unsupported routing schema")
	}
	return validateRouting(routing.Rules, packages)
}

func loadBundle(dir string) (*Bundle, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	b := &Bundle{Files: map[string][]byte{}}
	if err = readJSON(data, &b.Manifest); err != nil {
		return nil, err
	}
	for _, f := range b.Manifest.Files {
		if err = verifyFile(dir, f); err != nil {
			return nil, err
		}
		b.Files[f.Path], err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			return nil, err
		}
	}
	if err = validateBundle(b); err != nil {
		return nil, err
	}
	return b, nil
}

func atomicFile(name string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), name)
}

func writeBundle(dir string, b *Bundle) error {
	if err := validateBundle(b); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(dir), ".dist-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, data := range b.Files {
		file := filepath.Join(stage, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			return err
		}
		if err = os.WriteFile(file, data, 0644); err != nil {
			return err
		}
	}
	if err = os.WriteFile(filepath.Join(stage, "manifest.json"), jsonBytes(b.Manifest), 0644); err != nil {
		return err
	}
	backup := stage + "-previous"
	if _, err = os.Lstat(dir); err == nil {
		if err = os.Rename(dir, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = os.Rename(stage, dir); err != nil {
		if restore := os.Rename(backup, dir); restore != nil && !os.IsNotExist(restore) {
			return fmt.Errorf("apply failed: %v; restore failed: %w", err, restore)
		}
		return err
	}
	return os.RemoveAll(backup)
}
