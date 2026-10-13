#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${GITHUB_REPOSITORY:?Run this script in the repository release workflow}"
: "${GITHUB_SHA:?Missing source commit}"

rules_tmp=$(mktemp -d)
trap 'rm -rf "$rules_tmp"' EXIT
python3 - > "$rules_tmp/assets" <<'PY'
import hashlib, json
from pathlib import Path, PurePosixPath
names = ['manifest.json']
if Path('dist/routing-v2.json').exists():
    assert Path('dist/manifest-v2.json').exists(), 'Missing v2 manifest'
if Path('dist/manifest-v2.json').exists():
    names.append('manifest-v2.json')
manifests = {name: json.loads((Path('dist') / name).read_text()) for name in names}
m = manifests[names[-1]]
assert manifests['manifest.json']['schema_version'] == 1
if len(names) == 2:
    legacy = manifests['manifest.json']
    assert legacy['schema_version'] == 1 and m['schema_version'] == 2
    for key in ('version', 'repository', 'kernel_revision', 'generator_sha256'):
        assert legacy[key] == m[key], key
    expected = [f for f in m['files'] if f.get('behavior') != 'classical' and f['path'] != 'routing-v2.json']
    assert legacy['files'] == expected, 'Legacy manifest must be the compatible subset'
assets = set(names)
root = Path('dist').resolve()
for f in m['files']:
    relative = PurePosixPath(f['path'])
    assert not relative.is_absolute() and '..' not in relative.parts
    p = (root / relative).resolve()
    assert p.is_relative_to(root) and p.name == f['asset']
    assert f['asset'] not in assets
    assets.add(f['asset'])
    data = p.read_bytes()
    assert len(data) == f['bytes'] and hashlib.sha256(data).hexdigest() == f['sha256']
    print(f['path'])
PY

rules_version=$(python3 - <<'PY'
import json, os, re
from pathlib import Path
m = json.loads(Path('dist/manifest.json').read_text())
assert m['repository'] == os.environ['GITHUB_REPOSITORY']
assert re.fullmatch(r'rules-[a-f0-9]{24}', m['version'])
print(m['version'])
PY
)

if gh api "repos/$GITHUB_REPOSITORY/releases/tags/$rules_version" > "$rules_tmp/release.json" 2> "$rules_tmp/error"; then
  rules_draft=$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["draft"]).lower())' "$rules_tmp/release.json")
  if [[ "$rules_draft" != true ]]; then
    gh release download "$rules_version" --repo "$GITHUB_REPOSITORY" --pattern 'manifest*.json' --dir "$rules_tmp"
    python3 - "$rules_tmp" <<'PY'
import json, sys
from pathlib import Path
def content(m):
    return [f for f in m['files'] if f['path'] != 'sources.lock.json']
for name in ('manifest.json', 'manifest-v2.json'):
    current = Path('dist') / name
    if not current.exists():
        continue
    old = json.loads((Path(sys.argv[1]) / name).read_text())
    new = json.loads(current.read_text())
    for key in ('version', 'schema_version', 'repository', 'kernel_revision', 'generator_sha256'):
        assert old[key] == new[key], key
    assert content(old) == content(new), 'Published content must never be overwritten'
PY
    echo "Already published: $rules_version"
    exit 0
  fi
elif ! grep -q 'HTTP 404' "$rules_tmp/error"; then
  cat "$rules_tmp/error" >&2
  exit 1
else
  python3 - > "$rules_tmp/notes.md" <<'PY'
import json
from pathlib import Path
name = 'manifest-v2.json' if Path('dist/manifest-v2.json').exists() else 'manifest.json'
m = json.loads((Path('dist') / name).read_text())
print('Generated and validated rule data. Android application code is not included.\n')
print('| Rule set | Format | Rules | Bytes |\n| --- | --- | ---: | ---: |')
for f in m['files']:
    if f['format'] == 'mrs' or f.get('behavior') == 'classical':
        print(f"| {f['id']} | {f['format']} | {f['count']} | {f['bytes']} |")
if name == 'manifest-v2.json':
    print('\nNew Android clients use manifest-v2.json. manifest.json preserves the v1 domain/IP interface for existing clients.')
print('\nSource provenance and licenses are included with this release.')
PY
  gh release create "$rules_version" --repo "$GITHUB_REPOSITORY" --target "$GITHUB_SHA" --draft --title "$rules_version" --notes-file "$rules_tmp/notes.md"
fi

rules_assets=(dist/manifest.json)
if [[ -f dist/manifest-v2.json ]]; then
  rules_assets+=(dist/manifest-v2.json)
fi
while IFS= read -r rules_path; do
  rules_assets+=("dist/$rules_path")
done < "$rules_tmp/assets"

gh release upload "$rules_version" --repo "$GITHUB_REPOSITORY" --clobber "${rules_assets[@]}"
gh release edit "$rules_version" --repo "$GITHUB_REPOSITORY" --draft=false --latest
