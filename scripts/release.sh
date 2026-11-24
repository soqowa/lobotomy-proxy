#!/bin/bash
set -euo pipefail

# An optional previously signed ZIP preserves the exact bits tested on a Mac.
archive="${1:-}"
if [[ -n "$archive" ]]; then
    archive="$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")"
fi
cd "$(dirname "$0")/.."
version="$(cat VERSION)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid VERSION' >&2; exit 1; }
tag="v$version"
commit="$(git rev-parse HEAD)"
repo="$(gh repo view "$(git remote get-url origin)" --json nameWithOwner --jq .nameWithOwner)"
[[ -z "$(git status --porcelain)" ]] || { echo 'Commit your changes before releasing.' >&2; exit 1; }
remote_main="$(git ls-remote origin refs/heads/main)"
[[ "${remote_main%%[[:space:]]*}" == "$commit" ]] || { echo 'Push the release commit to main first.' >&2; exit 1; }
# Never reuse a version for another commit, including annotated tags.
refs="$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")"
tag_commit="$(awk 'NF {sha=$1} END {print sha}' <<< "$refs")"
[[ -z "$tag_commit" || "$tag_commit" == "$commit" ]] || { echo 'Tag belongs to another commit.' >&2; exit 1; }

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
asset="Lobotomy-Proxy-$version-macOS-universal.zip"
app="$stage/Proxy Guard.app"
if [[ -n "$archive" ]]; then
    cp "$archive" "$stage/$asset"
    ditto -x -k "$stage/$asset" "$stage"
else
    if [[ -z "${PROXYGUARD_SIGNING_IDENTITY:-}" ]]; then
        identities="$(security find-identity -v -p codesigning)"
        PROXYGUARD_SIGNING_IDENTITY="$(awk '/"Developer ID Application:/ {print $2; exit}' <<< "$identities")"
        if [[ -z "$PROXYGUARD_SIGNING_IDENTITY" ]]; then
            PROXYGUARD_SIGNING_IDENTITY="$(awk '/"Apple Development:/ {print $2; exit}' <<< "$identities")"
        fi
        export PROXYGUARD_SIGNING_IDENTITY
    fi
    [[ -n "$PROXYGUARD_SIGNING_IDENTITY" ]] || { echo 'A signing identity is required.' >&2; exit 1; }
    ./build.sh "$app"
    ditto -c -k --keepParent "$app" "$stage/$asset"
fi
info="$app/Contents/Info.plist"
[[ "$(plutil -extract CFBundleIdentifier raw "$info")" == local.proxyguard.app ]]
[[ "$(plutil -extract CFBundleShortVersionString raw "$info")" == "$version" ]]
codesign --verify --deep --strict "$app"
signer="$(codesign -dv --verbose=4 "$app" 2>&1)"
if ! grep -Eq '^Authority=(Apple Development|Developer ID Application):' <<< "$signer"; then
    echo 'Expected an Apple Development or Developer ID Application signature.' >&2
    exit 1
fi
for binary in 'MacOS/ProxyGuard' 'Helpers/proxyguard' 'Library/LoginItems/Proxy Guard Relay.app/Contents/MacOS/ProxyGuardRelay'; do
    for arch in arm64 x86_64; do
        lipo -verify_arch "$arch" "$app/Contents/$binary"
    done
done
(cd "$stage" && shasum -a 256 "$asset" > SHA256SUMS.txt)
if [[ -n "${RELEASE_NOTES_FILE:-}" ]]; then
    cp "$RELEASE_NOTES_FILE" "$stage/notes.md"
else
    gh api --method POST "repos/$repo/releases/generate-notes" -f tag_name="$tag" -f target_commitish="$commit" --jq .body > "$stage/notes.md"
fi
if grep -q '^Authority=Apple Development:' <<< "$signer"; then
    echo >> "$stage/notes.md"
    echo 'Сборка подписана Apple Development. Для обычной установки через Gatekeeper на другом Mac требуется сборка с Developer ID и нотарификацией.' >> "$stage/notes.md"
fi

if [[ -z "$tag_commit" ]]; then
    git push origin "$commit:refs/tags/$tag"
fi
if draft="$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft 2>/dev/null)"; then
    [[ "$draft" == true ]] || { echo "Release $tag is already published." >&2; exit 1; }
else
    gh release create "$tag" --repo "$repo" --verify-tag --draft --title "Lobotomy Proxy $version" --notes-file "$stage/notes.md"
fi
gh release upload "$tag" "$stage/$asset" "$stage/SHA256SUMS.txt" --repo "$repo" --clobber
gh release edit "$tag" --repo "$repo" --draft=false --latest --notes-file "$stage/notes.md"
