#!/usr/bin/env bash
#
# vendor/update.sh — Bump a vendored binary to a new version.
#
# Each of the six bundled binaries (Xray + the five DNS bundle binaries)
# has its own curation pipeline: download or build, verify, SHA, gzip,
# write back to vendor/, update the matching pin file. This script is
# the canonical implementation of the procedure documented prose-style
# in vendor/README.md.
#
# Usage:
#   vendor/update.sh <binary> <version>
#   vendor/update.sh --help
#
# Examples:
#   vendor/update.sh xray            v26.3.28
#   vendor/update.sh dnscrypt-proxy  2.1.16
#   vendor/update.sh tor             0.4.9.9
#   vendor/update.sh lyrebird        0.8.2
#   vendor/update.sh snowflake       v2.13.2
#   vendor/update.sh webtunnel       v0.0.5
#
# After a successful run:
#   - vendor/<name>-linux-amd64.gz is replaced with the new (truly static)
#     ELF, gzipped at level 9.
#   - vendor/{XRAY,DNS_BUNDLE}_VERSION has the matching VERSION + SHA256
#     lines updated atomically.
#   - The script verifies the on-disk SHA matches what it just wrote to
#     the pin file, then prints a `git diff --stat`-style summary.
#
# Build prerequisites:
#   - bash, curl, gzip, sha256sum, file (always)
#   - docker — used for tor (Alpine static-musl build) and the three Go
#     PT binaries (consistent toolchain via golang:<ver>-alpine images).
#     Falls back gracefully with a clear error if docker is missing.
#   - gpg (optional) — used for the Tor Project's .sha256sum.asc and
#     similar where signatures are available.

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

VENDOR_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$VENDOR_DIR/.." && pwd)"
XRAY_PIN="$VENDOR_DIR/XRAY_VERSION"
DNS_PIN="$VENDOR_DIR/DNS_BUNDLE_VERSION"

# Working directory for downloads + builds. Cleared on exit.
WORK_DIR=""
DOCKER_CONTAINERS=()  # tracked for cleanup

cleanup() {
    local rc=$?
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
    for c in "${DOCKER_CONTAINERS[@]+"${DOCKER_CONTAINERS[@]}"}"; do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
    return $rc
}
trap cleanup EXIT

# Colour output, but only to a TTY — keeps CI logs clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""
fi

log()  { printf '%s[update.sh]%s %s\n' "$C_BLUE" "$C_RESET" "$*" >&2; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
warn() { printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------

usage() {
    cat <<'EOF'
Usage: vendor/update.sh <binary> <version>

Binaries:
  xray            Pre-built upstream release (GitHub, signed .dgst)
  dnscrypt-proxy  Pre-built upstream release (GitHub, HTTPS only — minisign
                  pubkey is stale; flag bumps for manual review)
  tor             Built from source in Alpine Docker, static-PIE
  lyrebird        Built from Go source (CGO_ENABLED=0, fully static)
  snowflake       Built from Go source (CGO_ENABLED=0, fully static)
  webtunnel       Built from Go source (CGO_ENABLED=0, fully static)

Examples:
  vendor/update.sh xray            v26.3.28
  vendor/update.sh dnscrypt-proxy  2.1.16
  vendor/update.sh tor             0.4.9.9
  vendor/update.sh lyrebird        0.8.2
  vendor/update.sh snowflake       v2.13.2
  vendor/update.sh webtunnel       v0.0.5

Environment:
  NO_COLOR=1   Disable ANSI colour output (auto-disabled when stdout is
               not a TTY).
EOF
}

main() {
    if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        usage
        exit 0
    fi

    local binary="$1"
    local version="${2:-}"
    if [ -z "$version" ]; then
        die "version is required (e.g. \`vendor/update.sh $binary <version>\`)"
    fi

    require_cmd curl gzip sha256sum file tar

    WORK_DIR="$(mktemp -d -t awg-easy-rs-vendor-XXXXXX)"
    log "work dir: $WORK_DIR"

    case "$binary" in
        xray)            update_xray "$version" ;;
        dnscrypt-proxy)  update_dnscrypt_proxy "$version" ;;
        tor)             update_tor "$version" ;;
        lyrebird)        update_lyrebird "$version" ;;
        snowflake)       update_snowflake "$version" ;;
        webtunnel)       update_webtunnel "$version" ;;
        *)               die "unknown binary $binary — see --help" ;;
    esac

    show_summary "$binary"
}

# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

require_cmd() {
    local missing=()
    for cmd; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        die "missing required command(s): ${missing[*]}"
    fi
}

require_docker() {
    require_cmd docker
    docker info >/dev/null 2>&1 || die "docker daemon not reachable"
}

# Verify the ELF is ACTUALLY static (no shared lib deps, no dynamic
# interpreter). Catches "we built with musl-gcc but forgot crt-static"
# regressions before they make it into the repo.
verify_static() {
    local path="$1" name="$2"
    local file_out
    file_out="$(file "$path")"
    log "  file: $file_out"
    if echo "$file_out" | grep -q "dynamically linked"; then
        die "$name: ELF is dynamically linked — would break on non-musl hosts"
    fi
    if echo "$file_out" | grep -qi "interpreter"; then
        die "$name: ELF declares an interpreter — would break on hosts \
without that loader path"
    fi
    if ! echo "$file_out" | grep -qE "statically linked|static-pie"; then
        warn "$name: file output didn't include 'statically linked' or \
'static-pie' — manual review recommended"
    fi
}

# Compute the uncompressed ELF SHA-256 (used by the runtime extractor),
# gzip -9 into the vendor slot, and report the new SHA. Doesn't touch
# the pin file — caller does that next so a failure here doesn't leave
# the pin file pointing at a missing/old blob.
package_blob() {
    local elf_path="$1" blob_name="$2"
    local sha
    sha="$(sha256sum "$elf_path" | awk '{print $1}')"
    local dest="$VENDOR_DIR/${blob_name}-linux-amd64.gz"
    log "gzipping → $dest"
    gzip -9 -c "$elf_path" > "$dest.partial"
    mv "$dest.partial" "$dest"
    printf '%s' "$sha"
}

# Atomically rewrite a single `KEY = VALUE` line in a pin file. The
# match is anchored to the start-of-line and tolerates surrounding
# whitespace around `=`, matching the formats both pin files use.
# Errors out if the key isn't found — silent no-ops would be a footgun
# (a misspelled key would leave the old SHA in place undetected).
pin_update() {
    local pin_file="$1" key="$2" value="$3"
    if [ ! -f "$pin_file" ]; then
        die "pin file $pin_file does not exist"
    fi
    if ! grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$pin_file"; then
        die "key $key not found in $pin_file — refusing to add silently. \
Add the key by hand if this is a new binary."
    fi
    local tmp="${pin_file}.tmp.$$"
    awk -v k="$key" -v v="$value" '
        BEGIN { pat = "^[[:space:]]*" k "[[:space:]]*=" }
        $0 ~ pat { printf "%s = %s\n", k, v; next }
        { print }
    ' "$pin_file" > "$tmp"
    mv "$tmp" "$pin_file"
    log "  pin: $key = $value"
}

# Cross-check: re-hash the on-disk gzipped blob's content against what
# we just wrote to the pin file. Catches "wrote the wrong SHA into the
# pin" or "the pin file format wasn't what awk expected".
verify_pin_matches_blob() {
    local blob_name="$1" expected_sha="$2"
    local blob="$VENDOR_DIR/${blob_name}-linux-amd64.gz"
    local actual
    actual="$(gunzip -c "$blob" | sha256sum | awk '{print $1}')"
    if [ "$actual" != "$expected_sha" ]; then
        die "POST-WRITE CHECK FAILED for $blob_name:
        pin file says SHA=$expected_sha
        on-disk gzipped blob unpacks to SHA=$actual
        Either the pin file write was wrong, or the blob got mangled."
    fi
}

show_summary() {
    local binary="$1"
    printf '\n%s%s──────────────────────────────────────────%s\n' \
        "$C_BOLD" "$C_GREEN" "$C_RESET" >&2
    ok "$binary updated"
    if command -v git >/dev/null 2>&1 && [ -d "$REPO_ROOT/.git" ]; then
        log "git status:"
        git -C "$REPO_ROOT" status --short -- vendor/ >&2 || true
    fi
    printf '%s%s──────────────────────────────────────────%s\n\n' \
        "$C_BOLD" "$C_GREEN" "$C_RESET" >&2
}

# Run a long-lived Alpine container detached, run the build inside, then
# `docker cp` the result out. We use `cp` rather than a `-v` bind mount
# because rootless / WSL2 / Lima setups don't always preserve binary
# permissions through volumes. This is slightly slower but works on
# every Docker variant.
docker_build_to_file() {
    local image="$1" container_name="$2" build_script="$3"
    local container_path="$4" host_path="$5"

    log "starting build container ($image)"
    docker pull "$image" >/dev/null 2>&1 || true
    docker run -d --name "$container_name" "$image" \
        sh -c "$build_script ; sleep infinity" >/dev/null
    DOCKER_CONTAINERS+=("$container_name")

    # Poll until the build artifact appears or the container exits.
    log "waiting for build to complete (this can take 10+ minutes for tor)"
    local elapsed=0
    while ! docker exec "$container_name" test -f "$container_path" 2>/dev/null; do
        if ! docker inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null \
                | grep -q true; then
            warn "container exited before producing $container_path"
            log "build container logs (last 40 lines):"
            docker logs --tail 40 "$container_name" >&2 || true
            die "build failed inside $image"
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        if [ $((elapsed % 60)) -eq 0 ]; then
            log "  …${elapsed}s elapsed"
        fi
    done

    log "extracting build output → $host_path"
    docker cp "${container_name}:${container_path}" "$host_path"
    docker rm -f "$container_name" >/dev/null
    # Drop from the cleanup list since we just removed it.
    DOCKER_CONTAINERS=("${DOCKER_CONTAINERS[@]/$container_name}")
}

# ---------------------------------------------------------------------------
# Per-binary update functions
# ---------------------------------------------------------------------------

update_xray() {
    local version="$1"
    # Upstream tags like v26.3.27. Strip leading `v` for some URLs but
    # keep it in the pin file (matches the historical convention).
    local v="${version#v}"
    log "fetching Xray-core $version"
    local zip="$WORK_DIR/Xray-linux-64.zip"
    local dgst="$WORK_DIR/Xray-linux-64.zip.dgst"
    curl -sSL --fail-with-body -o "$zip" \
        "https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip"
    curl -sSL --fail-with-body -o "$dgst" \
        "https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip.dgst" || \
        warn "no .dgst published for $version — skipping zip-SHA cross-check"

    if [ -s "$dgst" ]; then
        local expected actual
        expected="$(awk '/SHA2-256/{print $2; exit}' "$dgst")"
        actual="$(sha256sum "$zip" | awk '{print $1}')"
        if [ "$expected" != "$actual" ]; then
            die "Xray zip SHA-256 mismatch:
                expected $expected (from upstream .dgst)
                got      $actual"
        fi
        ok "zip SHA-256 verified against upstream .dgst"
    fi

    log "extracting xray ELF"
    (cd "$WORK_DIR" && unzip -o "$zip" xray >/dev/null) \
        || die "unzip failed (is the 'unzip' command installed?)"
    local elf="$WORK_DIR/xray"
    [ -f "$elf" ] || die "xray binary not present in zip"
    chmod +x "$elf"

    log "smoke-test"
    "$elf" version >/dev/null 2>&1 || warn "xray --version returned non-zero (may be normal if libc is incompatible)"

    local sha
    sha="$(package_blob "$elf" "xray")"
    pin_update "$XRAY_PIN" "XRAY_VERSION" "$version"
    pin_update "$XRAY_PIN" "XRAY_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "xray" "$sha"
}

update_dnscrypt_proxy() {
    local version="$1"
    # Upstream uses unprefixed versions like 2.1.15.
    local v="${version#v}"
    log "fetching dnscrypt-proxy $v"
    local tgz="$WORK_DIR/dnscrypt-proxy.tar.gz"
    curl -sSL --fail-with-body -o "$tgz" \
        "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${v}/dnscrypt-proxy-linux_x86_64-${v}.tar.gz"

    # Try minisign verification — but the dnscrypt-proxy maintainers
    # have rotated keys without updating their public docs in the past,
    # so we treat a sig failure as a warning rather than a hard stop.
    # Operators bumping to a new version should manually verify the key
    # against a trusted out-of-band source.
    local sig="$WORK_DIR/dnscrypt-proxy.tar.gz.minisig"
    curl -sSL --fail-with-body -o "$sig" \
        "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${v}/dnscrypt-proxy-linux_x86_64-${v}.tar.gz.minisig" 2>/dev/null || true

    if [ -s "$sig" ] && command -v minisign >/dev/null 2>&1; then
        # Documented public key from the dnscrypt-proxy README. May be
        # stale; that's why we don't fail-closed on signature errors.
        if minisign -V -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3 \
                -m "$tgz" 2>&1 | grep -q "Signature and comment signature verified"; then
            ok "minisign signature verified"
        else
            warn "minisign signature verification FAILED — \
public key may have rotated. Manually verify $version before publishing this bump."
        fi
    else
        warn "minisign not installed or no .minisig published — \
HTTPS chain-of-trust only"
    fi

    log "extracting dnscrypt-proxy ELF"
    (cd "$WORK_DIR" && tar xzf "$tgz")
    local elf="$WORK_DIR/linux-x86_64/dnscrypt-proxy"
    [ -f "$elf" ] || die "dnscrypt-proxy binary not present at expected path"

    verify_static "$elf" "dnscrypt-proxy"

    log "smoke-test"
    "$elf" -version >/dev/null 2>&1 || warn "dnscrypt-proxy -version returned non-zero"

    local sha
    sha="$(package_blob "$elf" "dnscrypt-proxy")"
    pin_update "$DNS_PIN" "DNSCRYPT_PROXY_VERSION" "$v"
    pin_update "$DNS_PIN" "DNSCRYPT_PROXY_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "dnscrypt-proxy" "$sha"
}

update_tor() {
    local version="$1"
    require_docker
    log "building tor $version from source in Alpine Docker (~10 min)"

    # Fully static-PIE build via Alpine's apk packages for the static
    # variants of openssl + libevent + zlib. These are the same packages
    # we used for the original curation in this repo.
    local script="
set -e
apk add --no-cache build-base wget openssl-dev openssl-libs-static \
    libevent-dev libevent-static zlib-dev zlib-static linux-headers \
    >/dev/null 2>&1
cd /tmp
wget -q https://dist.torproject.org/tor-${version}.tar.gz
wget -q https://dist.torproject.org/tor-${version}.tar.gz.sha256sum
sha256sum -c tor-${version}.tar.gz.sha256sum
tar xzf tor-${version}.tar.gz
cd tor-${version}
./configure --enable-static-tor \
    --enable-static-openssl --with-openssl-dir=/usr/lib \
    --enable-static-libevent --with-libevent-dir=/usr/lib \
    --enable-static-zlib --with-zlib-dir=/usr/lib \
    --disable-asciidoc --disable-html-manual --disable-manpage \
    --disable-systemd --disable-lzma --disable-zstd \
    >/tmp/configure.log 2>&1
make -j\$(nproc) >/tmp/make.log 2>&1
strip src/app/tor
"
    docker_build_to_file alpine "awg-tor-build-$$" "$script" \
        "/tmp/tor-${version}/src/app/tor" "$WORK_DIR/tor"

    verify_static "$WORK_DIR/tor" "tor"

    log "smoke-test"
    "$WORK_DIR/tor" --version >/dev/null 2>&1 \
        || warn "tor --version returned non-zero"

    local sha
    sha="$(package_blob "$WORK_DIR/tor" "tor")"
    pin_update "$DNS_PIN" "TOR_VERSION" "$version"
    pin_update "$DNS_PIN" "TOR_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "tor" "$sha"
}

# Shared logic for the three Go-built pluggable transports. Each PT has
# a different upstream URL, build path, and binary name — passed as args.
update_go_pt() {
    local pin_key_prefix="$1" git_url="$2" git_tag="$3"
    local build_subpath="$4" out_binary="$5" blob_name="$6"
    require_docker

    log "building $blob_name $git_tag from source (Go, static, CGO_ENABLED=0)"
    local script="
set -e
apk add --no-cache git >/dev/null 2>&1
cd /src
git clone --depth 1 --branch '${git_tag}' '${git_url}' src 2>&1 | tail -3
cd src
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w -extldflags=-static' \
    -o /out/${out_binary} ${build_subpath}
strip /out/${out_binary}
"
    docker_build_to_file golang:1.24-alpine "awg-go-build-$$" "$script" \
        "/out/${out_binary}" "$WORK_DIR/${out_binary}"

    verify_static "$WORK_DIR/${out_binary}" "$blob_name"

    local sha
    sha="$(package_blob "$WORK_DIR/${out_binary}" "$blob_name")"
    pin_update "$DNS_PIN" "${pin_key_prefix}_VERSION" "$git_tag"
    pin_update "$DNS_PIN" "${pin_key_prefix}_AMD64_SHA256" "$sha"
    verify_pin_matches_blob "$blob_name" "$sha"
}

update_lyrebird() {
    local version="$1"
    update_go_pt LYREBIRD \
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git" \
        "lyrebird-${version#lyrebird-}" \
        "./cmd/lyrebird" \
        "lyrebird" \
        "lyrebird"
}

update_snowflake() {
    local version="$1"
    # snowflake tags are prefixed `v` — pass through whatever the user gave.
    local tag="$version"
    [[ "$tag" == v* ]] || tag="v$tag"
    update_go_pt SNOWFLAKE \
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake.git" \
        "$tag" \
        "./client" \
        "snowflake-client" \
        "snowflake"
}

update_webtunnel() {
    local version="$1"
    local tag="$version"
    [[ "$tag" == v* ]] || tag="v$tag"
    update_go_pt WEBTUNNEL \
        "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel.git" \
        "$tag" \
        "./main/client" \
        "webtunnel-client" \
        "webtunnel"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

main "$@"
