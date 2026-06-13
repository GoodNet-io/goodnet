#!/usr/bin/env bash
# mirror-to-forgejo.sh — push every in-tree GoodNet sub-repo to the local
# Forgejo instance under the `goodnet-io` org. Idempotent.
#
# Pre-conditions:
#   - Forgejo running on $FORGEJO_HOST (default localhost:3000) with org
#     `goodnet-io` existing.
#   - SSH access to Forgejo on $FORGEJO_SSH (default ssh://git@localhost:222/goodnet-io).
#   - Forgejo API token in ~/.config/forgejo-token (or $FORGEJO_TOKEN env var).
#     Generate via web UI: Settings -> Applications -> Generate New Token.
#
# For each sub-repo this:
#   1. Resolves Forgejo repo name from the GitHub remote (or a hard-coded map).
#   2. Creates the Forgejo repo via API if it does not exist.
#   3. Adds (or rewrites) the `forgejo` remote.
#   4. Pushes `dev` and `main` branches (whichever exist locally).
#
# DOES NOT push the kernel itself (that is mirrored elsewhere).
# DOES NOT --force; if a remote branch diverged it is left untouched and flagged.

set -uo pipefail
set +e  # never abort on individual failures — collect into summary

FORGEJO_HOST="${FORGEJO_HOST:-localhost:3000}"
FORGEJO_API="${FORGEJO_API:-http://${FORGEJO_HOST}/api/v1}"
FORGEJO_ORG="${FORGEJO_ORG:-goodnet-io}"
FORGEJO_SSH="${FORGEJO_SSH:-ssh://git@localhost:222/${FORGEJO_ORG}}"
FORGEJO_TOKEN_FILE="${FORGEJO_TOKEN_FILE:-${HOME}/.config/forgejo-token}"

if [ -z "${FORGEJO_TOKEN:-}" ]; then
    if [ -r "$FORGEJO_TOKEN_FILE" ]; then
        FORGEJO_TOKEN="$(tr -d '[:space:]' < "$FORGEJO_TOKEN_FILE")"
    fi
fi

if [ -z "${FORGEJO_TOKEN:-}" ]; then
    cat >&2 <<'EOF'
ERROR: FORGEJO_TOKEN is not set and no token file found.

To create one:
  1. Open http://localhost:3000/user/settings/applications in a browser.
  2. Log in as admin (password lives in ~/forgejo/admin-password.txt).
  3. Under "Generate New Token" enter a name (e.g. "mirror") and pick the
     `write:repository` and `write:organization` scopes.
  4. Save the resulting token to ~/.config/forgejo-token (mode 0600).

Then re-run this script.
EOF
    exit 1
fi

# Locate the kernel root so the script works regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Sub-repo path (relative to kernel) : Forgejo repo name.
# When a sub-repo's GitHub remote URL is known the name there is preferred,
# but the explicit map below is the source of truth — it must match what is
# (or will be) on Forgejo. Names below mirror the existing GitHub names.
REPOS=(
    "plugins/handlers/heartbeat:handler-heartbeat"
    "plugins/handlers/store:handler-store"
    "plugins/handlers/dns:handler-dns"
    "plugins/handlers/web_api_proxy:handler-web-api-proxy"
    "plugins/handlers/ssh-modern:handler-ssh-modern"
    "plugins/links/tcp:link-tcp"
    "plugins/links/udp:link-udp"
    "plugins/links/tls:link-tls"
    "plugins/links/ws:link-ws"
    "plugins/links/ipc:link-ipc"
    "plugins/links/ice:link-ice"
    "plugins/links/quic:link-quic"
    "plugins/links/portmap:link-portmap"
    "plugins/security/noise:security-noise"
    "plugins/security/null:security-null"
    "plugins/security/pkcs11:security-pkcs11"
    "plugins/strategies/float_send_rtt:strategy-float-send-rtt"
    "bridges/cpp:bridges-cpp"
    "bridges/python:bridges-python"
    "bridges/rust:bridges-rust"
    "bridges/js:bridges-js"
    "apps/gssh:gssh"
    "apps/goodnetd:goodnetd"
    "tests/integration:integration-tests"
)

declare -a SUMMARY            # one line per repo
TOTAL_PUSHED=0
TOTAL_SKIPPED=0
TOTAL_FAILED=0

# forgejo_repo_exists <name> -> 0 if exists, 1 if not, 2 on error.
forgejo_repo_exists() {
    local name="$1"
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: token ${FORGEJO_TOKEN}" \
        "${FORGEJO_API}/repos/${FORGEJO_ORG}/${name}")
    case "$code" in
        200) return 0 ;;
        404) return 1 ;;
        *)
            echo "    (HTTP $code while probing ${FORGEJO_ORG}/${name})" >&2
            return 2
            ;;
    esac
}

# forgejo_repo_create <name> -> 0 ok, 1 fail. Prints diagnostic on stderr.
forgejo_repo_create() {
    local name="$1"
    local resp
    resp=$(curl -s -w '\nHTTP_STATUS:%{http_code}' \
        -X POST "${FORGEJO_API}/orgs/${FORGEJO_ORG}/repos" \
        -H "Authorization: token ${FORGEJO_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"${name}\",\"private\":false,\"auto_init\":false}")
    local status="${resp##*HTTP_STATUS:}"
    local body="${resp%HTTP_STATUS:*}"
    case "$status" in
        201) return 0 ;;
        409) return 0 ;;   # already exists — treat as success (idempotent)
        *)
            echo "    create failed (HTTP $status): $(echo "$body" | head -c 200)" >&2
            return 1
            ;;
    esac
}

# ensure_forgejo_remote <repo-dir> <name>
ensure_forgejo_remote() {
    local dir="$1"
    local name="$2"
    local want="${FORGEJO_SSH}/${name}.git"
    local have
    have=$(git -C "$dir" remote get-url forgejo 2>/dev/null)
    if [ -z "$have" ]; then
        git -C "$dir" remote add forgejo "$want"
    elif [ "$have" != "$want" ]; then
        git -C "$dir" remote set-url forgejo "$want"
    fi
}

# push_branch <repo-dir> <branch> -> echoes PUSHED|UPTODATE|MISSING|FAILED
push_branch() {
    local dir="$1"
    local br="$2"
    if ! git -C "$dir" show-ref --verify --quiet "refs/heads/${br}"; then
        echo "MISSING"
        return
    fi
    local out
    out=$(git -C "$dir" push forgejo "$br" 2>&1)
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        # Diverged / rejected — never force.
        echo "FAILED: $(echo "$out" | tail -1)"
        return
    fi
    if echo "$out" | grep -q "Everything up-to-date"; then
        echo "UPTODATE"
    else
        echo "PUSHED"
    fi
}

printf '%s\n' "=== mirror-to-forgejo.sh ==="
printf 'kernel    : %s\n' "$KERNEL_ROOT"
printf 'forgejo   : %s (api %s)\n' "${FORGEJO_SSH}" "${FORGEJO_API}"
printf 'sub-repos : %d\n\n' "${#REPOS[@]}"

for entry in "${REPOS[@]}"; do
    path="${entry%%:*}"
    name="${entry##*:}"
    dir="${KERNEL_ROOT}/${path}"

    printf -- '--- %s -> %s ---\n' "$path" "$name"

    if [ ! -d "${dir}/.git" ]; then
        printf '  no .git -- skip\n\n'
        SUMMARY+=("${path}|${name}|no-.git|-|-")
        TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
        continue
    fi

    forgejo_repo_exists "$name"
    case $? in
        0)
            create_status="existed"
            printf '  forgejo repo: existed\n'
            ;;
        1)
            if forgejo_repo_create "$name"; then
                create_status="created"
                printf '  forgejo repo: created\n'
            else
                create_status="create-failed"
                SUMMARY+=("${path}|${name}|create-failed|-|-")
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
                printf '\n'
                continue
            fi
            ;;
        *)
            create_status="probe-failed"
            SUMMARY+=("${path}|${name}|probe-failed|-|-")
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
            printf '\n'
            continue
            ;;
    esac

    ensure_forgejo_remote "$dir" "$name"

    dev_res=$(push_branch "$dir" dev)
    printf '  push dev : %s\n' "$dev_res"

    main_res=$(push_branch "$dir" main)
    printf '  push main: %s\n' "$main_res"

    # Tally: a sub-repo counts as pushed if at least one branch landed,
    # failed if any branch FAILED, skipped otherwise.
    if [[ "$dev_res" == FAILED:* || "$main_res" == FAILED:* ]]; then
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    elif [[ "$dev_res" == PUSHED || "$main_res" == PUSHED ]]; then
        TOTAL_PUSHED=$((TOTAL_PUSHED + 1))
    else
        TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
    fi

    SUMMARY+=("${path}|${name}|${create_status}|${dev_res}|${main_res}")
    printf '\n'
done

printf '=== summary ===\n'
printf '%-38s %-26s %-14s %-22s %-22s\n' \
    "path" "forgejo-name" "create" "push dev" "push main"
printf '%-38s %-26s %-14s %-22s %-22s\n' \
    "----" "------------" "------" "--------" "---------"
for row in "${SUMMARY[@]}"; do
    IFS='|' read -r p n c d m <<<"$row"
    printf '%-38s %-26s %-14s %-22s %-22s\n' "$p" "$n" "$c" "$d" "$m"
done
printf '\ntotal pushed : %d\n' "$TOTAL_PUSHED"
printf 'total skipped: %d\n' "$TOTAL_SKIPPED"
printf 'total failed : %d\n' "$TOTAL_FAILED"

if [ "$TOTAL_FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
