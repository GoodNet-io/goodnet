# CI — Forgejo runner setup

Forgejo is the sole CI. The workflow files at
`.forgejo/workflows/{ci,dev,release}.yml` target the runner label
`nix-self-hosted` and assume Nix is preinstalled on `PATH`. The
`.github/workflows/` directory is empty by design — no GitHub
Actions runs anything for this repo. Release artefacts are built on
the Forgejo runner on tag push and published to GitHub Releases via
the `gh` CLI; see "GitHub Releases publish" below for the token
secret setup. The full job list (build-and-test, plugin-verify
matrix, windows-cross-build, bench-smoke, ice-3node, fuzz-smoke,
asan-smoke, tsan-smoke, plus the cheap flake-check + livedoc-check
gates) lives in `ci.yml`. See the README "Local test gate and CI
gating" table for where each gate lands.

## Prerequisites

`forgejo-runner` ships in the user's Nix profile already:

```bash
~/.nix-profile/bin/forgejo-runner --version
```

If absent on a fresh machine:

```bash
nix profile install nixpkgs#forgejo-runner
```

## Registration token

The runner needs a one-time registration token from the Forgejo web
admin. Generate one at:

```
http://<forgejo-host>:<port>/-/admin/actions/runners
```

TODO: confirm forgejo web URL — the current instance exposes SSH on
:222 but the web port is not yet pinned; ask the operator who set
up the instance or check `docker-forgejo.service` / the systemd unit
for the `-p` mapping.

The page has a "Create new runner" button which yields a
`registration token` valid for ~1 hour. Keep it out of shell
history; pipe it via stdin or an env var.

## Path A — native (NixOS, systemd user unit)

```bash
mkdir -p ~/.config/forgejo-runner
cd ~/.config/forgejo-runner
~/.nix-profile/bin/forgejo-runner register \
  --no-interactive \
  --instance http://<forgejo-host>:<port>/ \
  --token "$REGISTRATION_TOKEN" \
  --name "$(hostname)-nix" \
  --labels nix-self-hosted
```

This drops a `.runner` file in the cwd. To run as a systemd user
unit (auto-start on login):

```ini
# ~/.config/systemd/user/forgejo-runner.service
[Unit]
Description=Forgejo Actions runner
After=network-online.target

[Service]
WorkingDirectory=%h/.config/forgejo-runner
ExecStart=%h/.nix-profile/bin/forgejo-runner daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now forgejo-runner.service
systemctl --user status forgejo-runner.service
```

## Path B — docker

```bash
docker run -d --restart=always \
  --name forgejo-runner \
  -v "$PWD/forgejo-runner-data:/data" \
  -e GITEA_INSTANCE_URL=http://<forgejo-host>:<port>/ \
  -e GITEA_RUNNER_REGISTRATION_TOKEN="$REGISTRATION_TOKEN" \
  -e GITEA_RUNNER_LABELS=nix-self-hosted \
  code.forgejo.org/forgejo/runner:latest
```

The image does **not** ship Nix. Either swap in a Nix-bearing base
or use the native path above. The native path is what the workflow
files assume.

## Sanity check

A throwaway workflow to confirm Nix is on `PATH` inside the runner:

```yaml
# .forgejo/workflows/sanity.yml (do not merge)
on: { workflow_dispatch: {} }
jobs:
  ping:
    runs-on: nix-self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: nix --version
      - run: nix flake check --print-build-logs
```

Trigger it from the Forgejo Actions UI; both `nix --version` and
`nix flake check` should succeed without any extra setup step.

## GitHub Releases publish

`.forgejo/workflows/release.yml` builds Linux+Windows x86_64
artefacts on tag push (tags matching `v*`) and publishes them to
GitHub Releases at `goodnet-io/goodnet`. The publish step uses the
`gh` CLI (staged from `nixpkgs#gh` on demand) — there is no
`softprops/action-gh-release` wrapper anymore.

### Token secret

The release job reads a per-repo Forgejo secret named **`GH_TOKEN`**.
Required scopes on the GitHub side:

- Classic PAT: `repo` (full), OR
- Fine-grained PAT: `Contents: read and write` on
  `goodnet-io/goodnet`, expiry as your security policy dictates.

Set it in the Forgejo web UI:

```
Repo Settings → Actions → Secrets → Add Secret
  Name:  GH_TOKEN
  Value: <github personal access token>
```

The runner exposes the secret to the `release` job through
`env.GH_TOKEN: ${{ secrets.GH_TOKEN }}`; the `gh` CLI picks it up
from that env var automatically (no `gh auth login` needed). The
same job pins `GH_REPO: goodnet-io/goodnet` so `gh` does not have
to infer the remote from the checkout.

### Publish command

The job uses a create-or-upload split so re-running the workflow on
the same tag stays idempotent:

```bash
nix shell nixpkgs#gh --command bash -euo pipefail -c '
  assets=(
    "goodnet-${TAG}-linux-x86_64.tar.gz"
    "goodnet-${TAG}-linux-x86_64.tar.gz.sha256"
    "goodnet-${TAG}-windows-x86_64.zip"
    "goodnet-${TAG}-windows-x86_64.zip.sha256"
  )
  if gh release view "${TAG}" >/dev/null 2>&1; then
    gh release upload "${TAG}" "${assets[@]}" --clobber
  else
    gh release create "${TAG}" "${assets[@]}" \
      --title "${TAG}" \
      --notes-file release-notes.md
  fi
'
```

`release-notes.md` is written one step earlier from the
`changelog` job's `notes` output (auto-generated diff `${PREV}..${TAG}`
in commit-list form). `--clobber` overwrites assets of the same name
on a re-run; the release row itself is preserved.

## Cross-references

- `.forgejo/workflows/ci.yml` — full job set
- `.forgejo/workflows/release.yml` — tag-push build + GitHub
  Releases publish via `gh` CLI
- README — CI gating table with the "Where" column
