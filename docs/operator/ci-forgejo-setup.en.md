# CI — Forgejo runner setup

The full CI matrix runs on a self-hosted Forgejo Actions runner. The
workflow files at `.forgejo/workflows/{ci,dev,release}.yml` target
the runner label `nix-self-hosted` and assume Nix is preinstalled
on `PATH`. The GitHub copy at `.github/workflows/ci.yml` carries
only `flake-check` + `livedoc-check` as a public smoke; the heavy
jobs (build-and-test, plugin-verify matrix, windows-cross-build,
bench-smoke, ice-3node, fuzz-smoke, asan-smoke, tsan-smoke) live on
Forgejo. See the README "Local test gate and CI gating" table for
where each gate lands.

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

## Cross-references

- `.forgejo/workflows/ci.yml` — full job set
- `.forgejo/workflows/release.yml` — TODO on aarch64 runner label
  and `softprops/action-gh-release@v2` validation
- README — CI gating table with the "Where" column
