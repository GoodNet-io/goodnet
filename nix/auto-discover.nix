# nix/auto-discover.nix — scan `plugins/<kind>/<name>/` for plugin
# derivations the kernel flake should expose.
#
# Why this exists: the top-level flake used to carry a hard-coded
# attrset of `goodnet-handler-heartbeat = callPlugin "heartbeat"
# "handlers"; goodnet-link-tcp = callPlugin "tcp" "links"; …`. Every
# new plugin required editing the kernel flake by hand, and the
# eventual `pull-plugin` workflow (clone an extracted plugin's repo
# back into `plugins/<kind>/<name>/`) would have meant editing the
# kernel flake on every clone too. Replacing the hard-coded list
# with a directory scan keeps the kernel flake stable while the
# plugin set grows or shrinks.
#
# Convention.  A plugin lives at `plugins/<kind>/<name>/` and
# carries a `default.nix` consumed via `pkgs.callPackage`. The
# directory's basename `<name>` becomes the unhyphenated plugin
# identifier. The flake's exposed attribute name is
# `goodnet-<singular(kind)>-<name>` — handlers/heartbeat ⇒
# `goodnet-handler-heartbeat`, links/tcp ⇒ `goodnet-link-tcp`,
# protocols/raw ⇒ `goodnet-protocol-raw`, security/noise ⇒
# `goodnet-security-noise`.
#
# A plugin directory missing `default.nix` is reported (via
# `missing`) so the flake can either log it or fail loud — the
# function is intentionally side-effect-free at evaluation time.
#
# Returned shape:
#   {
#     plugins = [ { kind = "links"; name = "tcp"; attr = "goodnet-link-tcp"; } … ];
#     missing = [ { kind = "links"; name = "broken-dir"; } … ];
#   }
#
# The caller composes the actual derivations with its own
# `callPlugin` helper (so this file does not import any
# nixpkgs-flavoured machinery and can be reasoned about
# independently from the rest of the flake).

{ pluginsDir }:

let
  # Singular name for the attr namespace. Plugin directories are
  # plural (`handlers`, `links`, `protocols`) but the kernel attr
  # convention is singular (`goodnet-handler-…`, `goodnet-link-…`,
  # `goodnet-protocol-…`). `security` is already singular and keeps
  # its name. Anything else falls back to the directory name
  # verbatim — a deliberate pass-through so a future kind can be
  # added without touching this file.
  kindSingular = kind: {
    handlers  = "handler";
    links     = "link";
    protocols = "protocol";
    security  = "security";
  }.${kind} or kind;

  isDir = path: builtins.pathExists path
              && builtins.readFileType path == "directory";

  hasDefaultNix = path: builtins.pathExists (path + "/default.nix");

  kinds = builtins.filter
    (kind: isDir (pluginsDir + "/${kind}"))
    (builtins.attrNames (builtins.readDir pluginsDir));

  pluginsForKind = kind:
    let
      kindDir = pluginsDir + "/${kind}";
      candidates = builtins.attrNames (builtins.readDir kindDir);
      isPluginDir = name: isDir (kindDir + "/${name}");
      pluginDirs = builtins.filter isPluginDir candidates;
    in
    map
      (name: {
        inherit kind name;
        attr = "goodnet-${kindSingular kind}-${name}";
        hasDefault = hasDefaultNix (kindDir + "/${name}");
      })
      pluginDirs;

  flat = builtins.concatMap pluginsForKind kinds;
in
{
  plugins = builtins.filter (p: p.hasDefault) flat;
  missing = builtins.filter (p: !p.hasDefault) flat;
}
