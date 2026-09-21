#!/usr/bin/env bash
# Reproducible demo recording for the README GIF.
# Requires: asciinema + agg (brew install asciinema agg).
# Produces docs/img/demo.gif directly.
set -euo pipefail

cd "$(dirname "$0")/.."
go build -o bin/agentvault ./cmd/agentvault

DEMO_HOME=$(mktemp -d)
export AGENTVAULT_HOME="$DEMO_HOME/vault"
BIN="$PWD/bin/agentvault"
trap 'rm -rf "$DEMO_HOME"' EXIT

mkdir -p "$DEMO_HOME/vault"
cat > "$DEMO_HOME/policy.yaml" <<YAML
version: 1
defaults: {action: deny}
rules:
  - name: block-destructive-shell
    match: {action: [shell.exec], cel: 'event.cmd == "rm" || event.argv.exists(a, a.startsWith("-rf"))'}
    effect: deny
    message: "destructive commands are blocked"
  - name: allow-ls
    match: {action: [shell.exec], cel: 'event.cmd == "ls"'}
    effect: allow
shims: {binaries: [rm, ls]}
sandbox: {enabled: true}
audit: {path: "$DEMO_HOME/vault/audit.db"}
YAML

# The inner demo script — written to a file so no nested quoting.
cat > "$DEMO_HOME/scene.sh" <<'SCENE'
#!/usr/bin/env bash
# env: BIN, POLICY
sleep 0.6
echo '$ agentvault run -- bash'
sleep 0.8
"$BIN" -c "$POLICY" run -- bash -c '
  echo "agent: let me clean up your disk"
  sleep 1.0
  echo "agent: $ rm -rf /tmp/important"
  sleep 0.6
  rm -rf /tmp/important
  echo "agent: rm exit code: $?"
  sleep 1.2
  echo "agent: fine, ls then"
  ls /tmp >/dev/null && echo "agent: $ ls /tmp  ✓ allowed"
'
sleep 0.8
echo
echo '$ agentvault log --export json | tail -2'
sleep 0.6
"$BIN" -c "$POLICY" log --export json | tail -2 | cut -c1-100
sleep 2.0
SCENE
chmod +x "$DEMO_HOME/scene.sh"

mkdir -p docs/img
BIN="$BIN" POLICY="$DEMO_HOME/policy.yaml" \
  asciinema rec --command "bash $DEMO_HOME/scene.sh" docs/img/demo.cast --overwrite --idle-time-limit 3

if command -v agg >/dev/null; then
  agg docs/img/demo.cast docs/img/demo.gif --font-size 16 --cols 90
  echo "✓ docs/img/demo.gif ($(du -h docs/img/demo.gif | cut -f1))"
else
  echo "✓ docs/img/demo.cast recorded (install agg to convert to GIF)"
fi
