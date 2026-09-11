#!/usr/bin/env bash
#
# A real SSH server to test against, without Docker and without root.
#
# sshd refuses to run as a non-root user only when it would have to change
# user. Serving the invoking account is exactly what we want, so a user-mode
# sshd on a high port is a complete test target: real key exchange, real
# authentication, a real SFTP subsystem. It is also faster to start than a
# container and leaves nothing behind.
#
#   scripts/dev-sshd.sh start     bring it up on 127.0.0.1:2222
#   scripts/dev-sshd.sh stop      shut it down
#   scripts/dev-sshd.sh info      print what a test needs to connect
#
# The keys it generates are throwaways in a temporary directory. Never point a
# test at a host you did not create here.
set -euo pipefail

DIR="${REMOTER_SSHD_DIR:-${TMPDIR:-/tmp}/remoter-dev-sshd}"
PORT="${REMOTER_SSHD_PORT:-2222}"
SSHD="$(command -v sshd || echo /usr/sbin/sshd)"

# True when this sshd accepts the given `key=value` directive. `sshd -G` parses
# a config and dumps it without binding a port, so it is a safe probe. Both it
# and the directives it is used to test below are recent; on an sshd too old for
# `-G` the probe fails, which is the answer we want, because such an sshd is
# also too old for the directive.
sshd_supports() {
  "$SSHD" -G -f /dev/null -o "$1" >/dev/null 2>&1
}

sftp_server() {
  for candidate in /usr/lib/ssh/sftp-server /usr/lib/openssh/sftp-server \
                   /usr/libexec/openssh/sftp-server /usr/lib/sftp-server; do
    [[ -x "$candidate" ]] && { echo "$candidate"; return; }
  done
  echo ""
}

start() {
  mkdir -p "$DIR"; chmod 700 "$DIR"

  [[ -f "$DIR/host_ed25519" ]] || ssh-keygen -t ed25519 -f "$DIR/host_ed25519" -N "" -q
  [[ -f "$DIR/host_rsa"     ]] || ssh-keygen -t rsa -b 2048 -f "$DIR/host_rsa" -N "" -q
  [[ -f "$DIR/client_ed25519" ]] || ssh-keygen -t ed25519 -f "$DIR/client_ed25519" -N "" -q
  # A passphrase-protected key, because that path has its own failure modes.
  [[ -f "$DIR/client_pass" ]] || ssh-keygen -t ed25519 -f "$DIR/client_pass" -N "testpassphrase" -q
  # An RSA client key in PEM form, to exercise a second parser.
  [[ -f "$DIR/client_rsa" ]] || ssh-keygen -t rsa -b 2048 -m PEM -f "$DIR/client_rsa" -N "" -q

  cat "$DIR"/client_*.pub > "$DIR/authorized_keys"
  chmod 600 "$DIR/authorized_keys" "$DIR"/host_* "$DIR"/client_*

  local sftp; sftp="$(sftp_server)"
  {
    echo "Port $PORT"
    echo "ListenAddress 127.0.0.1"
    echo "HostKey $DIR/host_ed25519"
    echo "HostKey $DIR/host_rsa"
    echo "PidFile $DIR/sshd.pid"
    echo "AuthorizedKeysFile $DIR/authorized_keys"
    echo "UsePAM no"
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
    echo "PubkeyAuthentication yes"
    echo "StrictModes no"
    echo "PrintMotd no"
    # sshd defaults to `MaxStartups 10:30:100`: past ten connections that have
    # not authenticated yet it starts dropping new ones at random, before it
    # even sends the banner. The live integration suite opens more than ten at
    # once, so it was failing on dropped connections and blaming the code —
    # a red suite that says nothing about the product is worse than no suite.
    # Raise the floor well above anything the suite opens. This is a throwaway
    # server on 127.0.0.1; the DoS protection the default provides is not
    # something a test target needs.
    echo "MaxStartups 100:30:200"
    # OpenSSH 9.8 turned PerSourcePenalties on by default, and it penalises the
    # *source address* — which here is always 127.0.0.1, the only address this
    # server listens on. Every connection the suite closes without
    # authenticating, every deliberate wrong-password case, every cancelled
    # connect adds seconds to a ban that compounds to ten minutes, after which
    # unrelated tests fail with no banner and no explanation. Same defect as the
    # MaxStartups one above: the suite failing for a reason that has nothing to
    # do with the product. Guarded because the directive does not exist before
    # 9.8 and an unknown keyword stops sshd from starting at all.
    if sshd_supports "PerSourcePenalties=no"; then echo "PerSourcePenalties no"; fi
    echo "LogLevel VERBOSE"
    # `if`, not `&&`: under `set -e` a trailing `&&` list that evaluates false
    # is a failing command, so the script used to exit here — silently, with no
    # config written — on any machine without an sftp-server binary.
    if [[ -n "$sftp" ]]; then echo "Subsystem sftp $sftp"; fi
  } > "$DIR/sshd_config"

  stop >/dev/null 2>&1 || true
  "$SSHD" -f "$DIR/sshd_config" -D -e > "$DIR/sshd.log" 2>&1 &
  echo $! > "$DIR/sshd.parent"

  for _ in $(seq 1 40); do
    ss -tln 2>/dev/null | grep -q "127.0.0.1:$PORT" && break
    sleep 0.25
  done

  if ! ss -tln 2>/dev/null | grep -q "127.0.0.1:$PORT"; then
    echo "sshd did not start. Log:" >&2
    tail -20 "$DIR/sshd.log" >&2
    exit 1
  fi
  info
}

stop() {
  [[ -f "$DIR/sshd.pid" ]] && kill "$(cat "$DIR/sshd.pid")" 2>/dev/null || true
  [[ -f "$DIR/sshd.parent" ]] && kill "$(cat "$DIR/sshd.parent")" 2>/dev/null || true
  rm -f "$DIR/sshd.pid" "$DIR/sshd.parent"
  echo "stopped"
}

info() {
  echo "host              127.0.0.1"
  echo "port              $PORT"
  echo "user              $(whoami)"
  echo "key               $DIR/client_ed25519"
  echo "key (passphrase)  $DIR/client_pass   passphrase: testpassphrase"
  echo "key (rsa, PEM)    $DIR/client_rsa"
  echo "host fingerprint  $(ssh-keygen -lf "$DIR/host_ed25519.pub" | awk '{print $2}')"
  echo "directory         $DIR"
}

case "${1:-start}" in
  start) start ;;
  stop)  stop ;;
  info)  info ;;
  *) echo "usage: $0 [start|stop|info]" >&2; exit 2 ;;
esac
