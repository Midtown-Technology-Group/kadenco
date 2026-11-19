#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Forced command for the Kadenco central edge's SSH key on a Windows T3 host
# (OpenSSH Server with Git Bash as DefaultShell). See
# packages/control-plane/deployment/linux-edge.md.
#
# Windows OpenSSH cannot open key-based sessions for Entra ID (AzureAD)
# accounts, so delivery sessions cannot be issued per command as on Linux
# hosts. The key is authorized for a local service account instead, and the
# owner's kadenco-edge-mint.ps1 task issues 15-minute eddie-t3-delivery
# sessions every 5 minutes into MINT_DIR (delivery-read.json: read scope;
# delivery.json: read+operate), readable only by the owner and that account.
# This wrapper allows exactly:
#   - T3 runtime metadata copied by the mint task (port discovery);
#   - the existing fleet read token (stat + cat);
#   - the edge's two delivery requests, answered with the pre-minted session of
#     the same scope, refused when it has under 4 minutes left;
#   - `auth session revoke <id>`: a deferred no-op; the session expires itself.
# Requests are compared as whole strings with the edge's exact argument vectors;
# nothing from the request is evaluated. Port forwards are bounded by
# permitopen/permitlisten in authorized_keys.
#
# Install admin-only writable; fill in the configuration block, nothing else.
# --- configuration -----------------------------------------------------------
account='t3-fleet'                       # local account holding the edge key
launcher='C:/Users/OWNER/AppData/Local/Programs/t3code/resources/server.asar/apps/server/dist/bin.mjs'
basedir='C:/Users/OWNER/.t3'             # owner's T3 base directory
token='/c/Users/OWNER/.local/share/t3-fleet/fleet.token'  # existing read token
minted='/c/Users/OWNER/.local/share/kadenco-edge'          # mint task output
# --- end configuration -------------------------------------------------------
set -fu
deny() { echo "kadenco-edge: refused" >&2; exit 126; }
# Git Bash prints MACHINE+account (or DOMAIN\account); accept only that account.
case $(whoami | tr 'A-Z' 'a-z') in "$account"|*+"$account"|*\\"$account") ;; *) deny ;; esac

cmd=${SSH_ORIGINAL_COMMAND-}
# Quote exactly as the callers do: '...' with each embedded ' written as '\''.
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
# One line of printable characters only: no newline, carriage return or control.
case $cmd in *[![:print:]]*|'') deny ;; esac
fresh() { # file, max age seconds
  [ -f "$1" ] || return 1
  age=$(( $(date +%s) - $(stat -c %Y "$1") ))
  [ "$age" -ge -60 ] && [ "$age" -le "$2" ]
}
serve() { # minted session file
  # Minted with a 15-minute TTL: at most 11 minutes old leaves 4 minutes.
  fresh "$1" 660 || { echo "kadenco-edge: no fresh delivery session; check the mint task" >&2; exit 1; }
  exec cat "$1"
}

if [ "$cmd" = 'cat "$HOME/.t3/userdata/server-runtime.json"' ]; then
  fresh "$minted/runtime.json" 900 || { echo "kadenco-edge: runtime metadata stale" >&2; exit 1; }
  exec cat "$minted/runtime.json"
fi
if [ "$cmd" = "stat -c %Y $(q "$token") && cat $(q "$token")" ]; then
  stat -c %Y "$token" && exec cat "$token"
  exit 1
fi

head="$(q "$launcher") 'auth' 'session'"
tail="'--ttl' '2m' '--subject' 'eddie-t3-delivery' '--label' 'Eddie T3 private delivery' '--json' '--base-dir' $(q "$basedir")"
[ "$cmd" = "$head 'issue' '--scope' 'orchestration:read' $tail" ] && serve "$minted/delivery-read.json"
[ "$cmd" = "$head 'issue' '--scope' 'orchestration:read' '--scope' 'orchestration:operate' $tail" ] && serve "$minted/delivery.json"

prefix="$head 'revoke' '"
suffix="' '--base-dir' $(q "$basedir")"
case $cmd in "$prefix"*"$suffix") ;; *) deny ;; esac
id=${cmd#"$prefix"}
id=${id%"$suffix"}
case $id in ''|*[!A-Za-z0-9_-]*) deny ;; esac
[ "${#id}" -le 200 ] && [ "$cmd" = "$prefix$id$suffix" ] || deny
exit 0
