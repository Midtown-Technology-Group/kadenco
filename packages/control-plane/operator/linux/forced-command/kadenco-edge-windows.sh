#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Forced command for the Kadenco central edge's SSH key on a Windows T3 host
# (OpenSSH Server with Git Bash as DefaultShell). See
# packages/control-plane/deployment/linux-edge.md.
#
# Windows OpenSSH cannot open key-based sessions for Entra ID (AzureAD)
# accounts, so delivery sessions cannot be issued per command as on Linux
# hosts. The key is authorized for a local service account instead, and the
# owner's kadenco-edge-mint.ps1 task issues a 15-minute eddie-t3-delivery
# session every 5 minutes into MINT_DIR, readable only by the owner and that
# account. This wrapper allows only:
#   - T3 runtime metadata copied by the mint task (port discovery);
#   - the existing fleet read token (stat + cat);
#   - `auth session issue` for the edge's exact delivery request, answered with
#     the pre-minted session, refused when it has under 4 minutes left;
#   - `auth session revoke <id>`: a deferred no-op; the session expires itself.
# Port forwards are bounded by permitopen/permitlisten in authorized_keys.
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
q() { printf "'%s'" "$1"; }
fresh() { # file, max age seconds
  [ -f "$1" ] || return 1
  age=$(( $(date +%s) - $(stat -c %Y "$1") ))
  [ "$age" -ge -60 ] && [ "$age" -le "$2" ]
}

case $cmd in
  'cat "$HOME/.t3/userdata/server-runtime.json"')
    fresh "$minted/runtime.json" 900 || { echo "kadenco-edge: runtime metadata stale" >&2; exit 1; }
    exec cat "$minted/runtime.json" ;;
esac
if [ "$cmd" = "stat -c %Y $(q "$token") && cat $(q "$token")" ]; then
  stat -c %Y "$token" && exec cat "$token"
  exit 1
fi

# Native session: only single-quoted words of plain characters, so the
# re-split below cannot expand, substitute or chain anything.
printf '%s' "$cmd" | grep -Eqx "'[A-Za-z0-9 ._:/=+@-]*'( '[A-Za-z0-9 ._:/=+@-]*')*" || deny
eval "set -- $cmd"
[ "$#" -ge 4 ] && [ "$1" = "$launcher" ] && [ "$2" = auth ] && [ "$3" = session ] || deny
sub=$4
shift 4
case $sub in
  revoke)
    [ "$#" -eq 3 ] && [ "$2" = --base-dir ] && [ "$3" = "$basedir" ] || deny
    printf '%s' "$1" | grep -Eqx '[A-Za-z0-9_-]{1,200}' || deny
    exit 0 ;;
  issue)
    subject= base=
    set -- "$@" --end
    while [ "$1" != --end ]; do
      case $1 in
        --json) shift ;;
        --scope)
          case $2 in orchestration:read|orchestration:operate) ;; *) deny ;; esac
          shift 2 ;;
        --ttl)
          case $2 in 2m) ;; *) deny ;; esac
          shift 2 ;;
        --subject)
          [ "$2" = eddie-t3-delivery ] || deny
          subject=$2; shift 2 ;;
        --label)
          [ "$2" = "Eddie T3 private delivery" ] || deny
          shift 2 ;;
        --base-dir)
          [ "$2" = "$basedir" ] || deny
          base=$2; shift 2 ;;
        *) deny ;;
      esac
    done
    [ -n "$subject" ] && [ -n "$base" ] || deny
    # Minted with a 15-minute TTL: at most 11 minutes old leaves 4 minutes.
    fresh "$minted/delivery.json" 660 || { echo "kadenco-edge: no fresh delivery session; check the mint task" >&2; exit 1; }
    exec cat "$minted/delivery.json" ;;
  *) deny ;;
esac
