# Deploy with Iru

Iru (formerly Kandji) can deploy Team Skills as a Custom Script assigned to a Blueprint. This
recipe is for a user-global installation on a Mac with a signed-in console user. Iru scripts run
as `root`, so the wrapper deliberately re-enters the console user's launch context before it runs
the Team Skills installer.

Use one Custom Script per Team Skills catalog. Repeating the same script is safe: installation is
idempotent, and each catalog keeps independent clone, state, hooks, and optional prefix.

## Prerequisites

- The target user has signed in and has a local home directory.
- Git is installed and available as `/usr/bin/git`.
- The Mac can reach the reviewed installer host and the catalog's Git remote.
- For a private catalog, noninteractive Git authentication is already configured for the target
  user. See [Private catalogs](#private-catalogs).
- The installer file and its SHA-256 digest have been reviewed together.

Pin the installer URL to a reviewed commit rather than a moving branch. For a public GitHub fork,
an administrator can download and hash it before creating the Iru item:

```sh
curl -fsSLo team-skills.sh \
  https://raw.githubusercontent.com/YOUR-ORG/YOUR-REPOSITORY/REVIEWED-COMMIT/scripts/team-skills.sh
shasum -a 256 team-skills.sh
```

## Deployment script

Replace the placeholder values in the configuration block. Leave `PREFIX` empty to use the
default from the catalog's `catalog.json`; set it to a value such as `security` when multiple
catalogs need distinct skill names.

```sh
#!/bin/sh
set -eu

# Pin this URL and digest to the same reviewed installer revision.
INSTALLER_URL='https://raw.githubusercontent.com/YOUR-ORG/YOUR-REPOSITORY/REVIEWED-COMMIT/scripts/team-skills.sh'
INSTALLER_SHA256='REPLACE-WITH-64-LOWERCASE-HEX-CHARACTERS'
REPOSITORY_URL='https://github.com/YOUR-ORG/YOUR-REPOSITORY.git'
PREFIX=''

fail() {
    printf '%s\n' "Team Skills MDM install failed: $*" >&2
    exit 1
}

[ "${#INSTALLER_SHA256}" -eq 64 ] || fail 'INSTALLER_SHA256 must contain 64 characters'
case $INSTALLER_SHA256 in
    *[!0-9a-f]*) fail 'INSTALLER_SHA256 must be lowercase hexadecimal' ;;
esac
case "$INSTALLER_URL $REPOSITORY_URL" in
    *YOUR-ORG*|*YOUR-REPOSITORY*|*REVIEWED-COMMIT*)
        fail 'replace the installer and repository placeholders'
        ;;
esac

console_user=$(/usr/bin/stat -f '%Su' /dev/console) || fail 'cannot identify the console user'
case $console_user in
    ''|root|loginwindow|_mbsetupuser)
        fail 'no eligible console user is signed in; retry this item after login'
        ;;
esac

user_id=$(/usr/bin/id -u "$console_user") || fail 'cannot resolve the console user ID'
user_home=$(
    /usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory 2>/dev/null |
        /usr/bin/awk 'sub(/^NFSHomeDirectory: /, "") { print; exit }'
) || fail 'cannot resolve the console user home directory'
[ -n "$user_home" ] && [ -d "$user_home" ] || fail 'console user home directory is unavailable'
/usr/bin/git --version >/dev/null 2>&1 || fail 'Git is required'

installer=$(/usr/bin/mktemp /private/tmp/team-skills-mdm.XXXXXX) || \
    fail 'cannot create temporary file'
cleanup() {
    /bin/rm -f "$installer"
}
trap cleanup EXIT HUP INT TERM

/usr/bin/curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    "$INSTALLER_URL" --output "$installer" || fail 'cannot download the installer'
actual_sha256=$(/usr/bin/shasum -a 256 "$installer" | /usr/bin/awk '{ print $1 }') || \
    fail 'cannot hash the installer'
[ "$actual_sha256" = "$INSTALLER_SHA256" ] || fail 'installer SHA-256 does not match'

# Keep the catalog current through session-start hooks. Without this argument, deployed
# installations stay at the installed revision until someone updates them.
set -- install "$REPOSITORY_URL" --setup-auto-update
if [ -n "$PREFIX" ]; then
    set -- "$@" --prefix "$PREFIX"
fi

/bin/launchctl asuser "$user_id" \
    /usr/bin/sudo -u "$console_user" \
    /usr/bin/env -i \
        HOME="$user_home" \
        USER="$console_user" \
        LOGNAME="$console_user" \
        PATH='/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin' \
        GIT_TERMINAL_PROMPT=0 \
        /bin/sh -s -- "$@" <"$installer" || fail 'user-scoped installer returned an error'

printf '%s\n' "Team Skills installed for $console_user"
```

The wrapper uses a fresh environment so an MDM agent's root-specific variables cannot redirect
the user-global installation. It downloads over HTTPS, checks the reviewed digest, passes the
root-owned file to the user-scoped shell over an already-open standard input, suppresses
interactive Git prompts, and removes only its exact temporary file.

## Configure Iru

1. In Iru Endpoint, open **Library**, choose **Add Library Item**, and create a **Script** (Custom
   Script in some interface versions).
2. Paste the configured deployment script into the script field.
3. Use an install-once execution mode for primary-user Macs. Do not use continuous enforcement for
   routine deployment; Team Skills owns its later session-start updates.
4. Assign the item to a small test Blueprint whose users have already completed macOS login.
5. Confirm the Iru result and perform the checks below, then assign the item to production
   Blueprints.

Iru documents both [adding a Script Library Item](https://docs.iru.com/en/endpoint/getting-started/blueprints-and-library/managing-library)
and [Custom Script execution modes](https://docs.iru.com/en/endpoint/library/library-items-profiles/library-overview).
If the item runs before login, the wrapper returns an error instead of installing under `root`;
configure Iru to retry after the user signs in. On a shared Mac, arrange a run for every intended
user rather than treating one device-level execution as coverage for every account.

## Private catalogs

Do not put a personal access token, password, or other secret in `INSTALLER_URL`,
`REPOSITORY_URL`, script parameters, or Iru output. Instead:

1. Publish the exact reviewed installer on an approved internal HTTPS artifact host, or use an
   Iru-managed file delivery mechanism, and keep the SHA-256 check.
2. Pre-provision noninteractive, user-scoped authentication for the exact Git origin—for example,
   an HTTPS credential helper backed by the user's Keychain or a narrowly scoped SSH key and
   pinned host key.
3. Test authentication in the target user's launch context. Agent-only SSH authentication is not
   inherited by the sanitized MDM environment.

Authentication must remain available later because session-start updates fetch the managed
clone's configured `origin`. `GIT_TERMINAL_PROMPT=0` makes missing authentication fail rather than
opening or waiting for a login prompt.

## Verify

On a test Mac, confirm that the target user's home—not `/var/root`—contains:

- `.local/share/team-skills/catalogs/` with one managed catalog clone;
- Team Skills links in `.agents/skills/` and `.claude/skills/`;
- preserved pre-existing skills and product hook settings.

Start a fresh Claude Code, Codex, and Cursor session and confirm that the catalog skills appear.
Codex still requires the user to review and trust a non-managed hook; MDM deployment must not
pre-approve that trust decision. See [manual verification](../manual-verification.md) for the full
product checks and [operations](../operations.md) for diagnostics and removal.
