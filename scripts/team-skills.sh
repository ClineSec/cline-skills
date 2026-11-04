#!/bin/sh
set -eu

# Team Skills lifecycle utility. Runtime dependencies: POSIX shell and Git.

PROGRAM=${0##*/}
ACTION=install
PREFIX_SET=0
PREFIX=
REPOSITORY_URL=
INSTANCE_ARGUMENT=
INSTALL_KEY_ARGUMENT=
CANDIDATE_ARGUMENT=
AUTO_UPDATE=

die() {
    printf '%s\n' "error: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<EOF
Usage: $PROGRAM install <repository-url> [--prefix <prefix>] [--setup-auto-update]
       $PROGRAM install <repository-url> --remove-auto-update
       $PROGRAM remove  <repository-url> [--prefix <prefix>]
       $PROGRAM update-all

Automatic updates are off unless enabled with --setup-auto-update. A plain install rerun updates
the named view and leaves the setting unchanged. --remove-auto-update only removes the catalog's
session hooks; it does not fetch or change skills. update-all updates every installed catalog now.

Environment overrides (primarily for tests and managed environments):
  TEAM_SKILLS_STATE_ROOT   default: \${XDG_DATA_HOME:-\$HOME/.local/share}/team-skills
  TEAM_SKILLS_AGENTS_ROOT  default: \$HOME/.agents/skills
  TEAM_SKILLS_CLAUDE_ROOT  default: \$HOME/.claude/skills
  TEAM_SKILLS_CLAUDE_HOOKS_FILE  default: \$HOME/.claude/settings.json
  TEAM_SKILLS_CODEX_HOOKS_FILE   default: \${CODEX_HOME:-\$HOME/.codex}/hooks.json
  TEAM_SKILLS_CURSOR_HOOKS_FILE  default: \$HOME/.cursor/hooks.json
  TEAM_SKILLS_THROTTLE_SECONDS  default: 21600 (six hours)
EOF
    exit 2
}

if [ "$#" -lt 1 ]; then
    usage
fi
ACTION=$1
case $ACTION in
    install|remove)
        [ "$#" -ge 2 ] || usage
        REPOSITORY_URL=$2
        shift 2
        ;;
    update-all)
        [ "$#" -eq 1 ] || usage
        shift
        ;;
    hook|hook-worker|update-instance)
        [ "$#" -eq 2 ] || usage
        INSTANCE_ARGUMENT=$2
        shift 2
        ;;
    update-prefix)
        { [ "$#" -eq 3 ] || [ "$#" -eq 4 ]; } || usage
        INSTANCE_ARGUMENT=$2
        INSTALL_KEY_ARGUMENT=$3
        if [ "$#" -eq 4 ]; then CANDIDATE_ARGUMENT=$4; fi
        shift "$#"
        ;;
    *) usage ;;
esac
while [ "$#" -gt 0 ]; do
    case $1 in
        --prefix)
            [ "$#" -ge 2 ] || usage
            PREFIX=$2
            PREFIX_SET=1
            shift 2
            ;;
        --setup-auto-update)
            [ "$ACTION" = install ] && [ -z "$AUTO_UPDATE" ] || usage
            AUTO_UPDATE=setup
            shift
            ;;
        --remove-auto-update)
            [ "$ACTION" = install ] && [ -z "$AUTO_UPDATE" ] || usage
            AUTO_UPDATE=remove
            shift
            ;;
        *) usage ;;
    esac
done
if [ "$AUTO_UPDATE" = remove ] && [ "$PREFIX_SET" -eq 1 ]; then
    die "--remove-auto-update applies to the whole catalog; omit --prefix"
fi
HOOK_REMOVING=0
if [ "$ACTION" = remove ] || [ "$AUTO_UPDATE" = remove ]; then
    HOOK_REMOVING=1
fi
if [ "$ACTION" = install ] || [ "$ACTION" = remove ]; then
    [ -n "$REPOSITORY_URL" ] || die "repository URL must not be blank"
fi

: "${HOME:?HOME must be set}"
STATE_ROOT=${TEAM_SKILLS_STATE_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/team-skills}
AGENTS_ROOT=${TEAM_SKILLS_AGENTS_ROOT:-$HOME/.agents/skills}
CLAUDE_ROOT=${TEAM_SKILLS_CLAUDE_ROOT:-$HOME/.claude/skills}
CLAUDE_HOOKS_FILE=${TEAM_SKILLS_CLAUDE_HOOKS_FILE:-$HOME/.claude/settings.json}
CODEX_HOOKS_FILE=${TEAM_SKILLS_CODEX_HOOKS_FILE:-${CODEX_HOME:-$HOME/.codex}/hooks.json}
CURSOR_HOOKS_FILE=${TEAM_SKILLS_CURSOR_HOOKS_FILE:-$HOME/.cursor/hooks.json}

# A user may intentionally make the portable Agent Skills roots converge on one physical
# directory. Resolve only the final, already-existing skill-root link once so every later
# ownership check and mutation operates on the stable physical directory. Other managed roots
# and hook files retain the stricter no-link rule below.
resolve_existing_skill_root_link() {
    skill_root=$1
    skill_root_label=$2
    if [ -L "$skill_root" ]; then
        [ -d "$skill_root" ] || die "$skill_root_label symlink must resolve to a directory"
        resolved_skill_root=$(CDPATH= cd -P "$skill_root" 2>/dev/null && pwd -P) || \
            die "$skill_root_label symlink cannot be resolved"
        [ -n "$resolved_skill_root" ] || die "$skill_root_label symlink cannot be resolved"
        printf '%s\n' "$resolved_skill_root"
    else
        printf '%s\n' "$skill_root"
    fi
}

AGENTS_ROOT=$(resolve_existing_skill_root_link "$AGENTS_ROOT" TEAM_SKILLS_AGENTS_ROOT) || exit 1
CLAUDE_ROOT=$(resolve_existing_skill_root_link "$CLAUDE_ROOT" TEAM_SKILLS_CLAUDE_ROOT) || exit 1

reject_unsafe_root() {
    root_value=$1
    root_label=$2
    [ -n "$root_value" ] || die "$root_label must not be blank"
    case $root_value in
        *'
'*|*''*|*'	'*) die "$root_label must not contain control characters" ;;
    esac
    case $root_value in
        /*) ;;
        *) die "$root_label must be an absolute path" ;;
    esac
    case $root_value in
        *[!/]*) ;;
        *) die "$root_label must not be the filesystem root" ;;
    esac
    case $root_value in
        *//*|*/./*|*/.|*/../*|*/..) die "$root_label must be normalized without empty, . or .. path components" ;;
    esac

    # Refuse an existing override target that is itself a symlink. Existing system ancestors can
    # legitimately be links (for example /var on macOS), so later owned-path checks remain the
    # boundary for descendants.
    [ ! -L "$root_value" ] || die "$root_label must not be a symlink"
}

reject_unsafe_root "$STATE_ROOT" TEAM_SKILLS_STATE_ROOT
reject_unsafe_root "$AGENTS_ROOT" TEAM_SKILLS_AGENTS_ROOT
reject_unsafe_root "$CLAUDE_ROOT" TEAM_SKILLS_CLAUDE_ROOT
reject_unsafe_root "$CLAUDE_HOOKS_FILE" TEAM_SKILLS_CLAUDE_HOOKS_FILE
reject_unsafe_root "$CODEX_HOOKS_FILE" TEAM_SKILLS_CODEX_HOOKS_FILE
reject_unsafe_root "$CURSOR_HOOKS_FILE" TEAM_SKILLS_CURSOR_HOOKS_FILE

owned_directory_is_safe() {
    owned_path=$1
    if [ -e "$owned_path" ] || [ -L "$owned_path" ]; then
        [ -d "$owned_path" ] && [ ! -L "$owned_path" ]
    fi
}

require_owned_directory() {
    owned_path=$1
    owned_label=$2
    owned_directory_is_safe "$owned_path" || die "$owned_label is not an owned directory"
}

require_instance_layout() {
    layout_root=$1
    require_owned_directory "$layout_root" "catalog instance state"
    require_owned_directory "$layout_root/repo" "managed catalog clone"
    [ -d "$layout_root/repo/.git" ] && [ ! -L "$layout_root/repo/.git" ] || \
        die "managed catalog clone metadata is invalid"
    require_owned_directory "$layout_root/installs" "catalog installation state"
}

acquire_removal_lock() {
    removal_lock_path=$INSTANCE_ROOT/update.lock
    if ! mkdir "$removal_lock_path" 2>/dev/null; then
        die "catalog update is in progress; retry removal after it completes"
    fi
    REMOVAL_LOCK=$removal_lock_path
    removal_lock_time=$(date +%s) || {
        rmdir "$REMOVAL_LOCK" 2>/dev/null || :
        die "cannot timestamp catalog removal lock"
    }
    REMOVAL_LOCK_CONTENT="$$
$removal_lock_time"
    if ! printf '%s\n' "$REMOVAL_LOCK_CONTENT" >"$REMOVAL_LOCK/owner"; then
        rmdir "$REMOVAL_LOCK" 2>/dev/null || :
        die "cannot record catalog removal lock ownership"
    fi
}

release_removal_lock() {
    [ -n "${REMOVAL_LOCK:-}" ] || return 0
    [ -d "$REMOVAL_LOCK" ] && [ ! -L "$REMOVAL_LOCK" ] || return 0
    [ -f "$REMOVAL_LOCK/owner" ] && [ ! -L "$REMOVAL_LOCK/owner" ] || return 0
    [ "$(cat "$REMOVAL_LOCK/owner" 2>/dev/null || :)" = "$REMOVAL_LOCK_CONTENT" ] || return 0
    lock_entries=0
    for lock_entry in "$REMOVAL_LOCK"/* "$REMOVAL_LOCK"/.[!.]* "$REMOVAL_LOCK"/..?*; do
        [ -e "$lock_entry" ] || [ -L "$lock_entry" ] || continue
        lock_entries=$((lock_entries + 1))
        [ "$lock_entry" = "$REMOVAL_LOCK/owner" ] || return 0
    done
    [ "$lock_entries" -eq 1 ] || return 0
    rm "$REMOVAL_LOCK/owner" 2>/dev/null && rmdir "$REMOVAL_LOCK" 2>/dev/null || :
    REMOVAL_LOCK=
}

shell_quote() {
    printf "'"
    printf '%s' "$1" | sed "s/'/'\\\\''/g"
    printf "'"
}

hook_config_path() {
    case $1 in
        claude) printf '%s\n' "$CLAUDE_HOOKS_FILE" ;;
        codex) printf '%s\n' "$CODEX_HOOKS_FILE" ;;
        cursor) printf '%s\n' "$CURSOR_HOOKS_FILE" ;;
        *) return 1 ;;
    esac
}

prepare_hook_edit() {
    hook_operation=$1
    hook_product=$2
    hook_config=$3
    hook_command=$4
    hook_stage=$WORK_ROOT/hooks/$hook_product
    mkdir -p "$hook_stage"
    hook_before=$hook_stage/before.json
    hook_after=$hook_stage/after.json
    hook_existed=$hook_stage/existed

    if [ -e "$hook_config" ] || [ -L "$hook_config" ]; then
        [ -f "$hook_config" ] && [ ! -L "$hook_config" ] || die "$hook_product hook configuration is not a regular file"
        cp -p "$hook_config" "$hook_before" || die "cannot stage $hook_product hook configuration"
        : >"$hook_existed"
    else
        printf '{}\n' >"$hook_before"
        if [ "$hook_operation" = add ]; then : >"$hook_stage/config-created"; fi
    fi
    if [ "$hook_operation" = add ] && [ "$hook_product" = cursor ] && \
            ! LC_ALL=C awk -v operation=cursor-version -f "$HOOK_EDITOR" "$hook_before" >/dev/null 2>&1; then
        : >"$hook_stage/cursor-version-created"
    fi
    if ! TEAM_SKILLS_JSON_COMMAND=$hook_command \
        TEAM_SKILLS_JSON_REMOVE_CURSOR_VERSION=${REMOVE_CURSOR_VERSION:-0} \
        LC_ALL=C awk -v operation="$hook_operation" -v product="$hook_product" \
        -f "$HOOK_EDITOR" "$hook_before" >"$hook_after"; then
        rm -f "$hook_after"
        die "$hook_product hook configuration is malformed, unsupported, or no longer owned"
    fi
}

inherit_hook_config_creation() {
    inherited_product=$1
    inherited_config=$2
    for inherited_owner in "$STATE_ROOT"/catalogs/*/hooks/$inherited_product.owner; do
        [ -f "$inherited_owner" ] && [ ! -L "$inherited_owner" ] || continue
        [ "$(sed -n '1p' "$inherited_owner")" = "$inherited_config" ] || continue
        inherited_flags=$(sed -n '3p' "$inherited_owner")
        case $inherited_flags in created|config-created|config-created,cursor-version-created) return 0 ;; esac
    done
    return 1
}

inherit_cursor_version_creation() {
    inherited_config=$1
    for inherited_owner in "$STATE_ROOT"/catalogs/*/hooks/cursor.owner; do
        [ -f "$inherited_owner" ] && [ ! -L "$inherited_owner" ] || continue
        [ "$(sed -n '1p' "$inherited_owner")" = "$inherited_config" ] || continue
        inherited_flags=$(sed -n '3p' "$inherited_owner")
        case $inherited_flags in cursor-version-created|config-created,cursor-version-created) return 0 ;; esac
    done
    return 1
}

other_hook_owner_exists() {
    owned_product=$1
    owned_config=$2
    current_owner=$3
    for candidate_owner in "$STATE_ROOT"/catalogs/*/hooks/$owned_product.owner; do
        [ "$candidate_owner" != "$current_owner" ] || continue
        [ -f "$candidate_owner" ] && [ ! -L "$candidate_owner" ] || continue
        [ "$(sed -n '1p' "$candidate_owner")" = "$owned_config" ] && return 0
    done
    return 1
}

auto_update_enabled() {
    for enabled_product in claude codex cursor; do
        [ -f "$1/hooks/$enabled_product.owner" ] && return 0
    done
    return 1
}

prepare_hook_registration() {
    HOOK_EDITOR=$SOURCE_ROOT/scripts/team-skills-json.awk
    HOOK_RUNTIME=$MANAGED_REPO/scripts/team-skills.sh
    [ -f "$HOOK_EDITOR" ] && [ ! -L "$HOOK_EDITOR" ] || die "catalog is missing its POSIX hook editor"
    [ -f "$SOURCE_ROOT/scripts/team-skills.sh" ] && [ ! -L "$SOURCE_ROOT/scripts/team-skills.sh" ] || die "catalog is missing its POSIX lifecycle utility"
    HOOK_COMMAND="sh $(shell_quote "$HOOK_RUNTIME") hook $(shell_quote "$INSTANCE_KEY")"
    HOOK_OWNERSHIP_ROOT=$INSTANCE_ROOT/hooks
    for hook_product in claude codex cursor; do
        hook_config=$(hook_config_path "$hook_product")
        hook_owner=$HOOK_OWNERSHIP_ROOT/$hook_product.owner
        if [ -f "$hook_owner" ] && [ ! -L "$hook_owner" ]; then
            [ "$(sed -n '1p' "$hook_owner")" = "$hook_config" ] || die "$hook_product hook ownership path changed"
            [ "$(sed -n '2p' "$hook_owner")" = "$HOOK_COMMAND" ] || die "$hook_product hook ownership command changed"
        elif [ -e "$hook_owner" ] || [ -L "$hook_owner" ]; then
            die "$hook_product hook ownership state is invalid"
        fi
        prepare_hook_edit add "$hook_product" "$hook_config" "$HOOK_COMMAND"
        if inherit_hook_config_creation "$hook_product" "$hook_config"; then
            : >"$WORK_ROOT/hooks/$hook_product/config-created"
        fi
        if [ "$hook_product" = cursor ] && inherit_cursor_version_creation "$hook_config"; then
            : >"$WORK_ROOT/hooks/$hook_product/cursor-version-created"
        fi
    done
    HOOK_CHANGES_PREPARED=1
}

prepare_hook_removal() {
    HOOK_OWNERSHIP_ROOT=$INSTANCE_ROOT/hooks
    [ -d "$HOOK_OWNERSHIP_ROOT" ] && [ ! -L "$HOOK_OWNERSHIP_ROOT" ] || return 0
    HOOK_EDITOR=$MANAGED_REPO/scripts/team-skills-json.awk
    [ -f "$HOOK_EDITOR" ] && [ ! -L "$HOOK_EDITOR" ] || die "catalog POSIX hook editor is missing"
    for hook_product in claude codex cursor; do
        hook_owner=$HOOK_OWNERSHIP_ROOT/$hook_product.owner
        if [ ! -e "$hook_owner" ] && [ ! -L "$hook_owner" ]; then
            continue
        fi
        [ -f "$hook_owner" ] && [ ! -L "$hook_owner" ] || die "$hook_product hook ownership state is invalid"
        hook_config=$(sed -n '1p' "$hook_owner")
        hook_command=$(sed -n '2p' "$hook_owner")
        hook_creation=$(sed -n '3p' "$hook_owner")
        case $hook_creation in ''|created|config-created|cursor-version-created|config-created,cursor-version-created) ;;
            *) die "$hook_product hook ownership state is invalid" ;;
        esac
        [ -z "$(sed -n '4p' "$hook_owner")" ] || die "$hook_product hook ownership state is invalid"
        reject_unsafe_root "$hook_config" "$hook_product owned hook configuration path"
        expected_command="sh $(shell_quote "$MANAGED_REPO/scripts/team-skills.sh") hook $(shell_quote "$INSTANCE_KEY")"
        [ "$hook_command" = "$expected_command" ] || die "$hook_product hook ownership command no longer matches its target"
        REMOVE_CURSOR_VERSION=0
        case $hook_creation in
            cursor-version-created|config-created,cursor-version-created)
                if ! other_hook_owner_exists "$hook_product" "$hook_config" "$hook_owner"; then
                    REMOVE_CURSOR_VERSION=1
                fi
                ;;
        esac
        prepare_hook_edit remove "$hook_product" "$hook_config" "$hook_command"
        case $hook_creation in created|config-created|config-created,cursor-version-created)
            : >"$WORK_ROOT/hooks/$hook_product/config-created"
            ;;
        esac
        case $hook_creation in cursor-version-created|config-created,cursor-version-created)
            : >"$WORK_ROOT/hooks/$hook_product/cursor-version-created"
            ;;
        esac
    done
    HOOK_CHANGES_PREPARED=1
}

rollback_hook_changes() {
    [ "${HOOK_CHANGES_COMMITTED:-0}" -eq 1 ] || return 0
    hook_rollback_failed=0
    for hook_product in claude codex cursor; do
        hook_stage=$WORK_ROOT/hooks/$hook_product
        [ -f "$hook_stage/committed" ] || continue
        hook_config=$(sed -n '1p' "$hook_stage/path")
        if [ -f "$hook_stage/deleted" ]; then
            if [ ! -e "$hook_config" ] && [ ! -L "$hook_config" ]; then
                hook_restore=$hook_config.team-skills-rollback.$$
                cp -p "$hook_stage/before.json" "$hook_restore" && mv "$hook_restore" "$hook_config" || hook_rollback_failed=1
            else
                hook_rollback_failed=1
            fi
            continue
        fi
        if [ -f "$hook_config" ] && [ ! -L "$hook_config" ] && cmp -s "$hook_config" "$hook_stage/after.json"; then
            if [ -f "$hook_stage/existed" ]; then
                hook_restore=$hook_config.team-skills-rollback.$$
                cp -p "$hook_stage/before.json" "$hook_restore" && mv "$hook_restore" "$hook_config" || hook_rollback_failed=1
            else
                rm "$hook_config" || hook_rollback_failed=1
            fi
        else
            hook_rollback_failed=1
        fi
    done
    HOOK_CHANGES_COMMITTED=0
    [ "$hook_rollback_failed" -eq 0 ]
}

commit_hook_changes() {
    [ "${HOOK_CHANGES_PREPARED:-0}" -eq 1 ] || return 0
    HOOK_CHANGES_COMMITTED=1
    for hook_product in claude codex cursor; do
        hook_stage=$WORK_ROOT/hooks/$hook_product
        [ -f "$hook_stage/after.json" ] || continue
        hook_config=$(hook_config_path "$hook_product")
        # Removal uses the path recorded by the owner rather than a possibly changed override.
        if [ "$HOOK_REMOVING" -eq 1 ]; then
            hook_config=$(sed -n '1p' "$INSTANCE_ROOT/hooks/$hook_product.owner")
        fi
        printf '%s\n' "$hook_config" >"$hook_stage/path"
        if [ -f "$hook_stage/existed" ]; then
            [ -f "$hook_config" ] && [ ! -L "$hook_config" ] && cmp -s "$hook_config" "$hook_stage/before.json" || {
                rollback_hook_changes || :
                die "$hook_product hook configuration changed during installation"
            }
        else
            [ ! -e "$hook_config" ] && [ ! -L "$hook_config" ] || {
                rollback_hook_changes || :
                die "$hook_product hook configuration appeared during installation"
            }
        fi
        hook_parent=${hook_config%/*}
        mkdir -p "$hook_parent" || {
            rollback_hook_changes || :
            die "cannot create $hook_product configuration directory"
        }
        if [ "$HOOK_REMOVING" -eq 1 ] && [ -f "$hook_stage/config-created" ] && \
                LC_ALL=C awk -v operation=empty -v product="$hook_product" \
                    -f "$HOOK_EDITOR" "$hook_stage/after.json" >/dev/null 2>&1; then
            rm "$hook_config" || {
                rollback_hook_changes || :
                die "cannot remove Team Skills-created $hook_product hook configuration"
            }
            : >"$hook_stage/deleted"
        else
            hook_temp=$hook_parent/.team-skills-hooks.$$
            if [ -f "$hook_stage/existed" ]; then
            # Seed the replacement from the staged original so POSIX cp -p carries
            # its mode forward, then replace only the bytes before the atomic move.
                if ! cp -p "$hook_stage/before.json" "$hook_temp" || \
                    ! cat "$hook_stage/after.json" >"$hook_temp"; then
                    rm -f "$hook_temp"
                    rollback_hook_changes || :
                    die "cannot preserve $hook_product hook configuration metadata"
                fi
            elif ! (umask 077; cp "$hook_stage/after.json" "$hook_temp"); then
                rm -f "$hook_temp"
                rollback_hook_changes || :
                die "cannot create secure $hook_product hook configuration"
            fi
            if ! mv "$hook_temp" "$hook_config"; then
                rm -f "$hook_temp"
                rollback_hook_changes || :
                die "cannot atomically update $hook_product hook configuration"
            fi
        fi
        : >"$hook_stage/committed"
    done
}

finalize_hook_ownership() {
    [ "${HOOK_CHANGES_PREPARED:-0}" -eq 1 ] || return 0
    if [ "$HOOK_REMOVING" -eq 1 ]; then
        rm -rf "$HOOK_OWNERSHIP_ROOT"
        HOOK_CHANGES_COMMITTED=0
        return 0
    fi
    if [ -e "$HOOK_OWNERSHIP_ROOT" ] || [ -L "$HOOK_OWNERSHIP_ROOT" ]; then
        [ -d "$HOOK_OWNERSHIP_ROOT" ] && [ ! -L "$HOOK_OWNERSHIP_ROOT" ] || die "catalog hook ownership root is invalid"
    else
        mkdir -p "$HOOK_OWNERSHIP_ROOT" || die "cannot create catalog hook ownership state"
    fi
    for hook_product in claude codex cursor; do
        hook_config=$(hook_config_path "$hook_product")
        hook_owner=$HOOK_OWNERSHIP_ROOT/$hook_product.owner
        hook_owner_temp=$HOOK_OWNERSHIP_ROOT/.$hook_product.owner.$$
        if [ -f "$WORK_ROOT/hooks/$hook_product/config-created" ] && \
                [ -f "$WORK_ROOT/hooks/$hook_product/cursor-version-created" ]; then
            printf '%s\n%s\nconfig-created,cursor-version-created\n' "$hook_config" "$HOOK_COMMAND" >"$hook_owner_temp"
        elif [ -f "$WORK_ROOT/hooks/$hook_product/config-created" ]; then
            printf '%s\n%s\nconfig-created\n' "$hook_config" "$HOOK_COMMAND" >"$hook_owner_temp"
        elif [ -f "$WORK_ROOT/hooks/$hook_product/cursor-version-created" ]; then
            printf '%s\n%s\ncursor-version-created\n' "$hook_config" "$HOOK_COMMAND" >"$hook_owner_temp"
        else
            printf '%s\n%s\n' "$hook_config" "$HOOK_COMMAND" >"$hook_owner_temp"
        fi
        mv "$hook_owner_temp" "$hook_owner" || die "cannot record $hook_product hook ownership"
    done
    HOOK_CHANGES_COMMITTED=0
}

valid_instance_key() {
    candidate_key=$1
    case $candidate_key in
        *[!a-z0-9-]*|'') return 1 ;;
    esac
    return 0
}

configured_origin_matches_instance() {
    origin_repo=$1
    origin_instance_key=$2
    origin_value=$(git -C "$origin_repo" remote get-url origin 2>/dev/null) || return 1
    [ -n "$origin_value" ] || return 1
    origin_digest=$(printf '%s' "$origin_value" | git hash-object --stdin 2>/dev/null) || return 1
    case $origin_digest in
        *[!0-9a-f]*|'') return 1 ;;
    esac
    { [ ${#origin_digest} -eq 40 ] || [ ${#origin_digest} -eq 64 ]; } || return 1
    case $origin_instance_key in
        *-"$origin_digest")
            origin_catalog_id=${origin_instance_key%"-$origin_digest"}
            valid_instance_key "$origin_catalog_id"
            ;;
        *) return 1 ;;
    esac
}

# A session hook honors the throttle. An explicit update-all is a request to update now, so it
# passes "manual" and skips the throttle while keeping every lock and validation rule.
run_catalog_update() {
    update_key=$1
    update_mode=${2:-session}
    UPDATE_OUTCOME=skipped
    valid_instance_key "$update_key" || {
        printf '%s\n' "error: invalid catalog instance key" >&2
        return 1
    }
    update_catalogs_root=$STATE_ROOT/catalogs
    owned_directory_is_safe "$update_catalogs_root" || {
        printf '%s\n' "error: catalog state root is invalid" >&2
        return 1
    }
    update_root=$update_catalogs_root/$update_key
    [ -d "$update_root" ] && [ ! -L "$update_root" ] && [ -d "$update_root/repo/.git" ] || {
        printf '%s\n' "error: catalog instance state is invalid" >&2
        return 1
    }
    lock_root=$update_root/update.lock
    now_value=${TEAM_SKILLS_NOW:-$(date +%s)}
    throttle_value=${TEAM_SKILLS_THROTTLE_SECONDS:-21600}
    stale_value=${TEAM_SKILLS_STALE_LOCK_SECONDS:-3600}
    case $now_value:$throttle_value:$stale_value in
        *[!0-9:]*|:*|*::*|*:) printf '%s\n' "error: update timing override is invalid" >&2; return 1 ;;
    esac

    if ! mkdir "$lock_root" 2>/dev/null; then
        [ -d "$lock_root" ] && [ ! -L "$lock_root" ] || {
            printf '%s\n' "warning: unsafe update lock path; skipping catalog" >&2
            return 0
        }
        lock_entry_count=0
        for lock_entry in "$lock_root"/* "$lock_root"/.[!.]* "$lock_root"/..?*; do
            [ -e "$lock_entry" ] || [ -L "$lock_entry" ] || continue
            lock_entry_count=$((lock_entry_count + 1))
            [ "$lock_entry" = "$lock_root/owner" ] || return 0
        done
        [ "$lock_entry_count" -eq 1 ] && [ -f "$lock_root/owner" ] && \
            [ ! -L "$lock_root/owner" ] || return 0
        [ "$(wc -l <"$lock_root/owner" 2>/dev/null || :)" -eq 2 ] 2>/dev/null || return 0
        lock_pid=$(sed -n '1p' "$lock_root/owner" 2>/dev/null || :)
        lock_time=$(sed -n '2p' "$lock_root/owner" 2>/dev/null || :)
        case $lock_pid:$lock_time in
            *[!0-9:]*|:*|*::*|*:) return 0 ;;
        esac
        if kill -0 "$lock_pid" 2>/dev/null; then
            return 0
        fi
        lock_age=$((now_value - lock_time))
        [ "$lock_age" -ge "$stale_value" ] || return 0
        stale_lock=$update_root/.stale-lock.$$
        if ! mv "$lock_root" "$stale_lock" 2>/dev/null; then
            return 0
        fi
        if ! mkdir "$lock_root" 2>/dev/null; then
            mv "$stale_lock" "$lock_root" 2>/dev/null || :
            return 0
        fi
        rm -rf "$stale_lock"
    fi
    printf '%s\n%s\n' "$$" "$now_value" >"$lock_root/owner" || {
        rm -rf "$lock_root"
        printf '%s\n' "error: cannot record update lock ownership" >&2
        return 1
    }
    UPDATE_LOCK=$lock_root
    trap 'rm -rf "$UPDATE_LOCK"' EXIT HUP INT TERM

    success_stamp=$update_root/last-success
    if [ "$update_mode" != manual ] && [ -f "$success_stamp" ] && [ ! -L "$success_stamp" ]; then
        last_success=$(sed -n '1p' "$success_stamp" 2>/dev/null || :)
        case $last_success in
            *[!0-9]*|'') ;;
            *)
                success_age=$((now_value - last_success))
                if [ "$success_age" -ge 0 ] && [ "$success_age" -lt "$throttle_value" ]; then
                    rm -rf "$UPDATE_LOCK"
                    trap - EXIT HUP INT TERM
                    return 0
                fi
                ;;
        esac
    fi

    update_failed=0
    installs_root=$update_root/installs
    [ -d "$installs_root" ] && [ ! -L "$installs_root" ] || update_failed=1
    update_candidate=
    if [ "$update_failed" -eq 0 ]; then
        update_repo=$update_root/repo
        if ! configured_origin_matches_instance "$update_repo" "$update_key"; then
            printf '%s\n' "error: managed catalog configured origin identity changed; restore it or remove and reinstall" >&2
            update_failed=1
        fi
    fi
    if [ "$update_failed" -eq 0 ]; then
        update_previous=$(git -C "$update_repo" rev-parse HEAD 2>/dev/null) || update_failed=1
        if [ "$update_failed" -eq 0 ] && ! GIT_TERMINAL_PROMPT=0 git -C "$update_repo" fetch --quiet origin '+HEAD:refs/team-skills/candidate' >/dev/null 2>&1; then
            printf '%s\n' "error: unable to fetch the managed catalog origin" >&2
            update_failed=1
        fi
        if [ "$update_failed" -eq 0 ]; then
            update_candidate=$(git -C "$update_repo" rev-parse --verify 'refs/team-skills/candidate^{commit}' 2>/dev/null) || update_failed=1
        fi
        if [ "$update_failed" -eq 0 ] && ! git -C "$update_repo" merge-base --is-ancestor "$update_previous" "$update_candidate" >/dev/null 2>&1; then
            printf '%s\n' "error: fetched catalog history is not a fast-forward; keeping the last known-good installation" >&2
            update_failed=1
        fi
    fi
    if [ "$update_failed" -eq 0 ]; then
        found_install=0
        for installed_view in "$installs_root"/*; do
            [ -d "$installed_view" ] && [ ! -L "$installed_view" ] || continue
            installed_key=${installed_view##*/}
            if [ "$installed_key" != _default ]; then
                if [ ${#installed_key} -gt 62 ] || ! printf '%s\n' "$installed_key" | LC_ALL=C grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$'; then
                    printf '%s\n' "warning: invalid installed prefix state; skipping catalog" >&2
                    update_failed=1
                    continue
                fi
            fi
            found_install=1
            if ! GIT_TERMINAL_PROMPT=0 sh "$SCRIPT_PATH" update-prefix "$update_key" "$installed_key" "$update_candidate"; then
                update_failed=1
            fi
        done
        [ "$found_install" -eq 1 ] || update_failed=1
    fi

    if [ "$update_failed" -eq 0 ]; then
        stamp_temp=$update_root/.last-success.$$
        printf '%s\n' "$now_value" >"$stamp_temp" && mv "$stamp_temp" "$success_stamp" || update_failed=1
    fi
    rm -rf "$UPDATE_LOCK"
    trap - EXIT HUP INT TERM
    if [ "$update_failed" -eq 0 ]; then
        if [ "$update_previous" = "$update_candidate" ]; then
            UPDATE_OUTCOME=current
        else
            UPDATE_OUTCOME=updated
        fi
    fi
    [ "$update_failed" -eq 0 ]
}

report_manual_update() {
    report_catalog=${1%-*}
    case $UPDATE_OUTCOME in
        updated) printf 'Catalog %s: updated %.12s to %.12s.\n' "$report_catalog" "$update_previous" "$update_candidate" ;;
        current) printf 'Catalog %s: already current at %.12s.\n' "$report_catalog" "$update_candidate" ;;
        *) printf 'Catalog %s: skipped because its update lock is held.\n' "$report_catalog" ;;
    esac
}

case $0 in
    /*) SCRIPT_PATH=$0 ;;
    *) SCRIPT_PATH=$(pwd)/$0 ;;
esac

if [ "$ACTION" = hook-worker ]; then
    valid_instance_key "$INSTANCE_ARGUMENT" || exit 0
    hook_root=$STATE_ROOT/catalogs/$INSTANCE_ARGUMENT
    [ -d "$hook_root" ] && [ ! -L "$hook_root" ] || exit 0
    hook_log=$hook_root/last-update.log
    hook_temp=$(mktemp "$hook_root/.last-update.XXXXXXXX") || exit 0
    hook_bounded=
    cleanup_hook_worker() {
        rm -f "$hook_temp"
        [ -z "$hook_bounded" ] || rm -f "$hook_bounded"
    }
    trap cleanup_hook_worker EXIT HUP INT TERM
    hook_result=0
    "$SCRIPT_PATH" update-instance "$INSTANCE_ARGUMENT" >"$hook_temp" 2>&1 || hook_result=$?
    hook_bytes=$(wc -c <"$hook_temp" 2>/dev/null | tr -d '[:space:]' || printf '%s' 0)
    case $hook_bytes in *[!0-9]*|'') hook_bytes=0 ;; esac
    if [ "$hook_bytes" -gt 65536 ]; then
        hook_bounded=$(mktemp "$hook_root/.last-update-bounded.XXXXXXXX") || exit "$hook_result"
        tail -c 65536 "$hook_temp" >"$hook_bounded" || exit "$hook_result"
        # tail(1) counts bytes and can begin inside a UTF-8 continuation sequence. Drop at most
        # three leading continuation bytes so diagnostics remain valid text without exceeding
        # the byte cap. Invalid source diagnostics still remain bounded and inert.
        while :; do
            hook_first_byte=$(LC_ALL=C od -An -tu1 -N1 "$hook_bounded" 2>/dev/null | tr -d '[:space:]' || :)
            case $hook_first_byte in *[!0-9]*|'') break ;; esac
            [ "$hook_first_byte" -ge 128 ] && [ "$hook_first_byte" -le 191 ] || break
            hook_trimmed=$(mktemp "$hook_root/.last-update-trimmed.XXXXXXXX") || exit "$hook_result"
            tail -c +2 "$hook_bounded" >"$hook_trimmed" || exit "$hook_result"
            mv "$hook_trimmed" "$hook_bounded" || exit "$hook_result"
        done
        mv "$hook_bounded" "$hook_log" || exit "$hook_result"
        hook_bounded=
    else
        mv "$hook_temp" "$hook_log" || exit "$hook_result"
        hook_temp=
    fi
    trap - EXIT HUP INT TERM
    exit "$hook_result"
fi

if [ "$ACTION" = hook ]; then
    valid_instance_key "$INSTANCE_ARGUMENT" || exit 0
    hook_root=$STATE_ROOT/catalogs/$INSTANCE_ARGUMENT
    [ -d "$hook_root" ] && [ ! -L "$hook_root" ] || exit 0
    hook_log=$hook_root/last-update.log
    if [ "${TEAM_SKILLS_TEST_FOREGROUND:-0}" = 1 ]; then
        "$SCRIPT_PATH" hook-worker "$INSTANCE_ARGUMENT" || :
    else
        nohup "$SCRIPT_PATH" hook-worker "$INSTANCE_ARGUMENT" </dev/null >/dev/null 2>&1 &
    fi
    exit 0
fi

if [ "$ACTION" = update-instance ]; then
    run_catalog_update "$INSTANCE_ARGUMENT"
    exit $?
fi

if [ "$ACTION" = update-all ]; then
    [ -f "$SCRIPT_PATH" ] || die "update-all must run from a script file; use the managed clone's scripts/team-skills.sh or rerun install"
    overall_status=0
    catalogs_root=$STATE_ROOT/catalogs
    [ ! -e "$catalogs_root" ] && [ ! -L "$catalogs_root" ] && exit 0
    owned_directory_is_safe "$catalogs_root" || die "catalog state root is invalid"
    for catalog_root in "$catalogs_root"/*; do
        [ -d "$catalog_root" ] && [ ! -L "$catalog_root" ] || continue
        catalog_key=${catalog_root##*/}
        if run_catalog_update "$catalog_key" manual; then
            report_manual_update "$catalog_key"
        else
            overall_status=1
            printf 'Catalog %s: update failed; keeping the last known-good installation.\n' "${catalog_key%-*}" >&2
        fi
    done
    exit "$overall_status"
fi

mkdir -p "$STATE_ROOT" || die "cannot create state root"
require_owned_directory "$STATE_ROOT/catalogs" "catalog state root"
require_owned_directory "$STATE_ROOT/origins" "catalog origin index root"
WORK_ROOT=$(mktemp -d "$STATE_ROOT/.operation.XXXXXXXX") || die "cannot create temporary state"
cleanup() {
    rollback_transaction
    release_removal_lock
    if [ -n "${CANDIDATE_WORKTREE:-}" ] && [ -n "${MANAGED_REPO:-}" ]; then
        git -C "$MANAGED_REPO" worktree remove --force "$CANDIDATE_WORKTREE" >/dev/null 2>&1 || :
    fi
    if [ -n "${NEXT_LINK:-}" ] && [ -L "$NEXT_LINK" ]; then
        rm "$NEXT_LINK" >/dev/null 2>&1 || :
    fi
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

replace_link() {
    replacement=$1
    destination=$2
    case $(uname -s) in
        Darwin) mv -f -h "$replacement" "$destination" ;;
        *) mv -f -T "$replacement" "$destination" ;;
    esac
}

rollback_transaction() {
    rollback_removal || printf '%s\n' "warning: removal rollback could not fully restore catalog-owned state" >&2
    # Hook edits can commit before an uninstall touches exposures. Always roll them back on a
    # later failure, even though removal does not activate an installation transaction.
    rollback_hook_changes || printf '%s\n' "warning: installation rollback could not fully restore catalog-owned hook configuration" >&2
    [ "${TRANSACTION_ACTIVE:-0}" -eq 1 ] || return 0
    TRANSACTION_ACTIVE=0
    rollback_failed=0

    # Remove newly created links while their candidate targets still exist. This keeps
    # ownership proof inspectable for Windows junctions as well as POSIX symlinks.
    if [ -f "${CREATED_EXPOSURES:-}" ]; then
        while IFS=/ read -r product effective_name; do
            case $product in
                agents) product_root=$AGENTS_ROOT ;;
                claude) product_root=$CLAUDE_ROOT ;;
                *) rollback_failed=1; continue ;;
            esac
            destination=$product_root/$effective_name
            expected_target=$CURRENT_TARGET/$effective_name
            if [ -L "$destination" ] && [ "$(readlink "$destination")" = "$expected_target" ]; then
                rm "$destination" || rollback_failed=1
            fi
        done <"$CREATED_EXPOSURES"
    fi

    if [ "${HAD_PREVIOUS_GENERATION:-0}" -eq 1 ]; then
        rollback_link=$INSTALL_ROOT/.rollback.$$
        if ln -s "$PREVIOUS_CURRENT_LINK" "$rollback_link" && replace_link "$rollback_link" "$CURRENT_TARGET"; then
            :
        else
            rollback_failed=1
            rm -f "$rollback_link" >/dev/null 2>&1 || :
        fi
    elif [ -L "$CURRENT_TARGET" ] && [ "$(readlink "$CURRENT_TARGET")" = "generations/$GENERATION_ID" ]; then
        rm "$CURRENT_TARGET" || rollback_failed=1
    fi

    if [ -n "${OWNERSHIP_SNAPSHOT:-}" ] && [ -d "$OWNERSHIP_SNAPSHOT" ]; then
        if ! rm -rf "$INSTALL_ROOT/ownership"; then
            rollback_failed=1
        elif ! cp -Rp "$OWNERSHIP_SNAPSHOT" "$INSTALL_ROOT/ownership"; then
            rollback_failed=1
        else
            # If an old exposure was removed before the failure, restore it only if its
            # destination is still absent. A racing replacement revokes ownership instead.
            for product in agents claude; do
                case $product in
                    agents) product_root=$AGENTS_ROOT ;;
                    claude) product_root=$CLAUDE_ROOT ;;
                esac
                owners=$INSTALL_ROOT/ownership/$product
                for owner_file in "$owners"/*.owner; do
                    [ -f "$owner_file" ] || continue
                    effective_name=${owner_file##*/}
                    effective_name=${effective_name%.owner}
                    destination=$product_root/$effective_name
                    expected_target=$(sed -n '1p' "$owner_file")
                    if [ -L "$destination" ] && [ "$(readlink "$destination")" = "$expected_target" ]; then
                        continue
                    fi
                    if [ -e "$destination" ] || [ -L "$destination" ]; then
                        rm "$owner_file" || rollback_failed=1
                        continue
                    fi
                    if ! ln -s "$expected_target" "$destination"; then
                        rm -f "$owner_file"
                        rollback_failed=1
                    fi
                done
            done
        fi
    fi

    if [ -n "${PREVIOUS_REPO_HEAD:-}" ] && [ -n "${MANAGED_REPO:-}" ]; then
        git -C "$MANAGED_REPO" reset --quiet --hard "$PREVIOUS_REPO_HEAD" >/dev/null 2>&1 || rollback_failed=1
    fi
    if [ "$rollback_failed" -ne 0 ]; then
        printf '%s\n' "warning: installation rollback could not fully restore catalog-owned state" >&2
    fi
}

rollback_removal() {
    [ "${REMOVAL_ACTIVE:-0}" -eq 1 ] || return 0
    REMOVAL_ACTIVE=0
    removal_rollback_failed=0

    if [ -n "${REMOVAL_STAGED_PATH:-}" ] && [ -n "${REMOVAL_ORIGINAL_PATH:-}" ]; then
        if { [ -e "$REMOVAL_STAGED_PATH" ] || [ -L "$REMOVAL_STAGED_PATH" ]; } && \
                [ ! -e "$REMOVAL_ORIGINAL_PATH" ] && [ ! -L "$REMOVAL_ORIGINAL_PATH" ]; then
            mv "$REMOVAL_STAGED_PATH" "$REMOVAL_ORIGINAL_PATH" || removal_rollback_failed=1
        elif [ -e "$REMOVAL_STAGED_PATH" ] || [ -L "$REMOVAL_STAGED_PATH" ]; then
            removal_rollback_failed=1
        fi
    fi

    if [ "${REMOVAL_ORIGIN_REMOVED:-0}" -eq 1 ] && \
            [ ! -e "$ORIGIN_INDEX" ] && [ ! -L "$ORIGIN_INDEX" ]; then
        removal_index_temp=$ORIGIN_INDEX_ROOT/.removal-rollback.$$
        if ! printf '%s\n' "$INSTANCE_KEY" >"$removal_index_temp" || \
                ! mv "$removal_index_temp" "$ORIGIN_INDEX"; then
            rm -f "$removal_index_temp" >/dev/null 2>&1 || :
            removal_rollback_failed=1
        fi
    fi

    if [ -f "${REMOVED_EXPOSURES:-}" ]; then
        while IFS=/ read -r product effective_name; do
            case $product in
                agents) product_root=$AGENTS_ROOT ;;
                claude) product_root=$CLAUDE_ROOT ;;
                *) removal_rollback_failed=1; continue ;;
            esac
            destination=$product_root/$effective_name
            expected_target=$INSTALL_ROOT/current/$effective_name
            if [ -L "$destination" ] && [ "$(readlink "$destination")" = "$expected_target" ]; then
                continue
            fi
            if [ -e "$destination" ] || [ -L "$destination" ] || [ ! -d "$expected_target" ]; then
                removal_rollback_failed=1
                continue
            fi
            ln -s "$expected_target" "$destination" || removal_rollback_failed=1
        done <"$REMOVED_EXPOSURES"
    fi
    [ "$removal_rollback_failed" -eq 0 ]
}

prepare_removal_plan() {
    REMOVAL_PLAN=$WORK_ROOT/removal-plan
    REMOVAL_OWNER_EXPECTED=$WORK_ROOT/expected-owner
    : >"$REMOVAL_PLAN"
    for product in agents claude; do
        owners=$INSTALL_ROOT/ownership/$product
        for owner_entry in "$owners"/*; do
            [ -e "$owner_entry" ] || [ -L "$owner_entry" ] || continue
            owner_name=${owner_entry##*/}
            case $owner_name in
                *.owner) effective_name=${owner_name%.owner} ;;
                *) die "$product skill ownership state is invalid" ;;
            esac
            valid_name "$effective_name" || die "$product skill ownership state is invalid"
            [ -f "$owner_entry" ] && [ ! -L "$owner_entry" ] || \
                die "$product skill ownership state is invalid"
            expected_target=$INSTALL_ROOT/current/$effective_name
            printf '%s\n' "$expected_target" >"$REMOVAL_OWNER_EXPECTED" || \
                die "cannot validate $product skill ownership state"
            cmp -s "$owner_entry" "$REMOVAL_OWNER_EXPECTED" || \
                die "$product skill ownership state is invalid"
            printf '%s/%s\n' "$product" "$effective_name" >>"$REMOVAL_PLAN" || \
                die "cannot stage removal plan"
        done
        if find "$owners" -mindepth 1 -maxdepth 1 -name '.*' -print -quit | grep -q .; then
            die "$product skill ownership state is invalid"
        fi
    done
}

valid_name() {
    value=$1
    [ ${#value} -le 64 ] || return 1
    printf '%s\n' "$value" | LC_ALL=C grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$'
}

validate_skill() {
    skill_dir=$1
    expected_name=$2
    skill_file=$skill_dir/SKILL.md
    [ -f "$skill_file" ] && [ ! -L "$skill_file" ] || return 1
    declared_name=$(awk '
        NR == 1 { if ($0 != "---") exit 2; in_frontmatter=1; next }
        in_frontmatter && $0 == "---" { closed=1; exit }
        in_frontmatter && $0 ~ /^name:[[:space:]]*/ {
            if (seen) exit 3
            seen=1
            sub(/^name:[[:space:]]*/, "")
            print
        }
        END { if (!closed || !seen) exit 4 }
    ' "$skill_file") || return 1
    [ "$declared_name" = "$expected_name" ] || return 1
}

validate_runtime() {
    runtime_root=$1/scripts
    [ -d "$runtime_root" ] && [ ! -L "$runtime_root" ] || return 1
    [ -f "$runtime_root/team-skills.sh" ] && [ ! -L "$runtime_root/team-skills.sh" ] && \
        [ -r "$runtime_root/team-skills.sh" ] && [ -x "$runtime_root/team-skills.sh" ] || return 1
    [ -f "$runtime_root/team-skills-json.awk" ] && [ ! -L "$runtime_root/team-skills-json.awk" ] && \
        [ -r "$runtime_root/team-skills-json.awk" ] || return 1
    [ -f "$runtime_root/team-skills.ps1" ] && [ ! -L "$runtime_root/team-skills.ps1" ] && \
        [ -r "$runtime_root/team-skills.ps1" ] || return 1
    sh -n "$runtime_root/team-skills.sh" >/dev/null 2>&1 || return 1
}

validate_catalog() {
    catalog_root=$1
    validate_runtime "$catalog_root" || return 1
    manifest=$catalog_root/catalog.json
    [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 1
    manifest_values=$WORK_ROOT/manifest-values
    LC_ALL=C awk -v operation=manifest -f "$catalog_root/scripts/team-skills-json.awk" \
        "$manifest" >"$manifest_values" 2>/dev/null || return 1
    CATALOG_ID=$(sed -n '1p' "$manifest_values")
    DEFAULT_PREFIX=$(sed -n '2p' "$manifest_values")
    skills_root=$catalog_root/skills
    [ -d "$skills_root" ] && [ ! -L "$skills_root" ] || return 1
    [ -z "$(find "$skills_root" -type l -print -quit)" ] || return 1
    found_skill=0
    for skill_dir in "$skills_root"/*; do
        [ -e "$skill_dir" ] || continue
        [ -d "$skill_dir" ] && [ ! -L "$skill_dir" ] || return 1
        skill_name=${skill_dir##*/}
        valid_name "$skill_name" || return 1
        validate_skill "$skill_dir" "$skill_name" || return 1
        found_skill=1
    done
    [ "$found_skill" -eq 1 ] || return 1
}

# Exact bootstrap URL values normally become exact configured-origin values. This private index
# lets reruns and removal find existing state without contacting a possibly unavailable remote.
ORIGIN_INDEX_ROOT=$STATE_ROOT/origins
EXISTING_INSTANCE=0
if [ "$ACTION" = update-prefix ]; then
    valid_instance_key "$INSTANCE_ARGUMENT" || die "invalid catalog instance key"
    INSTANCE_KEY=$INSTANCE_ARGUMENT
    INSTANCE_ROOT=$STATE_ROOT/catalogs/$INSTANCE_KEY
    require_instance_layout "$INSTANCE_ROOT"
    MANAGED_REPO=$INSTANCE_ROOT/repo
    if ! validate_catalog "$MANAGED_REPO"; then
        die "managed catalog clone is invalid; keeping the last known-good installation"
    fi
    CONFIGURED_ORIGIN=$(git -C "$MANAGED_REPO" remote get-url origin 2>/dev/null) || die "managed clone has no configured origin"
    [ -n "$CONFIGURED_ORIGIN" ] || die "managed clone origin must not be blank"
    configured_origin_matches_instance "$MANAGED_REPO" "$INSTANCE_KEY" || \
        die "managed catalog configured origin identity changed; restore it or remove and reinstall"
    INSTANCE_CATALOG_ID=$CATALOG_ID
    EXISTING_INSTANCE=1
    PREFIX_SET=1
    INSTALL_KEY=$INSTALL_KEY_ARGUMENT
    if [ "$INSTALL_KEY" = _default ]; then
        PREFIX=
    else
        valid_name "$INSTALL_KEY" || die "installed prefix state is invalid"
        [ ${#INSTALL_KEY} -le 62 ] || die "installed prefix state is invalid"
        PREFIX=$INSTALL_KEY
    fi
    [ -d "$INSTANCE_ROOT/installs/$INSTALL_KEY" ] && [ ! -L "$INSTANCE_ROOT/installs/$INSTALL_KEY" ] || die "installed prefix state is missing"
else
    SUPPLIED_DIGEST=$(printf '%s' "$REPOSITORY_URL" | git hash-object --stdin) || die "cannot calculate catalog identity"
    ORIGIN_INDEX=$ORIGIN_INDEX_ROOT/$SUPPLIED_DIGEST.instance
fi
if [ "$ACTION" != update-prefix ] && [ -f "$ORIGIN_INDEX" ] && [ ! -L "$ORIGIN_INDEX" ]; then
    INSTANCE_KEY=$(sed -n '1p' "$ORIGIN_INDEX")
    case $INSTANCE_KEY in
        *[!a-z0-9-]*|'') die "catalog origin index is invalid" ;;
    esac
    INSTANCE_ROOT=$STATE_ROOT/catalogs/$INSTANCE_KEY
    MANAGED_REPO=$INSTANCE_ROOT/repo
    require_instance_layout "$INSTANCE_ROOT"
    if ! validate_catalog "$MANAGED_REPO"; then
        die "managed catalog clone is invalid; keeping the last known-good installation"
    fi
    CONFIGURED_ORIGIN=$(git -C "$MANAGED_REPO" remote get-url origin 2>/dev/null) || die "managed clone has no configured origin"
    [ -n "$CONFIGURED_ORIGIN" ] || die "managed clone origin must not be blank"
    INSTANCE_DIGEST=${INSTANCE_KEY#"$CATALOG_ID"-}
    [ "$INSTANCE_DIGEST" != "$INSTANCE_KEY" ] || die "catalog origin index identity mismatch"
    [ ${#INSTANCE_DIGEST} -eq 40 ] || die "catalog origin index identity mismatch"
    case $INSTANCE_DIGEST in *[!0-9a-f]*) die "catalog origin index identity mismatch" ;; esac
    INSTANCE_CATALOG_ID=$CATALOG_ID
    EXISTING_INSTANCE=1
    if [ "$HOOK_REMOVING" -eq 0 ]; then
        configured_origin_matches_instance "$MANAGED_REPO" "$INSTANCE_KEY" || \
            die "managed catalog configured origin identity changed; restore it or remove and reinstall"
    fi
elif [ "$AUTO_UPDATE" = remove ]; then
    die "catalog instance is not installed"
elif [ "$ACTION" != update-prefix ]; then
    # Clone output is deliberately suppressed: Git may echo credential-bearing URLs on failure.
    BOOTSTRAP_CLONE=$WORK_ROOT/bootstrap
    if ! git clone --quiet --no-local -- "$REPOSITORY_URL" "$BOOTSTRAP_CLONE" >"$WORK_ROOT/clone.log" 2>&1; then
        die "unable to clone the supplied repository"
    fi
    if ! validate_catalog "$BOOTSTRAP_CLONE"; then
        die "supplied repository is not a valid catalog"
    fi
    CONFIGURED_ORIGIN=$(git -C "$BOOTSTRAP_CLONE" remote get-url origin 2>/dev/null) || die "clone has no configured origin"
    [ -n "$CONFIGURED_ORIGIN" ] || die "clone origin must not be blank"
    ORIGIN_DIGEST=$(printf '%s' "$CONFIGURED_ORIGIN" | git hash-object --stdin) || die "cannot calculate catalog identity"
    INSTANCE_KEY=$CATALOG_ID-$ORIGIN_DIGEST
    INSTANCE_CATALOG_ID=$CATALOG_ID
    INSTANCE_ROOT=$STATE_ROOT/catalogs/$INSTANCE_KEY
    MANAGED_REPO=$INSTANCE_ROOT/repo
fi

if [ "$PREFIX_SET" -eq 0 ]; then
    PREFIX=$DEFAULT_PREFIX
fi
if [ -n "$PREFIX" ]; then
    valid_name "$PREFIX" || die "invalid prefix"
    [ ${#PREFIX} -le 62 ] || die "prefix exceeds 62 characters"
    INSTALL_KEY=$PREFIX
else
    INSTALL_KEY=_default
fi
INSTALL_ROOT=$INSTANCE_ROOT/installs/$INSTALL_KEY

if [ "$EXISTING_INSTANCE" -eq 1 ]; then
    require_instance_layout "$INSTANCE_ROOT"
    if [ -e "$INSTALL_ROOT" ] || [ -L "$INSTALL_ROOT" ]; then
        [ -d "$INSTALL_ROOT" ] && [ ! -L "$INSTALL_ROOT" ] || \
            die "catalog installation view is not an owned directory"
        require_owned_directory "$INSTALL_ROOT/generations" "catalog generation state"
        require_owned_directory "$INSTALL_ROOT/ownership" "catalog ownership state"
        require_owned_directory "$INSTALL_ROOT/ownership/agents" "agents ownership state"
        require_owned_directory "$INSTALL_ROOT/ownership/claude" "Claude ownership state"
    fi
fi

# Turning automatic updates off must work when the origin is unreachable or no longer trusted, so
# this path never fetches and leaves the active skills exactly as they are.
if [ "$AUTO_UPDATE" = remove ]; then
    acquire_removal_lock
    require_instance_layout "$INSTANCE_ROOT"
    if auto_update_enabled "$INSTANCE_ROOT"; then
        AUTO_UPDATE_WAS_ENABLED=1
    else
        AUTO_UPDATE_WAS_ENABLED=0
    fi
    prepare_hook_removal
    commit_hook_changes
    finalize_hook_ownership
    if [ "$AUTO_UPDATE_WAS_ENABLED" -eq 1 ]; then
        printf '%s\n' "Automatic updates are off for catalog $CATALOG_ID. Installed skills were not changed."
    else
        printf '%s\n' "Automatic updates were already off for catalog $CATALOG_ID."
    fi
    exit 0
fi

if [ "$ACTION" = remove ]; then
    [ -d "$MANAGED_REPO" ] || die "catalog instance is not installed"
    [ -d "$INSTALL_ROOT" ] || {
        printf '%s\n' "Catalog $CATALOG_ID prefix '$PREFIX' is already absent."
        exit 0
    }
    # Removal and session-start reconciliation mutate the same generation, exposure, and hook
    # state. Winning this atomic directory creation excludes a later updater; an existing lock
    # fails closed before removal mutates anything.
    acquire_removal_lock
    require_instance_layout "$INSTANCE_ROOT"
    [ -d "$INSTALL_ROOT" ] && [ ! -L "$INSTALL_ROOT" ] || die "installed prefix state changed during removal"
    remaining_install=0
    for installed_view in "$INSTANCE_ROOT/installs"/*; do
        [ -d "$installed_view" ] && [ ! -L "$installed_view" ] || continue
        [ "$installed_view" = "$INSTALL_ROOT" ] || remaining_install=1
    done
    prepare_removal_plan
    if [ "$remaining_install" -eq 0 ]; then
        printf '%s\n' "$INSTANCE_KEY" >"$REMOVAL_OWNER_EXPECTED"
        [ -f "$ORIGIN_INDEX" ] && [ ! -L "$ORIGIN_INDEX" ] && \
            cmp -s "$ORIGIN_INDEX" "$REMOVAL_OWNER_EXPECTED" || \
            die "catalog origin index is invalid"
    fi
    REMOVED_EXPOSURES=$WORK_ROOT/removed-exposures
    : >"$REMOVED_EXPOSURES"
    REMOVAL_ACTIVE=1
    REMOVAL_ORIGIN_REMOVED=0
    if [ "$remaining_install" -eq 0 ]; then
        prepare_hook_removal
        commit_hook_changes
    fi
    while IFS=/ read -r product effective_name; do
        case $product in
            agents) product_root=$AGENTS_ROOT ;;
            claude) product_root=$CLAUDE_ROOT ;;
            *) die "skill ownership state is invalid" ;;
        esac
        destination=$product_root/$effective_name
        expected_target=$INSTALL_ROOT/current/$effective_name
        if [ -L "$destination" ] && [ "$(readlink "$destination")" = "$expected_target" ]; then
            printf '%s/%s\n' "$product" "$effective_name" >>"$REMOVED_EXPOSURES" || \
                die "cannot record removal transaction"
            rm "$destination" || die "cannot remove owned exposure $destination"
        elif [ -e "$destination" ] || [ -L "$destination" ]; then
            printf '%s\n' "warning: not removing changed path $destination" >&2
        fi
    done <"$REMOVAL_PLAN"
    if [ "$remaining_install" -eq 0 ]; then
        REMOVAL_ORIGINAL_PATH=$INSTANCE_ROOT
        REMOVAL_STAGED_PATH=$WORK_ROOT/removed-instance
    else
        REMOVAL_ORIGINAL_PATH=$INSTALL_ROOT
        REMOVAL_STAGED_PATH=$WORK_ROOT/removed-install
    fi
    mv "$REMOVAL_ORIGINAL_PATH" "$REMOVAL_STAGED_PATH" || \
        die "cannot atomically stage catalog state removal"
    if [ "$remaining_install" -eq 0 ]; then
        REMOVAL_ORIGIN_REMOVED=1
        rm "$ORIGIN_INDEX" || die "cannot remove catalog origin index"
    fi
    HOOK_CHANGES_COMMITTED=0
    REMOVAL_ACTIVE=0
    printf '%s\n' "Removed catalog $CATALOG_ID prefix '$PREFIX'."
    exit 0
fi

if [ "$EXISTING_INSTANCE" -eq 0 ]; then
    mkdir -p "$INSTANCE_ROOT"
    mv "$BOOTSTRAP_CLONE" "$MANAGED_REPO"
    mkdir -p "$ORIGIN_INDEX_ROOT"
    INDEX_TEMP=$ORIGIN_INDEX_ROOT/.$SUPPLIED_DIGEST.$$
    printf '%s\n' "$INSTANCE_KEY" >"$INDEX_TEMP"
    mv "$INDEX_TEMP" "$ORIGIN_INDEX"
    SOURCE_ROOT=$MANAGED_REPO
else
    # All later network behavior names the managed clone's configured origin, never a baked URL.
    PREVIOUS_REPO_HEAD=$(git -C "$MANAGED_REPO" rev-parse HEAD 2>/dev/null) || die "managed catalog clone has no Git revision"
    if [ -n "$CANDIDATE_ARGUMENT" ]; then
        case $CANDIDATE_ARGUMENT in *[!0-9a-f]*) die "pinned catalog candidate is invalid" ;; esac
        { [ ${#CANDIDATE_ARGUMENT} -eq 40 ] || [ ${#CANDIDATE_ARGUMENT} -eq 64 ]; } || die "pinned catalog candidate is invalid"
        CANDIDATE_REVISION=$(git -C "$MANAGED_REPO" rev-parse --verify "$CANDIDATE_ARGUMENT^{commit}" 2>/dev/null) || \
            die "pinned catalog candidate is unavailable"
        [ "$CANDIDATE_REVISION" = "$CANDIDATE_ARGUMENT" ] || die "managed origin candidate changed during catalog update"
    else
        if ! git -C "$MANAGED_REPO" fetch --quiet origin '+HEAD:refs/team-skills/candidate' >"$WORK_ROOT/fetch.log" 2>&1; then
            die "unable to fetch the managed catalog origin"
        fi
        CANDIDATE_REVISION=$(git -C "$MANAGED_REPO" rev-parse --verify 'refs/team-skills/candidate^{commit}' 2>/dev/null) || \
            die "managed origin HEAD has no commit"
    fi
    if ! git -C "$MANAGED_REPO" merge-base --is-ancestor "$PREVIOUS_REPO_HEAD" "$CANDIDATE_REVISION" >/dev/null 2>&1; then
        die "fetched catalog history is not a fast-forward; keeping the last known-good installation"
    fi
    CANDIDATE_WORKTREE=$WORK_ROOT/candidate
    if ! git -C "$MANAGED_REPO" worktree add --quiet --detach "$CANDIDATE_WORKTREE" "$CANDIDATE_REVISION" >"$WORK_ROOT/worktree.log" 2>&1; then
        die "unable to stage the fetched catalog"
    fi
    SOURCE_ROOT=$CANDIDATE_WORKTREE
    if ! validate_catalog "$SOURCE_ROOT"; then
        die "fetched catalog is invalid; keeping the last known-good installation"
    fi
fi

# Re-read from the selected candidate, not from bootstrap discovery data.
if ! validate_catalog "$SOURCE_ROOT"; then
    die "catalog is invalid; keeping the last known-good installation"
fi
[ "$CATALOG_ID" = "$INSTANCE_CATALOG_ID" ] || die "fetched catalog identity changed; keeping the last known-good installation"
if [ "$AUTO_UPDATE" = setup ]; then
    prepare_hook_registration
fi
if [ "$PREFIX_SET" -eq 0 ]; then
    PREFIX=$DEFAULT_PREFIX
fi
if [ -n "$PREFIX" ]; then
    INSTALL_KEY=$PREFIX
else
    INSTALL_KEY=_default
fi
INSTALL_ROOT=$INSTANCE_ROOT/installs/$INSTALL_KEY

GENERATION_ID=$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>/dev/null) || die "catalog has no Git revision"
STAGED_GENERATION=$WORK_ROOT/generation
mkdir -p "$STAGED_GENERATION"
for skill_dir in "$SOURCE_ROOT/skills"/*; do
    skill_name=${skill_dir##*/}
    if [ -n "$PREFIX" ]; then
        effective_name=$PREFIX-$skill_name
    else
        effective_name=$skill_name
    fi
    valid_name "$effective_name" || die "effective skill name is invalid or exceeds 64 characters: $effective_name"
    cp -Rp "$skill_dir" "$STAGED_GENERATION/$effective_name" || die "cannot stage skill $skill_name"
    if [ -n "$PREFIX" ]; then
        skill_file=$STAGED_GENERATION/$effective_name/SKILL.md
        rewritten=$skill_file.rewritten
        awk -v replacement="$effective_name" '
            NR == 1 { in_frontmatter=1; print; next }
            in_frontmatter && $0 == "---" { in_frontmatter=0; print; next }
            in_frontmatter && $0 ~ /^name:[[:space:]]*/ { print "name: " replacement; next }
            { print }
        ' "$skill_file" >"$rewritten" || die "cannot rewrite skill $skill_name"
        mv "$rewritten" "$skill_file"
    fi
    validate_skill "$STAGED_GENERATION/$effective_name" "$effective_name" || die "generated skill failed validation: $effective_name"
done

mkdir -p "$INSTALL_ROOT/generations" "$INSTALL_ROOT/ownership/agents" "$INSTALL_ROOT/ownership/claude"
require_owned_directory "$INSTALL_ROOT" "catalog installation view"
require_owned_directory "$INSTALL_ROOT/generations" "catalog generation state"
require_owned_directory "$INSTALL_ROOT/ownership" "catalog ownership state"
require_owned_directory "$INSTALL_ROOT/ownership/agents" "agents ownership state"
require_owned_directory "$INSTALL_ROOT/ownership/claude" "Claude ownership state"
GENERATION_PATH=$INSTALL_ROOT/generations/$GENERATION_ID
CURRENT_TARGET=$INSTALL_ROOT/current
EXPOSURE_PLAN=$WORK_ROOT/exposure-plan
CREATED_EXPOSURES=$WORK_ROOT/created-exposures
OWNERSHIP_SNAPSHOT=$WORK_ROOT/ownership.before
mkdir -p "$EXPOSURE_PLAN/agents" "$EXPOSURE_PLAN/claude"
cp -Rp "$INSTALL_ROOT/ownership" "$OWNERSHIP_SNAPSHOT" || die "cannot snapshot catalog ownership state"
: >"$CREATED_EXPOSURES"

# Preflight every destination before changing the current generation.
for product in agents claude; do
    case $product in
        agents) product_root=$AGENTS_ROOT ;;
        claude) product_root=$CLAUDE_ROOT ;;
    esac
    if [ -e "$product_root" ] && [ ! -d "$product_root" ]; then
        die "product skills root is not a directory: $product_root"
    fi
    for generated_skill in "$STAGED_GENERATION"/*; do
        effective_name=${generated_skill##*/}
        destination=$product_root/$effective_name
        owner_file=$INSTALL_ROOT/ownership/$product/$effective_name.owner
        expected_target=$CURRENT_TARGET/$effective_name
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            if [ -f "$owner_file" ] && [ -L "$destination" ] && [ "$(readlink "$destination")" = "$expected_target" ]; then
                :
            else
                printf '%s\n' "warning: catalog $CATALOG_ID skill $effective_name skipped; destination exists: $destination" >&2
            fi
        else
            : >"$EXPOSURE_PLAN/$product/$effective_name.create" || die "cannot stage exposure plan"
        fi
    done
done

if [ ! -d "$GENERATION_PATH" ]; then
    mv "$STAGED_GENERATION" "$GENERATION_PATH"
fi
NEXT_LINK=$INSTALL_ROOT/.current.$$
ln -s "generations/$GENERATION_ID" "$NEXT_LINK" || die "cannot stage current generation link"
if [ -e "$CURRENT_TARGET" ] || [ -L "$CURRENT_TARGET" ]; then
    [ -L "$CURRENT_TARGET" ] || die "catalog current view is not an owned directory link"
    PREVIOUS_CURRENT_LINK=$(readlink "$CURRENT_TARGET") || die "cannot read catalog current view"
    HAD_PREVIOUS_GENERATION=1
else
    PREVIOUS_CURRENT_LINK=
    HAD_PREVIOUS_GENERATION=0
fi
TRANSACTION_ACTIVE=1
# Plain POSIX mv follows a destination symlink to a directory. Use each supported platform's
# no-follow form so replacement changes the link itself and never writes inside an immutable view.
replace_link "$NEXT_LINK" "$CURRENT_TARGET" || die "cannot activate generated view"

for product in agents claude; do
    case $product in
        agents) product_root=$AGENTS_ROOT ;;
        claude) product_root=$CLAUDE_ROOT ;;
    esac
    mkdir -p "$product_root" || die "cannot create product skills root"
    # Remove exposures for skills no longer present, but only while both ownership proofs agree.
    owners=$INSTALL_ROOT/ownership/$product
    for owner_file in "$owners"/*.owner; do
        [ -f "$owner_file" ] || continue
        owned_name=${owner_file##*/}
        owned_name=${owned_name%.owner}
        [ -e "$CURRENT_TARGET/$owned_name" ] && continue
        destination=$product_root/$owned_name
        expected_target=$(sed -n '1p' "$owner_file")
        if [ -L "$destination" ] && [ "$(readlink "$destination")" = "$expected_target" ]; then
            rm "$destination" || die "cannot remove stale owned exposure $destination"
        elif [ -e "$destination" ] || [ -L "$destination" ]; then
            printf '%s\n' "warning: not removing changed path $destination" >&2
        fi
        rm "$owner_file"
    done
    for generated_skill in "$CURRENT_TARGET"/*; do
        effective_name=${generated_skill##*/}
        [ -f "$EXPOSURE_PLAN/$product/$effective_name.create" ] || continue
        destination=$product_root/$effective_name
        owner_file=$INSTALL_ROOT/ownership/$product/$effective_name.owner
        expected_target=$CURRENT_TARGET/$effective_name
        printf '%s/%s\n' "$product" "$effective_name" >>"$CREATED_EXPOSURES" || die "cannot record exposure transaction"
        # symlink(2) is an atomic no-clobber operation at the final destination. A temporary link
        # followed by mv could overwrite a file that appeared after the collision preflight.
        if ! ln -s "$expected_target" "$destination"; then
            # When both product roots resolve to the same directory, the agents pass created the
            # one physical exposure moments earlier. Accept it for Claude only when the complete
            # ownership proof matches this transaction; all other no-clobber failures still stop.
            shared_owner=$INSTALL_ROOT/ownership/agents/$effective_name.owner
            if [ "$product" = claude ] && [ "$AGENTS_ROOT" = "$CLAUDE_ROOT" ] && \
                    [ -f "$shared_owner" ] && [ ! -L "$shared_owner" ] && \
                    [ -L "$destination" ] && [ "$(readlink "$destination")" = "$expected_target" ] && \
                    printf '%s\n' "$expected_target" | cmp -s - "$shared_owner"; then
                :
            else
                die "cannot expose skill $effective_name"
            fi
        fi
        printf '%s\n' "$expected_target" >"$owner_file" || die "cannot record ownership for skill $effective_name"
    done
done

if [ -n "${CANDIDATE_WORKTREE:-}" ]; then
    git -C "$MANAGED_REPO" reset --quiet --hard "$CANDIDATE_REVISION" >"$WORK_ROOT/reset.log" 2>&1 || die "installed view is valid but managed clone could not advance"
fi
commit_hook_changes
finalize_hook_ownership
TRANSACTION_ACTIVE=0
printf '%s\n' "Installed catalog $CATALOG_ID as instance $INSTANCE_KEY with prefix '$PREFIX'."
if [ "$ACTION" = install ]; then
    if auto_update_enabled "$INSTANCE_ROOT"; then
        printf '%s\n' "Automatic updates are on for this catalog. Disable them with --remove-auto-update."
    else
        printf '%s\n' "Automatic updates are off. Rerun this install command to update, or add --setup-auto-update to enable them."
    fi
fi
