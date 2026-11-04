# Structural JSON hook editor for the POSIX Team Skills installer.
#
# Usage:
#   awk -v operation=check -f team-skills-json.awk hooks.json
#   TEAM_SKILLS_JSON_COMMAND='...' awk -v operation=add -v product=claude -f ... hooks.json
#   TEAM_SKILLS_JSON_COMMAND='...' awk -v operation=remove -v product=cursor -f ... hooks.json
#
# The implementation deliberately uses only POSIX awk. It parses the complete JSON document,
# rejects duplicate object keys, malformed UTF-8, excessive size/depth, mutates only the
# supported hook array, and emits valid JSON.

function byte_character(value) {
    if (!byte_table_ready) {
        for (byte_index = 0; byte_index < 256; byte_index++) {
            byte_table[byte_index] = sprintf("%c", byte_index)
            byte_number[byte_table[byte_index]] = byte_index
        }
        byte_table_ready = 1
    }
    return byte_table[value]
}

function fail(message, status) {
    print "json editor: " message > "/dev/stderr"
    exit (status ? status : 2)
}

function skip_space(    character) {
    while (position <= length(document)) {
        character = substr(document, position, 1)
        if (character !~ /[ \t\r\n]/) break
        position++
    }
}

function new_node(kind, value,    id) {
    id = ++node_count
    node_kind[id] = kind
    node_value[id] = value
    node_size[id] = 0
    return id
}

function append_child(parent, child,    position_index) {
    position_index = ++node_size[parent]
    node_child[parent SUBSEP position_index] = child
}

function append_member(parent, name, raw_name, child,    position_index) {
    position_index = ++node_size[parent]
    node_name[parent SUBSEP position_index] = name
    node_name_raw[parent SUBSEP position_index] = raw_name
    node_child[parent SUBSEP position_index] = child
}

function hex_value(character) {
    character = tolower(character)
    if (character >= "0" && character <= "9") return character + 0
    return index("abcdef", character) + 9
}

function byte_value(character) {
    byte_character(0)
    return byte_number[character]
}

function is_json_control(character,    value) {
    # Compare explicitly so behavior does not depend on locale character classes.
    # Awk implementations that expose an input NUL can match sprintf("%c", 0);
    # implementations that truncate at NUL reject the resulting incomplete JSON.
    for (value = 0; value < 32; value++) {
        if (character == byte_character(value)) return 1
    }
    return 0
}

function utf8_character(value,    first, second, third, fourth) {
    if (value < 128) return byte_character(value)
    if (value < 2048) {
        first = 192 + int(value / 64)
        second = 128 + (value % 64)
        return byte_character(first) byte_character(second)
    }
    if (value < 65536) {
        first = 224 + int(value / 4096)
        second = 128 + (int(value / 64) % 64)
        third = 128 + (value % 64)
        return byte_character(first) byte_character(second) byte_character(third)
    }
    first = 240 + int(value / 262144)
    second = 128 + (int(value / 4096) % 64)
    third = 128 + (int(value / 64) % 64)
    fourth = 128 + (value % 64)
    return byte_character(first) byte_character(second) byte_character(third) byte_character(fourth)
}

function validate_utf8(value,    index_value, first, second, third, fourth) {
    for (index_value = 1; index_value <= length(value); index_value++) {
        first = byte_value(substr(value, index_value, 1))
        if (first < 128) continue
        if (first >= 194 && first <= 223) {
            second = byte_value(substr(value, ++index_value, 1))
            if (second < 128 || second > 191) fail("invalid UTF-8")
            continue
        }
        if (first >= 224 && first <= 239) {
            second = byte_value(substr(value, ++index_value, 1))
            third = byte_value(substr(value, ++index_value, 1))
            if (third < 128 || third > 191 ||
                    (first == 224 && (second < 160 || second > 191)) ||
                    (first == 237 && (second < 128 || second > 159)) ||
                    (first != 224 && first != 237 && (second < 128 || second > 191))) {
                fail("invalid UTF-8")
            }
            continue
        }
        if (first >= 240 && first <= 244) {
            second = byte_value(substr(value, ++index_value, 1))
            third = byte_value(substr(value, ++index_value, 1))
            fourth = byte_value(substr(value, ++index_value, 1))
            if (third < 128 || third > 191 || fourth < 128 || fourth > 191 ||
                    (first == 240 && (second < 144 || second > 191)) ||
                    (first == 244 && (second < 128 || second > 143)) ||
                    (first != 240 && first != 244 && (second < 128 || second > 191))) {
                fail("invalid UTF-8")
            }
            continue
        }
        fail("invalid UTF-8")
    }
}

function decode_string(raw,    result, index_value, character, escape, hex, value, low_hex, low_value) {
    result = ""
    for (index_value = 2; index_value < length(raw); index_value++) {
        character = substr(raw, index_value, 1)
        if (character != "\\") {
            result = result character
            continue
        }
        escape = substr(raw, ++index_value, 1)
        if (escape == "\"" || escape == "\\" || escape == "/") result = result escape
        else if (escape == "b") result = result byte_character(8)
        else if (escape == "f") result = result byte_character(12)
        else if (escape == "n") result = result "\n"
        else if (escape == "r") result = result "\r"
        else if (escape == "t") result = result "\t"
        else if (escape == "u") {
            hex = substr(raw, index_value + 1, 4)
            value = hex_value(substr(hex, 1, 1)) * 4096 + \
                    hex_value(substr(hex, 2, 1)) * 256 + \
                    hex_value(substr(hex, 3, 1)) * 16 + \
                    hex_value(substr(hex, 4, 1))
            if (value >= 55296 && value <= 56319 && substr(raw, index_value + 5, 2) == "\\u") {
                low_hex = substr(raw, index_value + 7, 4)
                low_value = hex_value(substr(low_hex, 1, 1)) * 4096 + \
                            hex_value(substr(low_hex, 2, 1)) * 256 + \
                            hex_value(substr(low_hex, 3, 1)) * 16 + \
                            hex_value(substr(low_hex, 4, 1))
                if (low_hex ~ /^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/ &&
                        low_value >= 56320 && low_value <= 57343) {
                    result = result utf8_character(65536 + (value - 55296) * 1024 + low_value - 56320)
                    index_value += 10
                    continue
                }
            }
            if (value >= 55296 && value <= 57343) result = result "\\u" tolower(hex)
            else result = result utf8_character(value)
            index_value += 4
        }
    }
    return result
}

function parse_string(    start, character, escape, hex) {
    start = position
    position++
    while (position <= length(document)) {
        character = substr(document, position, 1)
        if (character == "\"") {
            position++
            return new_node("string", substr(document, start, position - start))
        }
        if (is_json_control(character)) fail("unescaped control character in string")
        if (character == "\\") {
            position++
            escape = substr(document, position, 1)
            if (escape ~ /^["\\\/bfnrt]$/) {
                position++
                continue
            }
            if (escape == "u") {
                hex = substr(document, position + 1, 4)
                if (length(hex) != 4 || hex !~ /^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/) {
                    fail("invalid Unicode escape")
                }
                position += 5
                continue
            }
            fail("invalid string escape")
        }
        position++
    }
    fail("unterminated string")
}

function parse_array(    id, child, character) {
    if (++parse_depth > 64) fail("JSON nesting exceeds 64 levels")
    id = new_node("array", "")
    position++
    skip_space()
    if (substr(document, position, 1) == "]") {
        position++
        parse_depth--
        return id
    }
    while (1) {
        child = parse_value()
        append_child(id, child)
        skip_space()
        character = substr(document, position, 1)
        if (character == "]") {
            position++
            parse_depth--
            return id
        }
        if (character != ",") fail("expected comma or closing bracket")
        position++
        skip_space()
    }
}

function parse_object(    id, key_node, key_name, child, character, duplicate_key) {
    if (++parse_depth > 64) fail("JSON nesting exceeds 64 levels")
    id = new_node("object", "")
    position++
    skip_space()
    if (substr(document, position, 1) == "}") {
        position++
        parse_depth--
        return id
    }
    while (1) {
        if (substr(document, position, 1) != "\"") fail("object key must be a string")
        key_node = parse_string()
        key_name = decode_string(node_value[key_node])
        duplicate_key = id SUBSEP key_name
        if (object_seen[duplicate_key]) fail("duplicate object key")
        object_seen[duplicate_key] = 1
        duplicate_key = id SUBSEP tolower(key_name)
        if (object_seen_folded[duplicate_key]) fail("case-colliding object key")
        object_seen_folded[duplicate_key] = 1
        skip_space()
        if (substr(document, position, 1) != ":") fail("expected colon after object key")
        position++
        skip_space()
        child = parse_value()
        append_member(id, key_name, node_value[key_node], child)
        skip_space()
        character = substr(document, position, 1)
        if (character == "}") {
            position++
            parse_depth--
            return id
        }
        if (character != ",") fail("expected comma or closing brace")
        position++
        skip_space()
    }
}

function parse_value(    character, remaining, matched) {
    skip_space()
    character = substr(document, position, 1)
    if (character == "{") return parse_object()
    if (character == "[") return parse_array()
    if (character == "\"") return parse_string()
    remaining = substr(document, position)
    if (substr(remaining, 1, 4) == "true") {
        position += 4
        return new_node("literal", "true")
    }
    if (substr(remaining, 1, 5) == "false") {
        position += 5
        return new_node("literal", "false")
    }
    if (substr(remaining, 1, 4) == "null") {
        position += 4
        return new_node("literal", "null")
    }
    if (match(remaining, /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/)) {
        matched = substr(remaining, 1, RLENGTH)
        position += RLENGTH
        return new_node("number", matched)
    }
    fail("invalid JSON value")
}

function quote_string(value,    result, index_value, character) {
    result = "\""
    for (index_value = 1; index_value <= length(value); index_value++) {
        character = substr(value, index_value, 1)
        if (character == "\"" || character == "\\") result = result "\\" character
        else if (character == "\n") result = result "\\n"
        else if (character == "\r") result = result "\\r"
        else if (character == "\t") result = result "\\t"
        else result = result character
    }
    return result "\""
}

function object_index(id, wanted,    index_value) {
    if (node_kind[id] != "object") return 0
    for (index_value = 1; index_value <= node_size[id]; index_value++) {
        if (node_name[id SUBSEP index_value] == wanted) return index_value
    }
    return 0
}

function object_value(id, wanted,    index_value) {
    index_value = object_index(id, wanted)
    return index_value ? node_child[id SUBSEP index_value] : 0
}

function add_named_value(id, name, child) {
    append_member(id, name, quote_string(name), child)
}

function ensure_named_container(id, name, kind,    child) {
    child = object_value(id, name)
    if (!child) {
        child = new_node(kind, "")
        add_named_value(id, name, child)
    } else if (node_kind[child] != kind) {
        fail(name " must be a JSON " kind)
    }
    return child
}

function string_equals(id, value) {
    return node_kind[id] == "string" && decode_string(node_value[id]) == value
}

function literal_equals(id, value) {
    return (node_kind[id] == "literal" || node_kind[id] == "number") && node_value[id] == value
}

function utf8_length(value,    index_value, count, first) {
    for (index_value = 1; index_value <= length(value); index_value++) {
        first = byte_value(substr(value, index_value, 1))
        count++
        if (first >= 194 && first <= 223) index_value += 1
        else if (first >= 224 && first <= 239) index_value += 2
        else if (first >= 240 && first <= 244) index_value += 3
    }
    return count
}

function portable_name(value, maximum, allow_blank) {
    if (value == "") return allow_blank
    return utf8_length(value) <= maximum && value ~ /^[a-z0-9]+(-[a-z0-9]+)*$/
}

function validate_manifest(root,    index_value, name, id_node, display_node, prefix_node) {
    if (node_size[root] != 6) fail("catalog manifest must have exactly six fields")
    for (index_value = 1; index_value <= node_size[root]; index_value++) {
        name = node_name[root SUBSEP index_value]
        if (name != "$schema" && name != "schema_version" && name != "catalog_id" &&
                name != "display_name" && name != "skills_directory" &&
                name != "default_prefix") fail("unknown catalog manifest field")
    }
    if (!string_equals(object_value(root, "$schema"), "./schemas/catalog.schema.json") ||
            !literal_equals(object_value(root, "schema_version"), "1") ||
            !string_equals(object_value(root, "skills_directory"), "skills")) {
        fail("unsupported catalog manifest contract")
    }
    id_node = object_value(root, "catalog_id")
    display_node = object_value(root, "display_name")
    prefix_node = object_value(root, "default_prefix")
    if (node_kind[id_node] != "string" ||
            !portable_name(decode_string(node_value[id_node]), 64, 0)) fail("invalid catalog id")
    if (node_kind[display_node] != "string" ||
            utf8_length(decode_string(node_value[display_node])) < 1 ||
            utf8_length(decode_string(node_value[display_node])) > 128) fail("invalid display name")
    if (node_kind[prefix_node] != "string" ||
            !portable_name(decode_string(node_value[prefix_node]), 62, 1)) fail("invalid default prefix")
    print decode_string(node_value[id_node])
    print decode_string(node_value[prefix_node])
}

function validate_codex_root(root,    index_value, name, description, hooks) {
    for (index_value = 1; index_value <= node_size[root]; index_value++) {
        name = node_name[root SUBSEP index_value]
        if (name != "description" && name != "hooks") {
            fail("unsupported Codex hook root field")
        }
    }
    description = object_value(root, "description")
    if (description && node_kind[description] != "string") {
        fail("Codex hook description must be a string")
    }
    hooks = object_value(root, "hooks")
    if (hooks && node_kind[hooks] != "object") {
        fail("Codex hooks must be a JSON object")
    }
}

function owned_handler(id,    type_id, command_id, async_id) {
    if (node_kind[id] != "object" || node_size[id] != 3) return 0
    type_id = object_value(id, "type")
    command_id = object_value(id, "command")
    async_id = object_value(id, "async")
    return string_equals(type_id, "command") && string_equals(command_id, command) && \
           literal_equals(async_id, "true")
}

function owned_group(id,    matcher_id, handlers_id, handler_id) {
    if (node_kind[id] != "object" || node_size[id] != 2) return 0
    matcher_id = object_value(id, "matcher")
    handlers_id = object_value(id, "hooks")
    if (!string_equals(matcher_id, "startup|clear") || node_kind[handlers_id] != "array" || \
        node_size[handlers_id] != 1) return 0
    handler_id = node_child[handlers_id SUBSEP 1]
    return owned_handler(handler_id)
}

function owned_cursor_hook(id,    command_id) {
    if (node_kind[id] != "object" || node_size[id] != 1) return 0
    command_id = object_value(id, "command")
    return string_equals(command_id, command)
}

function make_lifecycle_group(    group, matcher_node, handlers, handler) {
    group = new_node("object", "")
    matcher_node = new_node("string", quote_string("startup|clear"))
    add_named_value(group, "matcher", matcher_node)
    handlers = new_node("array", "")
    handler = new_node("object", "")
    add_named_value(handler, "type", new_node("string", quote_string("command")))
    add_named_value(handler, "command", new_node("string", quote_string(command)))
    add_named_value(handler, "async", new_node("literal", "true"))
    append_child(handlers, handler)
    add_named_value(group, "hooks", handlers)
    return group
}

function make_cursor_hook(    hook) {
    hook = new_node("object", "")
    add_named_value(hook, "command", new_node("string", quote_string(command)))
    return hook
}

function add_hook(root,    hooks, event, version, index_value, child) {
    hooks = ensure_named_container(root, "hooks", "object")
    if (product == "cursor") {
        version = object_value(root, "version")
        if (!version) add_named_value(root, "version", new_node("number", "1"))
        else if (!literal_equals(version, "1")) fail("Cursor hook version must be 1")
        event = ensure_named_container(hooks, "sessionStart", "array")
        for (index_value = 1; index_value <= node_size[event]; index_value++) {
            child = node_child[event SUBSEP index_value]
            if (owned_cursor_hook(child)) return
        }
        append_child(event, make_cursor_hook())
        return
    }
    event = ensure_named_container(hooks, "SessionStart", "array")
    for (index_value = 1; index_value <= node_size[event]; index_value++) {
        child = node_child[event SUBSEP index_value]
        if (owned_group(child)) return
    }
    append_child(event, make_lifecycle_group())
}

function remove_array_index(id, removed_index,    index_value) {
    for (index_value = removed_index; index_value < node_size[id]; index_value++) {
        node_child[id SUBSEP index_value] = node_child[id SUBSEP (index_value + 1)]
    }
    delete node_child[id SUBSEP node_size[id]]
    node_size[id]--
}

function remove_object_index(id, removed_index,    index_value) {
    for (index_value = removed_index; index_value < node_size[id]; index_value++) {
        node_name[id SUBSEP index_value] = node_name[id SUBSEP (index_value + 1)]
        node_name_raw[id SUBSEP index_value] = node_name_raw[id SUBSEP (index_value + 1)]
        node_child[id SUBSEP index_value] = node_child[id SUBSEP (index_value + 1)]
    }
    delete node_name[id SUBSEP node_size[id]]
    delete node_name_raw[id SUBSEP node_size[id]]
    delete node_child[id SUBSEP node_size[id]]
    node_size[id]--
}

function remove_hook(root,    hooks, event, event_name, event_index, hooks_index, version_index, version, index_value, child, matches, matched_index) {
    hooks = object_value(root, "hooks")
    if (!hooks || node_kind[hooks] != "object") fail("owned hook container is missing", 3)
    event_name = product == "cursor" ? "sessionStart" : "SessionStart"
    event = object_value(hooks, event_name)
    if (!event || node_kind[event] != "array") fail("owned hook event is missing", 3)
    for (index_value = 1; index_value <= node_size[event]; index_value++) {
        child = node_child[event SUBSEP index_value]
        if ((product == "cursor" && owned_cursor_hook(child)) || \
            (product != "cursor" && owned_group(child))) {
            matches++
            matched_index = index_value
        }
    }
    if (matches != 1) fail(matches ? "owned hook entry is ambiguous" : "owned hook entry changed or is missing", 3)
    remove_array_index(event, matched_index)
    if (!node_size[event]) {
        event_index = object_index(hooks, event_name)
        remove_object_index(hooks, event_index)
        if (!node_size[hooks]) {
            hooks_index = object_index(root, "hooks")
            remove_object_index(root, hooks_index)
        }
    }
    if (product == "cursor" && ENVIRON["TEAM_SKILLS_JSON_REMOVE_CURSOR_VERSION"] == "1") {
        version_index = object_index(root, "version")
        version = version_index ? node_child[root SUBSEP version_index] : 0
        if (!version || !literal_equals(version, "1")) fail("owned Cursor hook version changed or is missing", 3)
        remove_object_index(root, version_index)
    }
}

function removable_created_config(root,    version) {
    if (product == "cursor") {
        if (node_size[root] == 0) return 1
        if (node_size[root] != 1) return 0
        version = object_value(root, "version")
        return literal_equals(version, "1")
    }
    return node_size[root] == 0
}

function indent(level,    result, index_value) {
    result = ""
    for (index_value = 0; index_value < level; index_value++) result = result "  "
    return result
}

function render(id, level,    kind, result, index_value, child) {
    kind = node_kind[id]
    if (kind == "string" || kind == "literal" || kind == "number") return node_value[id]
    if (kind == "array") {
        if (!node_size[id]) return "[]"
        result = "[\n"
        for (index_value = 1; index_value <= node_size[id]; index_value++) {
            child = node_child[id SUBSEP index_value]
            result = result indent(level + 1) render(child, level + 1)
            result = result (index_value < node_size[id] ? ",\n" : "\n")
        }
        return result indent(level) "]"
    }
    if (kind == "object") {
        if (!node_size[id]) return "{}"
        result = "{\n"
        for (index_value = 1; index_value <= node_size[id]; index_value++) {
            child = node_child[id SUBSEP index_value]
            result = result indent(level + 1) node_name_raw[id SUBSEP index_value] ": " \
                     render(child, level + 1)
            result = result (index_value < node_size[id] ? ",\n" : "\n")
        }
        return result indent(level) "}"
    }
    fail("internal node type is invalid")
}

BEGIN {
    document = ""
}

{
    incoming_length = length($0) + (NR == 1 ? 0 : 1)
    if (length(document) + incoming_length > 1048576) {
        print "json editor: JSON input exceeds 1 MiB" > "/dev/stderr"
        input_failed = 1
        exit 2
    }
    document = document (NR == 1 ? "" : "\n") $0
}

END {
    if (input_failed) exit 2
    if (document == "") document = "{}"
    validate_utf8(document)
    position = 1
    root_node = parse_value()
    skip_space()
    if (position <= length(document)) fail("trailing content after JSON document")
    if (node_kind[root_node] != "object") fail("top-level JSON value must be an object")

    if (operation == "check") exit 0
    if (operation == "manifest") {
        validate_manifest(root_node)
        exit 0
    }
    if (operation == "cursor-version") {
        version = object_value(root_node, "version")
        exit(version && literal_equals(version, "1") ? 0 : 1)
    }
    if (operation != "add" && operation != "remove" && operation != "empty") fail("unsupported operation")
    if (product != "claude" && product != "codex" && product != "cursor") fail("unsupported product")
    if (product == "codex") validate_codex_root(root_node)
    if (operation == "empty") exit(removable_created_config(root_node) ? 0 : 1)
    if (command == "") command = ENVIRON["TEAM_SKILLS_JSON_COMMAND"]
    if (command == "") fail("command must not be blank")

    if (operation == "add") add_hook(root_node)
    else remove_hook(root_node)
    print render(root_node, 0)
}
