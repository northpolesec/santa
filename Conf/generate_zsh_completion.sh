#!/bin/bash
# Generates a zsh completion function for santactl from santactl's own help
# output, so the completion cannot drift from the binary it ships alongside.
#
# Usage: generate_zsh_completion.sh /path/to/santactl > _santactl
#
# Only what `santactl help` documents is completed: hidden commands stay hidden
# and DEBUG-only flags appear only in completions built from a DEBUG build.

set -e

SANTACTL="${1:?usage: $0 /path/to/santactl}"

# `santactl help <command>` exits non-zero even when it succeeds, hence `|| true`.
collect() {
  "${SANTACTL}" help || true
  "${SANTACTL}" help | /usr/bin/sed -n 's/^[[:space:]]*\([a-zA-Z0-9_-]*\) - .*/\1/p' |
    while read -r cmd; do
      echo "##COMMAND ${cmd}"
      "${SANTACTL}" help "${cmd}" || true
    done
}

read -r -d '' AWK_PROGRAM <<'AWK' || true
# Escape a string for use inside a single-quoted _arguments spec.
function quote(s) {
  gsub(/\\/, "\\\\", s)
  gsub(/'/, "'\\''", s)
  return s
}

# Escape a description for use inside the [...] of an _arguments spec.
function describe(s) {
  s = quote(s)
  gsub(/\[/, "\\[", s)
  gsub(/\]/, "\\]", s)
  sub(/\.$/, "", s)
  return s
}

# Help text wraps descriptions over several lines. Keep the first sentence.
function firstsentence(s) {
  if (match(s, /\. /)) s = substr(s, 1, RSTART - 1)
  return s
}

function trim(s) {
  sub(/^[[:space:]]+/, "", s)
  sub(/[[:space:]]+$/, "", s)
  return s
}

function indent(s,   t) {
  t = s
  sub(/[^[:space:]].*$/, "", t)
  return length(t)
}

# The command summary list, printed before the first ##COMMAND marker.
!started && /^[[:space:]]+[a-zA-Z0-9_-]+ - / {
  line = trim($0)
  name = line
  sub(/ - .*$/, "", name)
  desc = line
  sub(/^[^ ]+ - /, "", desc)
  order[++n] = name
  summary[name] = desc
  next
}

/^##COMMAND / {
  started = 1
  cmd = $2
  flag = ""
  next
}

!started { next }

/^Aliases: / {
  count = split(substr($0, 10), parts, ",")
  for (i = 1; i <= count; i++) {
    aliasorder[++an] = trim(parts[i])
    aliases[trim(parts[i])] = cmd
  }
  next
}

/^Usage: santactl / {
  if (index($0, "<command>")) subcommands[cmd] = ""
  if (index($0, "[arguments...]")) rest[cmd] = "normal"
  next
}

{
  line = trim($0)

  # A documented option: "--flag (-f) {arg}: description".
  if (line ~ /^--[a-zA-Z0-9][a-zA-Z0-9-]*([[:space:]]\(-[a-zA-Z]\))?([[:space:]]\{[^}]*\})*:[[:space:]]/) {
    head = line
    sub(/:[[:space:]].*$/, "", head)
    desc = line
    sub(/^[^:]*:[[:space:]]*/, "", desc)

    flag = head
    sub(/[[:space:]].*$/, "", flag)

    key = cmd SUBSEP flag
    flags[cmd] = flags[cmd] " " flag
    descs[key] = desc
    shorts[key] = match(head, /\(-[a-zA-Z]\)/) ? substr(head, RSTART + 1, RLENGTH - 2) : ""
    # Argument names hinting at a filesystem path get file completion.
    paths[key] = (head ~ /\{[^}]*([Pp]ath|[Ff]ile)[^}]*\}/)
    args[key] = gsub(/\{[^}]*\}/, "&", head)
    flagindent = indent($0)
    next
  }

  if (flag != "") {
    key = cmd SUBSEP flag
    # An indented, quoted string alone on a line is a valid value for the flag.
    if (line ~ /^"[^"]*"$/ && indent($0) > flagindent) {
      values[key] = values[key] substr(line, 2, length(line) - 2) SUBSEP
      next
    }
    if (index(line, "repeating this flag")) repeat[key] = 1
    # Descriptions wrap onto continuation lines; keep pulling them in until a
    # whole sentence has been seen.
    if (line != "" && indent($0) > flagindent && index(descs[key], ".") == 0)
      descs[key] = descs[key] " " line
  }

  # A subcommand of a "santactl <cmd> <command>" style command.
  if (cmd in subcommands && line ~ /^[a-z][a-zA-Z0-9-]*:[[:space:]]/ && indent($0) <= 4) {
    name = line
    sub(/:.*$/, "", name)
    desc = line
    sub(/^[^:]*:[[:space:]]*/, "", desc)
    subcommands[cmd] = subcommands[cmd] name SUBSEP desc SUBSEP
  }
}

# The ":action" part of an _arguments spec for one argument of a flag.
function action(key,   parts, count, i, out, v) {
  if (values[key] != "") {
    count = split(values[key], parts, SUBSEP)
    out = ":value:("
    for (i = 1; i < count; i++) {
      v = quote(parts[i])
      gsub(/ /, "\\ ", v)
      out = out (i > 1 ? " " : "") v
    }
    return out ")"
  }
  return paths[key] ? ":file:_files" : ": :"
}

function emitflags(cmd,   list, count, i, f, key, suffix, j) {
  count = split(flags[cmd], list, " ")
  for (i = 1; i <= count; i++) {
    f = list[i]
    if (f == "") continue
    key = cmd SUBSEP f
    suffix = "[" describe(firstsentence(descs[key])) "]"
    # A flag documented without a {placeholder} still takes a value if the
    # help text lists valid values for it.
    for (j = 0; j < (args[key] ? args[key] : (values[key] != "")); j++)
      suffix = suffix action(key)
    if (shorts[key] != "") {
      # The long and short spellings exclude each other. Brace expansion would
      # need unquoted braces, so spell both out instead.
      printf "            '(%s %s)%s%s' \\\n", f, shorts[key], f, suffix
      printf "            '(%s %s)%s%s' \\\n", f, shorts[key], shorts[key], suffix
    } else {
      printf "            '%s%s%s' \\\n", repeat[key] ? "*" : "", f, suffix
    }
  }
  printf "            '%s'\n", (rest[cmd] == "normal") ? "*:: :_normal" : "*:file:_files"
}

END {
  print "#compdef santactl"
  print ""
  print "# GENERATED FILE - DO NOT EDIT."
  print "# Produced by Conf/generate_zsh_completion.sh from santactl's own help output."
  print ""
  print "_santactl() {"
  print "  local curcontext=\"$curcontext\" state line"
  print "  local -a commands aliases"
  print ""
  print "  commands=("
  for (i = 1; i <= n; i++)
    printf "    '%s:%s'\n", order[i], describe(summary[order[i]])
  print "  )"
  print ""
  print "  aliases=("
  for (i = 1; i <= an; i++)
    printf "    '%s:alias for %s'\n", aliasorder[i], aliases[aliasorder[i]]
  print "  )"
  print ""
  print "  _arguments -C '1: :->command' '*:: :->args'"
  print ""
  print "  case $state in"
  print "    command)"
  print "      _describe -t commands 'santactl command' commands"
  print "      _describe -t aliases 'santactl alias' aliases"
  print "      ;;"
  print "    args)"
  print "      case $words[1] in"
  print "        help) _describe -t commands 'santactl command' commands ;;"

  for (i = 1; i <= n; i++) {
    cmd = order[i]
    pattern = cmd
    for (j = 1; j <= an; j++)
      if (aliases[aliasorder[j]] == cmd) pattern = pattern "|" aliasorder[j]
    printf "        %s)\n", pattern

    if (subcommands[cmd] != "") {
      print "          if (( CURRENT == 2 )); then"
      print "            local -a subcommands"
      printf "            subcommands=("
      count = split(subcommands[cmd], parts, SUBSEP)
      for (j = 1; j < count; j += 2)
        printf " '%s:%s'", parts[j], describe(parts[j + 1])
      print " )"
      print "            _describe -t commands 'santactl subcommand' subcommands"
      print "            return"
      print "          fi"
      print "          shift words; (( CURRENT-- ))"
    }

    print "          _arguments \\"
    emitflags(cmd)
    print "          ;;"
  }

  print "      esac"
  print "      ;;"
  print "  esac"
  print "}"
  print ""
  print "_santactl \"$@\""
}
AWK

collect | /usr/bin/awk "${AWK_PROGRAM}"
