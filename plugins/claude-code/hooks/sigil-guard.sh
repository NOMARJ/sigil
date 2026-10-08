#!/bin/sh
# sigil-guard.sh — PreToolUse gate for Bash tool calls.
#
# Enforces Sigil's quarantine-first workflow: acquisition commands (git clone,
# package installs, curl|sh) are denied with a redirect to the sigil equivalent.
# Delegates to `sigil hook pretooluse` when the binary is on PATH; otherwise a
# pure pattern gate (POSIX sh, grep, sed, tr, awk) that never touches the
# network.
#
# Policy summary:
#   DENY  — commands that pull unscanned third-party code into the environment
#           (git clone, npm/pip/cargo/gem/go installs with explicit packages,
#           curl|sh pipelines). Redirected to sigil clone / sigil npm / sigil pip.
#   DENY  — also npx/bunx/uvx/pipx run/dlx remote runners (native hook:
#           `sigil hook pretooluse` allows npx of a project-local binary),
#           and npm exec|x, bun x, uv tool run of a registry package.
#   DENY  — remote execution one step removed, judged per pipeline stage like
#           the native hook: a download piped through `tee` or into
#           `bash -s` / `sudo -u user bash` / `env -i bash` / python / node /
#           iex, also through filters (`| tr -d '\r' | bash`), or
#           substituted into one (`bash <(curl …)`, `bash < <(curl …)`); a
#           file downloaded and run in the same command
#           (`curl -o i.sh … && bash i.sh`, `. ./i.sh`, `cat i.sh | sh`,
#           `bash < i.sh`, `eval "$(cat i.sh)"`, a copy of it) unless a
#           real `sigil scan i.sh &&` comes between; a download saved into
#           agent tooling (`~/.claude/skills`,
#           `.mcp.json`, `.cursor/rules`, ..., also through `| tee`);
#           `pipx install` / `uv tool install`; `deno run npm:…|https://…`.
#   ASK   — commands that are lower risk but still execute third-party code
#           (bare lockfile restores).
#   ALLOW — everything else.
#
# Escape hatches:
#   SIGIL_BYPASS=1        — allow this one command (also honoured as a prefix
#                           inside the command string itself).
#   SIGIL_GUARD_MODE      — "enforce" (default), "advise" (deny -> ask), "off".
#
# Always exits 0 with valid PreToolUse JSON on stdout.

MODE="${SIGIL_GUARD_MODE:-enforce}"

emit() {
  # $1 = permissionDecision, $2 = reason (JSON-escaped here when it quotes
  # the command).
  e_reason=$2
  case $e_reason in
    *[\"\\]*|*[[:cntrl:]]*)
      e_reason=$(printf '%s' "$2" | tr '\t\n\r' '   ' | tr -d '\000-\037\177' \
        | sed 's/\\/\\\\/g; s/"/\\"/g') ;;
  esac
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' "$1" "$e_reason"
  exit 0
}

deny() {
  # In advise mode every deny is downgraded to ask.
  if [ "$MODE" = "advise" ]; then
    emit ask "$1"
  else
    emit deny "$1"
  fi
}

# ── Mode / bypass short-circuits ───────────────────────────────────────────

[ "$MODE" = "off" ] && emit allow "Sigil guard disabled (SIGIL_GUARD_MODE=off)"
[ "$SIGIL_BYPASS" = "1" ] && emit allow "Sigil guard bypassed (SIGIL_BYPASS=1)"

# ── Extract .tool_input.command from the hook JSON on stdin ────────────────

INPUT=$(cat)

# ── Delegate to the native implementation when available ───────────────────
# `sigil hook pretooluse` (CLI v1.3.0+) is the maintained home of this
# policy; the patterns below are the dependency-free fallback for missing or
# older binaries (which exit non-zero on the unknown subcommand and fall
# through here).
if command -v sigil >/dev/null 2>&1; then
  NATIVE=$(printf '%s' "$INPUT" | sigil hook pretooluse 2>/dev/null) || NATIVE=""
  case "$NATIVE" in
    *permissionDecision*) printf '%s\n' "$NATIVE"; exit 0 ;;
  esac
fi

NL='
'
# Tab, SOH (\001), US (\037) and CR, from one printf.
CTL=$(printf '\t\001\037\r')
TAB=${CTL%???}
SOH=${CTL#?}
SOH=${SOH%??}
US=${CTL#??}
US=${US%?}
CR=${CTL#???}
IFS_DEFAULT=" $TAB$NL"

if command -v jq >/dev/null 2>&1; then
  # The working directory (for relative paths), SOH, then the command.
  CMD=$(printf '%s' "$INPUT" \
    | jq -r '((.cwd // "") | tostring) + "\u0001" + ((.tool_input.command // "") | tostring)' 2>/dev/null)
  CWD=${CMD%%"$SOH"*}
  CMD=${CMD#*"$SOH"}
else
  # Conservative fallback: grab the text after "command":" and cut at the
  # first unescaped double quote, then undo the JSON escapes that matter:
  # \n becomes a newline (a command separator, as for jq), \t and \r
  # spaces, \" and \\ their characters. Prefer installing jq for exact
  # extraction.
  STX=$(printf '\002')
  CMD=$(printf '%s' "$INPUT" | tr '\n' ' ' \
    | sed -n 's/.*"command"[ 	]*:[ 	]*"//p' \
    | sed 's/\\\\/'"$SOH"'/g; s/\\"/'"$STX"'/g; s/".*//; s/\\[tr]/ /g; s/\\\//\//g' \
    | sed 's/\\n/\
/g; s/'"$STX"'/"/g; s/'"$SOH"'/\\/g')
  CWD=$(printf '%s' "$INPUT" | tr '\n' ' ' \
    | sed -n 's/.*"cwd"[ 	]*:[ 	]*"\([^"\\]*\)".*/\1/p')
fi

# Fail-open on parse: if the command can't be extracted we allow rather than
# block. We gate acquisition patterns, not people — an unparseable payload is
# a hook-plumbing problem, not evidence of an acquisition attempt.
[ -z "$CMD" ] && emit allow "Sigil guard: no command extracted"

# Nothing below expands a glob.
set -f

# has_in <text> <ERE>
has_in() {
  printf '%s\n' "$1" | grep -Eq "$2"
}

BYPASS_HINT="Bypass: SIGIL_BYPASS=1"

# Left word boundary: start of string, a shell separator, or a quote (so
# `bash -c 'npm install evil'` is still seen).
WB='(^|[[:space:];&|("'\''])'
# Any run of flag tokens, then at least one non-flag token (a package arg).
FLAGS='([[:space:]]+-[^[:space:]]+)*'
PKG='[[:space:]]+[^-[:space:]]'
# Modifier tokens between a tool name and its subcommand: runs of -flag
# tokens, each optionally followed by one non-flag argument. Covers forms
# like `git -C /tmp clone`, `npm --prefix ./x install`, `go -C x install`.
MOD='([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*'

# SIGIL_BYPASS=1 given as an env prefix inside the command string (checked
# first, on the command as written, as the native hook does).
has_in "$CMD" "${WB}SIGIL_BYPASS=1([[:space:]]|\$)" \
  && emit allow "Sigil guard bypassed (SIGIL_BYPASS=1)"

# A backslash-newline is a line continuation: the shell removes both, so
# `… && sigil scan i.sh && \` then `bash i.sh` is one && chain (hook.rs
# join_continuations). Not inside a `# comment`, which a backslash does not
# continue: the comment ends at the line end. Reading that takes awk; without
# it every backslash-newline is joined, and a comment may swallow the line
# after it.
# shellcheck disable=SC2016 # an awk program, not shell
JOIN_AWK='
BEGIN { SQ = sprintf("%c", 39); DQ = "\""; buf = ""; seen = 0 }
{ buf = (seen ? buf "\n" : "") $0; seen = 1 }
END {
  s = buf; n = length(s); out = ""; i = 1; esc = 0; brace = 0; st = "o"; ansi = 0
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == "\\") {
      e = substr(s, i + 1, 1)
      if (e == "\n") { i += 2; continue }
      if (e == "\r" && substr(s, i + 2, 1) == "\n") { i += 3; continue }
      if (st == "o" || st == "d" || (st == "s" && ansi)) { out = out c e; esc = i + 1; i += 2; continue }
    }
    if (st == "o") {
      if (c == SQ) { ansi = (i > 1 && substr(s, i - 1, 1) == "$"); st = "s" }
      else if (c == DQ) st = "d"
      else if (c == "#" && brace == 0 && (i == 1 || (index(" \t\n;&|", substr(s, i - 1, 1)) && esc != i - 1))) {
        while (i <= n && substr(s, i, 1) != "\n") { out = out substr(s, i, 1); i++ }
        continue
      }
      else if (c == "{" && i > 1 && substr(s, i - 1, 1) == "$" && esc != i - 1) brace++
      else if (c == "}" && brace > 0) brace--
    } else if (st == "s") { if (c == SQ) st = "o" }
    else if (c == DQ) st = "o"
    out = out c; i++
  }
  printf "%s\n", out
}'
case $CMD in
  *"\\$NL"*|*"\\$CR$NL"*)
    CMD_JOINED=''
    if command -v awk >/dev/null 2>&1; then
      CMD_JOINED=$(printf '%s\n' "$CMD" | LC_ALL=C awk "$JOIN_AWK" 2>/dev/null) || CMD_JOINED=''
    fi
    if [ -n "$CMD_JOINED" ]; then
      CMD=$CMD_JOINED
    else
      CMD=$(printf '%s\n' "$CMD" \
        | sed -e ':a' -e "/\\\\$CR\$/{" -e '$!N' -e "s/\\\\$CR\\n//" -e 'ta' -e '}' \
          -e '/\\$/{' -e '$!N' -e 's/\\\n//' -e 'ta' -e '}')
    fi ;;
esac

# The command with quoting inside words removed (cmdline::dequote): quotes
# around a run with no whitespace or quote in it (`"bash"`, `de''no`) and a
# backslash in front of a word character (`b\ash`). Quoted strings with
# whitespace keep their quotes. Every pattern check below also reads it.
DCMD=$CMD
case $CMD in
  *[\"\'\\]*)
    DCMD=$(printf '%s\n' "$CMD" | LC_ALL=C sed \
      -e "s/'\\([^'\"[:space:]]*\\)'/\\1/g" \
      -e "s/\"\\([^'\"[:space:]]*\\)\"/\\1/g" \
      -e 's/\\\([A-Za-z0-9_./-]\)/\1/g') ;;
esac

has() {
  has_in "$CMD" "$1" && return 0
  [ "$DCMD" != "$CMD" ] && has_in "$DCMD" "$1"
}

# ── Helpers shared by the remote-execution checks ──────────────────────────
# Each mirrors the hook.rs / cmdline.rs function it names and leaves its
# result in R.

# first_url <text>: the first http(s) URL, as cmdline::first_url.
URL_END='[[:space:]'\''"|;&)<>`]*'
first_url() {
  R=''
  fu_s=$1
  while :; do
    case $fu_s in
      *http*) fu_s=${fu_s#*http} ;;
      *) return 0 ;;
    esac
    case $fu_s in
      ://*|s://*)
        # shellcheck disable=SC2295 # URL_END is a pattern
        fu_u=http${fu_s%%$URL_END}
        case $fu_u in
          http://?*|https://?*) R=$fu_u; return 0 ;;
        esac
        ;;
    esac
  done
}

# ── DENY: a download piped or substituted into an interpreter ──────────────
# cmdline::pipes_download_to_interpreter, on the command as written and
# dequoted. Judged on the whole command and never gated by a sigil call: the
# server decides per request what it serves. An interpreter that reads the
# download as data (`| python3 -m json.tool`, `| bash -c 'jq …'`,
# `| sh ./process.sh`) or not at all (`| bash < other.sh`) does not count.

case $DCMD in
  *[Cc][Uu][Rr][Ll]*|*[Ww][Gg][Ee][Tt]*|*[Ff][Ee][Tt][Cc][Hh]*|*[Ii][Ww][Rr]*|*[Ii][Rr][Mm]*|*[Ii][Nn][Vv][Oo][Kk][Ee]-*|*[Ww][Ee][Bb][Cc][Ll][Ii][Ee][Nn][Tt]*)
    PIPE_CHECK=1 ;;
  *) PIPE_CHECK=0 ;;
esac
if [ $PIPE_CHECK = 1 ]; then
  # The whole command on one line for grep, newlines as SOH: whitespace
  # between command words (as \s is to hook.rs), but the end of an
  # interpreter's arguments. A literal SOH in the command becomes x.
  FLAT=$(printf '%s' "$CMD" | tr "$SOH$NL" "x$SOH")
  DFLAT=$(printf '%s' "$DCMD" | tr "$SOH$NL" "x$SOH")

  # Command words match in any case, as hook.rs's (?i); interpreter flags
  # are compared exactly, so these spell out both cases rather than use
  # grep -i.
  # (curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)
  DL='([cC][uU][rR][lL]|[wW][gG][eE][tT]|[fF][eE][tT][cC][hH]|[iI][wW][rR]|[iI][rR][mM]|[iI][nN][vV][oO][kK][eE]-[wW][eE][bB][rR][eE][qQ][uU][eE][sS][tT]|[iI][nN][vV][oO][kK][eE]-[rR][eE][sS][tT][mM][eE][tT][hH][oO][dD])'
  TEE='[tT][eE][eE]'
  # (sudo|doas|env|command|builtin|exec|nohup|time|nice|timeout|stdbuf|setsid|ionice|busybox)
  WRAPW='([sS][uU][dD][oO]|[dD][oO][aA][sS]|[eE][nN][vV]|[cC][oO][mM][mM][aA][nN][dD]|[bB][uU][iI][lL][tT][iI][nN]|[eE][xX][eE][cC]|[nN][oO][hH][uU][pP]|[tT][iI][mM][eE]|[nN][iI][cC][eE]|[tT][iI][mM][eE][oO][uU][tT]|[sS][tT][dD][bB][uU][fF]|[sS][eE][tT][sS][iI][dD]|[iI][oO][nN][iI][cC][eE]|[bB][uU][sS][yY][bB][oO][xX])'
  # (sh|bash|zsh|dash|ksh|fish|$shell|${shell})
  # The shells of cmdline::SHELLS with a version suffix (ksh93), $SHELL and
  # $BASH.
  SH_I='(([sS][hH]|[bB][aA][sS][hH]|[zZ][sS][hH]|[dD][aA][sS][hH]|[kK][sS][hH]|[fF][iI][sS][hH]|[aA][sS][hH]|[mM][kK][sS][hH]|[pP][dD][kK][sS][hH]|[oO][kK][sS][hH]|[yY][aA][sS][hH]|[pP][oO][sS][hH]|[rR][bB][aA][sS][hH]|[cC][sS][hH]|[tT][cC][sS][hH])[0-9.]*|[$][sS][hH][eE][lL][lL]|[$][{][sS][hH][eE][lL][lL][}]|[$][bB][aA][sS][hH]|[$][{][bB][aA][sS][hH][}])'
  # (python[0-9.]*|node|deno|bun|ruby|php); perl has options of its own.
  OT_I='([pP][yY][tT][hH][oO][nN][0-9.]*|[nN][oO][dD][eE]|[dD][eE][nN][oO]|[bB][uU][nN]|[rR][uU][bB][yY]|[pP][hH][pP])'
  PL_I='([pP][eE][rR][lL])'
  # (pwsh|powershell), (iex|invoke-expression)
  PW_I='([pP][wW][sS][hH]|[pP][oO][wW][eE][rR][sS][hH][eE][lL][lL])'
  IEX_I='([iI][eE][xX]|[iI][nN][vV][oO][kK][eE]-[eE][xX][pP][rR][eE][sS][sS][iI][oO][nN])'
  # PowerShell -c|-command|-f|-file|-encodedcommand|-e|-ec
  PW_ARG='([cC]|[cC][oO][mM][mM][aA][nN][dD]|[fF]|[fF][iI][lL][eE]|[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD]|[eE]|[eE][cC])'

  WS="[[:space:]$SOH]"
  NWS="[^[:space:]$SOH]"
  # A stage's arguments: anything up to a pipe or list operator, where
  # `2>&1`, `&>f` and `<&3` are redirections rather than `&`.
  ARGS="($WS([^|;&]|>&|&>|<&)*)?"
  # Commands that run the next word as the command (`sudo -u root`,
  # `env -i`, `command`, `doas`, `busybox`, `timeout 60`, ...).
  # Also `VAR=value` words before the command (`| INSTALL_DIR=~/bin bash`).
  WRAP="([A-Za-z_][A-Za-z0-9_]*=$NWS*$WS+|($NWS*/)?$WRAPW($WS+(-$NWS+($WS+[^-[:space:]$SOH|;&<>]$NWS*)?|[A-Za-z0-9_]+=$NWS*|[0-9.]+[sSmMhHdD]?))*$WS+)"

  # Interpreter arguments: the words after the interpreter word up to
  # | ; ) ' " ` a newline, or an & that is not part of a redirection. TC is
  # a character of a word; TOKC also takes the & of `2>&1` and `&>f`.
  TX="[:space:]|;&)'\"\`$SOH"
  TC="[^$TX]"
  TOKC="([^$TX]|[<>]&|&>)"
  STOP="([|;)'\"\`$SOH]|&([^>]|\$)|\$)"
  # The end of the arguments, after a word (END_T) or after the space that
  # follows one (END_S): a stop character or a `#` comment.
  END_T="([[:space:]]*$STOP|[[:space:]]+#)"
  END_S="($STOP|#)"
  # After a redirection operator whose file is missing (`2>` last), an &
  # belongs to the next word (`2>&1`) and does not end the stage.
  END_OP="([[:space:]]+#|[[:space:]]+$STOP|[|;)'\"\`$SOH]|\$)"
  # A word that neither redirects stdin (`< f`, `<<EOF`, `0<f`) nor starts
  # a comment. Once the interpreter is known to read stdin, every later
  # word must be one: a stdin redirection means the download is not read.
  # A redirection of stdin that reads the pipe itself (`<&0`, `< /dev/stdin`)
  # is not one: the download is still what runs (cmdline::apply_redirect).
  STDIN_P="/dev/stdin|/dev/fd/0|/proc/([\$][\$]|self)/fd/0"
  KEEP_W="0?<(&0|$STDIN_P)"
  KEEP_S="0?<[[:space:]]+($STDIN_P)"
  NS="(([^<0#$TX]|>&|&>)$TOKC*|0|0([^<$TX]|>&|&>)$TOKC*|$KEEP_W)"
  REST="([[:space:]]+($NS|$KEEP_S))*$END_T"
  # Redirections of stdout, stderr or another descriptor: skipped, with the
  # next word when the file is not attached (`> out.log`, `2>&1`, `3< f`).
  RN="[^<>$TX]"
  FDO="([0-9]*|&)"
  FDI="([1-9][0-9]*|0[0-9]+|&)"
  R_ALONE="($FDO(>>|>&|>)|$FDI(<<<|<<-|<<|<>|<))"
  R_OK="($FDO(>>|>&|>)$RN+|$FDI(<<<|<<-|<<|<>|<&|<)$RN+|$FDI<&|${R_ALONE}[[:space:]]+$NS|$KEEP_W|$KEEP_S)"
  # The same, written against the interpreter word (`bash>/dev/null`).
  G_ALONE="(&?(>>|>&|>))"
  G_OK="(&?(>>|>&|>)$RN+|${G_ALONE}[[:space:]]+$NS)"

  # hook.rs reads options after backslash removal (`bash \-s` is
  # `bash -s`).
  BQ='\\?'
  # Shells run stdin unless given -c or a script file; -s and - keep
  # reading stdin (`bash -s stable`), and so does a -- with nothing after it
  # but redirections (after --, a word is the script). -o/-O (also last in a
  # bundle, `-euo pipefail`), +o/+O, --rcfile and --init-file take a value;
  # as the last word, with no value, they leave stdin as the script. SH_LONG
  # is a long option other than --rcfile and --init-file.
  SH_LONG="([^ri$TX]$TC*|r([^c$TX]$TC*)?|rc([^f$TX]$TC*)?|rcf([^i$TX]$TC*)?|rcfi([^l$TX]$TC*)?|rcfil([^e$TX]$TC*)?|rcfile$TC+|i([^n$TX]$TC*)?|in([^i$TX]$TC*)?|ini([^t$TX]$TC*)?|init([^-$TX]$TC*)?|init-([^f$TX]$TC*)?|init-f([^i$TX]$TC*)?|init-fi([^l$TX]$TC*)?|init-fil([^e$TX]$TC*)?|init-file$TC+)"
  SH_PLAIN="$BQ(--$SH_LONG|[+]($TC*[^oO$TX])?|-([^-csoO$TX]|[^-cs$TX][^cs$TX]*[^csoO$TX]))"
  SH_VAL="$BQ(-([^-cs$TX][^cs$TX]*)?[oO]|[+]$TC*[oO]|--rcfile|--init-file)"
  SH_OK="($SH_PLAIN|${SH_VAL}[[:space:]]+$NS|$R_OK)"
  # A script that is stdin itself (`bash /dev/stdin`) runs the pipe.
  DD_RUN="$BQ--[[:space:]]+($STDIN_P)"
  DD_LAST="$BQ--([[:space:]]+$R_OK)*"
  SH_RUN="($BQ(-|-(s|[^-c$TX][^c$TX]*s)[^c$TX]*)|$STDIN_P|$DD_RUN)"
  SH_LAST="($SH_VAL|$DD_LAST)"
  # Other interpreters run stdin unless given inline code (-c -e -m -p -n
  # -r -E, --eval/--print/--module in any case) or a script (a word after
  # --, or any word not starting with -); -W/-X take a value (and, last
  # with none, leave stdin as the script). OT_LONG is any other long flag.
  # The native hook reads these options per interpreter, and so does the
  # per-stage check in the awk lexer below; this shared list reads -e -p -n
  # -r -E as inline code for every one of them, so without awk
  # `curl … | python3 -E` is allowed (see docs/detection/ux.md §8).
  OT_LONG="--([^epmEPM$TX]$TC*|[eE]([^vV$TX]$TC*|[vV]([^aA$TX]$TC*|[aA]([^lL$TX]$TC*|[lL]$TC+)?)?)?|[pP]([^rR$TX]$TC*|[rR]([^iI$TX]$TC*|[iI]([^nN$TX]$TC*|[nN]([^tT$TX]$TC*|[tT]$TC+)?)?)?)?|[mM]([^oO$TX]$TC*|[oO]([^dD$TX]$TC*|[dD]([^uU$TX]$TC*|[uU]([^lL$TX]$TC*|[lL]([^eE$TX]$TC*|[eE]$TC+)?)?)?)?)?)"
  OT_OK="($BQ(-[WX][[:space:]]+$NS|-([^-cmepnrEWX$TX][^cmepnrE$TX]*|[WX][^cmepnrE$TX]+)|$OT_LONG)|$R_OK)"
  OT_RUN="($BQ-|$STDIN_P|$DD_RUN)"
  OT_LAST="($BQ-[WX]|$DD_LAST)"
  # perl, read as cmdline.rs reads it: -e/-E are inline code; -I takes a
  # value, attached or as the next word (`perl -I lib` still runs stdin);
  # -M -m -x -F -i -l -0 -d take theirs attached; any other letter is a
  # plain flag, and so is a long one.
  PB1="[^-eEIMmxFil0d$TX]"
  PB="[^eEIMmxFil0d$TX]"
  PL_OK="($BQ(-($PB1$PB*)?([MmxFil0d]$TC*|I$TC+)|-$PB1$PB*|-($PB1$PB*)?I[[:space:]]+$NS|--$TC+)|$R_OK)"
  PL_LAST="($BQ-($PB1$PB*)?I|$DD_LAST)"
  # PowerShell runs stdin for `-`, `-Command -` / `-File -` (or -File
  # /dev/stdin); any other flag (`-NoProfile`, `-Sta`) keeps it reading.
  # PW_FLAG is a flag name other than PW_ARG (or `-`), in any case.
  PW_FLAG="([^cCeEfF$TX-]$TC*|-$TC+|[cC]([^oO$TX]$TC*|[oO]([^mM$TX]$TC*|[mM]([^mM$TX]$TC*|[mM]([^aA$TX]$TC*|[aA]([^nN$TX]$TC*|[nN]([^dD$TX]$TC*|[dD]$TC+)?)?)?)?)?)|[eE]([^cCnN$TX]$TC*|[cC]$TC+|[nN]([^cC$TX]$TC*|[cC]([^oO$TX]$TC*|[oO]([^dD$TX]$TC*|[dD]([^eE$TX]$TC*|[eE]([^dD$TX]$TC*|[dD]([^cC$TX]$TC*|[cC]([^oO$TX]$TC*|[oO]([^mM$TX]$TC*|[mM]([^mM$TX]$TC*|[mM]([^aA$TX]$TC*|[aA]([^nN$TX]$TC*|[nN]([^dD$TX]$TC*|[dD]$TC+)?)?)?)?)?)?)?)?)?)?)?)?)|[fF]([^iI$TX]$TC*|[iI]([^lL$TX]$TC*|[lL]([^eE$TX]$TC*|[eE]$TC+)?)?))"
  # Flags that take a value (cmdline.rs PWSH_VALUED): the next word is
  # the value, not the script (`pwsh -ExecutionPolicy Bypass` still reads
  # stdin); last with none, they leave stdin as the script.
  PW_VAL='([eE][xX]|[eE][pP]|[eE][xX][eE][cC][uU][tT][iI][oO][nN][pP][oO][lL][iI][cC][yY]|[wW]|[wW][iI][nN][dD][oO][wW][sS][tT][yY][lL][eE]|[wW][dD]|[wW][oO][rR][kK][iI][nN][gG][dD][iI][rR][eE][cC][tT][oO][rR][yY]|[oO]|[oO][fF]|[oO][uU][tT][pP][uU][tT][fF][oO][rR][mM][aA][tT]|[iI][fF]|[iI][nN][pP][uU][tT][fF][oO][rR][mM][aA][tT]|[cC][oO][nN][fF][iI][gG]|[cC][oO][nN][fF][iI][gG][uU][rR][aA][tT][iI][oO][nN][nN][aA][mM][eE]|[vV]|[vV][eE][rR][sS][iI][oO][nN]|[sS][eE][tT][tT][iI][nN][gG][sS][fF][iI][lL][eE]|[pP][sS][cC][oO][nN][sS][oO][lL][eE][fF][iI][lL][eE]|[cC][uU][sS][tT][oO][mM][pP][iI][pP][eE][nN][aA][mM][eE]|[cC][oO][nN][fF][iI][gG][uU][rR][aA][tT][iI][oO][nN][fF][iI][lL][eE])'
  PW_OK="($BQ-${PW_VAL}[[:space:]]+$NS|$BQ-$PW_FLAG|$R_OK)"
  PW_RUN="($BQ(-|-${PW_ARG}[[:space:]]+$BQ-)|$BQ-[fF]([iI][lL][eE])?[[:space:]]+($STDIN_P)|$DD_RUN)"
  PW_LAST="($BQ-$PW_FLAG|$BQ-$PW_VAL|$DD_LAST)"

  tail_re() {
    # $1 = a word that keeps the interpreter reading stdin (an option with
    # its value), $2 = a word that settles it (no later word may redirect
    # stdin), $3 = a last word that may lack its value (as may a
    # redirection). Right after the interpreter: a stop character,
    # whitespace and the words, or a redirection written against it.
    tr_seq="(($1)[[:space:]]+)*(($2)$REST|($1|$3)$END_T|$R_ALONE$END_OP|$END_S)"
    R="([\"')\`;|$SOH]|&([^>]|\$)|\$|[[:space:]]+$tr_seq|$G_OK([[:space:]]+$tr_seq|$END_T)|$G_ALONE$END_OP)"
  }
  tail_re "$SH_OK" "$SH_RUN" "$SH_LAST"; SH_TAIL=$R
  tail_re "$OT_OK" "$OT_RUN" "$OT_LAST"; OT_TAIL=$R
  tail_re "$PL_OK" "$OT_RUN" "$PL_LAST"; PL_TAIL=$R
  tail_re "$PW_OK" "$PW_RUN" "$PW_LAST"; PW_TAIL=$R

  # `| tee file |` stages in between still hand the interpreter the
  # download; `|&` pipes stderr as well. A group or compound command the
  # download is in, with any commands after it (`{ curl …; } | sh`,
  # `(curl …; true) | sh`, `for …; do curl …; done | sh`), pipes its
  # output.
  GROUP="(($WS*(;|&&|[|][|]?|$SOH)[^;&|$SOH]*)*$WS*;?$WS*([})]|(^|[[:space:]$SOH;&|])([fF][iI]|[dD][oO][nN][eE]|[eE][sS][aA][cC]))$ARGS)*"
  PIPE_HEAD="(^|[[:space:]$SOH;&|(\"'\`\$])($NWS*/)?$DL$ARGS$GROUP([|]&?$WS*($WRAP)*($NWS*/)?$TEE$ARGS)*[|]&?$WS*($WRAP)*($NWS*/)?"
  PIPE_RE="$PIPE_HEAD($SH_I$SH_TAIL|$PL_I$PL_TAIL|$OT_I$OT_TAIL|$PW_I$PW_TAIL|$IEX_I([[:space:]$SOH\"')\`;&|<>]|\$))"

  INTERP='((sh|bash|zsh|dash|ksh|fish|ash|mksh|pdksh|oksh|yash|posh|rbash|csh|tcsh)[0-9.]*|python[0-9.]*|node|deno|bun|perl|ruby|php|iex|invoke-expression|pwsh|powershell|[$]shell|[$][{]shell[}]|[$]bash|[$][{]bash[}])'
  DLW='(curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)'
  # `bash <(curl …)`, `bash < <(curl …)`, `bash <<< "$(curl …)"`,
  # `sh -c "$(curl …)"`, `source <(curl …)`, `eval "$(curl …)"`.
  SUBST_RE="(^|[[:space:]$SOH;&|(\"'\`])(($NWS*/)?$INTERP$WS+(-$NWS+$WS+)*(<<<$WS*|<$WS*)?|source$WS+|[.]$WS+|eval$WS+)[\"']?(<[(]|[\$][(]|\`)$WS*($NWS*/)?$DLW$WS"
  PS_RE="(iex|invoke-expression)$WS*[(]?$WS*([(]|[\$][(])?$WS*(iwr|irm|invoke-webrequest|invoke-restmethod|[(]?new-object$WS+(system[.])?net[.]webclient)"

  pipe_hit() {
    has_in "$1" "$PIPE_RE" || printf '%s\n' "$1" | grep -Eiq "($SUBST_RE)|($PS_RE)"
  }
  if pipe_hit "$FLAT" || { [ "$DFLAT" != "$FLAT" ] && pipe_hit "$DFLAT"; }; then
    first_url "$CMD"
    if [ -n "$R" ]; then
      deny "Piping a download into an interpreter executes unscanned code. Use: sigil scan $R — or download it (curl -fsSLo script.sh $R), run sigil scan script.sh, then run the file you scanned. $BYPASS_HINT"
    fi
    deny "Piping a download into an interpreter executes unscanned code. Download the script, run sigil scan on it, then execute the file you scanned. $BYPASS_HINT"
  fi
fi

# ── DENY: remote execution and agent-tooling writes, stage by stage ────────
# Like hook.rs classify_in: the command is split into list segments (; && ||
# & newlines, $( <( >( and backticks) and pipeline stages (| and |&). Each
# stage is read as the shell runs it (cmdline::command_words): grouping
# (`(`, `{`, `if`, `do`), redirections, VAR=value words and wrapper commands
# (sudo -u root, env -i, command, exec, nohup, time, timeout, xargs, doas,
# busybox, ...) are removed before its command word is judged. A `sigil`
# stage is allowed and, when it is the bare `sigil` on PATH running a real
# `sigil scan|clone|pip|npm <target>` (no --help, --fail-on critical, ...)
# as the last stage of its pipeline, outside quotes, comments and
# substitutions, vets that target for the stages chained after it with &&.
# Checked here, per stage:
#   - deno run|x|install|serve of an npm:/jsr:/http(s) module
#   - curl/wget saving into agent tooling, also through `| tee` or a
#     redirect after the download (never gated)
#   - pipx install / uv tool install <pkg> (gated by sigil pip <pkg>)
#   - running a file downloaded earlier in the same command (or a copy of
#     it): an interpreter's script (read per interpreter: `bash -e i.sh`,
#     `python3 -X dev i.py`), `. i.sh`, `./i.sh`, `bash < i.sh`,
#     `cat i.sh | sh`, `eval "$(cat i.sh)"` (gated by sigil scan <file>
#     after the last download)
#   - an interpreter that runs a download coming down the pipe through
#     other stages (`curl … | tr -d '\r' | bash`; never gated)
#   - npm exec|x, bun x and uv tool run of a registry package in command
#     position (gated by sigil npm|pip <pkg>)
#   - the string of `bash -c '…'`, `su -c '…'` and `eval '…'`, as a command
#     line of its own
# hook.rs settles agent-CLI acquisition and package runners first, so those
# stages skip the deno, tooling and installer checks; npx, bunx, uvx, pipx
# run and dlx are left to the rules further down. Each check reads the stage
# as written and dequoted (`"npm" exec`, `pip''x install`).

# Lexer (POSIX awk). Records, one per line, fields separated by US:
#   S op opens exec text words…
#                           a list segment: op A (after &&), O (after ; ||
#                           & or a newline), U (after $( <( ), u (after
#                           >( ), B / b (after an opening / closing
#                           backtick); the number of `(` it opens; 1 when it
#                           opens a substitution whose output runs as code
#                           (`eval "$(…)"`); its text; its command words
#                           (for `cd`, `pushd`, `popd`)
#   O f / I f / J           per stage: a stdout redirection target; stdin
#                           from file f; stdin from a here-document
#   X f / R                 the file the stage runs; it runs its stdin
#                           (an interpreter, a shell `sudo -s` or `su`
#                           starts, or inline code xargs fills in)
#   V                       it sources a file (`.`, `source`)
#   K                       it passes its stdin on (`cat`, `tr -d '\r'`)
#   H                       its code runs what it reads on stdin
#                           (`eval "$l"`, `python3 -c "exec(sys.stdin…)"`)
#   L                       its whole command is a variable (`$l`)
#   G opens closes          the groups and compound commands it opens and
#                           closes (`{`, `if`, `(`; `}`, `fi`, `)`)
#   D f / F                 a file a curl/wget stage saves to; it writes
#                           the download to stdout
#   C f / Z f               a file argument (read); a file `tee` writes
#   N f / Y f               the destination / a source of cp, mv, ln,
#                           install, rsync
#   M f                     a file it edits in place (`sed -i`, `perl -pi`)
#   W words…                the stage's command words
#   T k flags text dqtext toks…
#                           the stage (index k in its pipeline), its flags
#                           (q: it starts inside quotes, a comment or a
#                           here-document; l: the last stage of its
#                           pipeline; t: the words after the ) of the
#                           substitution the segment starts), its text as
#                           written and dequoted, and its tokens
#   P k inherits / Q        before / after a `bash -c` string's records:
#                           the index of the stage that hands it over, and
#                           1 when that stage's stdin is not redirected
#   E closes                the end of a segment and the `)` it closes
# A US in the command becomes STX first: to hook.rs it is an ordinary word
# character, and left in place it would shift every field after it.
# shellcheck disable=SC2016 # an awk program, not shell
LEX_AWK='
BEGIN {
  US = sprintf("%c", 31); STX = sprintf("%c", 2); SQ = sprintf("%c", 39); DQ = "\""
  VT = sprintf("%c", 11); WSC = "[ \t\n\r\f" VT "]"
  n = split("( { ! if then else elif do while until", kw, " ")
  for (i = 1; i <= n; i++) KW[kw[i]] = 1
  wr("sudo", "ugCDhprtTUR", "--user --group --close-from --chdir --host --prompt --role --type --command-timeout --other-user --chroot", "lveVK", 0, 1, "", "si")
  wr("doas", "u", "", "CL", 0, 0, "", "s")
  wr("env", "uCS", "--unset --chdir --split-string", "", 0, 1)
  wr("command", "", "", "vV", 0, 0)
  wr("builtin", "", "", "", 0, 0); wr("nohup", "", "", "", 0, 0)
  wr("busybox", "", "", "", 0, 0); wr("setsid", "", "", "", 0, 0)
  wr("exec", "a", "", "", 0, 0)
  wr("time", "fo", "--format --output", "", 0, 0)
  wr("nice", "n", "--adjustment", "", 0, 0)
  wr("timeout", "sk", "--signal --kill-after", "", 1, 0)
  wr("stdbuf", "ioe", "--input --output --error", "", 0, 0)
  wr("ionice", "cnpPu", "--class --classdata --pid --pgid --uid", "", 0, 0)
  wr("xargs", "adEILnPs", "--arg-file --delimiter --eof --max-lines --max-args --max-procs --max-chars --process-slot-var", "", 0, 0)
  wr("setpriv", "", "", "", 0, 0)
  wr("flock", "wE", "--timeout --conflict-exit-code", "hV", 1, 0, "c")
  wr("chroot", "", "--userspec --groups", "", 1, 0)
  wr("taskset", "", "", "p", 1, 0)
  wr("chrt", "T", "", "pm", 1, 0)
  wr("unshare", "SGRw", "", "", 0, 0)
  wr("strace", "eopsuEaIbOPSXnlwAL", "", "hV", 0, 0)
  wr("ltrace", "eopsuEaIbOPSXnlwAL", "", "hV", 0, 0)
  wr("watch", "n", "--interval", "hv", 0, 0)
  wr("script", "EIOTBmo", "", "hV", 0, 0, "c")
  wr("sg", "", "", "", 1, 0, "c")
  wr("runuser", "ugGsw", "--user --group --supp-group --shell --whitelist-environment", "hV", 1, 0, "c")
  CURLV = "dHuXAebcFTxwmrCEKYyzUQtPD"; WGETV = "oaeiBtTwQUDRAIXl"
  PWV = " -ex -ep -executionpolicy -w -windowstyle -wd -workingdirectory -o -of -outputformat -if -inputformat -config -configurationname -v -version -settingsfile -psconsolefile -custompipename -configurationfile "
  URLRE = "https?://[^ \t\n\r\f" VT SQ DQ "|;&)<>`]+"
  UNQ_S = SQ "[^" SQ DQ " \t\n\r\f" VT "]*" SQ
  UNQ_D = DQ "[^" SQ DQ " \t\n\r\f" VT "]*" DQ
}
# A wrapper command (cmdline::wrapper): short options that take a value,
# long options that take the next word, short options after which nothing
# runs, operands before the command, whether VAR=value may follow, short
# options whose value is a command line for a shell (flock -c), and short
# options that start a shell when no command follows (sudo -s, doas -s).
function wr(h, v, l, nc, o, a, so, sh) { WV[h] = v; WL[h] = " " l " "; WN[h] = nc; WO[h] = o; WA[h] = a; WSO[h] = so; WSH[h] = sh }
function trim(s) { sub(/^[ \t\r\f\v]+/, "", s); sub(/[ \t\r\f\v]+$/, "", s); return s }
function fld(s) { gsub(/\n/, STX, s); return s }
function bname(t) { sub(/.*[\/\\]/, "", t); return t }
function isassign(t) { return t ~ /^[A-Za-z_][A-Za-z0-9_]*\+?=/ }
# cmdline::tokenize, into A[1..n].
function toka(s, A,    n, cur, inw, i, L, c, d, e) {
  n = 0; cur = ""; inw = 0; L = length(s)
  for (i = 1; i <= L; i++) {
    c = substr(s, i, 1)
    if (c == SQ) {
      inw = 1
      for (i++; i <= L; i++) { d = substr(s, i, 1); if (d == SQ) break; cur = cur d }
    } else if (c == DQ) {
      inw = 1
      for (i++; i <= L; i++) {
        d = substr(s, i, 1)
        if (d == DQ) break
        e = substr(s, i + 1, 1)
        if (d == "\\" && (e == DQ || e == "\\" || e == "$" || e == "`")) { cur = cur e; i++ }
        else cur = cur d
      }
    } else if (c == "\\") {
      inw = 1
      if (i < L) { i++; cur = cur substr(s, i, 1) }
    } else if (c ~ WSC) {
      if (inw) { A[++n] = cur; cur = ""; inw = 0 }
    } else { inw = 1; cur = cur c }
  }
  if (inw) A[++n] = cur
  return n
}
function tok(s,    A, n, i, out) {
  n = toka(s, A); out = ""
  for (i = 1; i <= n; i++) out = out US fld(A[i])
  return out
}
# cmdline::dequote.
function unq(s, re,    out) {
  out = ""
  while (match(s, re)) { out = out substr(s, 1, RSTART - 1) substr(s, RSTART + 1, RLENGTH - 2); s = substr(s, RSTART + RLENGTH) }
  return out s
}
function dq(s,    out) {
  if (!index(s, SQ) && !index(s, DQ) && !index(s, "\\")) return s
  s = unq(s, UNQ_S); s = unq(s, UNQ_D); out = ""
  while (match(s, /\\[A-Za-z0-9_.\/-]/)) { out = out substr(s, 1, RSTART - 1) substr(s, RSTART + 1, 1); s = substr(s, RSTART + 2) }
  return out s
}
# cmdline::redirection: sets RD_STDIN, RD_INLINE, RD_STDOUT, RD_NEXT (the
# file is the next word), RD_TARGET / RD_HAS (the file in the word) and
# RD_DUP / RD_HASDUP (the descriptor it copies: 1 in 2>&1, 0 in <&0).
function isstdinpath(p) { return p == "/dev/stdin" || p == "/dev/fd/0" || p == "/proc/self/fd/0" || p == "/proc/$$/fd/0" }
function isstdoutpath(p) { return p == "-" || p == "/dev/stdout" || p == "/dev/fd/1" || p == "/proc/self/fd/1" || p == "/proc/$$/fd/1" }
function rdop(r,    a) {
  a = substr(r, 1, 3); if (a == "<<<" || a == "<<-") return a
  a = substr(r, 1, 2); if (a == "<<" || a == "<>" || a == "<&" || a == ">&" || a == ">>" || a == ">|") return a
  a = substr(r, 1, 1); if (a == "<" || a == ">") return a
  return ""
}
function isredir(t,    fd, r, op, rest, input, onstdin) {
  fd = ""; r = t
  if (match(r, /^[0-9]+/)) { fd = substr(r, 1, RLENGTH); r = substr(r, RLENGTH + 1) }
  op = rdop(r)
  if (op == "" && fd == "" && substr(t, 1, 1) == "&") { fd = "&"; r = substr(t, 2); op = rdop(r) }
  if (op == "") return 0
  rest = substr(r, length(op) + 1)
  if (rest ~ /[<>]/) return 0
  input = (substr(op, 1, 1) == "<")
  onstdin = input && (fd == "" || fd == "0")
  RD_STDIN = onstdin; RD_INLINE = onstdin && (op == "<<" || op == "<<-" || op == "<<<")
  RD_STDOUT = !input && (fd == "" || fd == "1" || fd == "&")
  RD_NEXT = 0; RD_HAS = 0; RD_TARGET = ""; RD_HASDUP = 0; RD_DUP = ""
  if (op == ">&" || op == "<&") {
    if (rest == "" && op == ">&") RD_NEXT = 1
    else if (rest ~ /^[0-9-]*$/) { RD_STDOUT = 0; RD_HASDUP = 1; RD_DUP = rest }
    else { RD_TARGET = rest; RD_HAS = 1 }
    return 1
  }
  if (rest == "") RD_NEXT = 1; else { RD_TARGET = rest; RD_HAS = 1 }
  return 1
}
# cmdline::command_words: W[1..NW], CW_IN ("" inherited, F file, I text),
# CW_INF, CW_OUT[1..NO].
function cwords(s,    A, B, C, S, n, i, j, k, m, q, x, t, tg, hastg, h, ops, step, L, c, att, val, nn, pk, sh) {
  n = toka(s, A)
  i = 1
  while (i <= n) {
    t = A[i]
    if (t == "" || (t in KW)) { i++; continue }
    if (substr(t, 1, 1) == "(") { sub(/^\(+/, "", t); A[i] = t; continue }
    break
  }
  m = 0; for (j = i; j <= n; j++) B[++m] = A[j]
  while (m >= 1) {
    t = B[m]
    if (t == ")" || t == "}") { m--; continue }
    if (t ~ /\)$/ && index(t, "(") == 0) { sub(/\)+$/, "", t); B[m] = t; continue }
    break
  }
  # A redirection that reads the pipe itself (< /dev/stdin, <&0) leaves
  # stdin as it was; one that copies it elsewhere (3<&0) keeps it reachable
  # (pk), and then no stdin redirection counts (cmdline::apply_redirect).
  CW_IN = ""; CW_INF = ""; NO = 0; n = 0; pk = 0
  for (i = 1; i <= m; i++) {
    t = B[i]
    if (!isredir(t)) { A[++n] = t; continue }
    if (RD_NEXT) { if (i < m) { i++; tg = B[i]; hastg = 1 } else hastg = 0 } else { tg = RD_TARGET; hastg = RD_HAS }
    if (RD_HASDUP && RD_DUP == "0" && !RD_STDIN) pk = 1
    if (RD_INLINE) CW_IN = "I"
    else if (RD_STDIN) {
      if (RD_HASDUP) { if (RD_DUP != "0") CW_IN = "I" }
      else if (hastg && isstdinpath(tg)) { }
      else if (hastg) { CW_IN = "F"; CW_INF = tg }
      else CW_IN = "I"
    }
    else if (RD_STDOUT && hastg) CW_OUT[++NO] = tg
  }
  m = n; for (i = 1; i <= m; i++) B[i] = A[i]
  i = 1
  # CW_XARGS: behind xargs, which reads the words it appends from stdin (S)
  # or the file CW_XARGSF (F: xargs -a f). sh: a sudo -s / doas -s seen.
  CW_XARGS = ""; CW_XARGSF = ""; sh = 0
  while (1) {
    while (i <= m && isassign(B[i])) i++
    if (i > m) break
    h = tolower(bname(B[i]))
    if (!(h in WV)) break
    j = i + 1; ops = WO[h]
    if (h == "xargs") CW_XARGS = "S"
    if (h == "runuser") {
      # With -u the command follows the options; without, the user is an
      # operand and no command means a shell.
      q = 0
      for (x = j; x <= m; x++) if (B[x] == "-u" || B[x] == "--user" || substr(B[x], 1, 7) == "--user=") q = 1
      if (q) ops = 0; else sh = 1
    }
    while (j <= m) {
      t = B[j]
      if (t == "--") { j++; break }
      if (h == "xargs") {
        val = ""
        if (t == "-a" || t == "--arg-file") { if (j + 1 <= m) val = B[j + 1] }
        else if (substr(t, 1, 11) == "--arg-file=") val = substr(t, 12)
        else if (substr(t, 1, 2) == "-a") val = substr(t, 3)
        if (val != "") { CW_XARGS = "F"; CW_XARGSF = val }
      }
      if (h == "sudo" && (t == "--shell" || t == "--login")) sh = 1
      if (WSO[h] != "" && (t == "--command" || substr(t, 1, 10) == "--command=")) {
        # flock l --command "bash i.sh": a shell runs the string.
        if (substr(t, 1, 10) == "--command=") val = substr(t, 11)
        else val = (j + 1 <= m) ? B[j + 1] : ""
        cw_string(val, pk); return
      }
      if (h == "env" && (t == "--split-string" || substr(t, 1, 15) == "--split-string=")) {
        # env --split-string=VALUE i.sh, as -S.
        if (substr(t, 1, 15) == "--split-string=") { val = substr(t, 16); step = 1 }
        else { val = (j + 1 <= m) ? B[j + 1] : ""; step = 2 }
        nn = toka(val, S); q = 0
        for (x = 1; x < j; x++) C[++q] = B[x]
        for (x = 1; x <= nn; x++) C[++q] = S[x]
        for (x = j + step; x <= m; x++) C[++q] = B[x]
        m = q; for (x = 1; x <= m; x++) B[x] = C[x]
        continue
      }
      if (substr(t, 1, 2) == "--") {
        if (index(t, "=") == 0 && index(WL[h], " " t " ")) j += 2; else j++
        continue
      }
      if (length(t) > 1 && substr(t, 1, 1) == "-") {
        step = 1; L = length(t)
        for (k = 2; k <= L; k++) {
          c = substr(t, k, 1)
          if (index(WN[h], c)) { NW = 0; return }
          if (WSH[h] != "" && index(WSH[h], c)) sh = 1
          if (WSO[h] != "" && index(WSO[h], c)) {
            att = substr(t, k + 1)
            if (att == "") val = (j + 1 <= m) ? B[j + 1] : ""; else val = att
            cw_string(val, pk); return
          }
          if (!index(WV[h], c)) continue
          att = substr(t, k + 1)
          if (att == "") { step = 2; val = (j + 1 <= m) ? B[j + 1] : "" } else val = att
          if (h == "env" && c == "S") {
            nn = toka(val, S); q = 0
            for (x = 1; x < j; x++) C[++q] = B[x]
            for (x = 1; x <= nn; x++) C[++q] = S[x]
            for (x = j + step; x <= m; x++) C[++q] = B[x]
            m = q; for (x = 1; x <= m; x++) B[x] = C[x]
            step = 0
          }
          break
        }
        j += step
        continue
      }
      if (t == "-" || (WA[h] && isassign(t))) { j++; continue }
      if (ops > 0) { ops--; j++; continue }
      break
    }
    i = j
  }
  NW = 0; for (x = i; x <= m; x++) W[++NW] = B[x]
  # sudo -s, sudo -i, doas -s with nothing to run, and su with no -c: a
  # shell that reads its commands from stdin.
  q = 0
  if (NW >= 1 && bname(W[1]) == "su") {
    q = 1
    for (x = 2; x <= NW; x++) if (W[x] == "-c" || W[x] == "--command" || substr(W[x], 1, 10) == "--command=") q = 0
  }
  if ((NW == 0 && sh) || q) { NW = 1; W[1] = "sh" }
  if (pk) CW_IN = ""
}
# A wrapper that hands v to a shell as a command line (cmdline.rs
# shell_string): the command is read as sh -c v.
function cw_string(v, pk) {
  NW = 3; W[1] = "sh"; W[2] = "-c"; W[3] = v
  if (pk) CW_IN = ""
}
# cmdline::passes_stdin: does the stage (W, CW_IN) copy its stdin to its
# stdout: a filter given no file of its own, or a bare < /dev/stdin?
function passes(    h, x, t, f) {
  if (CW_IN != "") return 0
  if (NW < 1) return 1
  h = bname(W[1]); f = 0
  for (x = 2; x <= NW; x++) {
    t = W[x]; sub(/^\++/, "", t)
    if (substr(W[x], 1, 1) != "-" && !isstdinpath(W[x]) && t !~ /^[0-9]*$/) f++
  }
  if (h == "tr" || h == "tee") return 1
  if (h ~ /^(cat|head|tail|tac|rev|nl|base64|base32|gunzip|gzip|zcat|bzcat|bzip2|xz|xzcat|unxz|zstd|zstdcat|xxd|sort|uniq|fold|expand|iconv)$/) return f == 0
  if (h ~ /^(sed|awk|gawk|mawk|grep|egrep|fgrep|cut)$/) return f <= 1
  if (h == "dd") { for (x = 2; x <= NW; x++) if (substr(W[x], 1, 3) == "if=") return 0; return 1 }
  if (h == "openssl") { for (x = 2; x <= NW; x++) if (W[x] == "-in") return 0; return 1 }
  return 0
}
# hook.rs xargs_code: where xargs gets the code it runs when it hands the
# words it reads to inline code of no code of its own ("" when it does
# not): S (stdin) or F (the file CW_XARGSF).
function xcode(    fromin, c) {
  if (CW_XARGS == "") return ""
  runs(); if (RUNS != "I") return ""
  inner()
  if (HASINNER) { c = trim(INNER); fromin = index(INNER, "{}") || c == "$0" || c == "$1" || c == "$@" || c == "$*" }
  else fromin = (substr(W[NW], 1, 1) == "-")
  return fromin ? CW_XARGS : ""
}
# hook.rs runs_read_code on W: a variable run as code (eval "$l",
# bash -c "$l"), or python/node/perl/ruby/php inline code that evaluates
# what it reads on stdin.
function rrc(    f, code, lc, x) {
  inner()
  if (HASINNER && trim(INNER) ~ /^\$(\{?[A-Za-z_][A-Za-z0-9_]*\}?|[0-9@*])$/) return 1
  if (NW < 1) return 0
  f = family(W[1])
  if (f != "py" && f != "node" && f != "perl" && f != "ruby" && f != "php") return 0
  runs(); if (RUNS != "I") return 0
  code = ""; for (x = 2; x <= NW; x++) code = code " " W[x]
  if (code !~ /(^|[^.A-Za-z0-9_]|[^\/][.])(exec|eval|Function|instance_eval)[ \t\n\r\f\v]*[( \t\n\r\f\v]/) return 0
  lc = tolower(code)
  return lc ~ /stdin|readfilesync\([ \t\n\r\f\v]*0|<>|\$<|argf|php:\/\/input|(^|[^a-z0-9_])input\(/
}
# hook.rs compound_marks: the groups and compound commands t (at position
# at of the command) opens (CM_O: {, if, while, until, for, case, select,
# an unquoted () and closes (CM_C: }, fi, done, esac, an unquoted )).
function cmarks(t, at, d,    A, n, x, c) {
  n = toka(t, A)
  CM_O = (n >= 1 && A[1] ~ /^(\{|if|while|until|for|case|select)$/)
  CM_C = (n >= 1 && A[1] ~ /^(\}|fi|done|esac)$/)
  for (x = 1; x <= length(t); x++) {
    if (Q[d, at + x - 1] != "o") continue
    c = substr(t, x, 1)
    if (c == "(") CM_O++
    else if (c == ")") CM_C++
  }
}
# hook.rs overwrites, in part: the files sed -i, perl -i and ruby -i edit
# in place (an -i before any option whose value is attached).
function inplace(h, att,    x, t, k, c) {
  for (x = 2; x <= NW; x++) {
    t = W[x]
    if (t == "--in-place" || substr(t, 1, 11) == "--in-place=") return 1
    if (substr(t, 1, 1) != "-" || substr(t, 1, 2) == "--") continue
    for (k = 2; k <= length(t); k++) {
      c = substr(t, k, 1)
      if (index(att, c)) break
      if (c == "i") return 1
    }
  }
  return 0
}
# cmdline::interpreter (SHELLS: the shells, a version suffix dropped).
function family(w,    b) {
  w = tolower(w)
  if (w == "$shell" || w == "${shell}" || w == "$bash" || w == "${bash}") return "sh"
  b = bname(w); sub(/\.exe$/, "", b)
  if (b == "." || b == "source") return "src"
  sub(/[0-9.]+$/, "", b)
  if (b ~ /^(sh|bash|zsh|dash|ksh|fish|ash|mksh|pdksh|oksh|yash|posh|rbash|csh|tcsh)$/) return "sh"
  if (b == "python") return "py"
  if (b == "node" || b == "bun") return "node"
  if (b == "deno" || b == "perl" || b == "ruby" || b == "php" ) return b
  if (b == "pwsh" || b == "powershell") return "pwsh"
  return ""
}
# cmdline::interpreter_runs on W: RUNS "" (not an interpreter), F (the file
# RUNSF), S (stdin) or I (inline code). A script that is stdin itself
# (bash /dev/stdin, pwsh -File -) runs the pipe.
function runs() {
  runs0()
  if (RUNS == "F" && (RUNSF == "-" || isstdinpath(RUNSF))) RUNS = "S"
}
function runs0(    kind, a, i, t, L, k, c, step, rest, l, INL, VAL, ATT, LV) {
  RUNS = ""; RUNSF = ""
  if (NW < 1) return
  kind = family(W[1]); if (kind == "") return
  if (kind == "src") { if (NW >= 2) { RUNS = "F"; RUNSF = W[2] } else RUNS = "S"; return }
  a = 2
  if ((kind == "deno" || kind == "node") && NW >= 2) {
    if (W[2] == "run") a = 3
    else if (W[2] == "eval" && kind == "deno") { RUNS = "I"; return }
  }
  INL = ""; VAL = ""; ATT = ""; LV = " "
  if (kind == "sh") { INL = "c"; VAL = "oO"; LV = " --rcfile --init-file " }
  else if (kind == "py") { INL = "cm"; VAL = "WX"; LV = " --check-hash-based-pycs " }
  else if (kind == "node") { INL = "ep"; VAL = "rC"; LV = " --require --import --loader --experimental-loader --conditions --env-file " }
  else if (kind == "deno") { VAL = "cL"; LV = " --config --import-map --lock --cert --location --seed --log-level " }
  else if (kind == "perl") { INL = "eE"; VAL = "I"; ATT = "MmxFil0d" }
  else if (kind == "ruby") { INL = "e"; VAL = "rICE"; ATT = "xFi0" }
  else if (kind == "php") { INL = "rRBE"; VAL = "cdzt" }
  i = a
  while (i <= NW) {
    t = W[i]
    if (t == "-") { RUNS = "S"; return }
    if (t == "--") { if (i + 1 <= NW) { RUNS = "F"; RUNSF = W[i + 1] } else RUNS = "S"; return }
    if (substr(t, 1, 1) != "-" && !(kind == "sh" && substr(t, 1, 1) == "+")) { RUNS = "F"; RUNSF = t; return }
    if (kind == "pwsh") {
      l = tolower(t)
      if (l ~ /^-(c|command|e|ec|encodedcommand)$/ && i + 1 <= NW && W[i + 1] == "-") { RUNS = "S"; return }
      if (l ~ /^-(c|command|e|ec|enc|encodedcommand|cwa|commandwithargs)$/) { RUNS = "I"; return }
      if (l == "-f" || l == "-file") { if (i + 1 <= NW) { RUNS = "F"; RUNSF = W[i + 1] }; return }
      if (index(PWV, " " l " ")) i += 2; else i++
      continue
    }
    if (substr(t, 1, 2) == "--") {
      if (kind == "node" && (t == "--eval" || t == "--print")) { RUNS = "I"; return }
      if (index(t, "=") == 0 && index(LV, " " t " ")) i += 2; else i++
      continue
    }
    L = length(t); step = 1
    for (k = 2; k <= L; k++) {
      c = substr(t, k, 1)
      if (index(INL, c)) { RUNS = "I"; return }
      if (kind == "sh" && c == "s") { RUNS = "S"; return }
      if (kind == "php" && c == "f") {
        rest = substr(t, k + 1)
        if (rest != "") { RUNS = "F"; RUNSF = rest } else if (i + 1 <= NW) { RUNS = "F"; RUNSF = W[i + 1] }
        return
      }
      if (index(VAL, c)) { if (k == L) step = 2; break }
      if (index(ATT, c)) break
    }
    i += step
  }
  RUNS = "S"
}
# hook.rs inner_command: the string of `bash -c`, `su -c`, `eval`.
function inner(    b, i, t, flag, valued) {
  INNER = ""; HASINNER = 0
  if (NW < 1) return
  b = W[1]; sub(/.*\//, "", b)
  if (b == "eval") {
    if (NW > 1) { INNER = W[2]; for (i = 3; i <= NW; i++) INNER = INNER " " W[i]; HASINNER = 1 }
    return
  }
  # trap "bash i.sh" EXIT: the shell runs the string when the signal
  # arrives.
  if (b == "trap") {
    if (NW > 2 && substr(W[2], 1, 1) != "-") { INNER = W[2]; HASINNER = 1 }
    return
  }
  if (b == "su" || b == "runuser") {
    for (i = 2; i <= NW; i++) {
      t = W[i]
      if (t == "-c" || t == "--command") { if (i < NW) { INNER = W[i + 1]; HASINNER = 1 }; return }
      if (substr(t, 1, 10) == "--command=") { INNER = substr(t, 11); HASINNER = 1; return }
    }
    return
  }
  if (family(W[1]) != "sh") return
  runs(); if (RUNS != "I") return
  i = 2
  while (i <= NW) {
    t = W[i]
    flag = (substr(t, 1, 1) == "-" || substr(t, 1, 1) == "+") && length(t) > 1
    if (t == "--") { i++; break }
    if (!flag) break
    valued = (substr(t, 1, 2) != "--" && t ~ /[oO]$/) || t == "--rcfile" || t == "--init-file"
    i += valued ? 2 : 1
  }
  if (i <= NW) { INNER = W[i]; HASINNER = 1 }
}
# The last path component of the first URL (hook.rs url_name).
function urlname(s,    u, p) {
  if (!match(s, URLRE)) return ""
  u = substr(s, RSTART, RLENGTH)
  sub(/[?#].*/, "", u)
  p = index(u, "://"); if (!p) return ""
  u = substr(u, p + 3)
  p = index(u, "://"); if (p) u = substr(u, 1, p - 1)
  p = index(u, "/"); if (!p) return ""
  u = substr(u, p + 1)
  sub(/.*\//, "", u)
  return u
}
function djoin(f, d, hd) { if (hd && index(f, "/") == 0) { sub(/\/+$/, "", d); return d "/" f }; return f }
# hook.rs download: D records for the files a curl/wget stage saves to
# (curl --output-dir applies to -o and -O, wget -P only to a name from the
# URL; -O ignores it) (a
# bare "." for the working directory), F when it writes to stdout.
function dl(text,    h, wget, i, t, lg, eq, name, att, hasatt, valued, val, hasval, no, OUTS, dir, hasdir, remote, L, k, c, takes, rest, body, j, nm, nr) {
  if (NW < 1) return
  h = W[1]; sub(/.*\//, "", h)
  wget = (h == "wget"); if (!wget && h != "curl") return
  no = 0; hasdir = 0; remote = 0; dir = ""
  i = 2
  while (i <= NW) {
    t = W[i]; i++
    if (t == "--") break
    if (substr(t, 1, 2) == "--") {
      lg = substr(t, 3); eq = index(lg, "=")
      if (eq) { name = substr(lg, 1, eq - 1); att = substr(lg, eq + 1); hasatt = 1 } else { name = lg; hasatt = 0 }
      if (wget) valued = (name ~ /^(output-document|directory-prefix|output-file|append-output|input-file)$/)
      else valued = (name == "output" || name == "output-dir")
      if (!valued) { if (!wget && (name == "remote-name" || name == "remote-name-all")) remote = 1; continue }
      if (hasatt) { val = att; hasval = 1 } else { i++; if (i - 1 <= NW) { val = W[i - 1]; hasval = 1 } else hasval = 0 }
      if (name == "output" || name == "output-document") { if (hasval) OUTS[++no] = val }
      else if (name == "output-dir" || name == "directory-prefix") { dir = val; hasdir = hasval }
      continue
    }
    if (length(t) < 2 || substr(t, 1, 1) != "-") continue
    if (wget && substr(t, 2, 1) == "n") continue
    L = length(t)
    for (k = 2; k <= L; k++) {
      c = substr(t, k, 1)
      if (!wget && c == "O") { remote = 1; continue }
      takes = wget ? (c == "O" || c == "P" || index(WGETV, c) > 0) : (c == "o" || index(CURLV, c) > 0)
      if (!takes) continue
      rest = substr(t, k + 1)
      if (rest == "") { i++; if (i - 1 <= NW) { val = W[i - 1]; hasval = 1 } else hasval = 0 } else { val = rest; hasval = 1 }
      if ((c == "o" && !wget) || (c == "O" && wget)) { if (hasval) OUTS[++no] = val }
      else if (c == "P" && wget) { dir = val; hasdir = hasval }
      break
    }
  }
  body = 0
  for (j = 1; j <= no; j++) {
    t = OUTS[j]
    if (isstdoutpath(t)) body = 1
    else if (substr(t, 1, 5) != "/dev/") print "D" US fld(djoin(t, dir, hasdir && !wget))
  }
  if (remote || (wget && no == 0)) {
    nm = urlname(text)
    if (nm != "") print "D" US fld(djoin(nm, dir, hasdir))
    else if (hasdir) print "D" US fld(dir)
    else print "D" US "."
  } else if (!wget && no == 0) body = 1
  nr = 0
  for (j = 1; j <= NO; j++) if (!isstdoutpath(CW_OUT[j])) { nr++; if (body) print "D" US fld(CW_OUT[j]) }
  if (body && nr == 0) print "F"
}
# hook.rs copies: for cp/mv/ln/install/rsync, N (the destination) and a Y
# record per source file.
function copies(h,    valued, x, t, na, AR, tgt, hastgt, dest) {
  if (h != "cp" && h != "mv" && h != "ln" && h != "install" && h != "rsync") return
  if (h == "rsync") valued = " -e --rsh --exclude --include --filter -f "
  else if (h == "install") valued = " -m --mode -o --owner -g --group "
  else valued = " -S --suffix "
  na = 0; hastgt = 0
  for (x = 2; x <= NW; x++) {
    t = W[x]
    if (t == "-t" || t == "--target-directory") { if (x < NW) { tgt = W[x + 1]; hastgt = 1 } else hastgt = 0; x++ }
    else if (substr(t, 1, 19) == "--target-directory=") { tgt = substr(t, 20); hastgt = 1 }
    else if (index(valued, " " t " ")) x++
    else if (substr(t, 1, 1) != "-") AR[++na] = t
  }
  if (hastgt) dest = tgt
  else if (na > 0) dest = AR[na--]
  else return
  print "N" US fld(dest)
  for (x = 1; x <= na; x++) print "Y" US fld(AR[x])
}
# hook.rs uncommented: s (starting at position p of the command) without
# the characters of a # comment.
function uncom(s, p, d,    x, L, out) {
  L = length(s); out = ""
  for (x = 1; x <= L; x++) if (Q[d, p + x - 1] != "c") out = out substr(s, x, 1)
  return out
}
# A stage: its records, then T with its flags (q: it starts inside quotes
# or a comment; l: the last stage of its pipeline). What it runs is read
# from tb, the stage without its # comment; the T record keeps it whole.
function stage(t, tb, k, fl,    x, h, xc) {
  cwords(tb)
  inner()
  for (x = 1; x <= NO; x++) print "O" US fld(CW_OUT[x])
  if (CW_IN == "F") print "I" US fld(CW_INF); else if (CW_IN == "I") print "J"
  runs()
  if (RUNS == "F") print "X" US fld(RUNSF)
  else if (RUNS == "S") { if (CW_IN == "F") print "X" US fld(CW_INF); print "R" }
  else if (RUNS == "" && NW >= 1 && index(W[1], "/")) print "X" US fld(W[1])
  if (NW >= 1 && family(W[1]) == "src") print "V"
  # xargs -0 bash -c, xargs -I{} sh -c "{}": the words xargs reads are the
  # code (from stdin: it runs its stdin; from xargs -a f: it runs f).
  xc = xcode()
  if (xc == "S" && CW_IN == "") print "R"
  else if (xc == "F") print "X" US fld(CW_XARGSF)
  if (passes()) print "K"
  # Code that runs what the stage reads on stdin: eval "$l", bash -c "$l",
  # python3 -c "exec(sys.stdin.read())" (hook.rs runs_read_code), also as
  # read whole when a separator in its quotes cut the stage short.
  if (STAGE_RRC || rrc()) print "H"
  if (NW == 1 && trim(W[1]) ~ /^\$(\{?[A-Za-z_][A-Za-z0-9_]*\}?|[0-9@*])$/) print "L"
  dl(t)
  h = W[1]; sub(/.*\//, "", h)
  # Every file argument is read (cat f, head f, base64 -d f); tee also
  # writes its files.
  for (x = 2; x <= NW; x++) if (substr(W[x], 1, 1) != "-") print "C" US fld(W[x])
  if (NW >= 1 && h == "tee")
    for (x = 2; x <= NW; x++) if (substr(W[x], 1, 1) != "-") print "Z" US fld(W[x])
  # dd if=f of=g reads f and writes g, as < f and > g would.
  if (NW >= 1 && h == "dd")
    for (x = 2; x <= NW; x++) {
      if (substr(W[x], 1, 3) == "if=") print "C" US fld(substr(W[x], 4))
      else if (substr(W[x], 1, 3) == "of=") print "O" US fld(substr(W[x], 4))
    }
  if (NW >= 1) copies(h)
  # Files edited in place: sed -i, perl -pi, ruby -i.
  if (NW >= 1 && (((h == "sed" || h == "gsed") && inplace(h, "ef")) || (h == "perl" && inplace(h, "MmxFl0dIeEC")) || (h == "ruby" && inplace(h, "rIxFeE0C"))))
    for (x = 2; x <= NW; x++) if (substr(W[x], 1, 1) != "-") print "M" US fld(W[x])
  printf "W"; for (x = 1; x <= NW; x++) printf "%s%s", US, fld(W[x]); printf "\n"
  printf "T%s%d%s%s%s%s%s%s%s\n", US, k, US, fl, US, t, US, dq(t), tok(t)
}
# hook.rs heredoc_at: the delimiter of a here-document whose << starts at
# i (HD_TABS: <<-), or "" (a here-string, a shift, no word).
function hdat(cmd, i,    j, c, hw) {
  HD_TABS = 0
  if (substr(cmd, i, 2) != "<<" || substr(cmd, i + 2, 1) == "<" || (i > 1 && substr(cmd, i - 1, 1) == "<")) return ""
  j = i + 2
  if (substr(cmd, j, 1) == "-") { HD_TABS = 1; j++ }
  while (substr(cmd, j, 1) == " " || substr(cmd, j, 1) == "\t") j++
  hw = ""
  for (; j <= length(cmd); j++) {
    c = substr(cmd, j, 1)
    if (c ~ WSC || index(";&|<>()", c)) break
    if (c != SQ && c != DQ && c != "\\") hw = hw c
  }
  if (hw ~ /^[0-9]/) return ""
  return hw
}
# hook.rs quote_map, into Q[d, 1..n]: o (outside quotes), s (single quotes
# or ANSI-C quotes), d (double quotes), c (a # comment) or h (the body of a
# here-document). An opening quote is outside, a closing one inside. A
# substitution opened inside double quotes is outside quotes until its ) or
# backtick (SK: a backtick one; SP: the ( nesting of the one below).
function qmap(cmd, d,    n, i, c, nx, st, ansi, ns, SK, SP, par, np, PD, PT, k, j, e, ln, hw, done, x, ar, esc, brace) {
  n = length(cmd); st = "o"; ansi = 0; ns = 0; par = 0; np = 0; ar = 0; esc = 0; brace = 0
  for (i = 1; i <= n; i++) {
    c = substr(cmd, i, 1); nx = substr(cmd, i + 1, 1)
    Q[d, i] = st
    if (c == "\\" && (st == "o" || st == "d" || (st == "s" && ansi))) { if (i < n) Q[d, i + 1] = st; esc = i + 1; i++; continue }
    if (st == "o") {
      if (c == SQ) { ansi = (i > 1 && substr(cmd, i - 1, 1) == "$"); st = "s" }
      else if (c == DQ) st = "d"
      else if (c == "#" && brace == 0 && (i == 1 || (index(" \t\n;&|", substr(cmd, i - 1, 1)) && esc != i - 1))) { st = "c"; Q[d, i] = "c" }
      else if (c == "{" && i > 1 && substr(cmd, i - 1, 1) == "$" && esc != i - 1) brace++
      else if (c == "}" && brace > 0) brace--
      else if (c == "(" && nx == "(") { ar++; Q[d, i + 1] = st; i++; continue }
      else if (c == ")" && nx == ")" && ar > 0) { ar--; Q[d, i + 1] = st; i++; continue }
      else if (c == "(" && ns > 0) par++
      else if (c == ")" && ns > 0 && !SK[ns]) { if (par > 0) par--; else { par = SP[ns]; ns--; st = "d" } }
      else if (c == "`" && ns > 0 && SK[ns]) { par = SP[ns]; ns--; st = "d" }
    } else if (st == "s") { if (c == SQ) st = "o" }
    else if (st == "d") {
      if (c == DQ) st = "o"
      else if (c == "$" && nx == "(") { Q[d, i + 1] = "d"; SK[++ns] = 0; SP[ns] = par; par = 0; st = "o"; i++; continue }
      else if (c == "`") { SK[++ns] = 1; SP[ns] = par; par = 0; st = "o" }
    }
    else if (c == "\n") { st = "o"; Q[d, i] = "o" }
    if (st == "o" && c == "<" && ar == 0) { hw = hdat(cmd, i); if (hw != "") { PD[++np] = hw; PT[np] = HD_TABS } }
    # After the line that opened them, the here-document bodies, each up to
    # its delimiter line.
    if (c == "\n" && st == "o" && np > 0) {
      j = i + 1
      for (k = 1; k <= np; k++) {
        while (j <= n) {
          e = index(substr(cmd, j), "\n"); e = e ? j + e - 1 : n + 1
          ln = substr(cmd, j, e - j)
          if (PT[k]) sub(/^\t+/, "", ln)
          done = (ln == PD[k])
          for (x = j; x < e; x++) Q[d, x] = "h"
          if (!done && e <= n) Q[d, e] = "h"
          j = e + 1
          if (done) break
        }
      }
      np = 0
      i = j - 1
    }
  }
}
# hook.rs inner_strings: the string of each bash -c / su -c / eval stage
# read whole (a separator inside quotes does not end a stage), into
# INN[d, index of the first character of the stage].
function instage(t, at, d,    lead) {
  if (!index(t, SQ) && !index(t, DQ) && !index(t, "\\")) return
  lead = match(t, "^" WSC "+") ? RLENGTH : 0
  cwords(t); inner()
  if (HASINNER) INN[d, at + lead] = INNER
  if (rrc()) INR[d, at + lead] = 1
}
function innerstr(cmd, d,    n, i, c, nx, pv, w, start, key, kk) {
  for (key in INN) { split(key, kk, SUBSEP); if (kk[1] == d) delete INN[key] }
  for (key in INR) { split(key, kk, SUBSEP); if (kk[1] == d) delete INR[key] }
  n = length(cmd); start = 1; i = 1
  while (i <= n) {
    c = substr(cmd, i, 1); nx = substr(cmd, i + 1, 1); pv = (i > 1) ? substr(cmd, i - 1, 1) : ""
    w = 0
    if (Q[d, i] == "o") {
      if ((c == "&" && nx == "&") || (c == "|" && (nx == "|" || nx == "&"))) w = 2
      else if ((c == "$" || c == "<" || c == ">") && nx == "(") w = 2
      else if (c == "&" && pv != ">" && pv != "|" && nx != ">") w = 1
      else if (c == "|" && pv != ">") w = 1
      else if (c == ";" || c == "\n" || c == "`") w = 1
    }
    if (w) { instage(substr(cmd, start, i - start), start, d); i += w; start = i } else i++
  }
  instage(substr(cmd, start), start, d)
}
# hook.rs stage_spans: the stages of a segment (split on | but not >|,
# skipping the & of |&) into SPT[1..n] with their offsets SPO[].
function spans(s,    L, x, off, n) {
  L = length(s); n = 0; off = 1
  for (x = 1; x <= L + 1; x++) {
    if (x <= L && !(substr(s, x, 1) == "|" && (x == 1 || substr(s, x - 1, 1) != ">"))) continue
    SPT[++n] = substr(s, off, x - off); SPO[n] = off
    off = x + 1
    if (substr(s, off, 1) == "&") off++
    x = off - 1
  }
  return n
}
# hook.rs runs_substitution: does the text in front of $( <( or a backtick
# run what the substitution prints?
function runsubst(b,    n, t, A, na, x, h) {
  n = spans(b); t = SPT[n]
  na = toka(t, A)
  if (na >= 1 && A[na] ~ /=$/) return 0
  cwords(t)
  if (NW < 1) return 1
  h = W[1]; sub(/.*\//, "", h)
  if (h == "eval") { for (x = 2; x <= NW; x++) if (W[x] != "") return 0; return 1 }
  runs()
  if (RUNS == "I") return (NW == 1 || W[NW] == "")
  return RUNS == "S"
}
# A segment: S op opens exec text words (exec: 1 when it opens a
# substitution whose output runs as code), its stages, the bash -c strings
# they hand over (P ... Q), then E and the ) it closes.
function seg(s, op, start, depth, ex,    x, c, L, k, n, t, opens, closes, open, IN, INK, INI, ni, lead, at, fl, SS, SO2, np, PT, PA, y) {
  L = length(s)
  opens = 0
  for (x = 1; x <= L; x++) {
    c = substr(s, x, 1)
    if (c == "(") { if (Q[depth, start + x - 1] == "o") opens++ }
    else if (c !~ WSC) break
  }
  closes = 0; open = 0
  for (; x <= L; x++) {
    if (Q[depth, start + x - 1] != "o") continue
    c = substr(s, x, 1)
    if (c == "(") open++
    else if (c == ")") { if (open > 0) open--; else closes++ }
  }
  cwords(uncom(s, start, depth))
  printf "S%s%s%s%d%s%d%s%s", US, op, US, opens, US, ex, US, trim(s)
  for (x = 1; x <= NW; x++) printf "%s%s", US, fld(W[x])
  printf "\n"
  n = spans(s); ni = 0
  for (k = 1; k <= n; k++) { SS[k] = SPT[k]; SO2[k] = SPO[k] }
  for (k = 1; k <= n; k++) {
    t = SS[k]
    lead = match(t, "^" WSC "+") ? RLENGTH : 0
    at = start + SO2[k] - 1 + lead
    t = trim(t)
    if (t == "") continue
    # A substitution ends at its ): >(bash) >/dev/null runs bash. What
    # follows belongs to the command around it and is judged as a stage of
    # its own, flagged t ($(true) npm install evil; hook.rs split_close).
    np = 1; PT[1] = t; PA[1] = at
    if (k == 1 && (op == "U" || op == "u")) {
      splitclose(t, at, depth)
      PT[1] = SC_HEAD
      if (SC_TAIL != "") { np = 2; PT[2] = SC_TAIL; PA[2] = SC_TAT }
    }
    for (y = 1; y <= np; y++) {
      if (PT[y] == "") continue
      fl = "-"
      if (Q[depth, PA[y]] != "o") fl = fl "q"
      if (k == n) fl = fl "l"
      if (y == 2) fl = fl "t"
      # The groups it opens and closes (not the substitution it starts).
      if (k == 1 && (op == "U" || op == "u") && y == 1) print "G" US 0 US 0
      else { cmarks(PT[y], PA[y], depth); print "G" US CM_O US CM_C }
      STAGE_RRC = ((depth, PA[y]) in INR)
      stage(PT[y], uncom(PT[y], PA[y], depth), k - 1, fl)
      if (depth < 3) {
        # The index of the stage and whether its stdin is inherited, for
        # the stdin of the string (P).
        if ((depth, PA[y]) in INN) { IN[++ni] = INN[depth, PA[y]]; INK[ni] = k - 1; INI[ni] = (CW_IN == "") }
        else if (HASINNER) { IN[++ni] = INNER; INK[ni] = k - 1; INI[ni] = (CW_IN == "") }
      }
    }
  }
  for (x = 1; x <= ni; x++) { print "P" US INK[x] US INI[x]; walk(IN[x], 1, depth + 1); print "Q" }
  printf "E%s%d\n", US, closes
}
# hook.rs split_close: t (at position at of the command) split at the first
# ) outside quotes that closes nothing opened in it, into SC_HEAD and
# SC_TAIL (trimmed; it starts at position SC_TAT).
function splitclose(t, at, d,    x, c, open, rest, lead) {
  open = 0; SC_HEAD = t; SC_TAIL = ""; SC_TAT = 0
  for (x = 1; x <= length(t); x++) {
    if (Q[d, at + x - 1] != "o") continue
    c = substr(t, x, 1)
    if (c == "(") open++
    else if (c == ")") {
      if (open > 0) { open--; continue }
      SC_HEAD = trim(substr(t, 1, x - 1))
      rest = substr(t, x + 1)
      lead = match(rest, "^" WSC "+") ? RLENGTH : 0
      SC_TAIL = trim(rest); SC_TAT = at + x + lead
      return
    }
  }
}
# hook.rs pieces: the list segments, each with the operator in front of it
# (A &&, G a single &, O other, U $( <(, u >(, B an opening backtick, b a
# closing one) and
# where it starts, then each segment.
function walk(cmd, inherit, depth,    n, i, c, nx, pv, w, op, nop, start, ns, ST, SO, SST, k, ticks, ex) {
  qmap(cmd, depth); innerstr(cmd, depth)
  n = length(cmd); op = inherit ? "A" : "O"; start = 1; i = 1; ns = 0; ticks = 0
  while (i <= n) {
    c = substr(cmd, i, 1); nx = substr(cmd, i + 1, 1); pv = (i > 1) ? substr(cmd, i - 1, 1) : ""
    w = 0
    if (c == "&" && nx == "&") { w = 2; nop = "A" }
    else if (c == "|" && nx == "|") { w = 2; nop = "O" }
    else if (c == "&" && pv != ">" && pv != "|" && nx != ">") { w = 1; nop = "G" }
    else if (c == ";" || c == "\n") { w = 1; nop = "O" }
    else if (c == "`") {
      w = 1
      if (Q[depth, i] == "s" || Q[depth, i] == "c") nop = "O"
      else { ticks++; nop = (ticks % 2) ? "B" : "b" }
    }
    else if ((c == "$" || c == "<") && nx == "(") { w = 2; nop = "U" }
    else if (c == ">" && nx == "(") { w = 2; nop = "u" }
    if (w) { ST[++ns] = substr(cmd, start, i - start); SO[ns] = op; SST[ns] = start; op = nop; i += w; start = i } else i++
  }
  ST[++ns] = substr(cmd, start); SO[ns] = op; SST[ns] = start
  for (k = 1; k <= ns; k++) {
    ex = (SO[k] == "U" || SO[k] == "B") && k > 1 && runsubst(ST[k - 1])
    seg(ST[k], SO[k], SST[k], depth, ex)
  }
}
{ cmd = (NR == 1) ? $0 : (cmd "\n" $0) }
END {
  gsub(US, STX, cmd)
  walk(cmd, 0, 0)
}'

# Directories and files an agent loads and runs from on its own (hook.rs
# agent_path).
AGENT_DIRS='\.claude/(skills|plugins|agents|commands|hooks)|\.codex/(skills|prompts)|\.agents/skills|\.gemini/(extensions|skills|commands)|\.cursor/(rules|skills)|\.windsurf/(rules|workflows)|\.codeium/windsurf|\.openclaw/(skills|workspace[^/]*)|\.(clawdbot|moltbot)/skills|\.config/opencode/(skills?|agents?|commands?|plugins?)|\.opencode/(skills?|agents?|commands?|plugins?)|\.github/(skills|prompts|instructions)|\.continue/(mcpServers|rules)|\.roo/rules|\.config/goose'
AGENT_FILES='\.claude/settings(\.local)?\.json|\.claude\.json|\.mcp\.json|\.codex/config\.toml|\.gemini/settings\.json|\.cursor/(mcp|hooks)\.json|\.vscode/mcp\.json|claude_desktop_config\.json|mcp_config\.json|\.clinerules'
AGENT_RE="(^|/)(($AGENT_DIRS)(/|\$)|($AGENT_FILES)\$)"

SIGIL_RE='^[[:space:]]*([A-Za-z0-9_]+=[^[:space:]]*[[:space:]]+)*(sudo([[:space:]]+-[^[:space:]]+)*[[:space:]]+)?([^[:space:]]*/)?sigil(\.exe)?([[:space:]]|$)'
# Only the bare `sigil` found on PATH vets anything (hook.rs trusted_sigil):
# not ./sigil or /tmp/x/sigil, and not with PATH reassigned for it.
TRUSTED_SIGIL_RE='^[[:space:]]*([A-Za-z0-9_]+=[^[:space:]]*[[:space:]]+)*(sudo([[:space:]]+-[^[:space:]]+)*[[:space:]]+)?sigil(\.exe)?([[:space:]]|$)'
# Nor with PATH, HOME or XDG_* (where its state and trust ledger live), any
# SIGIL_* setting (SIGIL_POLICY_FILE names a policy the scan trusts), or the
# loader's LD_* / DYLD_* (LD_PRELOAD loads code into sigil itself), set for
# it.
PATH_PREFIX_RE='^[[:space:]]*([A-Za-z0-9_]+=[^[:space:]]*[[:space:]]+)*(PATH|HOME|SIGIL_[A-Z_]*|XDG_[A-Z_]*|LD_[A-Z_]*|DYLD_[A-Z_]*)[+]?='
# The command can change what sigil runs or what its scan enforces (hook.rs
# redefines_sigil): a sigil function or alias, a builtin named sigil, hash -p,
# PATH, HOME, a SIGIL_* setting or LD_* / DYLD_* reassigned, a Sigil policy
# file named (.sigil.yml in the working directory is trusted), `sigil
# approve` or `sigil known-good` (both let content pass a later scan), or a
# write into sigil's state directory (~/.sigil/). Then no sigil call in it
# vets anything. (A sourced file can do
# the same; that counts from the `source` on: the V record below.)
REDEFINE_RE='(^|[[:space:];&|(){}])(function[[:space:]]+sigil([[:space:]]|[(]|$)|sigil[[:space:]]*[(][[:space:]]*[)]|alias([[:space:]]+[^[:space:];&|]+)*[[:space:]]+['\''"]?sigil['\''"]?=|hash[[:space:]]+-p[[:space:]]|enable([[:space:]]+[^[:space:];&|]+)*[[:space:]]+sigil([[:space:];&|]|$)|((export|declare|typeset|local|readonly)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*([^[:space:];&|]+[[:space:]]+)*)?(PATH|HOME|SIGIL_[A-Z_]*|LD_[A-Z_]*|DYLD_[A-Z_]*)[+]?=|([^[:space:]]*/)?sigil([.]exe)?([[:space:]]+-[^[:space:]]+)*[[:space:]]+(approve|known-good)([[:space:];&|)]|$))|[.]sigil/|[sS][iI][gG][iI][lL][.][yY][aA]?[mM][lL]'
# Stages hook.rs classify_stage settles before the checks below: agent-CLI
# acquisition, matched after any word boundary as agent_acquisition does,
# and a package runner in command position (RUNNER_PAT: the start of the
# stage after env assignments and wrappers, just inside a quote or paren,
# or after an argv `--`; or the stage's command word). A runner word
# anywhere else is not a run — a URL ending in /npx, an argument named
# bunx — and must not exempt the stage.
AGENT_ACQ_RE="${WB}(([^[:space:]]*/)?([A-Za-z0-9_.-]+[[:space:]]+mcp[[:space:]]+(add|add-json|add-from-claude-desktop)([[:space:]]|\$)|claude[[:space:]]+plugins?[[:space:]]+(marketplace[[:space:]]+add|install|i)[[:space:]]|gemini[[:space:]]+extensions?[[:space:]]+(install|link)[[:space:]]|clawhub(@[^[:space:]]+)?[[:space:]]+install[[:space:]])|(npx|bunx|pnpm[[:space:]]+dlx|yarn[[:space:]]+dlx)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(skills|add-skill|@vercel/skills)(@[^[:space:]]+)?[[:space:]]+(add|install)[[:space:]])"
RUNNER_POS_RE="(^[[:space:]]*([A-Za-z0-9_]+=[^[:space:]]*[[:space:]]+)*((sudo|exec|time|nohup|env|command|xargs)([[:space:]]+-[^[:space:]]+)*[[:space:]]+)*|[\"'(]|[[:space:]]--[[:space:]]+)([^[:space:]]*/)?(npx|bunx|uvx|pipx[[:space:]]+run|pnpm[[:space:]]+dlx|yarn[[:space:]]+dlx|npm[[:space:]]+(exec|x)|bun[[:space:]]+x|uv[[:space:]]+tool[[:space:]]+run)([[:space:]]|\$)"
DENO_RE="${WB}([^[:space:]]*/)?deno[[:space:]]+(run|x|install|serve)([[:space:]]|\$)"
TOOL_INSTALL_RE="${WB}([^[:space:]]*/)?(pipx|uv${MOD}[[:space:]]+tool)${MOD}[[:space:]]+install${FLAGS}${PKG}"

HOME_DIR=${HOME:-}
CUR_CWD=$CWD
LIST_CWD=$CWD

agent_path() {
  # A superset of AGENT_RE first, to spare ordinary paths the grep. The
  # match ignores case, as the default macOS and Windows file systems do
  # (~/.CLAUDE/skills is ~/.claude/skills there): a path with capitals goes
  # to the grep.
  case $1 in
    *[A-Z]*) ;;
    *.claude*|*.codex*|*.agents*|*.gemini*|*.cursor*|*.windsurf*|*.codeium*|*.openclaw*|*.clawdbot*|*.moltbot*|*opencode*|*.github*|*.continue*|*.roo*|*.config/goose*|*.mcp.json|*.vscode/mcp.json|*claude_desktop_config.json|*mcp_config.json|*.clinerules*) ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$1" | grep -iEq "$AGENT_RE"
}

# unquote <token>: surrounding whitespace, then quote characters, trimmed.
unquote() {
  R=$1
  while :; do case $R in [[:space:]]*) R=${R#?} ;; *) break ;; esac; done
  while :; do case $R in *[[:space:]]) R=${R%?} ;; *) break ;; esac; done
  while :; do case $R in [\"\']*) R=${R#?} ;; *) break ;; esac; done
  while :; do case $R in *[\"\']) R=${R%?} ;; *) break ;; esac; done
}

# expand <path> (hook.rs expand): ~, $HOME and $PWD (bare or as a prefix)
# expanded; a path starting with another variable ($TMPDIR/i.sh) taken as
# absolute under it; any other relative path joined to the working
# directory (which follows `cd`).
expand() {
  R=$1
  while :; do case $R in [\"\']*) R=${R#?} ;; *) break ;; esac; done
  while :; do case $R in *[\"\']) R=${R%?} ;; *) break ;; esac; done
  if [ -n "$HOME_DIR" ]; then
    # The literal words ~, $HOME and ${HOME} as the command wrote them.
    case $R in
      \~|\$HOME|\$\{HOME\}) R=$HOME_DIR; return 0 ;;
      \~/*) R=$HOME_DIR/${R#??}; return 0 ;;
      \$HOME/*) R=$HOME_DIR/${R#??????}; return 0 ;;
      \$\{HOME\}/*) R=$HOME_DIR/${R#????????}; return 0 ;;
    esac
  fi
  if [ -n "$CUR_CWD" ]; then
    case $R in
      \$PWD|\$\{PWD\}) R=$CUR_CWD; return 0 ;;
      \$PWD/*) R=$CUR_CWD/${R#?????}; return 0 ;;
      \$\{PWD\}/*) R=$CUR_CWD/${R#???????}; return 0 ;;
    esac
  fi
  case $R in
    /*|\$*) ;;
    *) [ -n "$CUR_CWD" ] && R=$CUR_CWD/$R ;;
  esac
}

# canon <path>: expanded, with "." components and repeated or trailing
# slashes dropped and ".." applied as text (hook.rs canon_path).
canon() {
  expand "$1"
  cn_in=$R
  R=''
  case $cn_in in /*) cn_abs=/ ;; *) cn_abs='' ;; esac
  IFS=/
  for cn_part in $cn_in; do
    case $cn_part in
      ''|.) ;;
      ..)
        case $R in
          ''|..|*/..) [ -n "$cn_abs" ] && [ -z "$R" ] || R=${R:+$R/}.. ;;
          */*) R=${R%/*} ;;
          *) R='' ;;
        esac ;;
      *) R=${R:+$R/}$cn_part ;;
    esac
  done
  IFS=$IFS_DEFAULT
  R=$cn_abs$R
}

is_local() {
  case $1 in .*|/*|\~*|\$HOME*) return 0 ;; esac
  return 1
}

in_list() {
  # in_list <newline list> <item>
  case "$NL$1$NL" in *"$NL$2$NL"*) return 0 ;; esac
  return 1
}

# canon_repo <url> [branch] (hook.rs canon_repo, with_branch): github.com/o/r
# for https://github.com/o/r.git, git@github.com:o/r, github:o/r and
# http://www.GitHub.com/o/r/, then #branch when one is given.
canon_repo() {
  unquote "$1"; cr=$R
  case $cr in github:*) cr=github.com/${cr#github:} ;; esac
  case $cr in git@*) cr=${cr#git@}; case $cr in *:*) cr=${cr%%:*}/${cr#*:} ;; esac ;; esac
  case $cr in *://*) cr=${cr#*://} ;; esac
  # user@host/...: credentials are not part of the identity.
  case $cr in *@*) case ${cr%%@*} in */*) ;; *) cr=${cr#*@} ;; esac ;; esac
  while :; do case $cr in www.*) cr=${cr#www.} ;; *) break ;; esac; done
  while :; do case $cr in */) cr=${cr%/} ;; *) break ;; esac; done
  cr=${cr%.git}
  case $cr in
    */*) cr_h=${cr%%/*}; cr_r=/${cr#*/} ;;
    *) cr_h=$cr; cr_r='' ;;
  esac
  cr_h=$(printf '%s' "$cr_h" | tr '[:upper:]' '[:lower:]')
  R=repo:$cr_h$cr_r
  if [ -n "${2-}" ]; then unquote "$2"; R=repo:$cr_h$cr_r#$R; fi
}

# github_url <src> (hook.rs github_url): owner/repo shorthand as a URL.
github_url() {
  unquote "$1"
  case $R in
    *://*|git@*) ;;
    *) R=https://github.com/${R#github:} ;;
  esac
}

# vet_opt FLAG HAS VALUE: one option of a `sigil <sub>` call (a short one
# named by its letter). Succeeds when it lets a scan of hostile code pass
# (hook.rs vetting_targets): help instead of a scan, a threshold other than
# low/medium/high, a subset of phases, a policy file or baseline of the
# command's choosing. Records -V/--version and -b/--branch.
vet_opt() {
  case $1 in
    h|--help|--config|--baseline) return 0 ;;
    --fail-on|s|--severity)
      [ "$2" = 1 ] || return 0
      case $3 in
        [Ll][Oo][Ww]|[Mm][Ee][Dd][Ii][Uu][Mm]|[Hh][Ii][Gg][Hh]) ;;
        *) return 0 ;;
      esac ;;
    p|--phases)
      [ "$2" = 1 ] || return 0
      case $3 in [Aa][Ll][Ll]) ;; *) return 0 ;; esac ;;
    V|--version) vt_ver=$3 ;;
    b|--branch) vt_branch=$3 ;;
  esac
  return 1
}

# vet_targets TOKENS: record what a `sigil scan|clone|pip|npm` stage vets,
# typed as hook.rs Target (npm:, pypi:, repo:, path:). Options are read as
# clap reads them: a short one's value attached (-pnetwork), after =
# (-s=critical) or the next word, also at the end of a bundle (-vp x); a
# long one's after = or the next word.
vet_targets() {
  while [ $# -gt 0 ]; do
    vt_b=${1##*/}
    [ "${vt_b%.exe}" = sigil ] && break
    shift
  done
  [ $# -ge 2 ] || return 0
  vt_sub=$2
  shift 2
  case $vt_sub in scan|clone|pip|npm) ;; *) return 0 ;; esac
  vt_names=''; vt_ver=''; vt_branch=''; vt_ops=0
  while [ $# -gt 0 ]; do
    vt_t=$1
    shift
    if [ $vt_ops = 1 ]; then unquote "$vt_t"; vt_names=$vt_names$US$R; continue; fi
    case $vt_t in
      --) vt_ops=1 ;;
      --*=*) vet_opt "${vt_t%%=*}" 1 "${vt_t#*=}" && return 0 ;;
      --format|--phases|--severity|--fail-on|--fail-on-verdict|--branch|--baseline|--output|--policy|--rules|--config|--version)
        if [ $# -gt 0 ]; then vt_v=$1; shift; vet_opt "$vt_t" 1 "$vt_v" && return 0
        else vet_opt "$vt_t" 0 '' && return 0; fi ;;
      --*) vet_opt "$vt_t" 0 '' && return 0 ;;
      -?*)
        vt_bd=${vt_t#-}
        while [ -n "$vt_bd" ]; do
          vt_c=${vt_bd%"${vt_bd#?}"}
          vt_bd=${vt_bd#?}
          case $vt_c in
            [psfobV])
              vt_bd=${vt_bd#=}
              if [ -n "$vt_bd" ]; then vet_opt "$vt_c" 1 "$vt_bd" && return 0
              elif [ $# -gt 0 ]; then vt_v=$1; shift; vet_opt "$vt_c" 1 "$vt_v" && return 0
              else vet_opt "$vt_c" 0 '' && return 0; fi
              break ;;
            *) vet_opt "$vt_c" 0 '' && return 0 ;;
          esac
        done ;;
      *) unquote "$vt_t"; vt_names=$vt_names$US$R ;;
    esac
  done
  IFS=$US
  for vt_n in $vt_names; do
    IFS=$IFS_DEFAULT
    [ -n "$vt_n" ] || continue
    case $vt_sub in
      npm) vt_x=npm:$vt_n${vt_ver:+@$vt_ver} ;;
      pip) vt_x=pypi:$vt_n${vt_ver:+==$vt_ver} ;;
      *)
        case $vt_n in
          *://*|git@*|github:*) canon_repo "$vt_n" "$vt_branch"; vt_x=$R ;;
          *) canon "$vt_n"; vt_x=path:$R ;;
        esac ;;
    esac
    GATES=${GATES:+$GATES$NL}$vt_x
  done
  IFS=$IFS_DEFAULT
}

# gated <targets>: every target (newline list) was vetted by the && chain.
gated() {
  [ -n "$1" ] || return 1
  IFS=$NL
  for gt_t in $1; do
    IFS=$IFS_DEFAULT
    [ "$gt_t" = '!' ] && return 1
    case $gt_t in path:*) in_list "$UNSETTLED" "${gt_t#path:}" && return 1 ;; esac
    in_list "$GATES" "$gt_t" || return 1
  done
  IFS=$IFS_DEFAULT
  return 0
}

# record_download <canonical path>: a file the command downloads. A scan of
# that path earlier in the chain read other bytes, so it no longer vets it.
record_download() {
  in_list "$DOWNLOADS" "$1" || DOWNLOADS=${DOWNLOADS:+$DOWNLOADS$NL}$1
  in_list "$LIST_DL" "$1" || LIST_DL=${LIST_DL:+$LIST_DL$NL}$1
  in_list "$GATES" "path:$1" || return 0
  rd_new=''
  IFS=$NL
  for rd_g in $GATES; do
    [ "$rd_g" = "path:$1" ] || rd_new=${rd_new:+$rd_new$NL}$rd_g
  done
  IFS=$IFS_DEFAULT
  GATES=$rd_new
}

# pm_targets WORDS: hook.rs stage_targets for a package-manager stage —
# every argument after the install verb, in the registry the manager
# installs from; "!" for what no sigil call vets by name.
pm_targets() {
  pt_out=''
  [ $# -gt 0 ] || { R=''; return 0; }
  pt_head=${1##*/}
  pt_kind=''
  case $pt_head in
    npm|yarn|pnpm|bun) pt_kind=npm ;;
    pip*|uv) pt_kind=pypi ;;
    python*) for pt_t; do [ "$pt_t" = pip ] && pt_kind=pypi; done ;;
  esac
  pt_found=0
  for pt_t; do
    if [ $pt_found = 0 ]; then
      case $pt_t in install|i|add|get) pt_found=1 ;; esac
      continue
    fi
    case $pt_t in -*) continue ;; esac
    unquote "$pt_t"; pt_u=$R
    if [ -n "$pt_kind" ] && is_local "$pt_u"; then
      canon "$pt_u"; pt_x=path:$R
    elif [ "$pt_kind" = npm ]; then
      pt_x=npm:$pt_u
    elif [ "$pt_kind" = pypi ]; then
      # `uv tool install ruff@0.4.0` is ruff==0.4.0.
      case $pt_u in
        *://*) ;;
        *@*) pt_u="${pt_u%%@*}==${pt_u#*@}" ;;
      esac
      pt_x=pypi:$pt_u
    else
      pt_x='!'
    fi
    pt_out=${pt_out:+$pt_out$NL}$pt_x
  done
  R=$pt_out
}

# deno_scan TOKENS: the module after `deno run|x|install|serve`, when it is
# fetched (https://, http://, npm:, jsr:). Fails when no deno word is found.
deno_scan() {
  R=''
  ds_found=0
  while [ $# -gt 0 ]; do
    if [ "${1##*/}" = deno ]; then
      case ${2-} in run|x|install|serve) shift 2; ds_found=1; break ;; esac
    fi
    shift
  done
  [ $ds_found = 1 ] || return 1
  for ds_m; do
    case $ds_m in
      -*) ;;
      https://*|http://*|npm:*|jsr:*) R=$ds_m; return 0 ;;
      *) return 0 ;;
    esac
  done
  return 0
}

# tool_pkg TOKENS: the package a `pipx install` / `uv tool install` names,
# in pip syntax.
pkg_scan() {
  while [ $# -gt 0 ]; do
    [ "$1" = install ] && break
    shift
  done
  [ $# -gt 0 ] || return 1
  shift
  for ps_p; do
    case $ps_p in -*) continue ;; esac
    unquote "$ps_p"
    while :; do case $R in *@*) R="${R%%@*}==${R#*@}" ;; *) break ;; esac; done
    return 0
  done
  return 1
}
tool_pkg() {
  # A quoted `bash -c 'pipx install x'` is one token: retry on its words.
  pkg_scan "$@" && return 0
  # shellcheck disable=SC2048,SC2086 # split every token into words
  set -- $*
  pkg_scan "$@" && return 0
  R='<pkg>'
}

# exact_version <v>: cmdline::exact_version — three dot-separated parts,
# each starting with a digit, after any leading v's and then ='s.
exact_version() {
  ev_v=$1
  while :; do case $ev_v in v*) ev_v=${ev_v#?} ;; *) break ;; esac; done
  while :; do case $ev_v in =*) ev_v=${ev_v#?} ;; *) break ;; esac; done
  IFS=.
  # shellcheck disable=SC2086 # split on the dots
  set -- $ev_v
  IFS=$IFS_DEFAULT
  [ $# -ge 3 ] || return 1
  case $1 in [0-9]*) ;; *) return 1 ;; esac
  case $2 in [0-9]*) ;; *) return 1 ;; esac
  case $3 in [0-9]*) ;; *) return 1 ;; esac
}

# runner_scan TOKENS: cmdline::parse_runner from the first package-runner
# word in TOKENS. Fails when there is none. Otherwise sets RN_TOOL (empty
# when parse_runner finds no package, or a local path) and, for a package:
# R, the typed target it fetches (npm:<spec> / pypi:<spec>), RN_SPEC,
# RN_REGISTRY, RN_ALT (the vetting sigil command), RN_UNPINNED (the
# message suffix) and RN_LOCAL (1 when `bun x <bin>` resolves to a
# node_modules/.bin of the working directory or one above it).
runner_scan() {
  RN_TOOL=''; RN_LOCAL=0; R=''
  while [ $# -gt 0 ]; do
    rn_h=${1##*/}
    case $rn_h:${2-}:${3-} in
      npx:*|bunx:*|uvx:*) RN_TOOL=$rn_h; shift; break ;;
      pipx:run:*|pnpm:dlx:*|yarn:dlx:*|npm:exec:*|npm:x:*|bun:x:*)
        RN_TOOL="$rn_h $2"; shift 2; break ;;
      uv:tool:run) RN_TOOL='uv tool run'; shift 3; break ;;
    esac
    shift
  done
  [ -n "$RN_TOOL" ] || return 1
  case $RN_TOOL in
    'npm x') RN_TOOL='npm exec' ;;
  esac
  case $RN_TOOL in
    uvx|'pipx run'|'uv tool run') rn_eco=pypi ;;
    *) rn_eco=npm ;;
  esac
  rn_spec=''; rn_has=0; rn_pos=''; rn_haspos=0
  while [ $# -gt 0 ]; do
    rn_t=$1
    shift
    case $rn_t in
      --)
        if [ $rn_haspos = 0 ] && [ $# -gt 0 ]; then rn_pos=$1; rn_haspos=1; fi
        break ;;
      -y|--yes) ;;
      -*=*)
        case ${rn_t%%=*} in
          --package|--from|--spec) rn_spec=${rn_t#*=}; rn_has=1 ;;
        esac ;;
      -*)
        rn_valued=0; rn_explicit=0
        if [ $rn_eco = npm ]; then
          case $rn_t in
            -p|--package) rn_valued=1; rn_explicit=1 ;;
            -c|--call|--registry|-w|--workspace|--cache|--userconfig) rn_valued=1 ;;
          esac
        else
          case $rn_t in
            --from|--spec) rn_valued=1; rn_explicit=1 ;;
            --with|--python|-p|--index-url|--extra-index-url|--index|--default-index|--pip-args|--with-requirements|--constraints) rn_valued=1 ;;
          esac
        fi
        if [ $rn_valued = 1 ]; then
          if [ $rn_explicit = 1 ]; then
            rn_has=0; [ $# -gt 0 ] && { rn_spec=$1; rn_has=1; }
          fi
          [ $# -gt 0 ] && shift
        fi ;;
      *) rn_pos=$rn_t; rn_haspos=1; break ;;
    esac
  done
  if [ $rn_has = 0 ]; then
    [ $rn_haspos = 1 ] || { RN_TOOL=''; return 0; }
    rn_spec=$rn_pos
  fi
  # cmdline::local_spec: not a registry package.
  case $rn_spec in
    .*|/*|\~*|file:*) RN_TOOL=''; return 0 ;;
    *://*) ;;
    *.tgz) RN_TOOL=''; return 0 ;;
  esac
  RN_SPEC=$rn_spec
  RN_UNPINNED=' (unpinned: whatever version is current)'
  if [ $rn_eco = npm ]; then
    RN_REGISTRY='npm registry'
    # Pinned: an exact version after the name's @ (cmdline::npm_split);
    # URLs and git/github specs never are.
    case $rn_spec in
      *://*) ;;
      @*)
        rn_rest=${rn_spec#@}
        case $rn_rest in
          *@*) exact_version "${rn_rest#*@}" && RN_UNPINNED='' ;;
        esac ;;
      *:*) ;;
      *@*) exact_version "${rn_spec#*@}" && RN_UNPINNED='' ;;
    esac
    RN_ALT="sigil npm $rn_spec"
    R=npm:$rn_spec
  else
    RN_REGISTRY='Python package index'
    case $rn_spec in
      *://*) ;;
      *==*) exact_version "${rn_spec#*==}" && RN_UNPINNED='' ;;
      *@*) exact_version "${rn_spec#*@}" && RN_UNPINNED='' ;;
    esac
    rn_vet=$rn_spec
    while :; do case $rn_vet in *@*) rn_vet="${rn_vet%%@*}==${rn_vet#*@}" ;; *) break ;; esac; done
    RN_ALT="sigil pip $rn_vet"
    R=pypi:$rn_vet
  fi
  # `bun x tsc` in a project that has typescript installed runs the local
  # binary (hook.rs runner(): npx, bunx and bun x, a bare name).
  case $RN_TOOL:$rn_spec in
    npx:*[@/]*|bunx:*[@/]*|'bun x':*[@/]*) ;;
    npx:*|bunx:*|'bun x':*)
      rn_d=$CUR_CWD
      while [ -n "$rn_d" ]; do
        if [ -e "${rn_d%/}/node_modules/.bin/$rn_spec" ]; then RN_LOCAL=1; break; fi
        case $rn_d in
          /) break ;;
          */*) rn_d=${rn_d%/*}; [ -n "$rn_d" ] || rn_d=/ ;;
          *) break ;;
        esac
      done ;;
  esac
  return 0
}

# runner_words WORDS: cmdline::parse_runner on the stage's command words,
# for a runner behind a wrapper (`sudo -u root npx …`, `(npx …)`). Fails
# when the command word is not a runner.
runner_words() {
  while [ $# -gt 0 ]; do
    case $1 in
      sudo|env|exec|command) shift ;;
      -*) break ;;
      *=*) shift ;;
      *) break ;;
    esac
  done
  # RW_PATH: the runner is named by a path (/usr/bin/npx), which the rules
  # at the end do not match.
  RW_PATH=0
  [ $# -gt 0 ] || return 1
  case $1 in */*) RW_PATH=1 ;; esac
  rw_h=${1##*/}
  rw_h=${rw_h%.cmd}
  rw_h=${rw_h%.exe}
  case $rw_h:${2-}:${3-} in
    npx:*|bunx:*|uvx:*|pipx:run:*|pnpm:dlx:*|yarn:dlx:*|npm:exec:*|npm:x:*|bun:x:*|uv:tool:run) ;;
    *) return 1 ;;
  esac
  runner_scan "$@"
}

# check_variant TEXT TOKENS: hook.rs classify_stage and stage_targets for
# the checks this script makes per stage, on one reading of the stage (as
# written, or dequoted). Sets CK_DENY (empty: nothing to deny) and
# CK_TARGETS (what a gate must have vetted; empty: never gated).
check_variant() {
  cv_text=$1
  shift
  CK_DENY=''; CK_TARGETS=''
  cv_earlier=0
  case $cv_text in
    *mcp*|*plugin*|*extension*|*clawhub*|*npx*|*bunx*|*uvx*|*pipx*|*dlx*|*npm*|*bun*|*uv*)
      if has_in "$cv_text" "$AGENT_ACQ_RE"; then
        cv_earlier=1
      else
        # hook.rs runner(): settled here only when parse_runner names a
        # registry package. npx, bunx, uvx, pipx run and dlx are denied by
        # the rules at the end; the runners those rules do not name are
        # judged here.
        RN_TOOL=''
        IFS=$US
        # shellcheck disable=SC2086 # the command words, US-separated
        runner_words $ST_W
        IFS=$IFS_DEFAULT
        if [ -z "$RN_TOOL" ] && has_in "$cv_text" "$RUNNER_POS_RE"; then
          # shellcheck disable=SC2048,SC2086 # split every token into words
          runner_scan "$@" || runner_scan $*
        fi
        if [ -n "$RN_TOOL" ]; then
          cv_earlier=1
          cv_run=$RN_TOOL
          [ "$RW_PATH" = 1 ] && cv_run='npm exec'
          case $cv_run in
            'npm exec'|'bun x'|'uv tool run')
              if [ "$RN_LOCAL" = 0 ]; then
                CK_DENY="\`$RN_TOOL $RN_SPEC\` downloads $RN_SPEC from the $RN_REGISTRY and runs it in one step, with no scan$RN_UNPINNED. Use: $RN_ALT && $cv_text. $BYPASS_HINT"
                CK_TARGETS=$R
              fi ;;
          esac
        fi
      fi ;;
  esac
  [ $cv_earlier = 0 ] || return 0
  cv_deno=''
  case $cv_text in
    *deno*)
      if has_in "$cv_text" "$DENO_RE"; then
        # A quoted `bash -c 'deno run …'` is one token: retry on its words.
        # shellcheck disable=SC2048,SC2086 # split every token into words
        deno_scan "$@" || deno_scan $*
        cv_deno=$R
      fi ;;
  esac
  if [ -n "$cv_deno" ]; then
    case $cv_deno in
      npm:*)
        cv_spec=${cv_deno#npm:}
        # The package, without the subpath deno loads from it
        # (`chalk@5.3.0/main`, `@scope/pkg@1/x`): sigil npm takes the
        # package, and npm reads `chalk@5.3.0/main` as a git shorthand.
        case $cv_spec in
          @*/*/*) cv_rest=${cv_spec#*/}; cv_spec=${cv_spec%%/*}/${cv_rest%%/*} ;;
          @*) ;;
          */*) cv_spec=${cv_spec%%/*} ;;
        esac
        CK_DENY="deno fetches $cv_spec from the npm registry and runs it in one step, with no scan. Use: sigil npm $cv_spec && $cv_text. $BYPASS_HINT"
        CK_TARGETS=npm:$cv_spec ;;
      *)
        CK_DENY="deno fetches $cv_deno and runs it in one step, with no scan (the server decides per request what it serves). Download the module, run sigil scan on it, then deno run the local file. $BYPASS_HINT"
        CK_TARGETS='!' ;;
    esac
    return 0
  fi
  # A curl/wget stage saving into agent tooling (hook.rs tooling_write).
  if [ -n "$ST_TOOLING" ]; then
    first_url "$cv_text"
    CK_DENY="Downloads into agent tooling ($ST_TOOLING) with no scan. Use: sigil scan ${R:-<url>} — it downloads into quarantine and scans first. $BYPASS_HINT"
    return 0
  fi
  case $cv_text in
    *install*)
      if has_in "$cv_text" "$TOOL_INSTALL_RE"; then
        tool_pkg "$@"
        CK_DENY="This installs $R from the Python package index with no scan; its build and entry points run with your privileges. Use: sigil pip $R && $cv_text — and pin an exact version. $BYPASS_HINT"
        IFS=$US
        # shellcheck disable=SC2086 # the command words, US-separated
        pm_targets $ST_W
        IFS=$IFS_DEFAULT
        CK_TARGETS=$R
      fi ;;
  esac
}

# judge_stage K FLAGS TEXT DQTEXT TOKENS: deny (and exit) when the stage
# runs remote code or writes into agent tooling and the && chain before it
# did not vet it. Uses the stage's records (ST_*) and the segment's
# (SEG_*). FLAGS: q, the stage starts inside quotes or a comment; l, it is
# the last stage of its pipeline; t, it is what follows a substitution's ).
judge_stage() {
  st_k=${1-0}; st_fl=${2-}; st_raw=${3-}; st_dq=${4-}
  # The segment opens a substitution whose output runs as code; not for the
  # words after its ) (flag t), which belong to the command around it.
  st_exec=$SEG_EXEC
  case $st_fl in *t*) st_exec=0 ;; esac
  if [ $# -ge 4 ]; then shift 4; else set --; fi
  case $st_raw in
    *sigil*)
      if has_in "$st_raw" "$SIGIL_RE"; then
        SIGIL_SEEN=1
        JS_SIGIL=1
        # A vetting call gates what follows it with && only when it is the
        # real sigil, outside quotes and substitutions, and the pipeline's
        # exit status is its own (the last stage: `sigil scan x | tee log`
        # exits with tee's).
        case $st_fl in
          *q*) ;;
          *l*)
            if [ "$UNTRUSTED" = 0 ] && [ "$SEG_INSUB" = 0 ] \
              && has_in "$st_raw" "$TRUSTED_SIGIL_RE" \
              && ! has_in "$st_raw" "$PATH_PREFIX_RE"; then
              vet_targets "$@"
            fi ;;
        esac
        return 0
      fi ;;
  esac
  # The files this stage saves a download to, resolved.
  st_files=''
  IFS=$NL
  for st_f in $ST_D; do
    IFS=$IFS_DEFAULT
    canon "$st_f"
    [ -n "$R" ] && st_files=${st_files:+$st_files$NL}$R
  done
  IFS=$IFS_DEFAULT
  ST_TOOLING=''
  IFS=$NL
  for st_f in $st_files; do
    IFS=$IFS_DEFAULT
    if agent_path "$st_f"; then ST_TOOLING=$st_f; break; fi
  done
  IFS=$IFS_DEFAULT
  ST_DENY=''
  # As written, then dequoted; each reading gated on its own targets.
  for st_v in raw dq; do
    if [ $st_v = raw ]; then st_text=$st_raw; else st_text=$st_dq; fi
    [ $st_v = dq ] && [ "$st_dq" = "$st_raw" ] && break
    check_variant "$st_text" "$@"
    if [ -n "$CK_DENY" ]; then
      if gated "$CK_TARGETS"; then
        GATED_REASON="Gated by a preceding sigil check on the same target"
      else
        ST_DENY=$CK_DENY
        break
      fi
    fi
  done
  # The files this stage reads (its arguments and a `< file`), and the
  # first of them that is a download.
  st_reads=''
  IFS=$NL
  for st_f in $ST_C; do
    IFS=$IFS_DEFAULT
    canon "$st_f"
    st_reads=${st_reads:+$st_reads$NL}$R
  done
  IFS=$IFS_DEFAULT
  if [ "$ST_INK" = F ]; then
    canon "$ST_IN"
    st_reads=${st_reads:+$st_reads$NL}$R
  fi
  st_rdl=''
  IFS=$NL
  for st_f in $st_reads; do
    IFS=$IFS_DEFAULT
    if in_list "$DOWNLOADS" "$st_f"; then st_rdl=$st_f; break; fi
  done
  IFS=$IFS_DEFAULT
  # A program that runs what comes down its stdin (an interpreter, a shell
  # `sudo -s` or `su` starts, inline code xargs fills in), after a download
  # written to it: `curl … | base64 -d | sh`, `curl … | (bash)`,
  # `curl … | node -r x`, `curl … | sudo -s`, `curl … | tee >(bash)`,
  # `curl … | sh -c 'source /dev/stdin'`. Or a substitution that prints
  # its stdin, the download, as code: `curl … | bash -c "$(cat)"`. Never
  # gated.
  st_runs=0
  [ -z "$ST_INK" ] && { [ "$ST_R" = 1 ] || [ "$ST_H" = 1 ]; } && st_runs=1
  # `… | while read l; do $l; done`: a variable as the whole command, inside
  # a compound command that reads the download (not `… | $PAGER`).
  [ -z "$ST_INK" ] && [ "$ST_L" = 1 ] && [ -n "$FED_DEPTH" ] && st_runs=1
  st_rpipe=0
  [ "$st_k" -gt 0 ] && [ $st_runs = 1 ] && st_rpipe=1
  st_pdeny=0
  [ $st_runs = 1 ] && [ "$SEG_FED" = 1 ] && st_pdeny=1
  [ "$st_exec" = 1 ] && [ "$st_k" = 0 ] && [ "$SEG_FED" = 1 ] && [ "$ST_K" = 1 ] && st_pdeny=1
  if [ -z "$ST_DENY" ] && [ $st_pdeny = 1 ]; then
    first_url "$CMD"
    if [ -n "$R" ]; then
      ST_DENY="Piping a download into an interpreter executes unscanned code. Use: sigil scan $R — or download it (curl -fsSLo script.sh $R), run sigil scan script.sh, then run the file you scanned. $BYPASS_HINT"
    else
      ST_DENY="Piping a download into an interpreter executes unscanned code. Download the script, run sigil scan on it, then execute the file you scanned. $BYPASS_HINT"
    fi
  fi
  # Download to a file, then run that file: the same remote execution as
  # curl | sh, one step removed — but gateable, as the scan reads the
  # bytes that run.
  st_ran=''
  if [ -n "$ST_X" ]; then
    canon "$ST_X"
    in_list "$DOWNLOADS" "$R" && { st_ran=$R; st_shown=$st_raw; }
  fi
  if [ -z "$st_ran" ] && [ $st_rpipe = 1 ]; then
    # `cat i.sh | sh`, `head i.sh | sh`: the file, read into an interpreter.
    IFS=$NL
    for st_f in $SEG_SOURCES; do
      IFS=$IFS_DEFAULT
      if in_list "$DOWNLOADS" "$st_f"; then st_ran=$st_f; st_shown=$SEG_TEXT; break; fi
    done
    IFS=$IFS_DEFAULT
  fi
  if [ -n "$st_ran" ]; then
    if gated "path:$st_ran"; then
      GATED_REASON="Gated by a preceding sigil check on the same target"
    else
      [ -n "$ST_DENY" ] || ST_DENY="Runs $st_ran, downloaded earlier in this command, without a scan: remote code execution one step removed from curl | sh. Use: sigil scan $st_ran && $st_shown (after the download). $BYPASS_HINT"
    fi
  fi
  # `eval "$(cat i.sh)"`, `bash <(cat i.sh)`: a substitution whose output
  # runs as code, printing a downloaded file.
  if [ "$st_exec" = 1 ] && [ -n "$st_rdl" ]; then
    if gated "path:$st_rdl"; then
      GATED_REASON="Gated by a preceding sigil check on the same target"
    else
      [ -n "$ST_DENY" ] || ST_DENY="Runs $st_rdl, downloaded earlier in this command, through a command substitution, without a scan: remote code execution one step removed from curl | sh. Use: sigil scan $st_rdl before running it. $BYPASS_HINT"
    fi
  fi
  # The download, passed on: `curl … | tee f`, `curl … | sed … > f`,
  # `cat i.sh > j.sh`.
  st_carried=0
  if [ "$SEG_FED" = 1 ]; then
    st_carried=1
  elif [ "$st_k" -gt 0 ]; then
    IFS=$NL
    for st_f in $SEG_SOURCES; do
      IFS=$IFS_DEFAULT
      if in_list "$DOWNLOADS" "$st_f"; then st_carried=1; break; fi
    done
    IFS=$IFS_DEFAULT
  fi
  if [ $st_carried = 1 ] || [ -n "$st_rdl" ]; then
    st_piped=$ST_OUTS
    [ $st_carried = 1 ] && st_piped=$ST_Z$ST_OUTS
    IFS=$NL
    for st_f in $st_piped; do
      IFS=$IFS_DEFAULT
      case $st_f in /dev/*) continue ;; esac
      canon "$st_f"
      st_p=$R
      if [ -z "$ST_DENY" ] && [ "$SEG_FED" = 1 ] && agent_path "$st_p"; then
        first_url "$SEG_TEXT"
        ST_DENY="Downloads into agent tooling ($st_p) with no scan. Use: sigil scan ${R:-<url>} — it downloads into quarantine and scans first. $BYPASS_HINT"
      fi
      [ -n "$st_p" ] && st_files=${st_files:+$st_files$NL}$st_p
    done
    IFS=$IFS_DEFAULT
  fi
  # `cp i.sh j.sh`, `mv i.sh j.sh`: the copy is the download too; a copy
  # of a file the chain has scanned holds the scanned bytes.
  st_vet=''
  if [ -n "$ST_N" ]; then
    canon "$ST_N"
    st_dest=$R
    IFS=$NL
    for st_f in $ST_Y; do
      IFS=$IFS_DEFAULT
      [ -n "$st_f" ] || continue
      canon "$st_f"
      if in_list "$DOWNLOADS" "$R"; then
        st_files=${st_files:+$st_files$NL}$st_dest$NL${st_dest%/}/${R##*/}
        gated "path:$R" && st_vet=$st_vet${NL}path:$st_dest${NL}path:${st_dest%/}/${R##*/}
      fi
    done
    IFS=$IFS_DEFAULT
  fi
  # A file downloaded earlier and written again — edited in place (sed -i,
  # perl -pi), appended to, overwritten or replaced by a copy — holds other
  # bytes than a scan of it read: the scan no longer vets it (hook.rs
  # overwrites).
  st_ow=$ST_OUTS$NL$ST_Z$NL$ST_M
  if [ -n "$ST_N" ]; then
    canon "$ST_N"
    st_dest=$R
    st_ow=$st_ow$NL$st_dest
    IFS=$NL
    for st_f in $ST_Y; do
      IFS=$IFS_DEFAULT
      [ -n "$st_f" ] || continue
      canon "$st_f"
      st_ow=$st_ow$NL${st_dest%/}/${R##*/}
    done
    IFS=$IFS_DEFAULT
  fi
  IFS=$NL
  for st_f in $st_ow; do
    IFS=$IFS_DEFAULT
    case $st_f in ''|/dev/*) continue ;; esac
    canon "$st_f"
    in_list "$DOWNLOADS" "$R" && st_files=${st_files:+$st_files$NL}$R
  done
  IFS=$IFS_DEFAULT
  [ -n "$ST_DENY" ] && deny "$ST_DENY"
  [ "$ST_F" = 1 ] && SEG_FED=1
  [ -n "$st_reads" ] && SEG_SOURCES=${SEG_SOURCES:+$SEG_SOURCES$NL}$st_reads
  IFS=$NL
  for st_f in $st_files; do
    IFS=$IFS_DEFAULT
    record_download "$st_f"
  done
  IFS=$IFS_DEFAULT
  [ -n "$st_vet" ] && GATES=${GATES:+$GATES}$st_vet
  # With a sigil call in the command, the rules at the end read only the
  # stages no sigil call vets (hook.rs judges each stage and gates it on
  # its own targets): record this one unless the && chain vetted all of
  # them.
  st_kept=1
  if [ "$RESID_ON" = 1 ]; then
    legacy_targets "$st_raw" "$@"
    if gated "$R"; then
      GATED_REASON="Gated by a preceding sigil check on the same target"
      st_kept=0
    else
      RESID=$RESID$NL$st_raw
    fi
  fi
  # `pip install -r req.txt evil` names a package besides the requirements
  # file: the pip rule at the end denies it (hook.rs reads each stage's
  # words with cmdline::pip_names_package).
  case $st_kept$st_raw in
    1*pip*install*)
      IFS=$US
      # shellcheck disable=SC2086 # the command words, US-separated
      set -- $ST_W
      IFS=$IFS_DEFAULT
      pip_named "$@" && PIP_NAMED=1 ;;
  esac
  return 0
}

# legacy_targets TEXT TOKENS: hook.rs stage_targets for the stages the
# rules at the end judge: a package runner (in command position, as
# runner_at finds it), git/gh clone, or a package manager. Reads ST_W.
legacy_targets() {
  lt_text=$1
  shift
  RN_TOOL=''
  IFS=$US
  # shellcheck disable=SC2086 # the command words, US-separated
  runner_words $ST_W
  IFS=$IFS_DEFAULT
  if [ -z "$RN_TOOL" ] && has_in "$lt_text" "$RUNNER_POS_RE"; then
    # shellcheck disable=SC2048,SC2086 # split every token into words
    runner_scan "$@" || runner_scan $*
  fi
  [ -n "$RN_TOOL" ] && return 0
  IFS=$US
  # shellcheck disable=SC2086 # the command words, US-separated
  set -- $ST_W
  IFS=$IFS_DEFAULT
  R=''
  case ${1##*/} in
    git|gh)
      while [ $# -gt 0 ] && [ "$1" != clone ]; do shift; done
      [ $# -gt 0 ] && shift
      lt_b=''; lt_u=''; lt_has=0
      while [ $# -gt 0 ]; do
        case $1 in
          -b|--branch) shift; lt_b=${1-}; [ $# -gt 0 ] && shift; continue ;;
          --branch=*) lt_b=${1#--branch=} ;;
          --depth|-o|--origin|-c|--config) shift; [ $# -gt 0 ] && shift; continue ;;
          -*) ;;
          *) [ $lt_has = 0 ] && { lt_u=$1; lt_has=1; } ;;
        esac
        shift
      done
      [ $lt_has = 1 ] || return 0
      if is_local "$lt_u"; then
        canon "$lt_u"; R=path:$R
      else
        github_url "$lt_u"; canon_repo "$R" "$lt_b"
      fi ;;
    *) pm_targets "$@" ;;
  esac
}

# pip_named WORDS: cmdline::pip_names_package — `pip install`,
# `python -m pip install` or `uv pip install` naming a package besides any
# requirements file (`pip install -r req.txt evil`). The values of the
# options that take one are not packages, except an editable install from
# a repository (-e git+https://…); a comment ends the words.
pip_named() {
  [ $# -gt 0 ] || return 1
  unquote "${1##*/}"; pn_b=$R
  case $pn_b in
    pip*[!0-9.]*) return 1 ;;
    pip*) shift ;;
    python*)
      [ "${2-}" = -m ] && [ "${3-}" = pip ] || return 1
      shift 3 ;;
    uv)
      [ "${2-}" = pip ] || return 1
      shift 2 ;;
    *) return 1 ;;
  esac
  while [ $# -gt 0 ] && [ "$1" != install ]; do shift; done
  [ $# -gt 0 ] || return 1
  shift
  while [ $# -gt 0 ]; do
    unquote "$1"; pn_t=$R
    shift
    case $pn_t in
      '') ;;
      \#*) return 1 ;;
      --)
        for pn_t; do
          unquote "$pn_t"
          case $R in
            '') ;;
            \#*) return 1 ;;
            *) return 0 ;;
          esac
        done
        return 1 ;;
      --editable=*) pn_remote "${pn_t#--editable=}" && return 0 ;;
      --*=*) ;;
      --editable)
        if [ $# -gt 0 ]; then
          unquote "$1"; shift
          pn_remote "$R" && return 0
        fi ;;
      --requirement|--requirements|--constraint|--constraints|--override|--overrides|\
      --build-constraint|--build-constraints|--target|--platform|\
      --python-platform|--python-version|--implementation|--abi|--root|--prefix|\
      --src|--upgrade-strategy|--config-settings|--config-setting|\
      --config-settings-package|--global-option|--build-option|--install-option|\
      --no-binary|--only-binary|--no-binary-package|--no-build-package|\
      --no-build-isolation-package|--progress-bar|--root-user-action|--report|\
      --index-url|--extra-index-url|--index|--default-index|--index-strategy|\
      --find-links|--group|--extra|--python|--log|--log-file|--keyring-provider|\
      --proxy|--retries|--timeout|--exists-action|--trusted-host|\
      --allow-insecure-host|--cert|--client-cert|--cache-dir|--use-feature|\
      --use-deprecated|--resume-retries|--upgrade-package|--reinstall-package|\
      --refresh-package|--resolution|--prerelease|--fork-strategy|--exclude-newer|\
      --exclude-newer-package|--link-mode|--config-file|--directory|--project|\
      --color|--torch-backend)
        [ $# -gt 0 ] && shift ;;
      --*) ;;
      -?*)
        # A bundle (-Ur req.txt, -rreq.txt): the first option that takes a
        # value takes the rest of the word, or the next word.
        pn_s=${pn_t#-}
        pn_v=${pn_s%%[rcetifpPbC]*}
        if [ "$pn_v" != "$pn_s" ]; then
          pn_o=${pn_s#"$pn_v"}
          pn_rest=${pn_o#?}
          pn_o=${pn_o%"$pn_rest"}
          if [ -z "$pn_rest" ] && [ $# -gt 0 ]; then
            unquote "$1"; pn_rest=$R; shift
          fi
          [ "$pn_o" = e ] && pn_remote "$pn_rest" && return 0
        fi ;;
      *) return 0 ;;
    esac
  done
  return 1
}

# pn_remote VALUE: cmdline::remote_editable — an editable install fetched
# from a repository (-e git+https://…), a package of its own.
pn_remote() {
  case $1 in
    *://*|git+*|hg+*|svn+*|bzr+*) return 0 ;;
  esac
  return 1
}

st_reset() {
  ST_OUTS=''; ST_IN=''; ST_INK=''; ST_X=''; ST_R=0; ST_D=''; ST_F=0
  ST_C=''; ST_Z=''; ST_W=''; ST_N=''; ST_Y=''; ST_V=0; ST_K=0; ST_M=''; ST_H=0
  ST_OPENS=0; ST_CLOSES=0; ST_L=0
}

# grp_pop: close a `( … )` group or a substitution (both subshells),
# restoring the directory it started in.
grp_pop() {
  [ -n "$GRP_STACK" ] || return 0
  gp_top=${GRP_STACK##*"$NL"}
  GRP_STACK=${GRP_STACK%"$NL"*}
  case $gp_top in [+=]*) CUR_CWD=${gp_top#?} ;; esac
}

# dir_change WORDS: follow `cd dir`, `cd -P dir`, `cd -- dir`, `cd -`,
# `pushd dir` and a bare `popd` (hook.rs dir_change). Fails, changing
# nothing, for any other command or form.
dir_change() {
  dc_h=${1-}
  case $dc_h in cd|pushd|popd) ;; *) return 1 ;; esac
  shift
  while [ $# -gt 0 ]; do
    case $1 in
      --) shift; break ;;
      -?*) case ${1#-} in *[!LPe@]*) break ;; esac; shift ;;
      *) break ;;
    esac
  done
  case $dc_h:$# in
    popd:0) dc_to=pop ;;
    cd:1) if [ "$1" = - ]; then dc_to=back; else dc_to=to; fi ;;
    cd:0) dc_to=to ;;
    pushd:1) dc_to=push ;;
    *) return 1 ;;
  esac
  dc_here=$CUR_CWD
  case $dc_to in
    to|push)
      if [ $# -eq 1 ]; then expand "$1"; dc_new=$R; else dc_new=$HOME_DIR; fi
      [ $dc_to = push ] && DIR_STACK=$DIR_STACK$NL+$dc_here
      CUR_CWD=$dc_new ;;
    back) [ "$OLD_SET" = 1 ] && CUR_CWD=$OLD_CWD ;;
    pop)
      if [ -n "$DIR_STACK" ]; then
        dc_top=${DIR_STACK##*"$NL"}
        DIR_STACK=${DIR_STACK%"$NL"*}
        CUR_CWD=${dc_top#+}
      fi ;;
  esac
  OLD_CWD=$dc_here; OLD_SET=1
  return 0
}

# dequote_cmd <text>: cmdline::dequote, into R.
dequote_cmd() {
  R=$1
  case $1 in
    *[\"\'\\]*)
      R=$(printf '%s\n' "$1" | LC_ALL=C sed \
        -e "s/'\\([^'\"[:space:]]*\\)'/\\1/g" \
        -e "s/\"\\([^'\"[:space:]]*\\)\"/\\1/g" \
        -e 's/\\\([A-Za-z0-9_./-]\)/\1/g') ;;
  esac
}

# Every check here needs a curl/wget download, deno, an install verb, npm
# exec|x, bun x, uv tool run or a sigil call in the command. Command words
# are compared after quote removal, as the shell and hook.rs's tokenizer see
# them (`cu''rl`, `c\url` and `"curl"` are all curl), so the pre-filter
# looks at the command with quotes and backslashes dropped. Without awk the
# lexer yields nothing and these checks are skipped.
LEX=''
LEX_TXT=$CMD
case $CMD in
  *[\"\'\\]*) LEX_TXT=$(printf '%s' "$CMD" | tr -d "\"'\\\\") ;;
esac
RESID_ON=0
case $LEX_TXT in *sigil*) RESID_ON=1 ;; esac
case $LEX_TXT in
  *curl*|*wget*|*deno*|*install*|*npm*[[:space:]]exec*|*npm*[[:space:]]x*|*bun*[[:space:]]x*|*uv*tool*run*|*sigil*|*/npx*|*/bunx*|*/uvx*|*/pipx*|*/pnpm*|*/yarn*)
    LEX=$(printf '%s\n' "$CMD" | LC_ALL=C awk "$LEX_AWK" 2>/dev/null) || LEX='' ;;
esac
[ -n "$LEX" ] || RESID_ON=0
UNTRUSTED=0
if [ -n "$LEX" ]; then
  has "$REDEFINE_RE" && UNTRUSTED=1
fi
GATES=''
DOWNLOADS=''
# Files downloaded in the current and-or list, and those downloaded in a list
# that & sent to the background: a scan may read one before its download
# ends, so no scan vets it until a `wait` (hook.rs Walk::unsettled).
LIST_DL=''
UNSETTLED=''
GATED_REASON=''
SIGIL_SEEN=0
RESID=''
PIP_NAMED=0
SKIP_SEG=0
GRP_STACK=''
DIR_STACK=''
OLD_CWD=''; OLD_SET=0
DEPTH=0
NOVET=0
SEG_TEXT=''; SEG_FED=0; SEG_SOURCES=''; SEG_EXEC=0; SEG_INSUB=0
STDIN_FED=0; SEG_PFED=0; LAST_IN=0; LAST_OUT=0; SEG_FEDIN_K=' '; FED_DEPTH=''
st_reset
IFS=$NL
for REC in $LEX; do
  IFS=$US
  # shellcheck disable=SC2086 # split the record into its fields
  set -- $REC
  IFS=$IFS_DEFAULT
  [ $# -ge 1 ] || continue
  REC_KIND=$1
  shift
  case $REC_KIND in
    S)
      # S op opens exec text words. `;`, `||`, newlines (O) and `&` (G) end
      # the && chain; a substitution (U, B) runs as part of the command
      # around it, so it neither ends the chain nor starts one. It is a
      # subshell (= on the group stack), which a closing backtick (b) or its
      # `)` (E) ends; so is a `( … )` group (+). A list that `&` ends ran in
      # a background subshell (`cd /tmp & …`): its cd ends with it.
      [ "${1-}" = G ] && { CUR_CWD=$LIST_CWD; UNSETTLED=$UNSETTLED$NL$LIST_DL; }
      case ${1-} in O|G) LIST_DL='' ;; esac
      case ${1-} in O|G) GATES=''; LIST_CWD=$CUR_CWD ;; esac
      case ${1-} in
        U|u|B) GRP_STACK=$GRP_STACK$NL=$CUR_CWD ;;
        b) grp_pop ;;
      esac
      # What the segment reads on stdin: a substitution reads what the
      # command around it gives it (its stdin for $( <( and backticks, its
      # output for >( ); anything else, the command line's own stdin (the
      # download, for the string of a `bash -c` fed from one).
      case ${1-} in
        U|B) SEG_PFED=$LAST_IN ;;
        u) SEG_PFED=$LAST_OUT ;;
        *) SEG_PFED=$STDIN_FED; [ -n "$FED_DEPTH" ] && SEG_PFED=1 ;;
      esac
      LAST_IN=0; LAST_OUT=0; SEG_FEDIN_K=' '
      rc_n=${2-0}
      while [ "$rc_n" -gt 0 ]; do GRP_STACK=$GRP_STACK$NL+$CUR_CWD; rc_n=$((rc_n - 1)); done
      # Inside a substitution no sigil call vets: its status is not the
      # command's (`echo $(sigil scan x) && bash x`).
      SEG_INSUB=$NOVET
      case "$NL$GRP_STACK" in *"$NL="*) SEG_INSUB=1 ;; esac
      SEG_EXEC=${3-0}
      SEG_TEXT=${4-}; SEG_FED=$SEG_PFED; SEG_SOURCES=''
      if [ $# -ge 4 ]; then shift 4; else set --; fi
      SKIP_SEG=0
      # `cd dir`, `pushd dir`, `popd`: where later segments run.
      dir_change "$@" && SKIP_SEG=1
      st_reset ;;
    O) ST_OUTS=$ST_OUTS$NL${1-} ;;
    I) ST_INK=F; ST_IN=${1-} ;;
    J) ST_INK=I ;;
    X) ST_X=${1-} ;;
    R) ST_R=1 ;;
    D) ST_D=$ST_D$NL${1-} ;;
    F) ST_F=1 ;;
    C) ST_C=$ST_C$NL${1-} ;;
    Z) ST_Z=$ST_Z$NL${1-} ;;
    N) ST_N=${1-} ;;
    Y) ST_Y=$ST_Y$NL${1-} ;;
    W) ST_W=${REC#W"$US"}; [ "$REC" = W ] && ST_W='' ;;
    V) ST_V=1 ;;
    K) ST_K=1 ;;
    H) ST_H=1 ;;
    L) ST_L=1 ;;
    G) ST_OPENS=${1-0}; ST_CLOSES=${2-0} ;;
    M) ST_M=$ST_M$NL${1-} ;;
    T)
      # Whether the stage's stdin carries a download, before judging it.
      ST_FEDIN=0
      [ "$SEG_FED" = 1 ] && [ -z "$ST_INK" ] && ST_FEDIN=1
      ST_FEDB=$SEG_FED
      JS_SIGIL=0
      if [ $SKIP_SEG = 0 ]; then
        judge_stage "$@"
        # `wait`: the background downloads have ended.
        case $ST_W in wait|"wait$US"*) UNSETTLED='' ;; esac
        if [ "$JS_SIGIL" = 0 ]; then
          [ $ST_FEDIN = 1 ] && SEG_FEDIN_K="$SEG_FEDIN_K${1-} "
          # A substitution that closes the segment opens in its last stage.
          case ${2-} in *l*) LAST_IN=$ST_FEDIN; LAST_OUT=$SEG_FED ;; esac
        fi
        # A compound command whose stdin is a download (`curl … | { echo;
        # bash; }`, `… | while read l; do eval "$l"; done`): every command
        # in it reads that stdin, until it closes (FED_DEPTH: how many of
        # the groups opened since are open).
        if [ -n "$FED_DEPTH" ]; then
          FED_DEPTH=$((FED_DEPTH + ST_OPENS - ST_CLOSES))
          [ "$FED_DEPTH" -gt 0 ] || FED_DEPTH=''
        elif [ "$ST_FEDB" = 1 ] && [ "$ST_OPENS" -gt "$ST_CLOSES" ]; then
          FED_DEPTH=$((ST_OPENS - ST_CLOSES))
        fi
      fi
      # A sourced file can define a sigil function or change PATH: no sigil
      # call after it vets anything.
      [ "$ST_V" = 1 ] && [ $SKIP_SEG = 0 ] && UNTRUSTED=1
      st_reset ;;
    P)
      # A `bash -c` string: its own `cd`s and groups end with it. It reads
      # the stdin of the stage that hands it over (P k inherits).
      DEPTH=$((DEPTH + 1))
      # A string handed over inside a substitution vets nothing either.
      eval "FR_CWD_$DEPTH=\$CUR_CWD; FR_GRP_$DEPTH=\$GRP_STACK; FR_NOVET_$DEPTH=\$NOVET; FR_INSUB_$DEPTH=\$SEG_INSUB; FR_LIST_$DEPTH=\$LIST_CWD; FR_SFED_$DEPTH=\$STDIN_FED; FR_LIN_$DEPTH=\$LAST_IN; FR_LOUT_$DEPTH=\$LAST_OUT; FR_FEDK_$DEPTH=\$SEG_FEDIN_K; FR_FDEP_$DEPTH=\$FED_DEPTH"
      NOVET=$SEG_INSUB
      LIST_CWD=$CUR_CWD
      STDIN_FED=0; FED_DEPTH=''
      case "$SEG_FEDIN_K" in *" ${1-x} "*) [ "${2-0}" = 1 ] && STDIN_FED=1 ;; esac
      GRP_STACK='' ;;
    Q)
      eval "CUR_CWD=\$FR_CWD_$DEPTH; GRP_STACK=\$FR_GRP_$DEPTH; NOVET=\$FR_NOVET_$DEPTH; SEG_INSUB=\$FR_INSUB_$DEPTH; LIST_CWD=\$FR_LIST_$DEPTH; STDIN_FED=\$FR_SFED_$DEPTH; LAST_IN=\$FR_LIN_$DEPTH; LAST_OUT=\$FR_LOUT_$DEPTH; SEG_FEDIN_K=\$FR_FEDK_$DEPTH; FED_DEPTH=\$FR_FDEP_$DEPTH"
      DEPTH=$((DEPTH - 1)) ;;
    E)
      rc_n=${1-0}
      while [ "$rc_n" -gt 0 ]; do grp_pop; rc_n=$((rc_n - 1)); done ;;
  esac
  IFS=$NL
done
IFS=$IFS_DEFAULT

# ── ASK: a sigil call that lets package code run before its scan ──────────
# `sigil pip|npm … --allow-build-scripts` lets pip or npm run the package's
# own setup or lifecycle scripts on this machine before the scan: the
# user's decision, not an agent's (hook.rs build_scripts_opt_in). This ask is
# the one layer aimed at an agent, and it is advisory: the CLI's own
# confirmation (a prompt at a terminal, or SIGIL_ALLOW_BUILD_SCRIPTS=1) stops
# accidents and unattended runs, but anything that opens a pseudo-terminal
# and answers, or sets the variable, passes it, and a pattern reader cannot
# see a flag a program builds at run time. This file reads the shapes hook.rs
# reads, with sed, awk and extended regular expressions; it is a coarser
# reading (it can ask where hook.rs allows), and nested-shell-agreement.py
# measures where the two differ. Fail-safe, not exact: where the text could
# mean the flag, it asks. Views of the command: as written (the line
# continuations joined and the `# comments` dropped by awk, as hook.rs does:
# a `#` starts a comment only at the start of a word, not after an escaped
# blank, not inside `${…}`, not glued to `)`, `<` or `>`; a backslash at the
# end of a comment's line does not continue it), with quotes removed from
# runs of plain word characters only (so a quoted `">"` or `"$X"` keeps its
# quotes), with the quotes of a string a shell hands to an interpreter
# unspliced (`'\''`, `'"'"'`, `\"`), with up to three layers of double-quote
# escaping undone (`\\` is `\`, `\$` is `$`), with every quote and backslash
# removed (only the rules that look for the flag itself read this one), and
# with the `;` `&` `|` `#` and line ends inside a quoted word masked
# (hook.rs mask_quoted_separators). A `--` word of its own inside a quoted
# string, or the file of a redirection (`> --`, `<<< --`), does not end the
# options.
#  1. FLAT: a `pip` or `npm` word, then, before a `--` word of its own, a
#     word starting with --allow-build-scripts, however the words between
#     them are quoted or separated (`sigil npm './a;b' --allow-build-scripts`,
#     an argv list over several lines) and however the command word before
#     `pip`/`npm` is spelled (`si${E}gil npm …`, `sig$(true)il npm …`). It
#     asks about more than the shell would run, never less.
#  2. ENV: the variable the CLI accepts in place of a terminal. Its name with
#     anything glued to it and then `=`; the first part of its name
#     (SIGIL_ALLOW_BUILD) next to a word that sets a variable by name
#     (export declare typeset readonly local printf read mapfile eval); an
#     assignment with an expansion in its name in a call with export,
#     declare, env, eval and the like (`export "$V=1"`).
#  3. What FLAT cannot see.
#     a. The flag after a command word that is or may be sigil, wherever the
#        subcommand is: `sigil`, or a word with an expansion, a glob
#        character, a backslash or a pair of quotes in it (`$S`, `si${E}gil`,
#        `s\igil`), then, before a `--`, a `# comment` or a `;`/`&`/`|`, a
#        word starting with `--allow-b` or a brace expansion or glob that
#        holds a piece of the flag's name.
#     b. `sigil`, its global options (-v, -f X, --format X|=X, -o X, --rules X,
#        --yara-engine X, --config X), then `pip` or `npm`, or a word that may
#        expand to one where the subcommand goes (an expansion, a quote, a
#        backslash, a glob, `{pip,npm}`), then a word starting with
#        --allow-build-scripts (a glued redirection included) or a word the
#        shell may expand to it: one with a `$` or backtick, or one that
#        begins like an option or a pattern (`-`, `{`, `*`, `?`, `[`) and
#        holds a brace expansion (`--allow-build-{scripts,x}`) or a glob
#        (`--allow-build-s*`, `--allow-build-scr?pts`,
#        `--allow-build-scr[i]pts`). Words are split at `[ ] ( ) ,` as well
#        as whitespace; the `&` or `|` of a redirection (`2>&1`, `&>f`, `>|f`)
#        does not end the call. A redirection and its file (`> "$LOG"`, a
#        lone `--` too) and one quoted word after -V/--version (`-V "$VER"`,
#        its value) are dropped first.
#     c. xargs: a sigil call behind it with pip/npm or a word that may be
#        one, with a replace option (-I, -i) before the sigil word, or with
#        no subcommand at all; or an xargs command that is an expansion. This
#        is coarser than hook.rs, which asks about a replace string only where
#        it stands in the subcommand place or after pip/npm.
# Every allow below becomes this ask; a deny still wins. Not read: a flag a
# program builds at run time, a file or variable the call takes its
# arguments from, a call a script or alias makes without the words
# appearing in the command (a script written by one tool call and run by
# the next), a command word and a subcommand that are both bare expansions
# with the flag in a third (`$S $M x $F`). Without awk, a `# comment` is not
# dropped, no quoted word is masked, and a line continuation after a comment
# is joined.
OPTIN=0
OPTIN_Q='\(["'\'']\)[^"'\''[:space:]]*\1'
# optin_prep <text>: R is the text with each redirection and its file
# dropped, and one quoted word after -V/--version replaced. A here-string's
# text is kept (a shell may run it: `bash <<< "sigil pip …"`), as are a
# process or command substitution in a file (`<(…)`, `> "$(…)"`), whose
# command runs.
optin_prep() {
  R=$(printf '%s\n' "$1" | LC_ALL=C sed \
    -e 's/^/ /' \
    -e 's/<<<[[:space:]]*--\([[:space:]]\)/ HERESTRING \1/g' \
    -e 's/<<</ HERESTRING /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*&>>[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*&>[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*>>[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*>|[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*>&[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*<<-*[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*<>[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*<&[[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e 's/[[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9]*[<>][[:space:]]*[^[:space:];&|(`<>]*/ /g' \
    -e "s/[[:space:]]-V[[:space:]][[:space:]]*$OPTIN_Q/ -V V/g" \
    -e "s/[[:space:]]-V=$OPTIN_Q/ -V V/g" \
    -e "s/[[:space:]]-V$OPTIN_Q/ -V V/g" \
    -e "s/[[:space:]]--version[[:space:]][[:space:]]*$OPTIN_Q/ -V V/g" \
    -e "s/[[:space:]]--version=$OPTIN_Q/ -V V/g")
}
# optin_dq <text>: DQ is the text with quotes removed from each run of
# plain word characters (hook.rs dequote_literals).
OPTIN_LIT='[^]'\''"[:space:]$`<>&|;()[,]*'
optin_dq() {
  DQ=$1
  case $1 in
    *[\"\'\\]*)
      DQ=$(printf '%s\n' "$1" | LC_ALL=C sed \
        -e "s/'\\($OPTIN_LIT\\)'/\\1/g" \
        -e "s/\"\\($OPTIN_LIT\\)\"/\\1/g" \
        -e 's/\\\([A-Za-z0-9_./-]\)/\1/g') ;;
  esac
}
# optin_unsplice <text>: UNS is the text a shell hands to an interpreter
# when the interpreter's own quotes sit inside a quoted string (hook.rs
# unsplice_quotes): `'\''` and `'"'"'` are one `'`, `\"` and `\'` a quote.
optin_unsplice() {
  UNS=$1
  OPTIN_SQ="'"; OPTIN_BS='\'
  case $1 in
    *\\*|*\"*)
      UNS=$(printf '%s\n' "$1" | LC_ALL=C sed \
        -e "s/${OPTIN_SQ}${OPTIN_BS}${OPTIN_BS}${OPTIN_SQ}${OPTIN_SQ}/${OPTIN_SQ}/g" \
        -e "s/${OPTIN_SQ}\"${OPTIN_SQ}\"${OPTIN_SQ}/${OPTIN_SQ}/g" \
        -e 's/\\"/"/g' \
        -e "s/${OPTIN_BS}${OPTIN_BS}${OPTIN_SQ}/${OPTIN_SQ}/g") ;;
  esac
}
# optin_lex <strip|mask> <text>: LX is the text with each `# comment`
# outside quotes dropped and, in mask mode, the `;` `&` `|` `#` and line
# ends inside a quoted word replaced (hook.rs mask_quoted_separators); a
# quoted string that holds a `pip` or `npm` word is a script, whose
# separators are real, and is read through. The text unchanged without awk.
# shellcheck disable=SC2016 # an awk program, not shell
OPTIN_AWK='
function mentions(s) { return s ~ /(^|[^A-Za-z0-9_.-])(pip|npm)([^A-Za-z0-9_.-]|$)/ }
function closing(s, n, open,   q, j, c) {
  q = substr(s, open, 1)
  for (j = open + 1; j <= n; j++) {
    c = substr(s, j, 1)
    if (q == DQ && c == "\\") { j++; continue }
    if (c == q) return j
  }
  return 0
}
# A `--` word of its own inside a quoted string is a piece of the string, not
# the end of the options: it becomes `-_`.
function neutral(t,   o, p, L, c) {
  o = ""; L = length(t); p = 1
  while (p <= L) {
    c = substr(t, p, 1)
    if (c == "-" && substr(t, p + 1, 1) == "-" && (p == 1 || substr(t, p - 1, 1) ~ /[ \t\n]/) && (p + 2 > L || substr(t, p + 2, 1) ~ /[ \t\n]/)) { o = o "-_"; p += 2 }
    else { o = o c; p++ }
  }
  return o
}
BEGIN { SQ = sprintf("%c", 39); DQ = "\""; buf = ""; seen = 0 }
{ buf = (seen ? buf "\n" : "") $0; seen = 1 }
END {
  s = buf; n = length(s); out = ""; depth = 0; tdepth = 0; i = 1; esc = 0; brace = 0
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == "\\") {
      e = substr(s, i + 1, 1)
      if (mode == "mask" && (e == ";" || e == "&" || e == "|" || e == "#")) e = "_"
      out = out c e; esc = i + 1; i += 2; continue
    }
    if (c == SQ || c == DQ) {
      if (i in closes) { out = out c; i++; tdepth--; continue }
      j = closing(s, n, i)
      if (j > 0) {
        inner = substr(s, i + 1, j - i - 1)
        if (mode == "mask" && mentions(inner)) { closes[j] = 1; tdepth++; out = out c; i++; continue }
        if (mode == "mask" && !mentions(inner)) { gsub(/[;&|#]/, "_", inner); gsub(/\n/, " ", inner) }
        out = out c neutral(inner) c; i = j + 1; continue
      }
      out = out c; i++; continue
    }
    if (c == "#" && tdepth == 0 && brace == 0 && (i == 1 || (substr(s, i - 1, 1) ~ /[ \t\n;&|]/ && esc != i - 1))) {
      while (i <= n && substr(s, i, 1) != "\n") i++
      continue
    }
    if (c == "{" && i > 1 && substr(s, i - 1, 1) == "$" && esc != i - 1) brace++
    else if (c == "}" && brace > 0) brace--
    if (tdepth > 0 && c == "-" && substr(s, i + 1, 1) == "-" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t\n]/) && (i + 2 > n || substr(s, i + 2, 1) ~ /[ \t\n]/)) { out = out "-_"; i += 2; continue }
    if (c == "[") depth++
    else if (c == "]") { if (depth > 0) depth-- }
    else if (c == "\n" && depth > 0 && mode == "mask") c = " "
    out = out c; i++
  }
  printf "%s\n", out
}'
optin_lex() {
  LX=$2
  if [ -n "$LEX_HAS_AWK" ]; then
    LX=$(printf '%s\n' "$2" | LC_ALL=C awk -v mode="$1" "$OPTIN_AWK" 2>/dev/null) || LX=$2
  fi
}
# optin_view <text>: add the text to the views the rules read: OPTIN_ALL
# (redirections and a -V value dropped; a line is the unit the rules match
# in, so a line end ends a call) and OPTIN_FLAT (the text on one line).
OPTIN_ALL=''
OPTIN_FLAT=''
# A redirection's file that is a lone `--` (`> --`, `3> --`, `{fd}> --`,
# `<<< --`) is a file, not the end of the options: it becomes `-_` (twice, as a
# match takes the blank after the file, which the next redirection needs).
OPTIN_DASHOPND='s/\([[:space:]]\({[A-Za-z_][A-Za-z0-9_]*}\)*[0-9&]*[<>][<>|&]*[[:space:]]*\)--\([[:space:]]\)/\1-_\3/g'
optin_view() {
  optin_prep "$1"
  OPTIN_ALL=$OPTIN_ALL$NL$R
  FL=$(printf '%s\n' "$1" | tr '\n' ' ' | LC_ALL=C sed -e "$OPTIN_DASHOPND" -e "$OPTIN_DASHOPND")
  OPTIN_FLAT=$OPTIN_FLAT$NL$FL
}
# optin_bare <text>: the text without any quote or backslash, in OPTIN_BARE
# (the rules that look for the flag itself read it, not the ones that look
# for an expansion: a quoted "$VER" would read as one that may split).
OPTIN_BARE=''
optin_bare() {
  BR=$(printf '%s\n' "$1" | tr -d "\"'\\\\")
  optin_prep "$BR"
  OPTIN_BARE=$OPTIN_BARE$NL$R
}
# optin_unescape <text>: UNE is the text with one layer of double-quote
# escaping undone (hook.rs unescape_layer): a backslash before a backslash,
# `$`, a backtick or `"` is dropped.
optin_unescape() {
  UNE=$1
  case $1 in
    *\\*)
      UNE=$(printf '%s\n' "$1" | LC_ALL=C sed -e 's/\\\([\\$`"]\)/\1/g') ;;
  esac
}
# optin_views1 <text>: the text, dequoted, unspliced, and unspliced and
# dequoted (the last two when the quotes of a string handed to an
# interpreter change it), and the bare text.
optin_views1() {
  optin_view "$1"
  optin_bare "$1"
  optin_dq "$1"; [ "$DQ" = "$1" ] || optin_view "$DQ"
  optin_unsplice "$1"
  if [ "$UNS" != "$1" ]; then
    optin_view "$UNS"
    optin_dq "$UNS"; [ "$DQ" = "$UNS" ] || optin_view "$DQ"
  fi
}
# optin_views <text>: the views of the text, and of the text a second shell
# reads once up to three layers of double-quote escaping are off it (hook.rs
# build_scripts_opt_in).
optin_views() {
  optin_views1 "$1"
  ov_layer=$1; ov_k=0
  while [ "$ov_k" -lt 3 ]; do
    optin_unescape "$ov_layer"
    [ "$UNE" = "$ov_layer" ] && break
    optin_views1 "$UNE"
    ov_layer=$UNE; ov_k=$((ov_k + 1))
  done
}
optin_has() {
  has_in "$OPTIN_ALL" "$1"
}
optin_bare_has() {
  has_in "$OPTIN_BARE" "$1"
}
OPTIN_C='([^][(),[:space:];&|]|[<>][&|]|&>)'
OPTIN_F='([^]#[(),[:space:];&|-]|[<>][&|]|&>)'
OPTIN_S='[][(),[:space:]]+'
OPTIN_W="(-|-?${OPTIN_F}${OPTIN_C}*|--${OPTIN_C}+)"
# A shell word's characters: not whitespace, `;&|` or a parenthesis (a `,`
# and `[]` stay in it: `--allow-build-{scripts,x}`).
OPTIN_P='[^][:space:];&|()]'
# A brace expansion inside a shell word: `{a,b}`, `{1..3}`.
OPTIN_BR="\\{${OPTIN_P}*(,|\\.\\.)${OPTIN_P}*\\}"
# `sigil` as a command word: the word, `/usr/bin/sigil`, `$(command -v
# sigil)` and `sigil.exe` too.
OPTIN_NAMED="(^|[^[:alnum:]_.-])sigil(\\.exe)?[)\`\"']*"
# A command word the shell may spell `sigil`: one with an expansion, a glob
# character, a backslash, or a pair of quotes (`$S`, `si${E}gil`, `sig?l`,
# `s\igil`, `'sigil'`).
OPTIN_SPELLED="(^|[][(),[:space:];&|])(${OPTIN_C}*[\$\`\\\\*?]${OPTIN_C}*|${OPTIN_C}*\"${OPTIN_C}*\"${OPTIN_C}*|${OPTIN_C}*'${OPTIN_C}*'${OPTIN_C}*)"
# A global option of sigil and its value (hook.rs global_option_words):
# `-v`, `--verbose`, `-f X`, `-fX`, `--format X`, `--format=X`, and `-o`,
# `--rules`, `--yara-engine`, `--config` alike; short options may be clustered.
OPTIN_G="(-v+|--verbose|(--(format|output|rules|yara-engine|config)|-[vfo]*[fo])${OPTIN_S}${OPTIN_C}+|--(format|output|rules|yara-engine|config)=${OPTIN_C}*|-[vfo]*[fo]${OPTIN_C}+)"
# `sigil`, any global options, then `pip` or `npm` (a piece of a brace
# group too: `{sigil,pip}`), or a command word that is an expansion.
OPTIN_SUB="(^|[^[:alnum:]_.-])(sigil(\\.exe)?[)\`\"']*(${OPTIN_S}${OPTIN_W})*|${OPTIN_C}*[\$\`*?\"'\\\\]${OPTIN_C}*)${OPTIN_S}[\"'{]*(pip|npm)[\"'}]*"
# `sigil`, its global options, and where the subcommand goes a word that may
# expand to `pip`/`npm`: an expansion, a quote, a backslash, a glob or a brace
# expansion (`$SUB`, `$'npm'`, `n\pm`, `np${x}m`, `{pip,npm}`).
OPTIN_SUBX="${OPTIN_NAMED}(${OPTIN_S}${OPTIN_G})*${OPTIN_S}(${OPTIN_C}*[\$\`\\\\'\"{*?]${OPTIN_C}*)"
# A word after it that is the flag, or may expand to it: `$` or a backtick.
OPTIN_FLAG="${OPTIN_S}([\"']*--allow-build-scripts|${OPTIN_C}*[\$\`])"
# A word that starts like the flag or that a brace expansion or a glob may
# make one (hook.rs flag_like): `--allow-build-${F}`, `{--allow-build-scripts,}`,
# `--allow-build-s*`, `[-]-allow-build-scripts`, `--allow-{build,x}-scripts`.
OPTIN_FLAGA="${OPTIN_S}[\"']*[][{}*?-]*allow-[b{*?[]"
# A shell word that begins like an option or a pattern (`-`, `{`, `*`, `?`,
# `[`) and holds a brace expansion or a glob, which the shell may expand to
# the flag. A bracket pattern counts in a word that starts with `-`
# (`--allow-build-scr[i]pts`) or opens with `[-`, `[!` or `[^`; `['sigil'`
# and `[sigil,pip]` are the elements of an argv list.
OPTIN_PAT="[[:space:]()][\"']*((-${OPTIN_P}*)?(${OPTIN_BR}|[*?])|-${OPTIN_P}*\\[[^]'\"[:space:];&|()]|\\[[-!^])"
# A brace group where the subcommand goes (`sigil {pip,npm} x`,
# `sigil {pip,--allow-build-scripts} evil`): its pieces are separate words
# once the shell expands it, the flag among them. hook.rs reads the first
# word after `sigil` that begins like an option or a pattern and holds a
# brace expansion, and a brace group after the global options whose first
# piece is `pip` or `npm`, as a pattern word that follows the subcommand.
OPTIN_BRM="(^|[^[:alnum:]_.-])sigil(\\.exe)?[)\`\"']*(${OPTIN_S}[\"']*((-|\\*|\\?)${OPTIN_P}*)?${OPTIN_BR}|(${OPTIN_S}${OPTIN_W})*${OPTIN_S}[\"']*[-{*?]${OPTIN_P}*(pip|npm)[\"'}]*,${OPTIN_P}*)"
# FLAT: the delimiters are whitespace and `;&|()[],`; a word is the run of
# anything else. A word that is not exactly `--`: a first character that is
# not `-`, a lone `-`, `-` and a non-dash, or `--` and more.
OPTIN_D='[][(),[:space:];&|]'
OPTIN_N='[^][(),[:space:];&|]'
OPTIN_ND='[^][(),[:space:];&|-]'
OPTIN_TOK="(${OPTIN_ND}${OPTIN_N}*|-|-${OPTIN_ND}${OPTIN_N}*|--${OPTIN_N}+)"
OPTIN_FLATRE="(^|${OPTIN_D})[\"'{]*(pip|npm)[\"'}]*${OPTIN_D}+(${OPTIN_TOK}${OPTIN_D}+)*[\"']*--allow-build-scripts"
# The confirmation variable (hook.rs sets_opt_in_env): its name with anything
# glued to it and then `=`; its first part next to a word that sets a
# variable by name; an assignment with an expansion in its name in a call
# with `export`, `env` or the like.
OPTIN_ENVRE='SIGIL_ALLOW_BUILD[^][(),[:space:];&|<>]*='
OPTIN_ENVPFX='SIGIL_ALLOW_BUILD'
OPTIN_ENVNAMER="(^|[][(),[:space:];&|\"'])(export|declare|typeset|readonly|local|printf|read|mapfile|readarray|eval)([][(),[:space:];&|\"']|\$)"
OPTIN_ENVBUILT="(^|[][(),[:space:];&|\"'])(export|declare|typeset|readonly|local|env|eval)([][(),[:space:]\"']+[^;&|]*)?[][(),[:space:]\"']+[\"']*[^[:space:];&|=\"']*[\$\`][^[:space:];&|=]*="
# 4. A nested shell (hook.rs nested_obscured_call, which this mirrors).
#    A double-quoted string keeps `\c` as it is, and the shell it is handed
#    to reads the unquoted text and drops the backslash:
#    `bash -c "`which sigil` pip x --allow-build-s\\cripts"` hands that shell
#    `s\cripts`, which it reads as `scripts` (and `np\\m` is `npm` to it). No
#    reading of the outer command knows what an inner one runs, and the
#    spellings are endless, so rather than chase them a `sigil`, `pip` or
#    `npm` word (a maximal run of [A-Za-z0-9_.-]; a `sigil` followed by a
#    plain word of another subcommand, `sigil scan …`, past its global
#    options, is not one) asks when
#     - it sits in a quoted string (the outermost '…' or "…" of the command,
#       a backslash escaping a character outside single quotes) and the
#       command holds a shell anywhere (a word that is sh bash dash zsh ksh
#       mksh ash csh tcsh fish busybox rbash rksh rzsh posh yash pdksh oksh
#       ssh su runuser eval source trap watch script flock or parallel, with
#       a version or extension after it (ksh93, bash.exe), $SHELL, $BASH, a
#       `.` of its own; also with its quotes and backslashes removed:
#       b"as"h), a -c-like flag with a quote or `$` or backtick after it
#       (`$B -c "…"`), or text piped (`|`, `|&`) or fed by a here-document or
#       here-string to a command that is not a known filter (cat tee grep
#       sed awk cut sort uniq wc head tail tr jq … and another language's
#       interpreter are; `rbash`, `$0`, `exec sh` are not), or
#     - it is unquoted and a shell stands in its own simple command (after
#       the last `;` `&` `|` `(` or line end), or text goes to a command that
#       is not a known filter (`printf … | sh`, `… | $0`), or the command holds
#       a `<<` and a shell as above, or its simple command holds a `$`,
#       backtick, `{`, `*` or `?` in front of it (a command word the shell
#       expands, `${S} --format json pip`);
#    and, for a `pip` or `npm` word, the words of its simple command in front
#    of it (after the last `;` `&` `|` `(` or line end, quoted or not) hold
#    `sigil` or one of \ ' " $ ` { * ? [ (a word the shell may spell `sigil`);
#    a `sigil` word needs nothing; and the text after the word, to the end of
#    its call (the next `;`, line end, `)`, `&` or `|`; past the end of its
#    quoted string if the call goes on), holds one of \ ' " $ ` { * ? [. The
#    quote that opens the string holding the word and the one that closes it
#    do not count. Over-asking is the intended failure. Without awk the same
#    is read coarsely, as a superset: a shell anywhere, then `sigil`, `pip` or
#    `npm`, then one of those characters.
NS_SQ="'"
NS_OBS_ERE="[\$\`\\\\${NS_SQ}\"*?[{]"
NS_NAMES='sh bash dash zsh ksh mksh ash csh tcsh fish busybox rbash rksh rzsh posh yash pdksh oksh ssh su runuser eval source trap watch script flock parallel'
NS_SHELLS='sh bash dash zsh ksh mksh ash csh tcsh fish busybox rbash rksh rzsh posh yash pdksh oksh'
NS_SHELL_ERE="(^|[^A-Za-z0-9_.-])(sh|bash|dash|zsh|ksh|mksh|ash|csh|tcsh|fish|busybox|rbash|rksh|rzsh|posh|yash|pdksh|oksh|ssh|su|runuser|eval|source|trap|watch|script|flock|parallel)[0-9.]*([^A-Za-z0-9_-]|\$)|[\$][{]?(SHELL|BASH)[}]?|(^|[[:space:];&|(])[.]([[:space:]]|\$)"
NS_DASHC_ERE="(^|[[:space:]])-[A-Za-z]*c([[:space:]]*[\"${NS_SQ}\$\`]|[\"${NS_SQ}\$\`])"  # coarse: any program
NS_COARSE_ERE="(^|[^A-Za-z0-9_.-])(sigil|pip|npm)([^A-Za-z0-9_.-]|\$).*${NS_OBS_ERE}"
# shellcheck disable=SC2016 # an awk program, not shell
NS_AWK='
function named(word, list,   k, nm, rest) {
  nm = split(list, names, " ")
  for (k = 1; k <= nm; k++) {
    if (substr(word, 1, length(names[k])) == names[k]) {
      rest = substr(word, length(names[k]) + 1)
      while (rest ~ /^[0-9]/) rest = substr(rest, 2)
      if (rest == "" || substr(rest, 1, 1) == ".") return 1
    }
  }
  return 0
}
function wordc(c) { return index(WORDCH, c) > 0 }
function opens(t) { return t != "" && index(DQ SQ "$`", substr(t, 1, 1)) > 0 }
# dashc(s): a -c-like flag followed by a quote or an expansion, on a program
# that is not an interpreter of another language.
function dashc(s,   nt, k, t, body, l, flag, rest, more, prog, b, j, q) {
  nt = 0; k = 1; q = length(s)
  while (k <= q) {
    while (k <= q && index(" \t\n", substr(s, k, 1)) > 0) k++
    if (k > q) break
    j = k
    while (j <= q && index(" \t\n", substr(s, j, 1)) == 0) j++
    tok[++nt] = substr(s, k, j - k); k = j
  }
  for (k = 1; k <= nt; k++) {
    t = tok[k]
    if (substr(t, 1, 1) != "-") continue
    body = substr(t, 2); l = 0
    while (l < length(body) && index(LETTERS, substr(body, l + 1, 1)) > 0) l++
    flag = substr(body, 1, l); rest = substr(body, l + 1)
    if (substr(flag, length(flag), 1) != "c" || flag == "") continue
    more = (rest == "") ? opens(tok[k + 1]) : opens(rest)
    if (!more) continue
    prog = (k > 1) ? tok[k - 1] : ""
    while (substr(prog, 1, 1) == DQ || substr(prog, 1, 1) == SQ) prog = substr(prog, 2)
    while ((b = index(prog, "/")) > 0) prog = substr(prog, b + 1)
    for (b = 1; b <= 12; b++) if (NOTSH[b] != "" && substr(prog, 1, length(NOTSH[b])) == NOTSH[b]) break
    if (b <= 12) continue
    return 1
  }
  return 0
}
# gopt(a): how many words the global option a of sigil takes (hook.rs
# global_option_words): 1 alone, 2 with a value word after it, 0 for a word
# that is not an option.
function gopt(a,   lng, name, eq, letters, k, ch) {
  if (substr(a, 1, 1) != "-" || a == "-" || a == "--") return 0
  if (substr(a, 1, 2) == "--") {
    lng = substr(a, 3); eq = index(lng, "=")
    name = eq ? substr(lng, 1, eq - 1) : lng
    if (!eq && (name == "format" || name == "output" || name == "rules" || name == "yara-engine" || name == "config")) return 2
    return 1
  }
  letters = substr(a, 2)
  for (k = 1; k <= length(letters); k++) {
    ch = substr(letters, k, 1)
    if (ch == "v") continue
    if (ch == "f" || ch == "o") return (k == length(letters)) ? 2 : 1
    return 1
  }
  return 1
}
# sigil_call(s, e): may the sigil word that ends just before position e be a
# pip/npm call (hook.rs ns_sigil_call): what follows it, past its global
# options and their values, is not a plain word of another subcommand.
function sigil_call(s, e,   n, i, st, w, nxt, k) {
  n = length(s); i = e
  while (1) {
    while (i <= n && (substr(s, i, 1) == " " || substr(s, i, 1) == "\t")) i++
    st = i
    while (i <= n && index(OPTCH, substr(s, i, 1)) > 0) i++
    w = substr(s, st, i - st)
    nxt = substr(s, i, 1)
    if (w == "" || (i <= n && index(" \t\n;&|)", nxt) == 0)) return 1
    k = gopt(w)
    if (k == 1) continue
    if (k == 2) {
      while (i <= n && (substr(s, i, 1) == " " || substr(s, i, 1) == "\t")) i++
      while (i <= n && index(" \t\n;&|)", substr(s, i, 1)) == 0) i++
      continue
    }
    if (w == "pip" || w == "npm") return 1
    return (w !~ /^[a-z-]+$/)
  }
}
# knownf(w): a program known not to read its stdin or a here-document as a
# command line (hook.rs ns_known_filter).
function knownf(w,   b, k) {
  sub("^[" DQ SQ "]+", "", w)
  b = w
  while ((k = index(b, "/")) > 0) b = substr(b, k + 1)
  for (k = 1; k <= NFLT; k++) if (FLT[k] == b) return 1
  for (k = 1; k <= 12; k++) if (NOTSH[k] != "" && substr(b, 1, length(NOTSH[k])) == NOTSH[k]) return 1
  return 0
}
# firstword(s, from): the first word of the command that starts at from
# (blanks and assignments skipped), up to a blank or one of ;&|<>().
function firstword(s, from,   n, i, st, w) {
  n = length(s); i = from
  while (1) {
    while (i <= n && index(" \t\n", substr(s, i, 1)) > 0) i++
    st = i
    while (i <= n && index(" \t\n;&|<>()", substr(s, i, 1)) == 0) i++
    w = substr(s, st, i - st)
    if (w ~ /^[A-Za-z0-9_]+=/ && i <= n) continue
    return w
  }
}
# to_unknown(s): text piped (| |&) into a command that is not a known filter,
# or the input of a here-document or here-string of one (hook.rs
# ns_text_to_unknown): it may be a shell (| rbash, | $0, | exec sh).
function to_unknown(s,   n, k, c, pv, nx, sepc, start, from, w, hs, hu) {
  n = length(s); start = 1; k = 1; hs = 0; hu = 0
  while (k <= n) {
    c = substr(s, k, 1); pv = (k > 1) ? substr(s, k - 1, 1) : ""; nx = substr(s, k + 1, 1)
    sepc = 0
    if (c == ";" || c == "\n" || c == "(") sepc = 1
    else if (c == "&") sepc = !(pv == ">" || pv == "<" || nx == ">")
    else if (c == "|") sepc = (pv != ">")
    if (sepc) {
      if (c == "|" && nx != "|" && pv != "|") {
        from = (nx == "&") ? k + 2 : k + 1
        w = firstword(s, from)
        if (w != "" && !knownf(w)) return 1
      }
      start = k + 1
    } else if (c == "<" && nx == "<") {
      if (hs != start) { hs = start; w = firstword(s, start); hu = (w != "" && !knownf(w)) }
      if (hu) return 1
      while (k <= n && substr(s, k, 1) == "<") k++
      continue
    }
    k++
  }
  return 0
}
# shells(s, all, out): out[last position of an occurrence] = its first
# position; the number of occurrences.
function shells(s, all, out,   n, i, a, w, c, cnt, rest, br, t, nxt) {
  n = length(s); cnt = 0; i = 1; split("", out)
  while (i <= n) {
    c = substr(s, i, 1)
    if (wordc(c)) {
      a = i
      while (i <= n && wordc(substr(s, i, 1))) i++
      w = substr(s, a, i - a)
      if (named(w, all ? NAMES : SHELLS)) { out[i - 1] = a; cnt++ }
      else if (all && w == ".") {
        t = (a == 1) ? " " : substr(s, a - 1, 1)
        nxt = (i > n) ? " " : substr(s, i, 1)
        if ((t == " " || t == "\t" || t == "\n" || t == ";" || t == "&" || t == "|" || t == "(") && (nxt == " " || nxt == "\t" || nxt == "\n")) { out[i - 1] = a; cnt++ }
      }
    } else {
      if (all && c == "$") {
        rest = substr(s, i + 1, 7); br = 0
        if (substr(rest, 1, 1) == "{") { br = 1; rest = substr(rest, 2) }
        if (substr(rest, 1, 5) == "SHELL") { out[i + br + 5] = i; cnt++ }
        else if (substr(rest, 1, 4) == "BASH") { out[i + br + 4] = i; cnt++ }
      }
      i++
    }
  }
  return cnt
}
BEGIN {
  SQ = sprintf("%c", 39); DQ = "\""
  OBS = "$`\\" SQ DQ "{*?["
  EXPANDING = "$`{*?"
  WORDCH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
  LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  split("python node deno bun perl ruby php lua awk gawk mawk sed", NOTSH, " ")
  NFLT = split("cat tee grep egrep fgrep rg cut sort uniq wc head tail tr jq less more column fold fmt nl od xxd base64 sha256sum md5sum shasum xargs diff cmp comm paste rev tac yes true false echo printf test [", FLT, " ")
  OPTCH = WORDCH "="
  buf = ""; seen = 0
}
{ buf = (seen ? buf "\n" : "") $0; seen = 1 }
END {
  n = length(buf); nm = 0; i = 1
  while (i <= n) {
    if (wordc(substr(buf, i, 1))) {
      st = i
      while (i <= n && wordc(substr(buf, i, 1))) i++
      w = substr(buf, st, i - st)
      if (w == "pip" || w == "npm") { mgr[++nm] = st; alen[nm] = 3 }
      else if (w == "sigil" && sigil_call(buf, i)) { mgr[++nm] = st; alen[nm] = 5 }
    } else i++
  }
  if (nm == 0) { print 0; exit }
  sep[0] = 0; psep[0] = 0; obs[0] = 0; xp[0] = 0; sig[0] = 0
  for (k = 1; k <= n; k++) {
    c = substr(buf, k, 1)
    sep[k] = (c == ";" || c == "&" || c == "|" || c == "(" || c == "\n") ? k : sep[k - 1]
    psep[k] = (c == ";" || c == "&" || c == "|" || c == "\n") ? k : psep[k - 1]
    obs[k] = obs[k - 1] + (index(OBS, c) > 0 ? 1 : 0)
    xp[k] = xp[k - 1] + (index(EXPANDING, c) > 0 ? 1 : 0)
    sig[k] = (k >= 5 && substr(buf, k - 4, 5) == "sigil") ? k - 4 : sig[k - 1]
  }
  # stp[k]: where the call that starts at position k ends: the next ; line
  # end ) & (not that of 2>&1 <&0 &>f) or | (not that of >|); n + 1: none.
  stp[n + 1] = n + 1
  for (k = n; k >= 1; k--) {
    c = substr(buf, k, 1)
    pv = (k > 1) ? substr(buf, k - 1, 1) : ""
    nx = (k < n) ? substr(buf, k + 1, 1) : ""
    isstop = 0
    if (c == ";" || c == "\n" || c == ")") isstop = 1
    else if (c == "&") isstop = !(pv == ">" || pv == "<" || nx == ">")
    else if (c == "|") isstop = (pv != ">")
    stp[k] = isstop ? k : stp[k + 1]
  }
  occ = shells(buf, 1, ends)
  for (k = 1; k <= n; k++) shl[k] = (k in ends) ? ends[k] : shl[k - 1]
  shl[0] = 0
  tobs = 0
  pipe = 0
  cnt = shells(buf, 0, ends2)
  for (e in ends2) {
    a = ends2[e]
    if (psep[a - 1] > 0 && substr(buf, psep[a - 1], 1) == "|") pipe = 1
  }
  stripped = buf
  gsub(DQ, "", stripped); gsub(SQ, "", stripped); gsub("\\\\", "", stripped)
  g = (occ > 0) || (shells(stripped, 1, ends3) > 0) || dashc(buf)
  here = (index(buf, "<<") > 0)
  ne = 0; i = 1
  while (i <= n) {
    c = substr(buf, i, 1)
    if (c == "\\") i += 2
    else if (c == "$" && substr(buf, i + 1, 1) == SQ) {
      j = i + 2
      while (j <= n && substr(buf, j, 1) != SQ) j += (substr(buf, j, 1) == "\\" ? 2 : 1)
      if (j > n + 1) j = n + 1
      ne++; eo[ne] = i + 1; ec[ne] = j; i = j + 1
    } else if (c == SQ) {
      j = i + 1
      while (j <= n && substr(buf, j, 1) != SQ) j++
      ne++; eo[ne] = i; ec[ne] = j; i = j + 1
    } else if (c == DQ) {
      j = i + 1
      while (j <= n && substr(buf, j, 1) != DQ) j += (substr(buf, j, 1) == "\\" ? 2 : 1)
      if (j > n + 1) j = n + 1
      ne++; eo[ne] = i; ec[ne] = j; i = j + 1
    } else i++
  }
  e = 1
  tu = to_unknown(buf)
  for (m = 1; m <= nm; m++) {
    p = mgr[m]; al = alen[m]
    while (e <= ne && ec[e] < p) e++
    inside = (e <= ne && eo[e] < p && p < ec[e])
    st = sep[p - 1] + 1
    opening = (inside && eo[e] >= st) ? 1 : 0
    spelled = (al == 5) || (sig[p - 1] >= st) || (obs[p - 1] - obs[st - 1] > opening)
    fin = stp[p + al] - 1
    closing = (inside && ec[e] <= n && ec[e] >= p + al && ec[e] <= fin) ? 1 : 0
    if (inside) applies = g || tu
    else applies = (shl[p - 1] >= st) || pipe || tu || (here && g) || (xp[p - 1] - xp[st - 1] > 0)
    if (applies && spelled && obs[fin] - obs[p + al - 1] > closing) { print 1; exit }
  }
  print 0
}'
ns_check() {
  if [ -n "$LEX_HAS_AWK" ]; then
    NS_OUT=$(printf '%s\n' "$CMD" | LC_ALL=C awk -v NAMES="$NS_NAMES" -v SHELLS="$NS_SHELLS" "$NS_AWK" 2>/dev/null) || NS_OUT=1
    [ "$NS_OUT" = 0 ] || OPTIN=1
  else
    ns_flat=$(printf '%s' "$CMD" | tr '\n' ' ')
    ns_bare=$(printf '%s' "$ns_flat" | tr -d "\"'\\\\")
    { has_in "$ns_flat" "$NS_SHELL_ERE" || has_in "$ns_bare" "$NS_SHELL_ERE" \
        || has_in "$ns_flat" "$NS_DASHC_ERE"; } \
      && has_in "$ns_flat" "$NS_COARSE_ERE" && OPTIN=1
  fi
}
# Only a command that holds one of these words (quotes and backslashes
# aside) can hold the call; the lexer's pre-filter text is that.
case $LEX_TXT in
  *pip*|*npm*|*sigil*|*SIGIL_ALLOW_BUILD*)
    LEX_HAS_AWK=''
    command -v awk >/dev/null 2>&1 && LEX_HAS_AWK=1
    optin_lex strip "$CMD"; OPTIN_BASE=$LX
    optin_views "$OPTIN_BASE"
    optin_lex mask "$CMD"
    [ "$LX" = "$OPTIN_BASE" ] || optin_views "$LX"
    has_in "$OPTIN_FLAT" "$OPTIN_FLATRE" && OPTIN=1
    # The confirmation variable, by its name, near a word that sets a variable
    # by name, or built from parts.
    has_in "$OPTIN_FLAT" "$OPTIN_ENVRE" && OPTIN=1
    has_in "$OPTIN_BARE" "$OPTIN_ENVRE" && OPTIN=1
    { has_in "$OPTIN_FLAT" "$OPTIN_ENVPFX" && has_in "$OPTIN_FLAT" "$OPTIN_ENVNAMER"; } && OPTIN=1
    { has_in "$OPTIN_BARE" "$OPTIN_ENVPFX" && has_in "$OPTIN_BARE" "$OPTIN_ENVNAMER"; } && OPTIN=1
    optin_has "$OPTIN_ENVBUILT" && OPTIN=1
    optin_bare_has "$OPTIN_ENVBUILT" && OPTIN=1
    # The flag after a command word that is or may be sigil, whatever the
    # subcommand is spelled like (also in the text without quotes).
    optin_has "${OPTIN_NAMED}(${OPTIN_S}${OPTIN_W})*${OPTIN_FLAGA}" && OPTIN=1
    optin_has "${OPTIN_SPELLED}(${OPTIN_S}${OPTIN_W})*${OPTIN_FLAGA}" && OPTIN=1
    optin_bare_has "${OPTIN_NAMED}(${OPTIN_S}${OPTIN_W})*${OPTIN_FLAGA}" && OPTIN=1
    optin_bare_has "${OPTIN_SPELLED}(${OPTIN_S}${OPTIN_W})*${OPTIN_FLAGA}" && OPTIN=1
    optin_has "${OPTIN_SUB}(${OPTIN_S}${OPTIN_W})*${OPTIN_FLAG}" && OPTIN=1
    optin_has "${OPTIN_SUB}(${OPTIN_S}${OPTIN_W})*${OPTIN_PAT}" && OPTIN=1
    optin_has "${OPTIN_SUBX}(${OPTIN_S}${OPTIN_W})*${OPTIN_FLAG}" && OPTIN=1
    optin_has "${OPTIN_SUBX}(${OPTIN_S}${OPTIN_W})*${OPTIN_PAT}" && OPTIN=1
    optin_has "$OPTIN_BRM" && OPTIN=1
    # xargs appends the words it reads, or puts them where its replace string
    # stands; the call it runs may be an expansion or have no subcommand yet.
    optin_has "(^|[^[:alnum:]_.-])xargs([[:space:]][^;&|#]*)?${OPTIN_SUB}([][(),[:space:];&|]|\$)" \
      && OPTIN=1
    optin_has "(^|[^[:alnum:]_.-])xargs([[:space:]][^;&|#]*)?${OPTIN_SUBX}" \
      && OPTIN=1
    optin_has "(^|[^[:alnum:]_.-])xargs[[:space:]]([^;&|#]*[[:space:]])?-[A-Za-z0-9]*[Ii]([^;&|#]*[^[:alnum:]_.-])?sigil(\\.exe)?([^[:alnum:]_.-]|\$)" \
      && OPTIN=1
    optin_has "(^|[^[:alnum:]_.-])xargs[[:space:]]([^;&|#]*[[:space:]])?sigil(\\.exe)?[)\`\"']*(${OPTIN_S}${OPTIN_G})*[[:space:]]*(\$|[;&|)])" \
      && OPTIN=1
    optin_has "(^|[^[:alnum:]_.-])xargs([[:space:]]+-[^[:space:];&|]*)*[[:space:]]+[\"']*[\$\`]" \
      && OPTIN=1
    ns_check ;;
esac
allow_unless_opt_in() {
  [ "$OPTIN" = 1 ] && emit ask "--allow-build-scripts lets pip or npm run the package's own setup or lifecycle scripts on this machine before Sigil scans it (or a word here may expand to it, or xargs may append it, or SIGIL_ALLOW_BUILD_SCRIPTS is being set). Confirm the package is trusted; without the flag sigil pip/npm downloads only what needs no build."
  emit allow "$1"
}

# ── A sigil call: the rules below judge only what it does not vet ───────────

# With the lexer, the rules below read only the stages that are not sigil
# calls and that no sigil call vetted (hook.rs judges each stage on its own
# and gates it on its own targets), so `sigil --version; npm install evil`
# is judged on `npm install evil`. Without awk, a sigil call at the start of
# the command or of any segment allows the whole command, as before.
# The reason for an allow, as hook.rs gives it: the gate, else "Command uses
# sigil" when the command starts with a sigil call.
ALLOW_REASON="No acquisition pattern matched"
AR_HEAD=$CMD
while :; do case $AR_HEAD in [[:space:]]*) AR_HEAD=${AR_HEAD#?} ;; *) break ;; esac; done
has_in "${AR_HEAD%%"$NL"*}" "$SIGIL_RE" && ALLOW_REASON="Command uses sigil"
if [ "$SIGIL_SEEN" = 1 ] && [ "$RESID_ON" = 1 ]; then
  CMD=${RESID#"$NL"}
  [ -n "$CMD" ] || allow_unless_opt_in "${GATED_REASON:-$ALLOW_REASON}"
  dequote_cmd "$CMD"; DCMD=$R
elif [ -z "$LEX" ]; then
  has '(^[[:space:]]*|[;&|][[:space:]]*)sigil[[:space:]]' \
    && allow_unless_opt_in "${GATED_REASON:-Command uses sigil}"
fi

# ── DENY: cloning repositories ─────────────────────────────────────────────

has "${WB}git${MOD}[[:space:]]+clone([[:space:]]|\$)" \
  && deny "git clone pulls unscanned code. Use: sigil clone <url> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

has "${WB}gh${MOD}[[:space:]]+repo[[:space:]]+clone([[:space:]]|\$)" \
  && deny "gh repo clone pulls unscanned code. Use: sigil clone <url> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

# ── npm: explicit package -> deny; bare lockfile restore -> ask ────────────

if has "${WB}npm${MOD}[[:space:]]+(install|i|add)([[:space:]]|\$)"; then
  if has "${WB}npm${MOD}[[:space:]]+(install|i|add)${FLAGS}${PKG}"; then
    deny "npm install with a package installs unscanned code. Use: sigil npm <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"
  else
    emit ask "Bare npm install restores the lockfile, which can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted."
  fi
fi

has "${WB}npm${MOD}[[:space:]]+ci([[:space:]]|\$)" \
  && emit ask "npm ci restores the lockfile, which can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted."

# ── yarn / pnpm / bun ──────────────────────────────────────────────────────

has "${WB}(yarn|pnpm|bun)${MOD}([[:space:]]+global)?[[:space:]]+add${FLAGS}${PKG}" \
  && deny "Adding a package installs unscanned code. Use: sigil npm <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

# Arbitrary-exec runners before bare installs: `pnpm dlx foo` must not fall
# through to the pnpm install branch.
has "${WB}(pnpm|yarn)${MOD}[[:space:]]+dlx[[:space:]]" \
  && deny "dlx downloads and executes a package in one step with no scan. Use: sigil npm <pkg> && <this command>. Bypass: SIGIL_BYPASS=1"

has "${WB}(yarn|pnpm)${MOD}[[:space:]]+install([[:space:]]|\$)" \
  && emit ask "Lockfile restore can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted."

# ── pip / uv: -r requirements -> ask, unless a package is named besides it
# (PIP_NAMED, from the lexer's stages; without awk, -r asks); explicit
# package -> deny ────────────────────────────────────────────────────────────

PIP_INSTALL="${WB}(pip[0-9.]*${MOD}[[:space:]]+install|python[0-9.]*[[:space:]]+-m[[:space:]]+pip[[:space:]]+install|uv[[:space:]]+pip[[:space:]]+install)"
if has "${PIP_INSTALL}([[:space:]]|\$)"; then
  if has "(^|[[:space:]])(-r|--requirement)([[:space:]]|\$)" && [ "$PIP_NAMED" != 1 ]; then
    emit ask "pip install -r installs every pinned dependency, any of which can run setup.py code. Confirm the requirements file is trusted."
  elif has "${PIP_INSTALL}${FLAGS}${PKG}"; then
    deny "pip install with a package installs unscanned code. Use: sigil pip <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"
  else
    emit ask "Bare pip install can execute setup.py from the current directory. Run sigil scan . first."
  fi
fi

has "${WB}uv${MOD}[[:space:]]+add${FLAGS}${PKG}" \
  && deny "uv add installs unscanned code. Use: sigil pip <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

# ── Other package managers with explicit packages ──────────────────────────

has "${WB}cargo${MOD}[[:space:]]+(install|add)${FLAGS}${PKG}" \
  && deny "cargo install/add builds and installs unscanned code. Quarantine + scan the crate source with sigil clone first. Bypass: SIGIL_BYPASS=1"

has "${WB}gem${MOD}[[:space:]]+install${FLAGS}${PKG}" \
  && deny "gem install runs unscanned code (gems can execute extensions at install). Quarantine + scan the source with sigil clone first. Bypass: SIGIL_BYPASS=1"

has "${WB}go${MOD}[[:space:]]+(install|get)${FLAGS}${PKG}" \
  && deny "go install/get fetches and builds unscanned code. Quarantine + scan the module source with sigil clone first. Bypass: SIGIL_BYPASS=1"

# ── ASK: remaining lockfile restores and arbitrary-exec runners ────────────

has "${WB}bundle[[:space:]]+install([[:space:]]|\$)" \
  && emit ask "bundle install restores the Gemfile.lock, which can run native extension code from unreviewed gems. Confirm the lockfile is trusted."

has "${WB}(npx|bunx)[[:space:]]+" \
  && deny "This runner downloads and executes a package in one step with no scan. Use: sigil npm <pkg> && <this command>. Bypass: SIGIL_BYPASS=1"

has "${WB}(uvx|pipx[[:space:]]+run)[[:space:]]" \
  && deny "This runner downloads and executes a package in one step with no scan. Use: sigil pip <pkg> && <this command>. Bypass: SIGIL_BYPASS=1"

# ── Default ────────────────────────────────────────────────────────────────

allow_unless_opt_in "${GATED_REASON:-$ALLOW_REASON}"
