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
#           `bash -s` / `sudo -u user bash` / python / node / iex, or
#           substituted into one (`bash <(curl …)`); a file downloaded and run
#           in the same command (`curl -o i.sh … && bash i.sh`) unless
#           `sigil scan i.sh &&` comes between; a download saved into agent
#           tooling (`~/.claude/skills`, `.mcp.json`, `.cursor/rules`, ...);
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
# Tab, SOH (\001) and US (\037), from one printf.
CTL=$(printf '\t\001\037')
TAB=${CTL%??}
SOH=${CTL#?}
SOH=${SOH%?}
US=${CTL#??}
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

has() {
  printf '%s\n' "$CMD" | grep -Eq "$1"
}

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
# first, as the native hook does).
has "${WB}SIGIL_BYPASS=1([[:space:]]|\$)" \
  && emit allow "Sigil guard bypassed (SIGIL_BYPASS=1)"

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
# cmdline::pipes_download_to_interpreter. Judged on the whole command and
# never gated by a sigil call: the server decides per request what it
# serves. An interpreter that reads the download as data (`| python3 -m
# json.tool`, `| bash -c 'jq …'`, `| sh ./process.sh`) does not count.

case $CMD in
  *[Cc][Uu][Rr][Ll]*|*[Ww][Gg][Ee][Tt]*|*[Ff][Ee][Tt][Cc][Hh]*|*[Ii][Ww][Rr]*|*[Ii][Rr][Mm]*|*[Ii][Nn][Vv][Oo][Kk][Ee]-*|*[Ww][Ee][Bb][Cc][Ll][Ii][Ee][Nn][Tt]*)
    PIPE_CHECK=1 ;;
  *) PIPE_CHECK=0 ;;
esac
if [ $PIPE_CHECK = 1 ]; then
  # The whole command on one line for grep, newlines as SOH: whitespace
  # between command words (as \s is to hook.rs), but the end of an
  # interpreter's arguments. A literal SOH in the command becomes x.
  FLAT=$(printf '%s' "$CMD" | tr "$SOH$NL" "x$SOH")

  # Command words match in any case, as hook.rs's (?i); interpreter flags
  # are compared exactly, so these spell out both cases rather than use
  # grep -i.
  # (curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)
  DL='([cC][uU][rR][lL]|[wW][gG][eE][tT]|[fF][eE][tT][cC][hH]|[iI][wW][rR]|[iI][rR][mM]|[iI][nN][vV][oO][kK][eE]-[wW][eE][bB][rR][eE][qQ][uU][eE][sS][tT]|[iI][nN][vV][oO][kK][eE]-[rR][eE][sS][tT][mM][eE][tT][hH][oO][dD])'
  TEE='[tT][eE][eE]'
  SUDO='[sS][uU][dD][oO]'
  ENVW='[eE][nN][vV]'
  # (sh|bash|zsh|dash|ksh|fish)
  SH_I='([sS][hH]|[bB][aA][sS][hH]|[zZ][sS][hH]|[dD][aA][sS][hH]|[kK][sS][hH]|[fF][iI][sS][hH])'
  # (python[0-9.]*|node|deno|bun|perl|ruby|php)
  OT_I='([pP][yY][tT][hH][oO][nN][0-9.]*|[nN][oO][dD][eE]|[dD][eE][nN][oO]|[bB][uU][nN]|[pP][eE][rR][lL]|[rR][uU][bB][yY]|[pP][hH][pP])'
  # (pwsh|powershell), (iex|invoke-expression)
  PW_I='([pP][wW][sS][hH]|[pP][oO][wW][eE][rR][sS][hH][eE][lL][lL])'
  IEX_I='([iI][eE][xX]|[iI][nN][vV][oO][kK][eE]-[eE][xX][pP][rR][eE][sS][sS][iI][oO][nN])'
  # PowerShell -c|-command|-f|-file|-encodedcommand|-e|-ec
  PW_ARG='([cC]|[cC][oO][mM][mM][aA][nN][dD]|[fF]|[fF][iI][lL][eE]|[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD]|[eE]|[eE][cC])'

  WS="[[:space:]$SOH]"
  NWS="[^[:space:]$SOH]"
  # Interpreter arguments: the text after the interpreter word up to
  # | ; & ) ' " ` or a newline — tokens of TC characters, each ending at TE.
  TX="[:space:]|;&)'\"\`$SOH"
  TC="[^$TX]"
  TE="([[:space:]]|[|;&)'\"\`$SOH]|\$)"
  STOP="([|;&)'\"\`$SOH]|\$)"

  # hook.rs tokenises the arguments, so a backslash in front of a flag is
  # quote removal (`bash \-s` is `bash -s`).
  BQ='\\?'
  # Shells run stdin unless given -c or a script file; -s, - and -- keep
  # reading stdin (`bash -s stable`). -o/+o take a value; as the last word,
  # with no value, they leave stdin as the script.
  SH_OK="$BQ(--$TC+|[+]([^o$TX]$TC*|o$TC+)?|[+-]o[[:space:]]+$TC+|-([^-cso$TX][^cs$TX]*|o[^cs$TX]+))"
  SH_RUN="$BQ(--|-|-(s|[^-c$TX][^c$TX]*s)[^c$TX]*)$TE"
  SH_LAST="${BQ}[+-]o"
  # Other interpreters run stdin unless given inline code (-c -e -m -p -n
  # -r -E, --eval/--print/--module in any case) or a script; -W/-X take a
  # value (and, last with none, leave stdin as the script). OT_LONG is any
  # other long flag.
  OT_LONG="--([^epmEPM$TX]$TC*|[eE]([^vV$TX]$TC*|[vV]([^aA$TX]$TC*|[aA]([^lL$TX]$TC*|[lL]$TC+)?)?)?|[pP]([^rR$TX]$TC*|[rR]([^iI$TX]$TC*|[iI]([^nN$TX]$TC*|[nN]([^tT$TX]$TC*|[tT]$TC+)?)?)?)?|[mM]([^oO$TX]$TC*|[oO]([^dD$TX]$TC*|[dD]([^uU$TX]$TC*|[uU]([^lL$TX]$TC*|[lL]([^eE$TX]$TC*|[eE]$TC+)?)?)?)?)?)"
  OT_OK="$BQ(-[WX][[:space:]]+$TC+|-([^-cmepnrEWX$TX][^cmepnrE$TX]*|[WX][^cmepnrE$TX]+)|$OT_LONG|[+]$TC*)"
  OT_RUN="$BQ(--|-)$TE"
  OT_LAST="$BQ-[WX]"
  # PowerShell runs stdin for `-` or `-Command -` / `-File -`; any other
  # flag (`-NoProfile`, `-Sta`, `+x`) keeps it reading. PW_FLAG is a flag
  # name other than PW_ARG (or `-`), in any case.
  PW_FLAG="([^cCeEfF$TX-]$TC*|-$TC+|[cC]([^oO$TX]$TC*|[oO]([^mM$TX]$TC*|[mM]([^mM$TX]$TC*|[mM]([^aA$TX]$TC*|[aA]([^nN$TX]$TC*|[nN]([^dD$TX]$TC*|[dD]$TC+)?)?)?)?)?)|[eE]([^cCnN$TX]$TC*|[cC]$TC+|[nN]([^cC$TX]$TC*|[cC]([^oO$TX]$TC*|[oO]([^dD$TX]$TC*|[dD]([^eE$TX]$TC*|[eE]([^dD$TX]$TC*|[dD]([^cC$TX]$TC*|[cC]([^oO$TX]$TC*|[oO]([^mM$TX]$TC*|[mM]([^mM$TX]$TC*|[mM]([^aA$TX]$TC*|[aA]([^nN$TX]$TC*|[nN]([^dD$TX]$TC*|[dD]$TC+)?)?)?)?)?)?)?)?)?)?)?)?)|[fF]([^iI$TX]$TC*|[iI]([^lL$TX]$TC*|[lL]([^eE$TX]$TC*|[eE]$TC+)?)?))"
  PW_OK="$BQ(-$PW_FLAG|[+]$TC*)"
  PW_RUN="$BQ((--|-)|-${PW_ARG}[[:space:]]+$BQ-)$TE"

  tail_re() {
    # $1 = token that keeps the interpreter reading stdin, $2 = token that
    # settles it, $3 = a valued flag that may end the arguments: all $1
    # tokens up to the end of the arguments (the last may be $3), or $1
    # tokens then a $2 token.
    R="([\"')$SOH]|\$|[[:space:]]+(($1[[:space:]]+)*$2|($1[[:space:]]+)*($1|$3)?[[:space:]]*$STOP))"
  }
  tail_re "$SH_OK" "$SH_RUN" "$SH_LAST"; SH_TAIL=$R
  tail_re "$OT_OK" "$OT_RUN" "$OT_LAST"; OT_TAIL=$R
  tail_re "$PW_OK" "$PW_RUN" "$PW_OK"; PW_TAIL=$R

  # `| tee file |` stages in between still hand the interpreter the
  # download; `sudo -u user` takes a value.
  PIPE_HEAD="(^|[[:space:]$SOH;&|(\"'\`\$])($NWS*/)?$DL(${WS}[^|;&]*)?([|]$WS*($NWS*/)?$TEE(${WS}[^|;&]*)?)*[|]$WS*($SUDO($WS+-$NWS+($WS+[^-[:space:]$SOH|;&]$NWS*)?)*$WS+)?($ENVW(${WS}+[A-Za-z0-9_]+=$NWS*)*$WS+)?($NWS*/)?"
  PIPE_RE="$PIPE_HEAD($SH_I$SH_TAIL|$OT_I$OT_TAIL|$PW_I$PW_TAIL|$IEX_I([[:space:]$SOH\"')]|\$))"

  INTERP='(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|deno|bun|perl|ruby|php|iex|invoke-expression|pwsh|powershell)'
  DLW='(curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)'
  SUBST_RE="(^|[[:space:]$SOH;&|(\"'\`])(($NWS*/)?$INTERP$WS+(-$NWS+$WS+)*|source$WS+|[.]$WS+|eval$WS+)[\"']?(<[(]|[\$][(]|\`)$WS*($NWS*/)?$DLW$WS"
  PS_RE="(iex|invoke-expression)$WS*[(]?$WS*([(]|[\$][(])?$WS*(iwr|irm|invoke-webrequest|invoke-restmethod|[(]?new-object$WS+(system[.])?net[.]webclient)"

  if has_in "$FLAT" "$PIPE_RE" \
    || printf '%s\n' "$FLAT" | grep -Eiq "($SUBST_RE)|($PS_RE)"; then
    first_url "$CMD"
    if [ -n "$R" ]; then
      deny "Piping a download into an interpreter executes unscanned code. Use: sigil scan $R — or download it (curl -fsSLo script.sh $R), run sigil scan script.sh, then run the file you scanned. $BYPASS_HINT"
    fi
    deny "Piping a download into an interpreter executes unscanned code. Download the script, run sigil scan on it, then execute the file you scanned. $BYPASS_HINT"
  fi
fi

# ── DENY: remote execution and agent-tooling writes, stage by stage ────────
# Like hook.rs classify_in: the command is split into list segments (; && ||
# & newlines, $( <( >( and backticks) and pipeline stages, each tokenised
# with shell quoting. A `sigil` stage is allowed and, when it is `sigil
# scan|clone|pip|npm <target>`, vets that target for the stages chained after
# it with &&. Checked here, per stage:
#   - deno run|x|install|serve of an npm:/jsr:/http(s) module
#   - curl/wget saving into agent tooling (never gated)
#   - pipx install / uv tool install <pkg> (gated by sigil pip <pkg>)
#   - running a file downloaded earlier in the same command (gated by
#     sigil scan <file>)
#   - npm exec|x, bun x and uv tool run of a registry package in command
#     position (gated by sigil npm|pip <pkg>)
# hook.rs settles agent-CLI acquisition and package runners first, so those
# stages skip the deno, tooling and installer checks; npx, bunx, uvx, pipx
# run and dlx are left to the rules further down.

# Lexer (POSIX awk): one record per segment — S, the operator in front of it
# (A for &&, O otherwise), its tokens — and per pipeline stage — T, the
# stage text, its tokens — fields separated by US. A US in the command
# itself becomes STX first: to hook.rs it is an ordinary word character,
# and left in place it would shift every field after it.
# shellcheck disable=SC2016 # an awk program, not shell
LEX_AWK='
BEGIN { US = sprintf("%c", 31); STX = sprintf("%c", 2); SQ = sprintf("%c", 39) }
function trim(s) { sub(/^[ \t\r\f\v]+/, "", s); sub(/[ \t\r\f\v]+$/, "", s); return s }
function tok(s,    out, cur, inw, i, n, c, d, e) {
  out = ""; cur = ""; inw = 0; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == SQ) {
      inw = 1
      for (i++; i <= n; i++) { d = substr(s, i, 1); if (d == SQ) break; cur = cur d }
    } else if (c == "\"") {
      inw = 1
      for (i++; i <= n; i++) {
        d = substr(s, i, 1)
        if (d == "\"") break
        e = substr(s, i + 1, 1)
        if (d == "\\" && (e == "\"" || e == "\\" || e == "$" || e == "`")) { cur = cur e; i++ }
        else cur = cur d
      }
    } else if (c == "\\") {
      inw = 1
      if (i < n) { i++; cur = cur substr(s, i, 1) }
    } else if (c ~ /[ \t\r\f\v]/) {
      if (inw) { out = out US cur; cur = ""; inw = 0 }
    } else { inw = 1; cur = cur c }
  }
  if (inw) out = out US cur
  return out
}
function seg(s, op,    n, st, k, x) {
  s = trim(s)
  printf "S%s%s%s\n", US, op, tok(s)
  n = split(s, st, /[|]/)
  for (k = 1; k <= n; k++) { x = trim(st[k]); if (x != "") printf "T%s%s%s\n", US, x, tok(x) }
}
{ cmd = (NR == 1) ? $0 : (cmd "\n" $0) }
END {
  gsub(US, STX, cmd)
  n = length(cmd); op = "O"; start = 1; i = 1
  while (i <= n) {
    c = substr(cmd, i, 1); nx = substr(cmd, i + 1, 1); pv = (i > 1) ? substr(cmd, i - 1, 1) : ""
    w = 0
    if (c == "&" && nx == "&") { w = 2; nop = "A" }
    else if (c == "|" && nx == "|") { w = 2; nop = "O" }
    else if (c == "&" && pv != ">" && nx != ">") { w = 1; nop = "O" }
    else if (c == ";" || c == "\n" || c == "`") { w = 1; nop = "O" }
    else if ((c == "$" || c == "<" || c == ">") && nx == "(") { w = 2; nop = "O" }
    if (w) { seg(substr(cmd, start, i - start), op); op = nop; i += w; start = i } else i++
  }
  seg(substr(cmd, start), op)
}'

# Directories and files an agent loads and runs from on its own (hook.rs
# agent_path).
AGENT_DIRS='\.claude/(skills|plugins|agents|commands|hooks)|\.codex/(skills|prompts)|\.agents/skills|\.gemini/(extensions|skills|commands)|\.cursor/(rules|skills)|\.windsurf/(rules|workflows)|\.codeium/windsurf|\.openclaw/(skills|workspace[^/]*)|\.(clawdbot|moltbot)/skills|\.config/opencode/(skills?|agents?|commands?|plugins?)|\.opencode/(skills?|agents?|commands?|plugins?)|\.github/(skills|prompts|instructions)|\.continue/(mcpServers|rules)|\.roo/rules|\.config/goose'
AGENT_FILES='\.claude/settings(\.local)?\.json|\.claude\.json|\.mcp\.json|\.codex/config\.toml|\.gemini/settings\.json|\.cursor/(mcp|hooks)\.json|\.vscode/mcp\.json|claude_desktop_config\.json|mcp_config\.json|\.clinerules'
AGENT_RE="(^|/)(($AGENT_DIRS)(/|\$)|($AGENT_FILES)\$)"

SIGIL_RE='^[[:space:]]*([A-Za-z0-9_]+=[^[:space:]]*[[:space:]]+)*(sudo([[:space:]]+-[^[:space:]]+)*[[:space:]]+)?([^[:space:]]*/)?sigil(\.exe)?([[:space:]]|$)'
# Stages hook.rs classify_stage settles before the checks below: agent-CLI
# acquisition, matched after any word boundary as agent_acquisition does,
# and a package runner in command position (RUNNER_PAT: the start of the
# stage after env assignments and wrappers, just inside a quote or paren,
# or after an argv `--`). A runner word anywhere else is not a run — a URL
# ending in /npx, an argument named bunx — and must not exempt the stage.
AGENT_ACQ_RE="${WB}(([^[:space:]]*/)?([A-Za-z0-9_.-]+[[:space:]]+mcp[[:space:]]+(add|add-json|add-from-claude-desktop)([[:space:]]|\$)|claude[[:space:]]+plugins?[[:space:]]+(marketplace[[:space:]]+add|install|i)[[:space:]]|gemini[[:space:]]+extensions?[[:space:]]+(install|link)[[:space:]]|clawhub(@[^[:space:]]+)?[[:space:]]+install[[:space:]])|(npx|bunx|pnpm[[:space:]]+dlx|yarn[[:space:]]+dlx)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*(skills|add-skill|@vercel/skills)(@[^[:space:]]+)?[[:space:]]+(add|install)[[:space:]])"
RUNNER_POS_RE="(^[[:space:]]*([A-Za-z0-9_]+=[^[:space:]]*[[:space:]]+)*((sudo|exec|time|nohup|env|command|xargs)([[:space:]]+-[^[:space:]]+)*[[:space:]]+)*|[\"'(]|[[:space:]]--[[:space:]]+)([^[:space:]]*/)?(npx|bunx|uvx|pipx[[:space:]]+run|pnpm[[:space:]]+dlx|yarn[[:space:]]+dlx|npm[[:space:]]+(exec|x)|bun[[:space:]]+x|uv[[:space:]]+tool[[:space:]]+run)([[:space:]]|\$)"
DENO_RE="${WB}([^[:space:]]*/)?deno[[:space:]]+(run|x|install|serve)([[:space:]]|\$)"
TOOL_INSTALL_RE="${WB}([^[:space:]]*/)?(pipx|uv${MOD}[[:space:]]+tool)${MOD}[[:space:]]+install${FLAGS}${PKG}"

HOME_DIR=${HOME:-}
CUR_CWD=$CWD

agent_path() {
  # A superset of AGENT_RE first, to spare ordinary paths the grep.
  case $1 in
    *.claude*|*.codex*|*.agents*|*.gemini*|*.cursor*|*.windsurf*|*.codeium*|*.openclaw*|*.clawdbot*|*.moltbot*|*opencode*|*.github*|*.continue*|*.roo*|*.config/goose*|*.mcp.json|*.vscode/mcp.json|*claude_desktop_config.json|*mcp_config.json|*.clinerules*) ;;
    *) return 1 ;;
  esac
  has_in "$1" "$AGENT_RE"
}

# unquote <token>: surrounding whitespace, then quote characters, trimmed.
unquote() {
  R=$1
  while :; do case $R in [[:space:]]*) R=${R#?} ;; *) break ;; esac; done
  while :; do case $R in *[[:space:]]) R=${R%?} ;; *) break ;; esac; done
  while :; do case $R in [\"\']*) R=${R#?} ;; *) break ;; esac; done
  while :; do case $R in *[\"\']) R=${R%?} ;; *) break ;; esac; done
}

# expand <path>: ~ and $HOME expanded, a relative path joined to the
# working directory (which follows `cd`).
expand() {
  R=$1
  while :; do case $R in [\"\']*) R=${R#?} ;; *) break ;; esac; done
  while :; do case $R in *[\"\']) R=${R%?} ;; *) break ;; esac; done
  if [ -n "$HOME_DIR" ]; then
    # The literal words ~/, $HOME/ and ${HOME}/ as the command wrote them.
    case $R in
      \~/*) R=$HOME_DIR/${R#??}; return 0 ;;
      \$HOME/*) R=$HOME_DIR/${R#??????}; return 0 ;;
      \$\{HOME\}/*) R=$HOME_DIR/${R#????????}; return 0 ;;
      \~) R=$HOME_DIR; return 0 ;;
    esac
  fi
  case $R in
    /*) ;;
    *) [ -n "$CUR_CWD" ] && R=$CUR_CWD/$R ;;
  esac
}

# canon <path>: expanded, with "." components and repeated or trailing
# slashes dropped (hook.rs canon_path).
canon() {
  expand "$1"
  cn_in=$R
  R=''
  case $cn_in in /*) cn_abs=/ ;; *) cn_abs='' ;; esac
  IFS=/
  for cn_part in $cn_in; do
    case $cn_part in ''|.) ;; *) R=${R:+$R/}$cn_part ;; esac
  done
  IFS=$IFS_DEFAULT
  R=$cn_abs$R
}

is_agent_dest() {
  unquote "$1"
  agent_path "$R" && return 0
  expand "$1"
  agent_path "$R"
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

# vet_targets TOKENS: record what a `sigil scan|clone|pip|npm` stage vets,
# typed as hook.rs Target (npm:, pypi:, path:). Repositories are not
# recorded: nothing below is gated on one.
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
  vt_names=''; vt_ver=''
  while [ $# -gt 0 ]; do
    vt_t=$1
    shift
    case $vt_t in
      -V|--version) vt_ver=''; [ $# -gt 0 ] && { vt_ver=$1; shift; } ;;
      --version=*) vt_ver=${vt_t#*=} ;;
      -f|--format|-p|--phases|-s|--severity|--fail-on|-b|--branch|--baseline|-o|--output|--policy|--rules|--config)
        [ $# -gt 0 ] && shift ;;
      -*) ;;
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
        case $vt_n in *://*|git@*|github:*) continue ;; esac
        canon "$vt_n"; vt_x=path:$R ;;
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
    in_list "$GATES" "$gt_t" || return 1
  done
  IFS=$IFS_DEFAULT
  return 0
}

# pm_targets TOKENS: hook.rs stage_targets for a package-manager stage —
# every argument after the install verb, in the registry the manager
# installs from; "!" for what no sigil call vets by name.
pm_targets() {
  pt_out=''
  while [ $# -gt 0 ]; do
    case $1 in sudo) shift ;; -*) break ;; *=*) shift ;; *) break ;; esac
  done
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

# download_file RAW TOKENS: the file a curl/wget stage saves to, resolved
# like canon (hook.rs download_file); empty for stdout or no download.
download_file() {
  R=''
  df_raw=$1
  shift
  while [ $# -gt 0 ]; do
    case $1 in sudo|env) shift ;; -*) break ;; *=*) shift ;; *) break ;; esac
  done
  [ $# -gt 0 ] || return 0
  case ${1##*/} in wget) df_wget=1 ;; curl) df_wget=0 ;; *) return 0 ;; esac
  shift
  df_out=''; df_has=0; df_dir=''; df_hasdir=0; df_remote=$df_wget
  while [ $# -gt 0 ]; do
    df_t=$1
    shift
    case $df_t in
      '>'|'>>')
        df_has=0; [ $# -gt 0 ] && { df_out=$1; df_has=1; shift; } ;;
      '>&'*) ;;
      '>'*)
        df_out=$df_t
        while :; do case $df_out in '>'*) df_out=${df_out#?} ;; *) break ;; esac; done
        df_has=1 ;;
      --output|--output-document)
        df_has=0; [ $# -gt 0 ] && { df_out=$1; df_has=1; shift; } ;;
      -o)
        if [ $df_wget = 1 ]; then
          [ $# -gt 0 ] && shift   # wget -o is its log file
        else
          df_has=0; [ $# -gt 0 ] && { df_out=$1; df_has=1; shift; }
        fi ;;
      -O)
        if [ $df_wget = 1 ]; then
          df_has=0; [ $# -gt 0 ] && { df_out=$1; df_has=1; shift; }
        else
          df_remote=1
        fi ;;
      --remote-name) df_remote=1 ;;
      -P|--directory-prefix|--output-dir)
        df_hasdir=0; [ $# -gt 0 ] && { df_dir=$1; df_hasdir=1; shift; } ;;
      --output-document=*|--output=*) df_out=${df_t#*=}; df_has=1 ;;
      --directory-prefix=*|--output-dir=*) df_dir=${df_t#*=}; df_hasdir=1 ;;
      --*) ;;
      -*)
        # Bundled short flags: curl -fsSLo file, -fsSLO; wget -qO file, -qO-.
        df_f=${df_t#-}
        if [ $df_wget = 1 ]; then
          case $df_f in
            *O*)
              df_rest=${df_f#*O}
              if [ -n "$df_rest" ]; then
                df_out=$df_rest; df_has=1
              else
                df_has=0; [ $# -gt 0 ] && { df_out=$1; df_has=1; shift; }
              fi ;;
          esac
        else
          case $df_f in
            *o) df_has=0; [ $# -gt 0 ] && { df_out=$1; df_has=1; shift; } ;;
            *O*) df_remote=1 ;;
          esac
        fi ;;
    esac
  done
  if [ $df_has = 0 ]; then
    [ $df_remote = 1 ] || return 0
    # The URL's last path component.
    first_url "$df_raw"
    df_out=${R%%[?#]*}
    R=''
    case $df_out in *://*/*) ;; *) return 0 ;; esac
    df_out=${df_out#*://}
    df_out=${df_out#*/}
    df_out=${df_out##*/}
    [ -n "$df_out" ] || return 0
  fi
  case $df_out in -|/dev/*) return 0 ;; esac
  if [ $df_hasdir = 1 ]; then
    case $df_out in
      */*) ;;
      *)
        while :; do case $df_dir in */) df_dir=${df_dir%?} ;; *) break ;; esac; done
        df_out=$df_dir/$df_out ;;
    esac
  fi
  canon "$df_out"
}

# exec_file TOKENS: the file a stage executes — an interpreter's script
# argument (`bash x.sh`, `python3 x.py`) or a path run directly (`./x`).
exec_file() {
  R=''
  while [ $# -gt 0 ]; do
    case $1 in sudo|env) shift ;; -*) break ;; *=*) shift ;; *) break ;; esac
  done
  [ $# -gt 0 ] || return 0
  ef_head=$1
  shift
  ef_base=${ef_head##*/}
  while :; do case $ef_base in *[0-9.]) ef_base=${ef_base%?} ;; *) break ;; esac; done
  case $ef_base in
    sh|bash|zsh|dash|ksh|fish|python|node|deno|bun|perl|ruby|php|pwsh|powershell|source) ;;
    *)
      case $ef_head in */*) canon "$ef_head" ;; esac
      return 0 ;;
  esac
  for ef_t; do
    case $ef_t in
      -c|-e|-m|-Command|-EncodedCommand) return 0 ;;   # inline code or a module
      run|-*) continue ;;
    esac
    canon "$ef_t"
    return 0
  done
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

# tooling_download RAW TOKENS: a curl/wget stage saving into agent tooling
# (hook.rs tooling_write). Uses ST_DLF, the stage's download_file.
tooling_download() {
  td_raw=$1
  shift
  while [ $# -gt 0 ]; do
    case $1 in sudo) shift ;; -*) break ;; *=*) shift ;; *) break ;; esac
  done
  [ $# -gt 0 ] || return 1
  td_head=${1##*/}
  case $td_head in curl|wget) ;; *) return 1 ;; esac
  shift
  td_dest=''; td_has=0; td_remote=0
  [ "$td_head" = wget ] && td_remote=1
  while [ $# -gt 0 ]; do
    td_t=$1
    shift
    case $td_t in
      -O)
        if [ "$td_head" = wget ]; then
          td_has=0; [ $# -gt 0 ] && { td_dest=$1; td_has=1; shift; }
        else
          td_remote=1
        fi ;;
      -o|--output|--output-document)
        td_has=0; [ $# -gt 0 ] && { td_dest=$1; td_has=1; shift; } ;;
      --output-dir|-P|--directory-prefix)
        td_has=0; [ $# -gt 0 ] && { td_dest=$1; td_has=1; shift; }
        td_remote=1 ;;
      --remote-name) td_remote=1 ;;
      --output-document=*|--directory-prefix=*) td_dest=${td_t#*=}; td_has=1 ;;
      --*) ;;
      -*)
        if [ "$td_head" = curl ]; then
          case $td_t in
            *o) td_has=0; [ $# -gt 0 ] && { td_dest=$1; td_has=1; shift; } ;;
            *O*) td_remote=1 ;;
          esac
        fi ;;
    esac
  done
  # No destination: a remote-named download lands in the working directory.
  if [ $td_has = 0 ] && [ $td_remote = 1 ] && [ -n "$CUR_CWD" ]; then
    td_dest=$CUR_CWD; td_has=1
  fi
  td_hit=''
  if [ $td_has = 1 ] && [ "$td_dest" != - ] && is_agent_dest "$td_dest"; then
    td_hit=$td_dest
  elif [ -n "$ST_DLF" ] && agent_path "$ST_DLF"; then
    td_hit=$ST_DLF
  fi
  [ -n "$td_hit" ] || return 1
  first_url "$td_raw"
  ST_DENY="Downloads into agent tooling ($td_hit) with no scan. Use: sigil scan ${R:-<url>} — it downloads into quarantine and scans first. $BYPASS_HINT"
  return 0
}

# judge_stage RAW TOKENS: deny (and exit) when the stage runs remote code
# or writes into agent tooling and the && chain before it did not vet it.
judge_stage() {
  st_raw=$1
  shift
  [ $# -gt 0 ] || return 0
  case $st_raw in
    *sigil*)
      if has_in "$st_raw" "$SIGIL_RE"; then
        vet_targets "$@"
        return 0
      fi ;;
  esac
  ST_DENY=''
  st_targets=''
  download_file "$st_raw" "$@"
  ST_DLF=$R
  st_earlier=0
  case $st_raw in
    *mcp*|*plugin*|*extension*|*clawhub*|*npx*|*bunx*|*uvx*|*pipx*|*dlx*|*npm*|*bun*|*uv*)
      if has_in "$st_raw" "$AGENT_ACQ_RE"; then
        st_earlier=1
      elif has_in "$st_raw" "$RUNNER_POS_RE"; then
        # hook.rs runner(): settled here only when parse_runner names a
        # registry package. npx, bunx, uvx, pipx run and dlx are denied by
        # the rules at the end; the runners those rules do not name are
        # judged here.
        # shellcheck disable=SC2048,SC2086 # split every token into words
        runner_scan "$@" || runner_scan $*
        if [ -n "$RN_TOOL" ]; then
          st_earlier=1
          case $RN_TOOL in
            'npm exec'|'bun x'|'uv tool run')
              if [ "$RN_LOCAL" = 0 ]; then
                ST_DENY="\`$RN_TOOL $RN_SPEC\` downloads $RN_SPEC from the $RN_REGISTRY and runs it in one step, with no scan$RN_UNPINNED. Use: $RN_ALT && $st_raw. $BYPASS_HINT"
                st_targets=$R
              fi ;;
          esac
        fi
      fi ;;
  esac
  if [ $st_earlier = 0 ]; then
    st_deno=''
    case $st_raw in
      *deno*)
        if has_in "$st_raw" "$DENO_RE"; then
          # A quoted `bash -c 'deno run …'` is one token: retry on its words.
          # shellcheck disable=SC2048,SC2086 # split every token into words
          deno_scan "$@" || deno_scan $*
          st_deno=$R
        fi ;;
    esac
    if [ -n "$st_deno" ]; then
      case $st_deno in
        npm:*)
          st_spec=${st_deno#npm:}
          ST_DENY="deno fetches $st_spec from the npm registry and runs it in one step, with no scan. Use: sigil npm $st_spec && $st_raw. $BYPASS_HINT"
          st_targets=npm:$st_spec ;;
        *)
          ST_DENY="deno fetches $st_deno and runs it in one step, with no scan (the server decides per request what it serves). Download the module, run sigil scan on it, then deno run the local file. $BYPASS_HINT"
          st_targets='!' ;;
      esac
    elif tooling_download "$st_raw" "$@"; then
      pm_targets "$@"
      st_targets=$R
    else
      case $st_raw in
        *install*)
          if has_in "$st_raw" "$TOOL_INSTALL_RE"; then
            tool_pkg "$@"
            ST_DENY="This installs $R from the Python package index with no scan; its build and entry points run with your privileges. Use: sigil pip $R && $st_raw — and pin an exact version. $BYPASS_HINT"
            pm_targets "$@"
            st_targets=$R
          fi ;;
      esac
    fi
  fi
  # Download to a file, then run that file: the same remote execution as
  # curl | sh, one step removed — but gateable, as the scan reads the
  # bytes that run.
  exec_file "$@"
  if [ -n "$R" ] && in_list "$DOWNLOADS" "$R"; then
    [ -n "$ST_DENY" ] || ST_DENY="Runs $R, downloaded earlier in this command, without a scan: remote code execution one step removed from curl | sh. Use: sigil scan $R && $st_raw (after the download). $BYPASS_HINT"
    st_targets=path:$R
  fi
  [ -n "$ST_DLF" ] && DOWNLOADS=${DOWNLOADS:+$DOWNLOADS$NL}$ST_DLF
  if [ -n "$ST_DENY" ]; then
    gated "$st_targets" || deny "$ST_DENY"
    GATED_REASON="Gated by a preceding sigil check on the same target"
  fi
  return 0
}

# Every check here needs a curl/wget download, deno, an install verb, npm
# exec|x, bun x or uv tool run in the command. Command words are compared
# after quote removal, as the shell and
# hook.rs's tokenizer see them (`cu''rl`, `c\url` and `"curl"` are all
# curl), so the pre-filter looks at the command with quotes and backslashes
# dropped. Without awk the lexer yields nothing and these checks are skipped.
LEX=''
LEX_TXT=$CMD
case $CMD in
  *[\"\'\\]*) LEX_TXT=$(printf '%s' "$CMD" | tr -d "\"'\\\\") ;;
esac
case $LEX_TXT in
  *curl*|*wget*|*deno*|*install*|*npm*[[:space:]]exec*|*npm*[[:space:]]x*|*bun*[[:space:]]x*|*uv*tool*run*)
    LEX=$(printf '%s\n' "$CMD" | LC_ALL=C awk "$LEX_AWK" 2>/dev/null) || LEX='' ;;
esac
GATES=''
DOWNLOADS=''
GATED_REASON=''
SKIP_SEG=0
IFS=$NL
for REC in $LEX; do
  IFS=$US
  # shellcheck disable=SC2086 # split the record into its fields
  set -- $REC
  IFS=$IFS_DEFAULT
  [ $# -ge 2 ] || continue
  REC_KIND=$1
  shift
  case $REC_KIND in
    S)
      # A segment not chained with && starts with no vetted targets.
      [ "$1" = A ] || GATES=''
      shift
      SKIP_SEG=0
      # `cd dir` / `pushd dir`: where later segments run.
      case ${1-} in
        cd|pushd)
          if [ $# -le 2 ]; then
            if [ $# -eq 2 ]; then expand "$2"; CUR_CWD=$R; else CUR_CWD=$HOME_DIR; fi
            SKIP_SEG=1
          fi ;;
      esac
      ;;
    T)
      [ $SKIP_SEG = 1 ] || judge_stage "$@"
      ;;
  esac
done
IFS=$IFS_DEFAULT

# ── Bypass: the command is already going through sigil ─────────────────────

# A sigil invocation at the start of the command or of any pipeline/list
# segment is the acquiring command — allow it.
has '(^[[:space:]]*|[;&|][[:space:]]*)sigil[[:space:]]' \
  && emit allow "${GATED_REASON:-Command uses sigil}"

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

# ── pip / uv: -r requirements -> ask; explicit package -> deny ─────────────

PIP_INSTALL="${WB}(pip[0-9.]*${MOD}[[:space:]]+install|python[0-9.]*[[:space:]]+-m[[:space:]]+pip[[:space:]]+install|uv[[:space:]]+pip[[:space:]]+install)"
if has "${PIP_INSTALL}([[:space:]]|\$)"; then
  if has "(^|[[:space:]])(-r|--requirement)([[:space:]]|\$)"; then
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

emit allow "${GATED_REASON:-No acquisition pattern matched}"
