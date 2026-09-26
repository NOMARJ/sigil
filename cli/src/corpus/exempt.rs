//! Match-local exemptions (`suppress.match_context`, `suppress.value_matches`).
//!
//! The older suppression predicates decide per *line*: `line_contains` drops
//! the finding whenever a string appears anywhere on the line, which is
//! both too blunt (it cannot tell a method definition from a call of the same name) and
//! easy to exploit (append the string to a malicious line). These decide per
//! *match*, from the text immediately around it, and a line is dropped only
//! when every match of the rule on it is exempt:
//!
//! - Iteration is overlap-safe: after an exempt match starting at `s` the
//!   search restarts at the next character after `s`, so an exempt match
//!   cannot swallow a real one that overlaps it.
//! - It fails closed: past [`MAX_MATCHES_PER_LINE`] matches on one line the
//!   line is kept.
//! - A pack whose predicates do not compile is refused by the loaders
//!   ([`validate`]); if one reaches the compiled corpus anyway its
//!   exemptions are disabled, which can only keep findings.

use regex::{Captures, Regex};

use super::schema::{MatchContext, SuppressionPredicates};

/// Longest window, in bytes, on each side of the anchor.
pub const WINDOW_BYTES: usize = 120;
/// Matches examined on one line before the line is kept unexamined.
pub const MAX_MATCHES_PER_LINE: usize = 64;

struct Context {
    before: Option<Regex>,
    after: Option<Regex>,
    extensions: Vec<String>,
    same: Vec<(String, String)>,
}

/// A rule's match-local exemptions, compiled.
#[derive(Default)]
pub struct Exemptions {
    contexts: Vec<Context>,
    values: Vec<Regex>,
}

impl std::fmt::Debug for Exemptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exemptions")
            .field("contexts", &self.contexts.len())
            .field("values", &self.values.len())
            .finish()
    }
}

fn group_names(re: &Regex) -> Vec<&str> {
    re.capture_names().flatten().collect()
}

/// Check a rule's match-local predicates against its pattern: every regex
/// compiles, `value_matches` has a `value` group to read, and every `same`
/// pair names groups its context defines.
pub fn validate(pattern: &str, s: &SuppressionPredicates) -> Result<(), String> {
    compile(pattern, s).map(|_| ())
}

/// Compile a rule's match-local predicates. `Err` says what is wrong.
pub fn compile(pattern: &str, s: &SuppressionPredicates) -> Result<Exemptions, String> {
    if s.match_context.is_empty() && s.value_matches.is_empty() {
        return Ok(Exemptions::default());
    }
    let rule = Regex::new(pattern).map_err(|e| format!("pattern: {e}"))?;
    let rule_groups = group_names(&rule);
    if !s.value_matches.is_empty() && !rule_groups.contains(&"value") {
        return Err("value_matches needs a (?P<value>...) group in the rule's pattern".to_string());
    }
    let values = s
        .value_matches
        .iter()
        .map(|v| Regex::new(&format!("^(?:{v})$")).map_err(|e| format!("value_matches '{v}': {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let contexts = s
        .match_context
        .iter()
        .map(compile_context)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Exemptions { contexts, values })
}

fn compile_context(c: &MatchContext) -> Result<Context, String> {
    if c.before.is_none() && c.after.is_none() {
        return Err("match_context needs `before`, `after` or both".to_string());
    }
    let before = c
        .before
        .as_ref()
        .map(|b| Regex::new(&format!("(?:{b})$")).map_err(|e| format!("match_context before: {e}")))
        .transpose()?;
    let after = c
        .after
        .as_ref()
        .map(|a| Regex::new(&format!("^(?:{a})")).map_err(|e| format!("match_context after: {e}")))
        .transpose()?;
    let mut names: Vec<&str> = Vec::new();
    for re in before.iter().chain(after.iter()) {
        names.extend(group_names(re));
    }
    for [a, b] in &c.same {
        for g in [a, b] {
            if !names.contains(&g.as_str()) {
                return Err(format!(
                    "match_context same: no group named '{g}' in its before/after"
                ));
            }
        }
    }
    Ok(Context {
        before,
        after,
        extensions: c.extensions.clone(),
        same: c.same.iter().map(|[a, b]| (a.clone(), b.clone())).collect(),
    })
}

/// The window before `at`: at most [`WINDOW_BYTES`], starting on a
/// character boundary.
fn window_before(line: &str, at: usize) -> &str {
    let mut start = at.saturating_sub(WINDOW_BYTES);
    while !line.is_char_boundary(start) {
        start += 1;
    }
    &line[start..at]
}

/// The window after `at`: at most [`WINDOW_BYTES`], ending on a character
/// boundary.
fn window_after(line: &str, at: usize) -> &str {
    let mut end = (at + WINDOW_BYTES).min(line.len());
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    &line[at..end]
}

impl Exemptions {
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty() && self.values.is_empty()
    }

    /// Is this one match exempt?
    fn exempt(&self, caps: &Captures<'_>, line: &str, ext: &str) -> bool {
        if let Some(v) = caps.name("value") {
            if self.values.iter().any(|r| r.is_match(v.as_str())) {
                return true;
            }
        }
        let Some(anchor) = caps.name("anchor").or_else(|| caps.get(0)) else {
            return false;
        };
        let before_w = window_before(line, anchor.start());
        let after_w = window_after(line, anchor.end());
        'contexts: for c in &self.contexts {
            if !c.extensions.is_empty() && !c.extensions.iter().any(|e| e == ext) {
                continue;
            }
            let bc = match &c.before {
                Some(re) => match re.captures(before_w) {
                    Some(bc) => Some(bc),
                    None => continue,
                },
                None => None,
            };
            let ac = match &c.after {
                Some(re) => match re.captures(after_w) {
                    Some(ac) => Some(ac),
                    None => continue,
                },
                None => None,
            };
            let group = |name: &str| {
                bc.as_ref()
                    .and_then(|c| c.name(name))
                    .or_else(|| ac.as_ref().and_then(|c| c.name(name)))
                    .map(|m| m.as_str())
            };
            for (a, b) in &c.same {
                match (group(a), group(b)) {
                    (Some(x), Some(y)) if x == y => {}
                    _ => continue 'contexts,
                }
            }
            return true;
        }
        false
    }

    /// Whether `re` matches `line` at least once and every match is exempt.
    /// `ext` is the file's extension without the dot.
    pub fn line_exempt(&self, re: &Regex, line: &str, ext: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        let mut pos = 0usize;
        let mut seen = 0usize;
        while pos <= line.len() {
            let Some(caps) = re.captures_at(line, pos) else {
                break;
            };
            seen += 1;
            if seen > MAX_MATCHES_PER_LINE || !self.exempt(&caps, line, ext) {
                return false;
            }
            let start = caps.get(0).map_or(pos, |m| m.start());
            pos = start + line[start..].chars().next().map_or(1, char::len_utf8);
        }
        seen > 0
    }
}

/// The extension of a file name, without the dot (`""` when there is none).
pub fn extension(filename: &str) -> &str {
    filename.rsplit_once('.').map(|(_, e)| e).unwrap_or("")
}
