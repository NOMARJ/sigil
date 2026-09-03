//! Typosquat detection for declared dependencies.
//!
//! A dependency whose name is one edit away from a very popular package is
//! the registry-side supply-chain attack that needs no code at all: `reqeusts`
//! resolves, installs, and runs a setup hook before anyone reads a line. The
//! check is deliberately simple and ecosystem-aware:
//!
//! - the declared name is compared against an embedded list of the most
//!   depended-upon packages *in the same ecosystem* (an npm `request` is a
//!   real, popular package; a PyPI `request` is a squat of `requests`);
//! - separators are normalised first (`python-dateutil` and
//!   `python_dateutil` are the same name), and an exact match is never a
//!   finding;
//! - a Damerau–Levenshtein distance of 1 (one insertion, deletion,
//!   substitution or adjacent transposition) is a finding, unless the name is
//!   on the short allowlist of legitimate near-names.
//!
//! The lists are small on purpose: distance-1 neighbours of a 150-name list
//! are a few thousand strings, which is exactly the space squatters target.
//! Names beyond the list are the long tail, where the signal is weak.

use std::path::Path;

use super::{Finding, Phase, Severity};

/// Weight for a typosquat finding. Provenance findings default to 1; a
/// distance-1 name to a top package is a stronger signal than a hidden
/// file, and one High finding at weight 5 lands at MEDIUM RISK on its own.
pub const WEIGHT: u32 = 5;

/// Most depended-upon npm packages (hand-curated from the registry's
/// dependents counts; names only, no ranking is implied).
const NPM_TOP: &[&str] = &[
    "lodash",
    "chalk",
    "request",
    "commander",
    "react",
    "express",
    "debug",
    "async",
    "fs-extra",
    "moment",
    "prop-types",
    "react-dom",
    "bluebird",
    "underscore",
    "vue",
    "axios",
    "tslib",
    "mkdirp",
    "glob",
    "yargs",
    "colors",
    "inquirer",
    "webpack",
    "uuid",
    "classnames",
    "minimist",
    "body-parser",
    "rxjs",
    "babel-runtime",
    "jquery",
    "yeoman-generator",
    "through2",
    "babel-core",
    "core-js",
    "semver",
    "typescript",
    "cheerio",
    "dotenv",
    "eslint",
    "rimraf",
    "shelljs",
    "q",
    "socket.io",
    "redux",
    "babel-loader",
    "aws-sdk",
    "mocha",
    "node-fetch",
    "object-assign",
    "ws",
    "path",
    "cors",
    "css-loader",
    "winston",
    "ora",
    "underscore.string",
    "ramda",
    "jest",
    "js-yaml",
    "immutable",
    "mongodb",
    "mongoose",
    "handlebars",
    "superagent",
    "redis",
    "gulp",
    "optimist",
    "meow",
    "node-sass",
    "readable-stream",
    "xml2js",
    "fs",
    "ejs",
    "extend",
    "cookie-parser",
    "clone",
    "morgan",
    "postcss",
    "http-proxy",
    "chokidar",
    "styled-components",
    "es6-promise",
    "babel-eslint",
    "koa",
    "jsonwebtoken",
    "bcrypt",
    "passport",
    "nodemon",
    "prettier",
    "next",
    "vite",
    "esbuild",
    "tailwindcss",
    "zod",
    "openai",
    "@anthropic-ai/sdk",
    "langchain",
    "puppeteer",
    "playwright",
    "sharp",
    "pg",
    "mysql",
    "sqlite3",
    "ioredis",
    "nanoid",
    "date-fns",
    "dayjs",
    "validator",
    "joi",
    "yup",
    "helmet",
    "compression",
    "multer",
    "socket.io-client",
    "cross-env",
    "concurrently",
    "ts-node",
    "tsx",
    "npm",
    "yarn",
    "pnpm",
    "left-pad",
    "event-stream",
    "ua-parser-js",
    "coa",
    "rc",
    "colors.js",
    "faker",
    "node-ipc",
];

/// Most downloaded PyPI packages (hand-curated; names only).
const PYPI_TOP: &[&str] = &[
    "boto3",
    "urllib3",
    "requests",
    "botocore",
    "setuptools",
    "certifi",
    "idna",
    "charset-normalizer",
    "typing-extensions",
    "python-dateutil",
    "s3transfer",
    "packaging",
    "six",
    "pyyaml",
    "numpy",
    "pip",
    "cryptography",
    "wheel",
    "cffi",
    "pycparser",
    "jmespath",
    "attrs",
    "pandas",
    "click",
    "pydantic",
    "pytz",
    "markupsafe",
    "jinja2",
    "platformdirs",
    "protobuf",
    "rsa",
    "pyasn1",
    "colorama",
    "importlib-metadata",
    "zipp",
    "filelock",
    "google-api-core",
    "tomli",
    "aiohttp",
    "fsspec",
    "pyjwt",
    "wrapt",
    "cachetools",
    "psutil",
    "virtualenv",
    "sqlalchemy",
    "pluggy",
    "pytest",
    "scipy",
    "grpcio",
    "pillow",
    "docutils",
    "pyparsing",
    "iniconfig",
    "tqdm",
    "httpx",
    "anyio",
    "sniffio",
    "h11",
    "httpcore",
    "flask",
    "django",
    "fastapi",
    "uvicorn",
    "starlette",
    "werkzeug",
    "itsdangerous",
    "blinker",
    "openai",
    "anthropic",
    "langchain",
    "tiktoken",
    "tenacity",
    "distro",
    "openpyxl",
    "matplotlib",
    "scikit-learn",
    "torch",
    "transformers",
    "tokenizers",
    "huggingface-hub",
    "beautifulsoup4",
    "lxml",
    "soupsieve",
    "paramiko",
    "bcrypt",
    "pynacl",
    "celery",
    "redis",
    "kombu",
    "billiard",
    "vine",
    "amqp",
    "greenlet",
    "gunicorn",
    "python-dotenv",
    "toml",
    "pyopenssl",
    "oauthlib",
    "requests-oauthlib",
    "google-auth",
    "googleapis-common-protos",
    "azure-core",
    "msal",
    "black",
    "ruff",
    "mypy",
    "isort",
    "flake8",
    "pycodestyle",
    "coverage",
    "pytest-cov",
    "mock",
    "decorator",
    "regex",
    "msgpack",
    "websockets",
    "python-multipart",
    "pymongo",
    "psycopg2",
    "psycopg2-binary",
    "mysql-connector-python",
    "sqlparse",
    "markdown",
    "pygments",
    "rich",
    "typer",
    "shellingham",
    "poetry",
    "colorlog",
    "pexpect",
    "ptyprocess",
    "jsonschema",
    "referencing",
    "jupyter",
    "ipython",
    "notebook",
    "nltk",
    "spacy",
    "opencv-python",
    "pyarrow",
    "polars",
    "dask",
];

/// Legitimate names that sit one edit from a top package and must not be
/// flagged. Keep this list short and justified.
///
/// Every entry must name a package that is actually published and in real use,
/// and say so. An entry for a name nobody has published is not "harmless
/// symmetry": it pre-authorises that exact name, so whoever registers it later
/// inherits a rule that has been told to stay quiet. Entries removed on those
/// grounds (2026-09-03, each checked against the registry): npm `jquery3`,
/// `eslint4` and PyPI `pillow2`, `toml2`, `cffi2` all returned 404, and npm
/// `reduxs`, `vue3` had no published version.
const ALLOWLIST: &[(&str, &str)] = &[
    // npm: genuine, widely used packages that happen to be near-names.
    ("npm", "requests"), // near `request`; scoped differently on PyPI
    ("npm", "nodemailer"),
    ("npm", "pg-native"),
    ("npm", "mysql2"),
    ("npm", "ioredis-mock"),
    // Near-names measured against a 150-package clean npm control set, where
    // each was a dependency of a top-download package. Downloads are npm's own
    // last-month counts on 2026-09-03.
    ("npm", "pathe"),        // path utilities, ~575M/month, one edit from `path`
    ("npm", "upath"),        // path utilities, ~85M/month, one edit from `path`
    ("npm", "tsd"),          // type-definition tester, ~1.9M/month, one edit from `tsx`
    ("npm", "http-proxy-3"), // maintained http-proxy fork, ~780K/month
    ("npm", "eclint"),       // EditorConfig linter, ~103K/month, one edit from `eslint`
    ("npm", "fake"),         // published 2011, ~27K/month, one edit from `faker`
    // PyPI: real packages adjacent to popular ones.
    ("pypi", "pyasn1-modules"),
    ("pypi", "pytest-xdist"),
    ("pypi", "boto"), // the legacy AWS SDK, one edit from boto3
    ("pypi", "tomlkit"),
    ("pypi", "attr"), // real, distinct package adjacent to attrs
    ("pypi", "h2"),   // real HTTP/2 package, one edit from h11
    ("pypi", "h5py"),
    ("pypi", "py"),
    ("pypi", "mypy-extensions"),
    ("pypi", "flask-cors"),
    // pydantic's next-generation HTTP client (pypi.org/project/httpx2), one
    // edit from httpx and a real dependency of Sigil's own API.
    ("pypi", "httpx2"),
    // Near-names measured against a 150-package clean PyPI control set, each
    // an established project on PyPI (release counts read 2026-09-03).
    ("pypi", "authlib"), // OAuth/OpenID library, 64 releases, one edit from oauthlib
    ("pypi", "psycopg"), // psycopg 3, 62 releases, one edit from psycopg2
    ("pypi", "psycopg-binary"), // the psycopg 3 binary wheel, 57 releases
    ("pypi", "tomli-w"), // the TOML writer companion to tomli, 9 releases
];

/// Which registry a manifest belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pypi,
}

impl Ecosystem {
    fn name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
        }
    }
    fn top(self) -> &'static [&'static str] {
        match self {
            Ecosystem::Npm => NPM_TOP,
            Ecosystem::Pypi => PYPI_TOP,
        }
    }
}

/// A declared dependency and where it was declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    pub name: String,
    pub line: Option<usize>,
}

/// Normalise a package name for comparison: lowercase, separators removed.
///
/// PEP 503 treats `-`, `_` and `.` as equivalent; npm names are case-
/// insensitive in practice. Removing separators entirely means a squat that
/// only moves a hyphen (`python-dateutil` vs `pythondateutil`) compares
/// equal to the real name and is treated as a match, not a squat — which is
/// right for PyPI (they resolve to the same project) and harmless for npm.
pub fn normalize(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Damerau–Levenshtein distance (optimal string alignment) between two
/// strings, capped: returns 2 as soon as it is certain the distance is >1.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > 1 {
        return 2;
    }
    let (n, m) = (a.len(), b.len());
    let mut prev2: Vec<usize> = vec![0; m + 1];
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur: Vec<usize> = vec![0; m + 1];
    for i in 1..=n {
        cur[0] = i;
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                cur[j] = cur[j].min(prev2[j - 2] + 1);
            }
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m].min(2)
}

/// The top package a declared name squats, if any.
pub fn squats(ecosystem: Ecosystem, declared: &str) -> Option<&'static str> {
    let norm = normalize(declared);
    if norm.len() < 3 {
        return None;
    }
    if ALLOWLIST
        .iter()
        .any(|(eco, name)| *eco == ecosystem.name() && normalize(name) == norm)
    {
        return None;
    }
    let top = ecosystem.top();
    // Exact match to any top package: not a squat.
    if top.iter().any(|t| normalize(t) == norm) {
        return None;
    }
    top.iter()
        .copied()
        .find(|t| distance(&normalize(t), &norm) == 1)
}

/// Dependencies declared in a `package.json`.
pub fn parse_package_json(contents: &str) -> Vec<Declared> {
    let mut out = Vec::new();
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(contents) else {
        return out;
    };
    for key in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(map) = doc.get(key).and_then(|v| v.as_object()) {
            for (name, spec) in map {
                // An npm alias (`"prettier-2": "npm:prettier@^2"`) installs the
                // aliased package under a local key, which is how a project
                // depends on two majors at once. The key is the caller's own
                // label, so the name that must be judged is the alias target.
                let declared = spec
                    .as_str()
                    .and_then(alias_target)
                    .unwrap_or_else(|| name.clone());
                out.push(Declared {
                    name: declared,
                    line: find_line(contents, &format!("\"{name}\"")),
                });
            }
        }
    }
    out
}

/// The package an `npm:` alias specifier points at.
///
/// `npm:prettier@^2` -> `prettier`, `npm:@scope/pkg@1` -> `@scope/pkg`.
/// Returns `None` for anything that is not an alias specifier.
fn alias_target(spec: &str) -> Option<String> {
    let rest = spec.trim().strip_prefix("npm:")?;
    // A scoped name keeps its leading `@`; the version separator is the `@`
    // that follows the name.
    let name = match rest.strip_prefix('@') {
        Some(scoped) => match scoped.find('@') {
            Some(at) => &rest[..at + 1],
            None => rest,
        },
        None => rest.split('@').next().unwrap_or(rest),
    };
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Dependencies declared in a `requirements*.txt`.
pub fn parse_requirements(contents: &str) -> Vec<Declared> {
    let mut out = Vec::new();
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let name: String = line
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();
        if !name.is_empty() {
            out.push(Declared {
                name,
                line: Some(idx + 1),
            });
        }
    }
    out
}

/// Dependencies declared in `pyproject.toml` (`[project] dependencies`,
/// `[project.optional-dependencies]`, `[tool.poetry.dependencies]`) or a
/// `Pipfile` (`[packages]`, `[dev-packages]`), read line by line without a
/// TOML parser: enough for names, which is all this check needs.
pub fn parse_pyproject_like(contents: &str) -> Vec<Declared> {
    let mut out = Vec::new();
    let mut in_dep_list = false;
    let mut in_dep_table = false;
    let mut in_group_table = false;
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_dep_table = matches!(
                line,
                "[tool.poetry.dependencies]"
                    | "[tool.poetry.dev-dependencies]"
                    | "[tool.poetry.group.dev.dependencies]"
                    | "[packages]"
                    | "[dev-packages]"
            );
            // `[project.optional-dependencies]` (PEP 621) and
            // `[dependency-groups]` (PEP 735) map a *group* name to a list of
            // requirements. Reading them as `name = version` tables would take
            // the group name for a dependency ("xml = ['lxml>=5.3.0']" declares
            // lxml, not a package called xml) and would split each list item on
            // the `=` inside its version specifier.
            in_group_table = line.starts_with("[project.optional-dependencies")
                || line.starts_with("[dependency-groups");
            in_dep_list = false;
            continue;
        }
        if (line.starts_with("dependencies") || in_group_table) && line.contains('[') {
            in_dep_list = !line.contains(']');
            for item in quoted_items(line) {
                push_requirement(&mut out, &item, idx + 1);
            }
            continue;
        }
        if in_dep_list {
            if line.starts_with(']') {
                in_dep_list = false;
                continue;
            }
            for item in quoted_items(line) {
                push_requirement(&mut out, &item, idx + 1);
            }
            continue;
        }
        if in_dep_table {
            if let Some((key, _)) = line.split_once('=') {
                // Truncate at the first character a package name cannot
                // contain, so a line the caller misclassified (or an inline
                // `>=` in the key half) yields "pytest", never "pytest>".
                let name: String = key
                    .trim()
                    .trim_matches('"')
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                    .collect();
                if name != "python" && !name.is_empty() {
                    out.push(Declared {
                        name,
                        line: Some(idx + 1),
                    });
                }
            }
        }
    }
    out
}

fn push_requirement(out: &mut Vec<Declared>, item: &str, line: usize) {
    let name: String = item
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    if !name.is_empty() {
        out.push(Declared {
            name,
            line: Some(line),
        });
    }
}

/// The TOML strings of an array line, in the positions where a requirement can
/// appear: at the start of the array or straight after a comma.
///
/// Anchoring on position rather than searching for quote characters is what
/// keeps two shapes out of the results. A quote *inside* a requirement belongs
/// to its environment marker (`"pytest; implementation == 'PyPy'"` declares
/// pytest, not PyPy), and an entry that does not open with a quote is not a
/// requirement at all — `{ include-group = "fix" }` (PEP 735) references
/// another dependency group.
fn quoted_items(line: &str) -> Vec<String> {
    let mut items = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    // Skip anything before the array actually opens, so a key such as
    // `dev = [` never contributes its own name.
    if let Some(open) = line.find('[') {
        i = open + 1;
    }
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let c = bytes[i] as char;
        if c == '"' || c == '\'' {
            let after = &line[i + 1..];
            let Some(end) = after.find(c) else { break };
            items.push(after[..end].to_string());
            i += 1 + end + 1;
        } else if c == ']' {
            break;
        }
        // Whatever this entry was, resume at the next separator.
        match line[i..].find(',') {
            Some(comma) => i += comma + 1,
            None => break,
        }
    }
    items
}

fn find_line(contents: &str, needle: &str) -> Option<usize> {
    contents
        .lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
}

/// A manifest parser: file contents to declared dependencies.
pub type Parser = fn(&str) -> Vec<Declared>;

/// Which parser handles this manifest, by basename.
pub fn ecosystem_for(filename: &str) -> Option<(Ecosystem, Parser)> {
    if filename == "package.json" {
        return Some((Ecosystem::Npm, parse_package_json));
    }
    if filename.starts_with("requirements") && filename.ends_with(".txt") {
        return Some((Ecosystem::Pypi, parse_requirements));
    }
    if filename == "pyproject.toml" || filename == "Pipfile" {
        return Some((Ecosystem::Pypi, parse_pyproject_like));
    }
    None
}

/// Scan the manifests among `files` and report typosquats.
pub fn scan(strip_base: &Path, files: &[std::path::PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for path in files {
        let Some(filename) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        let Some((eco, parser)) = ecosystem_for(filename) else {
            continue;
        };
        // Manifests inside vendored trees are someone else's declarations.
        let rel = path
            .strip_prefix(strip_base)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        if rel.contains("node_modules/") || rel.contains("site-packages/") {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for dep in parser(&contents) {
            if let Some(target) = squats(eco, &dep.name) {
                out.push(Finding {
                    phase: Phase::Provenance,
                    rule: "TYPOSQUAT-001".to_string(),
                    severity: Severity::High,
                    file: rel.clone(),
                    line: dep.line,
                    snippet: format!(
                        "Dependency name one edit from a top {} package: \"{}\" (did you mean \"{}\"?)",
                        eco.name(),
                        dep.name,
                        target
                    ),
                    weight: WEIGHT,
                    kev: false,
                    epss: 0.0,
                    fingerprint: String::new(),
                    locator: None,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_dependency_groups_declare_their_items_not_their_group_name() {
        // PEP 621: `[project.optional-dependencies]` maps a group name to a
        // list. Reading it as `name = version` took the group name for a
        // package and split each item on the `=` of its version specifier.
        let names: Vec<String> = parse_pyproject_like(
            r#"
[project]
dependencies = ["idna>=3.18"]

[project.optional-dependencies]
xml = ['lxml>=5.3.0']
dev = [
    "pytest>=8.4",
    "pytest-cov>=6.2.0",
]
"#,
        )
        .into_iter()
        .map(|d| d.name)
        .collect();
        assert_eq!(names, vec!["idna", "lxml", "pytest", "pytest-cov"]);
        assert!(!names.iter().any(|n| n.ends_with('>')), "{names:?}");
        assert!(
            !names.iter().any(|n| n == "xml" || n == "dev"),
            "group names are not dependencies: {names:?}"
        );
    }

    #[test]
    fn dependency_groups_skip_include_group_references() {
        // PEP 735: `{ include-group = "fix" }` references another group, and
        // an environment marker's own quotes are not a second item.
        let names: Vec<String> = parse_pyproject_like(
            r#"
[dependency-groups]
fix = ["pre-commit>=4"]
test = [
  { include-group = "fix" },
  "pytest>=8; platform_python_implementation=='PyPy'",
]
"#,
        )
        .into_iter()
        .map(|d| d.name)
        .collect();
        assert_eq!(names, vec!["pre-commit", "pytest"]);
        assert!(
            !names.iter().any(|n| n == "fix" || n == "PyPy"),
            "{names:?}"
        );
    }

    #[test]
    fn poetry_table_key_never_carries_a_version_specifier() {
        let names: Vec<String> = parse_pyproject_like(
            "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"^2.31\"\n",
        )
        .into_iter()
        .map(|d| d.name)
        .collect();
        assert_eq!(names, vec!["requests"], "python itself is not a dependency");
    }

    #[test]
    fn npm_alias_resolves_to_the_aliased_package() {
        // `"prettier-2": "npm:prettier@^2"` installs prettier, not a package
        // called prettier-2; the key is the caller's own label.
        assert_eq!(alias_target("npm:prettier@^2").as_deref(), Some("prettier"));
        assert_eq!(
            alias_target("npm:@scope/pkg@1.2.3").as_deref(),
            Some("@scope/pkg")
        );
        assert_eq!(alias_target("npm:lodash").as_deref(), Some("lodash"));
        assert_eq!(alias_target("^2.0.0"), None);

        let names: Vec<String> = parse_package_json(
            r#"{"devDependencies": {"prettier": "^3.5.3", "prettier-2": "npm:prettier@^2"}}"#,
        )
        .into_iter()
        .map(|d| d.name)
        .collect();
        assert_eq!(names, vec!["prettier", "prettier"]);
    }

    #[test]
    fn allowlisted_near_names_are_real_published_packages() {
        // Each of these was measured firing on a top-download package that
        // depends on it. An allowlist entry for an *unpublished* name would
        // pre-authorise whoever registers it later, so there are none.
        for (eco, name) in [
            (Ecosystem::Npm, "pathe"),
            (Ecosystem::Npm, "upath"),
            (Ecosystem::Npm, "tsd"),
            (Ecosystem::Npm, "eclint"),
            (Ecosystem::Pypi, "authlib"),
            (Ecosystem::Pypi, "psycopg"),
            (Ecosystem::Pypi, "tomli-w"),
        ] {
            assert_eq!(squats(eco, name), None, "{name} is allowlisted");
        }
        // The narrowing must not cost real detections.
        assert_eq!(squats(Ecosystem::Pypi, "reqeusts"), Some("requests"));
        assert_eq!(squats(Ecosystem::Npm, "lodahs"), Some("lodash"));
    }

    #[test]
    fn distance_counts_one_edit_and_transposition() {
        assert_eq!(distance("requests", "reqeusts"), 1);
        assert_eq!(distance("requests", "request"), 1);
        assert_eq!(distance("colorama", "coloramma"), 1);
        assert_eq!(distance("lodash", "lodash"), 0);
        assert_eq!(distance("lodash", "underscore"), 2);
    }

    #[test]
    fn ecosystem_aware_squat_detection() {
        assert_eq!(squats(Ecosystem::Pypi, "reqeusts"), Some("requests"));
        assert_eq!(squats(Ecosystem::Pypi, "coloramma"), Some("colorama"));
        assert_eq!(squats(Ecosystem::Pypi, "requests"), None, "exact match");
        assert_eq!(
            squats(Ecosystem::Pypi, "python_dateutil"),
            None,
            "separator-equivalent"
        );
        assert_eq!(squats(Ecosystem::Pypi, "boto"), None, "allowlisted");
        assert_eq!(
            squats(Ecosystem::Pypi, "h2"),
            None,
            "allowlisted / too short"
        );
        assert_eq!(
            squats(Ecosystem::Pypi, "httpx2"),
            None,
            "pydantic httpx2 is real"
        );
        assert_eq!(squats(Ecosystem::Npm, "request"), None, "real npm package");
        assert_eq!(squats(Ecosystem::Npm, "lodahs"), Some("lodash"));
        assert_eq!(squats(Ecosystem::Npm, "expres"), Some("express"));
        assert_eq!(squats(Ecosystem::Npm, "some-long-unrelated-name"), None);
    }

    #[test]
    fn parses_manifests() {
        let pkg = r#"{"name":"x","dependencies":{"reqeusts":"^1","lodash":"^4"},"devDependencies":{"expres":"*"}}"#;
        let names: Vec<String> = parse_package_json(pkg)
            .into_iter()
            .map(|d| d.name)
            .collect();
        // serde_json iterates object keys in sorted order.
        let mut names = names;
        names.sort();
        assert_eq!(names, vec!["expres", "lodash", "reqeusts"]);

        let req = "# comment\nrequests>=2\ncoloramma==0.4\n-r other.txt\nnumpy[extra]>=1\n";
        let names: Vec<String> = parse_requirements(req)
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(names, vec!["requests", "coloramma", "numpy"]);

        let py = "[project]\nname = \"x\"\ndependencies = [\n  \"reqeusts>=2\",\n  \"click\",\n]\n[tool.poetry.dependencies]\npython = \"^3.9\"\ncoloramma = \"*\"\n";
        let names: Vec<String> = parse_pyproject_like(py)
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(names, vec!["reqeusts", "click", "coloramma"]);
    }

    #[test]
    fn scan_reports_squats_with_lines() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("package.json"),
            "{\n  \"dependencies\": {\n    \"lodahs\": \"^4.17.0\",\n    \"coloramma\": \"^0.4.0\"\n  }\n}\n",
        )
        .unwrap();
        std::fs::write(root.join("requirements.txt"), "reqeusts\nrequests\n").unwrap();
        let files = vec![root.join("package.json"), root.join("requirements.txt")];
        let findings = scan(root, &files);
        // Ecosystem-aware: "coloramma" is one edit from PyPI's colorama but
        // is declared in package.json, where nothing is near it; "lodahs" is
        // a transposition of npm's lodash; "reqeusts" is one edit from
        // PyPI's requests.
        let mut got: Vec<(String, Option<usize>, String)> = findings
            .iter()
            .map(|f| (f.file.clone(), f.line, f.snippet.clone()))
            .collect();
        got.sort();
        assert_eq!(got.len(), 2, "{got:#?}");
        assert!(
            got[0].0 == "package.json" && got[0].1 == Some(3),
            "{got:#?}"
        );
        assert!(got[0].2.contains("\"lodash\""));
        assert!(got[1].0 == "requirements.txt" && got[1].2.contains("\"requests\""));
        assert!(findings
            .iter()
            .all(|f| f.rule == "TYPOSQUAT-001" && f.weight == WEIGHT));
    }
}
