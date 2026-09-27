//! `sigil scan mcp:<server-name>[@<version>]`: scan an MCP server straight
//! from the MCP registry, before anyone adds it to an agent.
//!
//! The registry (<https://registry.modelcontextprotocol.io>, or a private
//! sub-registry named by `SIGIL_MCP_REGISTRY_URL`) says where a server's code
//! is published. This module turns an entry into something [`crate::ingest`]
//! already knows how to fetch safely:
//!
//! 1. an npm package: the exact tarball the registry entry pins
//!    (`dist.tarball` of `<identifier>@<version>` on registry.npmjs.org);
//! 2. a PyPI package: the sdist of that version, else its first wheel;
//! 3. an `.mcpb` bundle: its https URL;
//! 4. otherwise the source repository (with its `subfolder`, if the entry
//!    names one), cloned at its default branch.
//!
//! A remote-only server (streamable HTTP / SSE with no package and no
//! repository) has no code to scan; that is an error that says so, not a
//! clean verdict. Packages from any npm registry other than the public one
//! are not followed (their base URL comes from the registry entry, so it is
//! untrusted input); the repository is used instead.

use serde_json::Value;

use crate::ingest::Plan;

const DEFAULT_REGISTRY: &str = "https://registry.modelcontextprotocol.io";
const NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// What a registry entry resolved to, for the progress line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub plan: Plan,
    /// Human description: `npm tarball of foo@1.2.3`.
    pub what: String,
    /// Registry facts worth showing before the scan: transport, secrets the
    /// server asks for, remote endpoints.
    pub notes: Vec<String>,
}

fn registry_base() -> String {
    std::env::var("SIGIL_MCP_REGISTRY_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REGISTRY.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Split `name@version`. Server names contain `/` and `.`, never `@`.
pub fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.rsplit_once('@') {
        Some((n, v)) if !n.is_empty() && !v.is_empty() => (n, Some(v)),
        _ => (target, None),
    }
}

fn is_latest(entry: &Value) -> bool {
    entry
        .pointer("/_meta/io.modelcontextprotocol.registry~1official/isLatest")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Pick the server entry for `name` (and `version`, if given) out of a
/// `/v0/servers` search response. With no version, the entry the registry
/// marks latest wins, else the last listed.
pub fn pick_server<'a>(
    doc: &'a Value,
    name: &str,
    version: Option<&str>,
) -> Result<&'a Value, String> {
    let servers = doc
        .get("servers")
        .and_then(Value::as_array)
        .ok_or("registry response has no servers array")?;
    let matching: Vec<&Value> = servers
        .iter()
        .filter(|e| e.pointer("/server/name").and_then(Value::as_str) == Some(name))
        .collect();
    if matching.is_empty() {
        let near: Vec<&str> = servers
            .iter()
            .filter_map(|e| e.pointer("/server/name").and_then(Value::as_str))
            .take(5)
            .collect();
        return Err(if near.is_empty() {
            format!("no server named {name:?} in the MCP registry")
        } else {
            format!(
                "no server named {name:?} in the MCP registry (did you mean: {})",
                near.join(", ")
            )
        });
    }
    if let Some(v) = version {
        return matching
            .into_iter()
            .find(|e| e.pointer("/server/version").and_then(Value::as_str) == Some(v))
            .ok_or_else(|| format!("{name} has no version {v} in the MCP registry"));
    }
    Ok(matching
        .iter()
        .copied()
        .find(|e| is_latest(e))
        .unwrap_or(matching[matching.len() - 1]))
}

/// Registry facts shown before the scan.
fn notes_for(server: &Value) -> Vec<String> {
    let mut notes = Vec::new();
    for pkg in server
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(t) = pkg.pointer("/transport/type").and_then(Value::as_str) {
            notes.push(format!("transport: {t}"));
        }
        let secrets: Vec<&str> = pkg
            .get("environmentVariables")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|e| e.get("isSecret").and_then(Value::as_bool) == Some(true))
            .filter_map(|e| e.get("name").and_then(Value::as_str))
            .collect();
        if !secrets.is_empty() {
            notes.push(format!("asks for secrets: {}", secrets.join(", ")));
        }
    }
    for r in server
        .get("remotes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(u) = r.get("url").and_then(Value::as_str) {
            notes.push(format!(
                "remote endpoint ({}): {u} — runs on someone else's server; only its client-side package can be scanned",
                r.get("type").and_then(Value::as_str).unwrap_or("http")
            ));
        }
    }
    notes.dedup();
    notes
}

/// A package the entry publishes that this build can fetch, in preference
/// order: npm, PyPI, mcpb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageRef {
    Npm { name: String, version: String },
    Pypi { name: String, version: String },
    Bundle { url: String },
}

pub fn choose_package(server: &Value) -> Option<PackageRef> {
    let pkgs = server.get("packages").and_then(Value::as_array)?;
    let field = |p: &Value, k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);
    let version_of = |p: &Value| {
        field(p, "version").or_else(|| {
            server
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
    };
    for want in ["npm", "pypi", "mcpb"] {
        for p in pkgs {
            if field(p, "registryType").as_deref() != Some(want) {
                continue;
            }
            let Some(id) = field(p, "identifier") else {
                continue;
            };
            match want {
                "npm" => {
                    let base = field(p, "registryBaseUrl").unwrap_or_else(|| NPM_REGISTRY.into());
                    if base.trim_end_matches('/') != NPM_REGISTRY {
                        continue;
                    }
                    if let Some(v) = version_of(p) {
                        return Some(PackageRef::Npm {
                            name: id,
                            version: v,
                        });
                    }
                }
                "pypi" => {
                    if let Some(v) = version_of(p) {
                        return Some(PackageRef::Pypi {
                            name: id,
                            version: v,
                        });
                    }
                }
                _ => {
                    if id.starts_with("https://") {
                        return Some(PackageRef::Bundle { url: id });
                    }
                }
            }
        }
    }
    None
}

/// The tarball URL in an npm version document.
pub fn npm_tarball(doc: &Value) -> Option<String> {
    doc.pointer("/dist/tarball")
        .and_then(Value::as_str)
        .filter(|u| u.starts_with("https://"))
        .map(str::to_string)
}

/// The sdist (else first wheel) URL in a PyPI version document.
pub fn pypi_artifact(doc: &Value) -> Option<String> {
    let urls = doc.get("urls").and_then(Value::as_array)?;
    let of = |kind: &str| {
        urls.iter()
            .find(|u| u.get("packagetype").and_then(Value::as_str) == Some(kind))
            .and_then(|u| u.get("url").and_then(Value::as_str))
            .filter(|u| u.starts_with("https://"))
            .map(str::to_string)
    };
    of("sdist").or_else(|| of("bdist_wheel"))
}

/// `https://github.com/o/r` → (`https://github.com/o/r.git`).
fn github_repo(url: &str) -> Option<String> {
    let rest = url
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .strip_prefix("https://github.com/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    (parts.len() == 2 && parts.iter().all(|p| !p.is_empty()))
        .then(|| format!("https://github.com/{}/{}.git", parts[0], parts[1]))
}

fn default_branch(repo: &str) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .args(["ls-remote", "--symref", repo, "HEAD"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git ls-remote {repo} failed"));
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            l.strip_prefix("ref: refs/heads/")
                .and_then(|r| r.split('\t').next())
                .map(str::to_string)
        })
        .ok_or_else(|| format!("cannot find the default branch of {repo}"))
}

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("{url}: invalid JSON: {e}"))
}

fn encode_component(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Resolve `mcp:<name>[@<version>]` (without the `mcp:` prefix) to a plan.
pub async fn resolve(target: &str) -> Result<Resolution, String> {
    let (name, version) = split_target(target.trim());
    if name.is_empty() {
        return Err("usage: sigil scan mcp:<server-name>[@<version>]".into());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("sigil/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let base = registry_base();
    let search = format!(
        "{base}/v0/servers?search={}&limit=100",
        encode_component(name)
    );
    let doc = get_json(&client, &search).await?;
    let entry = pick_server(&doc, name, version)?;
    let server = entry.get("server").unwrap_or(entry);
    let ver = server
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    let notes = notes_for(server);

    match choose_package(server) {
        Some(PackageRef::Npm {
            name: pkg,
            version: v,
        }) => {
            let url = format!(
                "{NPM_REGISTRY}/{}/{}",
                pkg.replace('/', "%2F"),
                encode_component(&v)
            );
            let meta = get_json(&client, &url).await?;
            let tarball = npm_tarball(&meta)
                .ok_or_else(|| format!("{pkg}@{v} has no https tarball on npm"))?;
            return Ok(Resolution {
                plan: Plan::Download(tarball),
                what: format!("{name} {ver}: npm package {pkg}@{v}"),
                notes,
            });
        }
        Some(PackageRef::Pypi {
            name: pkg,
            version: v,
        }) => {
            let url = format!(
                "https://pypi.org/pypi/{}/{}/json",
                encode_component(&pkg),
                encode_component(&v)
            );
            let meta = get_json(&client, &url).await?;
            let artifact = pypi_artifact(&meta)
                .ok_or_else(|| format!("{pkg}=={v} has no sdist or wheel on PyPI"))?;
            return Ok(Resolution {
                plan: Plan::Download(artifact),
                what: format!("{name} {ver}: PyPI package {pkg}=={v}"),
                notes,
            });
        }
        Some(PackageRef::Bundle { url }) => {
            return Ok(Resolution {
                plan: Plan::Download(url.clone()),
                what: format!("{name} {ver}: MCP bundle {url}"),
                notes,
            });
        }
        None => {}
    }

    let repo_url = server
        .pointer("/repository/url")
        .and_then(Value::as_str)
        .unwrap_or("");
    if let Some(repo) = github_repo(repo_url) {
        let branch = default_branch(&repo)?;
        let mut segments = vec![branch.clone()];
        if let Some(sub) = server
            .pointer("/repository/subfolder")
            .and_then(Value::as_str)
        {
            segments.extend(sub.split('/').filter(|s| !s.is_empty()).map(str::to_string));
        }
        return Ok(Resolution {
            what: format!(
                "{name} {ver}: source repository {repo_url} ({branch}{})",
                server
                    .pointer("/repository/subfolder")
                    .and_then(Value::as_str)
                    .map(|s| format!(", {s}"))
                    .unwrap_or_default()
            ),
            plan: Plan::GitHubTree { repo, segments },
            notes,
        });
    }

    Err(
        if server
            .get("remotes")
            .and_then(Value::as_array)
            .is_some_and(|r| !r.is_empty())
        {
            format!(
            "{name} is a remote-only MCP server: its code runs on the publisher's host, so there is nothing to scan locally ({})",
            notes.join("; ")
        )
        } else {
            format!("{name} publishes no npm, PyPI or bundle package and no GitHub repository that sigil can fetch")
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn search() -> Value {
        json!({"servers": [
            {"server": {"name": "io.github.acme/files", "version": "1.0.0",
                "packages": [{"registryType": "npm", "identifier": "@acme/files-mcp", "version": "1.0.0",
                              "transport": {"type": "stdio"}}]},
             "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": false}}},
            {"server": {"name": "io.github.acme/files", "version": "1.1.0",
                "packages": [{"registryType": "npm", "identifier": "@acme/files-mcp", "version": "1.1.0",
                              "transport": {"type": "stdio"},
                              "environmentVariables": [{"name": "ACME_TOKEN", "isSecret": true}, {"name": "ROOT"}]}]},
             "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": true}}},
            {"server": {"name": "io.github.acme/files-extra", "version": "0.1.0"}}
        ]})
    }

    #[test]
    fn picks_the_latest_exact_name_or_a_pinned_version() {
        let doc = search();
        let latest = pick_server(&doc, "io.github.acme/files", None).unwrap();
        assert_eq!(latest["server"]["version"], "1.1.0");
        let pinned = pick_server(&doc, "io.github.acme/files", Some("1.0.0")).unwrap();
        assert_eq!(pinned["server"]["version"], "1.0.0");
        assert!(pick_server(&doc, "io.github.acme/files", Some("9.9.9")).is_err());
        let err = pick_server(&doc, "io.github.acme/fil", None).unwrap_err();
        assert!(err.contains("did you mean"), "{err}");
    }

    #[test]
    fn split_target_keeps_scoped_names_whole() {
        assert_eq!(
            split_target("io.github.a/b@2.0.1"),
            ("io.github.a/b", Some("2.0.1"))
        );
        assert_eq!(split_target("io.github.a/b"), ("io.github.a/b", None));
        assert_eq!(split_target("@x"), ("@x", None));
    }

    #[test]
    fn package_preference_and_untrusted_registries() {
        let s = json!({"version": "2.0.0", "packages": [
            {"registryType": "oci", "identifier": "docker.io/acme/x"},
            {"registryType": "pypi", "identifier": "acme-mcp"},
            {"registryType": "npm", "identifier": "acme-mcp", "version": "2.0.0"}
        ]});
        assert_eq!(
            choose_package(&s),
            Some(PackageRef::Npm {
                name: "acme-mcp".into(),
                version: "2.0.0".into()
            })
        );
        // An npm package on some other registry is not followed.
        let s = json!({"version": "1", "packages": [
            {"registryType": "npm", "identifier": "x", "version": "1", "registryBaseUrl": "https://npm.evil.example"},
            {"registryType": "pypi", "identifier": "x-mcp", "version": "1"}
        ]});
        assert_eq!(
            choose_package(&s),
            Some(PackageRef::Pypi {
                name: "x-mcp".into(),
                version: "1".into()
            })
        );
        let s =
            json!({"packages": [{"registryType": "mcpb", "identifier": "http://insecure/x.mcpb"}]});
        assert_eq!(choose_package(&s), None);
    }

    #[test]
    fn artifact_urls_come_from_the_registry_documents() {
        assert_eq!(
            npm_tarball(
                &json!({"dist": {"tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"}})
            )
            .as_deref(),
            Some("https://registry.npmjs.org/x/-/x-1.0.0.tgz")
        );
        assert_eq!(
            npm_tarball(&json!({"dist": {"tarball": "http://x/y.tgz"}})),
            None
        );
        let py = json!({"urls": [
            {"packagetype": "bdist_wheel", "url": "https://files.pythonhosted.org/x-1-py3-none-any.whl"},
            {"packagetype": "sdist", "url": "https://files.pythonhosted.org/x-1.tar.gz"}
        ]});
        assert_eq!(
            pypi_artifact(&py).as_deref(),
            Some("https://files.pythonhosted.org/x-1.tar.gz")
        );
    }

    #[test]
    fn notes_name_secrets_and_remote_endpoints() {
        let doc = search();
        let latest = pick_server(&doc, "io.github.acme/files", None).unwrap();
        let notes = notes_for(&latest["server"]);
        assert!(
            notes.iter().any(|n| n == "asks for secrets: ACME_TOKEN"),
            "{notes:?}"
        );
        let remote =
            json!({"remotes": [{"type": "streamable-http", "url": "https://mcp.acme.dev/mcp"}]});
        assert!(notes_for(&remote)[0].contains("https://mcp.acme.dev/mcp"));
    }

    #[test]
    fn github_repo_urls_are_normalised() {
        assert_eq!(
            github_repo("https://github.com/acme/servers/").as_deref(),
            Some("https://github.com/acme/servers.git")
        );
        assert_eq!(github_repo("https://gitlab.com/acme/x"), None);
        assert_eq!(github_repo("https://github.com/acme"), None);
    }
}
