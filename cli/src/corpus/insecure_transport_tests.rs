//! Unit tests for the insecure-transport pack (`insecure_transport.json`,
//! rules `TLS-*`).
//!
//! Each test pairs the shape a rule exists for with the ordinary shapes it
//! must leave alone: verification pointed at a CA bundle, a comparison rather
//! than an assignment, a comment, a prose warning, a command against
//! localhost, a test file.
//!
//! This file is read by the repository's self-scan, so fixture text is written
//! with a `~~` marker inside the reported token (`Fal~~se`) and assembled at
//! runtime by [`fx`]. The file itself never contains a line the rules report.

use super::engine::scan_file_with_packs;
use super::loader::load_all_packs;
use super::schema::SignaturePack;
use crate::scanner::{Finding, Severity, Verdict};

/// Fixture text with the `~~` markers removed.
fn fx(s: &str) -> String {
    s.replace("~~", "")
}

fn packs() -> Vec<SignaturePack> {
    load_all_packs().expect("embedded packs must parse")
}

fn pack() -> SignaturePack {
    packs()
        .into_iter()
        .find(|p| p.meta.id == "sigil-core-insecure-transport")
        .expect("insecure transport pack is embedded")
}

fn scan_at(path: &str, contents: &str) -> Vec<Finding> {
    let filename = path.rsplit('/').next().unwrap_or(path);
    scan_file_with_packs(&packs(), path, filename, &fx(contents))
}

/// Does `rule` fire on `contents` (after [`fx`]) scanned as the file at `path`?
fn fires(path: &str, contents: &str, rule: &str) -> bool {
    scan_at(path, contents).iter().any(|f| f.rule == rule)
}

/// Every TLS rule that fires on `contents`.
fn tls_rules(path: &str, contents: &str) -> Vec<String> {
    let mut ids: Vec<String> = scan_at(path, contents)
        .into_iter()
        .filter(|f| f.rule.starts_with("TLS-"))
        .map(|f| f.rule)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

// ---------------------------------------------------------------------------
// Pack hygiene
// ---------------------------------------------------------------------------

#[test]
fn every_rule_documents_itself() {
    let p = pack();
    assert_eq!(p.rules.len(), 10, "pack lost or gained rules");
    for r in &p.rules {
        assert!(r.id.starts_with("TLS-"), "{} is outside the family", r.id);
        assert_eq!(r.phase, "network_exfil", "{}", r.id);
        let rem = r.remediation.as_deref().unwrap_or("");
        assert!(rem.len() > 120, "{} needs actionable remediation", r.id);
        assert!(r.references.iter().any(|x| x == "CWE-295"), "{}", r.id);
        assert!(r.tags.iter().any(|t| t == "tls"), "{}", r.id);
        assert!(
            regex::Regex::new(&r.pattern).is_ok(),
            "{} pattern does not compile",
            r.id
        );
        // Configuration hygiene, not an attack shape: never High on its own.
        let want = if r.id == "TLS-003" { "low" } else { "medium" };
        assert_eq!(r.severity, want, "{}", r.id);
    }
    assert_eq!(p.correlation_rules.len(), 1);
    let c = &p.correlation_rules[0];
    assert_eq!(c.id, "TLS-CHAIN-001");
    assert_eq!(c.severity, "high");
    assert!(c.sink_window_before > 0);
    assert!(c.remediation.is_some() && !c.references.is_empty() && !c.tags.is_empty());
}

#[test]
fn behaviours_are_labelled_and_never_actions() {
    use crate::scanner::profile::behavior_for;
    let p = pack();
    for r in &p.rules {
        assert_eq!(behavior_for(&r.id), Some("insecure_transport"), "{}", r.id);
    }
    assert_eq!(
        behavior_for("TLS-CHAIN-001"),
        Some("exposes_credentials_in_transit")
    );
    // Not one of scoring.rs's ACTION_BEHAVIOURS: a TLS finding may never
    // lower the HIGH threshold for the rest of a package.
    for b in ["insecure_transport", "exposes_credentials_in_transit"] {
        assert!(![
            "install_time_execution",
            "exfiltration_endpoint",
            "installs_persistence",
            "dynamic_execution",
            "drive_by_install",
        ]
        .contains(&b));
    }
}

// ---------------------------------------------------------------------------
// TLS-001 / TLS-002 / TLS-003: Python
// ---------------------------------------------------------------------------

#[test]
fn tls_001_python_clients() {
    for line in [
        "resp = requests.get(url, verify=Fal~~se)",
        "    verify=Fal~~se,",
        "session.verify = Fal~~se",
        "client = httpx.AsyncClient(verify=Fal~~se, timeout=10)",
        "connector = aiohttp.TCPConnector(ssl=Fal~~se)",
        "async with session.get(url, ssl=Fal~~se) as resp:",
        "kwargs = {\"verify\": Fal~~se, \"timeout\": 5}",
        // SkillSpector TM3's own example: a bare assignment.
        "verify = Fal~~se",
    ] {
        assert!(fires("client.py", line, "TLS-001"), "{line}");
    }
    for line in [
        "resp = requests.get(url, verify=True)",
        "resp = requests.get(url, verify=ca_bundle)",
        "resp = requests.get(url, verify=os.environ.get(\"CA_BUNDLE\", True))",
        "if session.verify == Fal~~se:",
        // A database driver's ssl=False means plaintext to a local server,
        // not a skipped certificate check.
        "conn = await asyncpg.connect(dsn, ssl=Fal~~se)",
        // Comments and prose warnings.
        "# requests.get(url, verify=Fal~~se) is what we used to do",
        "x = fetch(url)  # never pass verify=Fal~~se here",
        "Both endpoints serve TLS; `requests` verifies by default, do not pass `verify=Fal~~se`.",
    ] {
        assert!(!fires("client.py", line, "TLS-001"), "{line}");
    }
}

#[test]
fn tls_002_ssl_contexts() {
    for line in [
        "ctx.verify_mode = ssl.CERT_N~~ONE",
        "ctx.check_hostname = Fal~~se",
        "ssl._create_default_https_context = ssl._create_unverified_con~~text",
        "http = urllib3.PoolManager(cert_reqs=\"CERT_N~~ONE\")",
        "sock = ssl.wrap_socket(raw, cert_reqs=ssl.CERT_N~~ONE)",
    ] {
        assert!(fires("fetch.py", line, "TLS-002"), "{line}");
    }
    for line in [
        "ctx.verify_mode = ssl.CERT_REQUIRED",
        "if ctx.verify_mode == ssl.CERT_N~~ONE:",
        "ctx.check_hostname = True",
        "ctx = ssl.create_default_context(cafile=CA_PATH)",
        "    # context.check_hostname = Fal~~se",
    ] {
        assert!(!fires("fetch.py", line, "TLS-002"), "{line}");
    }
}

#[test]
fn tls_003_silenced_warning_is_an_observation() {
    for line in [
        "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWa~~rning)",
        "requests.packages.urllib3.disable_warnings(InsecureRequestWa~~rning)",
        "requests.packages.urllib3.disable_warn~~ings()",
        "warnings.simplefilter(\"ignore\", InsecureRequestWa~~rning)",
    ] {
        let hits = scan_at("fetch.py", line);
        let f = hits
            .iter()
            .find(|f| f.rule == "TLS-003")
            .unwrap_or_else(|| panic!("{line}"));
        assert_eq!(f.severity, Severity::Low);
    }
    assert!(!fires(
        "fetch.py",
        "warnings.filterwarnings(\"ignore\", category=DeprecationWarning)",
        "TLS-003"
    ));
}

// ---------------------------------------------------------------------------
// TLS-004 / TLS-005: Node.js and process-wide switches
// ---------------------------------------------------------------------------

#[test]
fn tls_004_node_agents() {
    for line in [
        "const agent = new https.Agent({ rejectUnauthorized: fal~~se });",
        "            rejectUnauthorized: fal~~se, // Set to true if you want strict SSL",
        "  \"rejectUnauthorized\": fal~~se,",
        "request({ url, strictSSL: fal~~se }, cb);",
        "const opts = { checkServerIdentity: () => undef~~ined };",
    ] {
        assert!(fires("client.js", line, "TLS-004"), "{line}");
    }
    for line in [
        "const agent = new https.Agent({ ca, rejectUnauthorized: true });",
        "rejectUnauthorized: process.env.NODE_ENV === \"production\",",
        "  rejectUnauthorized?: boolean;",
        "// rejectUnauthorized: fal~~se",
        "   * rejectUnauthorized: fal~~se disables the check",
        // A message that names the setting inside a string it never closes.
        "throw new Error(\"rejectUnauthorized: fal~~se is not allowed here\");",
    ] {
        assert!(!fires("client.js", line, "TLS-004"), "{line}");
    }
}

#[test]
fn tls_005_process_wide_switches() {
    for (path, line) in [
        (
            "config.js",
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '~~0';",
        ),
        (
            "api.js",
            "        process.env[\"NODE_TLS_REJECT_UNAUTHORIZED\"] = \"~~0\";",
        ),
        ("start.sh", "export NODE_TLS_REJECT_UNAUTHORIZED=~~0"),
        ("Dockerfile", "ENV NODE_TLS_REJECT_UNAUTHORIZED ~~0"),
        (
            "mcp.json",
            "        \"NODE_TLS_REJECT_UNAUTHORIZED\": \"~~0\"",
        ),
        ("setup.ps1", "$env:NODE_TLS_REJECT_UNAUTHORIZED = \"~~0\""),
        (
            "SKILL.md",
            "Run `NODE_TLS_REJECT_UNAUTHORIZED=~~0 npx the-tool` first.",
        ),
        ("run.py", "os.environ[\"PYTHONHTTPSVERIFY\"] = \"~~0\""),
        (
            "run.py",
            "os.environ.setdefault(\"PYTHONHTTPSVERIFY\", \"~~0\")",
        ),
        ("run.py", "os.environ[\"CURL_CA_BUNDLE\"] = \"\"~~"),
        // A docker `-e` argument in an MCP server's launch configuration.
        (
            "mcp.json",
            "  \"args\": [\"run\", \"-e\", \"NODE_TLS_REJECT_UNAUTHORIZED=~~0\", \"img\"]",
        ),
    ] {
        assert!(fires(path, line, "TLS-005"), "{path}: {line}");
    }
    for (path, line) in [
        (
            "runtime.js",
            "const insecure = process.env.NODE_TLS_REJECT_UNAUTHORIZED === \"~~0\";",
        ),
        ("start.sh", "export NODE_TLS_REJECT_UNAUTHORIZED=1"),
        (
            "README.md",
            "| NODE_TLS_REJECT_UNAUTHORIZED | Set to `~~0` for a self-signed server |",
        ),
        (
            "runtime.js",
            " * Can be disabled via NODE_TLS_REJECT_UNAUTHORIZED=~~0",
        ),
        (
            "index.js",
            "  }; // no way to override this if `NODE_TLS_REJECT_UNAUTHORIZED=~~0`.",
        ),
        ("run.py", "os.environ[\"CURL_CA_BUNDLE\"] = certifi.where()"),
        (
            "run.py",
            "    raise SystemExit(\"PYTHONHTTPSVERIFY=~~0 is only allowed for a local server\")",
        ),
    ] {
        assert!(!fires(path, line, "TLS-005"), "{path}: {line}");
    }
}

// ---------------------------------------------------------------------------
// TLS-006: other languages
// ---------------------------------------------------------------------------

#[test]
fn tls_006_other_languages() {
    for (path, line) in [
        ("client.go", "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: tr~~ue}}"),
        ("client.rs", "let c = reqwest::Client::builder().danger_accept_invalid_certs(tr~~ue).build()?;"),
        ("client.rb", "http.verify_mode = OpenSSL::SSL::VERIFY_N~~ONE"),
        ("client.rb", "conn = Faraday.new(url, ssl: { verify: fal~~se })"),
        ("client.php", "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, fal~~se);"),
        ("client.c", "curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, ~~0L);"),
        ("client.php", "$client = new Client(['verify' => fal~~se]);"),
        ("Client.cs", "handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValid~~ator;"),
        ("Client.cs", "ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => tr~~ue;"),
        ("Client.java", ".setSSLHostnameVerifier(NoopHostnameVerifier.INST~~ANCE)"),
        ("Client.kt", "builder.hostnameVerifier { _, _ -> tr~~ue }"),
    ] {
        assert!(fires(path, line, "TLS-006"), "{path}: {line}");
    }
    for (path, line) in [
        (
            "client.go",
            "tlsConf := &tls.Config{InsecureSkipVerify: cfg.Insecure}",
        ),
        ("client.rs", "builder.danger_accept_invalid_certs(false)"),
        (
            "client.php",
            "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);",
        ),
        ("client.rb", "http.verify_mode = OpenSSL::SSL::VERIFY_PEER"),
        (
            "client.go",
            "// InsecureSkipVerify: tr~~ue is only for the local test server",
        ),
    ] {
        assert!(!fires(path, line, "TLS-006"), "{path}: {line}");
    }
}

// ---------------------------------------------------------------------------
// TLS-007 / TLS-008 / TLS-009: commands
// ---------------------------------------------------------------------------

#[test]
fn tls_007_download_commands() {
    for (path, line) in [
        (
            "SKILL.md",
            "curl -~~k https://api.example.invalid/v1/status",
        ),
        (
            "install.sh",
            "curl -sSL~~k https://example.invalid/tool.tar.gz -o tool.tar.gz",
        ),
        (
            "AGENTS.md",
            "- Fetch it with `curl --insec~~ure https://example.invalid/x`.",
        ),
        (
            "fetch.sh",
            "wget --no-check-certif~~icate https://example.invalid/a.tar.gz",
        ),
        (
            "get.ps1",
            "Invoke-WebRequest -Uri $u -OutFile a.zip -SkipCertificateCh~~eck",
        ),
        ("deploy.sh", "kubectl --insecure-skip-tls-ver~~ify get pods"),
        (
            "run.py",
            "subprocess.run([\"curl\", \"-~~k\", url], check=True)",
        ),
    ] {
        assert!(fires(path, line, "TLS-007"), "{path}: {line}");
    }
    for (path, line) in [
        (
            "install.sh",
            "curl -fsSL https://example.invalid/tool.tar.gz -o tool.tar.gz",
        ),
        ("health.sh", "curl -~~k https://localhost:8443/health"),
        ("health.sh", "curl -sk~~ https://127.0.0.1:9443/ready"),
        ("fetch.sh", "curl -K curl.config https://example.invalid/"),
        (
            "fetch.sh",
            "curl -fsSL https://example.invalid/a.tgz && tar -xk~~f a.tgz",
        ),
        (
            "fetch.sh",
            "# curl -~~k https://example.invalid/ was the old workaround",
        ),
        (
            "README.md",
            "Use curl with --cacert /etc/ssl/internal-ca.pem.",
        ),
    ] {
        assert!(!fires(path, line, "TLS-007"), "{path}: {line}");
    }
}

#[test]
fn tls_008_git() {
    for line in [
        "git -c http.sslVerify=fal~~se clone https://example.invalid/repo.git",
        "git config --global http.sslVerify fal~~se",
        "GIT_SSL_NO_VERIFY=~~1 git clone https://example.invalid/repo.git",
        "export GIT_SSL_NO_VERIFY=tr~~ue",
        "os.environ[\"GIT_SSL_NO_VERIFY\"] = \"~~1\"",
    ] {
        assert_eq!(tls_rules("setup.sh", line), vec!["TLS-008"], "{line}");
    }
    for line in [
        "git config --global http.sslVerify true",
        "git config --global http.sslCAInfo /etc/ssl/certs/internal.pem",
        "export GIT_SSL_NO_VERIFY=0",
    ] {
        assert!(tls_rules("setup.sh", line).is_empty(), "{line}");
    }
}

#[test]
fn tls_009_package_managers() {
    for (path, line) in [
        (
            "Dockerfile",
            "RUN pip install --trusted-ho~~st pypi.example.invalid -r requirements.txt",
        ),
        (
            "SKILL.md",
            "python3 -m pip install foo --trusted-ho~~st=files.pythonhosted.org",
        ),
        (
            "setup.sh",
            "pip config set global.trusted-ho~~st pypi.example.invalid",
        ),
        ("Dockerfile", "ENV PIP_TRUSTED_HO~~ST=pypi.example.invalid"),
        (
            "setup.sh",
            "uv pip install --allow-insecure-ho~~st pypi.example.invalid foo",
        ),
        ("setup.sh", "npm config set strict-ssl fal~~se"),
        ("setup.sh", "yarn config set strict-ssl fal~~se"),
        ("setup.sh", "npm install --strict-ssl=fal~~se"),
        ("setup.sh", "npm_config_strict_ssl=fal~~se npm ci"),
        ("setup.sh", "echo \"strict-ssl=fal~~se\" >> ~/.npmrc"),
        ("setup.sh", "conda config --set ssl_verify fal~~se"),
    ] {
        assert!(fires(path, line, "TLS-009"), "{path}: {line}");
    }
    for (path, line) in [
        (
            "Dockerfile",
            "RUN pip install --no-cache-dir -r requirements.txt",
        ),
        // A requirements file's own option line is DEPSRC-004's.
        ("requirements.txt", "--trusted-ho~~st pypi.example.invalid"),
        ("setup.sh", "npm config set strict-ssl true"),
        (
            "SKILL.md",
            "Set PIP_TRUSTED_HO~~ST to the mirror host your admin gives you.",
        ),
        (
            "setup.sh",
            "pip install --trusted-ho~~st localhost -i http://localhost:3141/simple foo",
        ),
    ] {
        assert!(!fires(path, line, "TLS-009"), "{path}: {line}");
    }
}

// ---------------------------------------------------------------------------
// TLS-010: configuration keys
// ---------------------------------------------------------------------------

#[test]
fn tls_010_configuration_keys() {
    for (path, line) in [
        ("settings.py", "VERIFY_SSL = Fal~~se"),
        ("config.yaml", "  verify_ssl: fal~~se"),
        ("config.yaml", "  verify_ssl: \"fal~~se\""),
        ("mcp.json", "  \"sslVerify\": fal~~se,"),
        ("prometheus.yml", "    insecure_skip_verify: tr~~ue"),
        ("kubeconfig", "    insecure-skip-tls-verify: tr~~ue"),
        (".condarc", "ssl_verify: fal~~se"),
        (
            "client.py",
            "h = httplib2.Http(disable_ssl_certificate_validation=Tr~~ue)",
        ),
        (
            "client.py",
            "async with session.get(url, verify_ssl=Fal~~se) as r:",
        ),
        ("config.py", "        self.verify_ssl = Fal~~se"),
        (
            "mcp.json",
            "  \"args\": [\"-e\", \"SSL_VERIFY=fal~~se\", \"img\"]",
        ),
        (
            "README.md",
            "Set `verify_ssl: fal~~se` in config.yaml for a self-signed server.",
        ),
    ] {
        assert!(fires(path, line, "TLS-010"), "{path}: {line}");
    }
    for (path, line) in [
        ("config.yaml", "  verify_ssl: true"),
        (
            "config.py",
            "verify_ssl = settings.get(\"verify_ssl\", True)",
        ),
        ("config.py", "if not verify_ssl:"),
        ("config.py", "    verify_ssl: bool = True"),
        ("config.py", "use_verify_ssl = Fal~~se"),
        // A message that names the setting: the bare value is followed by a
        // closing quote it never opened.
        (
            "depsrc.rs",
            "    out.tls_off(i + 1, \"Pipfile verify_ssl = fal~~se\");",
        ),
        // The same skill's instructions confine the switch to loopback.
        (
            "SKILL.md",
            "`SSL_VERIFY` defaults to `true`; only set `SSL_VERIFY=fal~~se` for loopback testing.",
        ),
        // A guard's error message (reduced from an NVIDIA skill that refuses
        // the insecure setting except for loopback endpoints).
        (
            "run_calibration.py",
            "        \"SSL_VERIFY=fal~~se is only allowed for loopback endpoints. Use HTTPS \"",
        ),
        // git's key is TLS-008's; a shipped Pipfile is DEPSRC-004's.
        ("setup.sh", "git -c http.sslVerify=fal~~se fetch"),
        ("Pipfile", "verify_ssl = fal~~se"),
    ] {
        assert!(!fires(path, line, "TLS-010"), "{path}: {line}");
    }
}

// ---------------------------------------------------------------------------
// Suppression: test files and data files
// ---------------------------------------------------------------------------

#[test]
fn test_and_data_files_are_not_reported() {
    let line = "resp = requests.get(url, verify=Fal~~se)";
    assert!(fires("src/client.py", line, "TLS-001"));
    for path in [
        "tests/unit/test_client.py",
        "pkg/tests/test_client.py",
        "src/__tests__/client.test.js",
        "internal/client_test.go",
        "test/fixtures/client.py",
        "pkg/test_client.py",
        "data/records.jsonl",
    ] {
        assert!(!fires(path, line, "TLS-001"), "{path}");
    }
}

// ---------------------------------------------------------------------------
// TLS-CHAIN-001 and the verdict, through the full scanner
// ---------------------------------------------------------------------------

/// Scan `files` (path, contents after [`fx`]) as a directory.
fn scan_tree(files: &[(&str, &str)]) -> crate::scanner::ScanResult {
    let dir = tempfile::tempdir().expect("tempdir");
    for (rel, body) in files {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, fx(body)).unwrap();
    }
    crate::scanner::run_scan(dir.path(), None, None)
}

fn chain_lines(r: &crate::scanner::ScanResult) -> Vec<usize> {
    r.findings
        .iter()
        .filter(|f| f.rule == "TLS-CHAIN-001")
        .filter_map(|f| f.line)
        .collect()
}

#[test]
fn chain_credential_over_unverified_request_same_line() {
    let src = "import os\nimport requests\n\nAPI_KEY = os.environ[\"SERVICE_API_~~KEY\"]\n\ndef status(url):\n    return requests.post(url, headers={\"X-Api-Key\": API_KEY}, verify=Fal~~se)\n";
    let r = scan_tree(&[("client.py", src)]);
    assert_eq!(chain_lines(&r), vec![7], "{:#?}", r.findings);
    let chain = r
        .findings
        .iter()
        .find(|f| f.rule == "TLS-CHAIN-001")
        .unwrap();
    assert_eq!(chain.severity, Severity::High);
    assert!(chain
        .snippet
        .contains("CRED-001 (@L4) reaches TLS-001 (@L7)"));
}

#[test]
fn chain_reaches_arguments_above_a_trailing_keyword() {
    // Black puts every argument on its own line; the insecure keyword is
    // last, and the header that carries the token is above it.
    let src = "import os\nimport requests\n\ntoken = os.getenv(\"GITHUB_TO~~KEN\")\n\nresp = requests.get(\n    url,\n    headers={\"Authorization\": f\"Bearer {token}\"},\n    timeout=30,\n    verify=Fal~~se,\n)\n";
    let r = scan_tree(&[("client.py", src)]);
    assert_eq!(chain_lines(&r), vec![10], "{:#?}", r.findings);
}

#[test]
fn chain_node_agent_then_request() {
    let src = "const https = require('https');\nconst token = process.env.API_TO~~KEN;\nconst agent = new https.Agent({ rejectUnauthorized: fal~~se });\nfetch(url, { agent, headers: { Authorization: `Bearer ${token}` } });\n";
    let r = scan_tree(&[("client.js", src)]);
    assert_eq!(chain_lines(&r), vec![3], "{:#?}", r.findings);
}

#[test]
fn no_chain_without_a_credential_in_the_call() {
    // The key is read, but the unverified request is a health check that
    // never uses it: TLS-001 alone, Medium, and a MEDIUM verdict.
    let src = "import os\nimport requests\n\nAPI_KEY = os.environ[\"SERVICE_API_~~KEY\"]\n\ndef healthy(url):\n    r = requests.get(url + \"/health\", timeout=5,\n                     verify=Fal~~se)\n    return r.ok\n";
    let r = scan_tree(&[("client.py", src)]);
    assert!(chain_lines(&r).is_empty(), "{:#?}", r.findings);
    assert!(r
        .findings
        .iter()
        .any(|f| f.rule == "TLS-001" && f.severity == Severity::Medium));
    assert_eq!(r.verdict, Verdict::MediumRisk);
}

#[test]
fn a_medium_finding_alone_warns_and_never_blocks() {
    // A two-file skill whose script disables verification: the rule warns
    // (MEDIUM) and does not reach HIGH on its own, whatever the file count.
    let r = scan_tree(&[
        (
            "SKILL.md",
            "---\nname: fetcher\ndescription: fetch a report\n---\nRun scripts/fetch.py.\n",
        ),
        (
            "scripts/fetch.py",
            "import requests\nprint(requests.get(REPORT_URL, verify=Fal~~se).text)\n",
        ),
    ]);
    assert!(r.findings.iter().any(|f| f.rule == "TLS-001"));
    assert_eq!(r.verdict, Verdict::MediumRisk, "{:#?}", r.findings);
}
