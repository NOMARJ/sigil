#!/usr/bin/env node

import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import { dirname, join } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageRoot = join(__dirname, '..');
const binaryPath = join(packageRoot, 'bin', 'sigil');
const wrapperPath = join(packageRoot, 'bin', 'sigil-wrapper.js');
const packageJson = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
const version = packageJson.version;
const repo = 'NOMARJ/sigil';

const assets = {
  darwin: {
    x64: 'sigil-macos-x64.tar.gz',
    arm64: 'sigil-macos-arm64.tar.gz',
  },
  linux: {
    x64: 'sigil-linux-x64.tar.gz',
    arm64: 'sigil-linux-arm64.tar.gz',
  },
};

function fail(message) {
  console.error(`Sigil install failed: ${message}`);
  process.exit(1);
}

function assetName() {
  const platformAssets = assets[process.platform];
  const asset = platformAssets?.[process.arch];
  if (!asset) {
    fail(`unsupported platform ${process.platform}/${process.arch}`);
  }
  return asset;
}

async function download(url) {
  const response = await fetch(url, {
    headers: { 'User-Agent': `@nomarj/sigil/${version}` },
  });
  if (!response.ok) {
    fail(`could not download ${url} (${response.status})`);
  }
  return Buffer.from(await response.arrayBuffer());
}

function expectedHash(checksums, name) {
  const line = checksums
    .split(/\r?\n/)
    .find((entry) => entry.trim().endsWith(` ${name}`) || entry.trim().endsWith(`  ${name}`));
  if (!line) {
    fail(`checksum missing for ${name}`);
  }
  return line.trim().split(/\s+/)[0];
}

function verifyChecksum(buffer, expected) {
  const actual = createHash('sha256').update(buffer).digest('hex');
  if (actual !== expected) {
    fail(`checksum mismatch for native binary archive`);
  }
}

async function main() {
  if (!existsSync(wrapperPath)) {
    fail(`missing wrapper ${wrapperPath}`);
  }

  const name = assetName();
  const baseUrl = `https://github.com/${repo}/releases/download/v${version}`;
  const [archive, checksums] = await Promise.all([
    download(`${baseUrl}/${name}`),
    download(`${baseUrl}/SHA256SUMS.txt`).then((body) => body.toString('utf8')),
  ]);

  verifyChecksum(archive, expectedHash(checksums, name));

  const tempDir = mkdtempSync(join(tmpdir(), 'sigil-install-'));
  try {
    const archivePath = join(tempDir, name);
    writeFileSync(archivePath, archive);
    execFileSync('tar', ['-xzf', archivePath, '-C', tempDir, 'sigil'], {
      stdio: 'ignore',
    });
    mkdirSync(dirname(binaryPath), { recursive: true });
    copyFileSync(join(tempDir, 'sigil'), binaryPath);
    chmodSync(binaryPath, 0o755);
    chmodSync(wrapperPath, 0o755);
    execFileSync(binaryPath, ['--version'], { stdio: 'ignore' });
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  fail(error instanceof Error ? error.message : String(error));
});
