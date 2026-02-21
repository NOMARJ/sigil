#!/usr/bin/env node
/**
 * NPM postinstall script - downloads the correct Sigil binary for the platform
 * Falls back to bash script if binary is unavailable
 */

import { createWriteStream, chmodSync, existsSync, mkdirSync } from 'fs';
import { get as httpsGet } from 'https';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO = 'NOMARJ/sigil';
const BINARY_NAME = 'sigil';
const BIN_DIR = join(__dirname, '..', 'bin');

// Platform detection
const PLATFORM_MAP = {
  darwin: 'macos',
  linux: 'linux',
  win32: 'windows'
};

const ARCH_MAP = {
  x64: 'x64',
  arm64: 'arm64',
  aarch64: 'arm64'
};

const platform = PLATFORM_MAP[process.platform];
const arch = ARCH_MAP[process.arch];

if (!platform || !arch) {
  console.warn(`⚠️  Unsupported platform ${process.platform}/${process.arch}`);
  console.warn('   Falling back to bash script...');
  installBashScript();
  process.exit(0);
}

// Ensure bin directory exists
if (!existsSync(BIN_DIR)) {
  mkdirSync(BIN_DIR, { recursive: true });
}

// Get latest release version
async function getLatestVersion() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${REPO}/releases/latest`,
      headers: {
        'User-Agent': 'sigil-npm-installer'
      }
    };

    httpsGet(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const release = JSON.parse(data);
          resolve(release.tag_name);
        } catch (err) {
          reject(err);
        }
      });
    }).on('error', reject);
  });
}

// Download binary from GitHub releases
async function downloadBinary(version) {
  const extension = platform === 'windows' ? '.zip' : '.tar.gz';
  const assetName = `${BINARY_NAME}-${platform}-${arch}${extension}`;
  const url = `https://github.com/${REPO}/releases/download/${version}/${assetName}`;

  console.log(`📦 Downloading Sigil ${version} for ${platform}/${arch}...`);

  return new Promise((resolve, reject) => {
    httpsGet(url, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        // Follow redirect
        httpsGet(res.headers.location, handleDownload(resolve, reject))
          .on('error', reject);
      } else if (res.statusCode === 200) {
        handleDownload(resolve, reject)(res);
      } else {
        reject(new Error(`Download failed with status ${res.statusCode}`));
      }
    }).on('error', reject);
  });
}

function handleDownload(resolve, reject) {
  return (res) => {
    const archivePath = join(BIN_DIR, `sigil-archive${platform === 'windows' ? '.zip' : '.tar.gz'}`);
    const fileStream = createWriteStream(archivePath);

    res.pipe(fileStream);

    fileStream.on('finish', () => {
      fileStream.close();
      extractArchive(archivePath)
        .then(resolve)
        .catch(reject);
    });

    fileStream.on('error', reject);
  };
}

// Extract downloaded archive
async function extractArchive(archivePath) {
  const binaryPath = join(BIN_DIR, platform === 'windows' ? 'sigil.exe' : 'sigil');

  try {
    if (platform === 'windows') {
      // Unzip on Windows
      execSync(`powershell -command "Expand-Archive -Force '${archivePath}' '${BIN_DIR}'"`, {
        stdio: 'ignore'
      });
    } else {
      // Extract tar.gz on Unix
      execSync(`tar -xzf "${archivePath}" -C "${BIN_DIR}"`, {
        stdio: 'ignore'
      });
    }

    // Make executable on Unix
    if (platform !== 'windows') {
      chmodSync(binaryPath, 0o755);
    }

    // Clean up archive
    execSync(`rm -f "${archivePath}"`, { stdio: 'ignore' });

    console.log('✅ Sigil binary installed successfully');
    return binaryPath;
  } catch (err) {
    throw new Error(`Extraction failed: ${err.message}`);
  }
}

// Fallback: install bash script
function installBashScript() {
  console.log('📄 Installing bash script fallback...');

  const scriptUrl = `https://raw.githubusercontent.com/${REPO}/main/bin/sigil`;
  const scriptPath = join(BIN_DIR, 'sigil');

  httpsGet(scriptUrl, (res) => {
    const fileStream = createWriteStream(scriptPath);
    res.pipe(fileStream);

    fileStream.on('finish', () => {
      fileStream.close();
      chmodSync(scriptPath, 0o755);
      console.log('✅ Bash script installed successfully');
    });
  }).on('error', (err) => {
    console.error('❌ Failed to download bash script:', err.message);
    process.exit(1);
  });
}

// Main installation flow
async function install() {
  try {
    const version = await getLatestVersion();
    await downloadBinary(version);
  } catch (err) {
    console.warn(`⚠️  Binary installation failed: ${err.message}`);
    console.warn('   Falling back to bash script...');
    installBashScript();
  }
}

install();
