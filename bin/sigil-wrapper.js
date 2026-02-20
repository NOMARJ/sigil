#!/usr/bin/env node
/**
 * NPM binary wrapper - executes the downloaded Sigil binary
 */

import { spawn } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const platform = process.platform;
const binaryName = platform === 'win32' ? 'sigil.exe' : 'sigil';
const binaryPath = join(__dirname, binaryName);

// Check if binary exists
if (!existsSync(binaryPath)) {
  console.error('❌ Sigil binary not found. Installation may have failed.');
  console.error('   Try reinstalling: npm install -g @nomark/sigil');
  process.exit(1);
}

// Execute the binary with all arguments
const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  shell: false
});

child.on('error', (err) => {
  console.error('❌ Failed to execute Sigil:', err.message);
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code || 0);
});
