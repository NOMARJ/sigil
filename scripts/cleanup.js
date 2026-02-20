#!/usr/bin/env node
/**
 * NPM preuninstall script - cleanup installed binaries
 */

import { rmSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const BIN_DIR = join(__dirname, '..', 'bin');

// Remove binaries
const binaries = ['sigil', 'sigil.exe'];

for (const binary of binaries) {
  const path = join(BIN_DIR, binary);
  if (existsSync(path)) {
    try {
      rmSync(path, { force: true });
      console.log(`🗑️  Removed ${binary}`);
    } catch (err) {
      console.warn(`⚠️  Could not remove ${binary}: ${err.message}`);
    }
  }
}

console.log('✅ Cleanup complete');
