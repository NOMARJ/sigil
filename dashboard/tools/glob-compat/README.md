# Next ESLint directory glob compatibility

Next's ESLint plugin currently calls `fast-glob.globSync(pattern,
{ onlyDirectories: true })` to discover configured `settings.next.rootDir`
directories. Its dependency chain includes `braces` 3.0.3, which has no patched
release for GHSA-vfj7-8cjw-p6xm. This private npm override uses maintained
`tinyglobby` for that narrow API while preserving static-directory and absolute
path behavior. It fails explicitly if a future consumer requests another API.

Keep the complete Next ESLint configuration enabled. Recheck the upstream
plugin when upgrading Next and remove this adapter when its directory discovery
no longer requires the vulnerable dependency chain. The dashboard Dockerfile
copies this local package before `npm ci` because npm installs it as a symlink.

Tailwind 4 removes the other dashboard dependency path to `braces`. Existing
Tailwind 3 colour tokens, preflight defaults and renamed small-size utilities
are preserved in the dashboard styles. Tailwind 4 requires Safari 16.4+,
Chrome 111+ or Firefox 128+.
