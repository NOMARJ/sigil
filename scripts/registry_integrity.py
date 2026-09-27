#!/usr/bin/env python3
"""Check every npm-packaged server in the official MCP registry against npm.

The registry is a directory an agent installs from. This asks one question of
every listing: does the npm package it names actually exist, at the version it
names? Nothing is downloaded or executed — only the registry's own metadata
documents are read.

Output: <out>.json with one record per server name.
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

REG = 'https://registry.modelcontextprotocol.io/v0/servers?limit=100'
UA = {'User-Agent': 'sigil-registry-audit (+https://github.com/NOMARJ/sigil)'}

def get(url, timeout=45, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (404, 405):
                return e.code
            if attempt == retries - 1:
                return f'HTTP {e.code}'
            time.sleep(2 ** attempt)
        except Exception as e:
            if attempt == retries - 1:
                return type(e).__name__
            time.sleep(2 ** attempt)
    return 'unknown'

def listings():
    cursor, pages, out = None, 0, {}
    while True:
        d = get(REG + (f'&cursor={cursor}' if cursor else ''))
        if not isinstance(d, dict):
            print(f'registry page failed: {d}', file=sys.stderr)
            break
        for s in d.get('servers', []):
            sv = s.get('server', {})
            meta = (s.get('_meta') or {}).get('io.modelcontextprotocol.registry/official', {})
            name = sv.get('name')
            for p in sv.get('packages') or []:
                if p.get('registryType') != 'npm':
                    continue
                rec = out.setdefault(name, {'server': name, 'npm': p.get('identifier'),
                                            'version': p.get('version'), 'published': meta.get('publishedAt'),
                                            'is_latest': bool(meta.get('isLatest'))})
                # Keep the listing the registry marks latest, else the newest seen.
                if meta.get('isLatest') or (meta.get('publishedAt') or '') > (rec.get('published') or ''):
                    rec.update({'npm': p.get('identifier'), 'version': p.get('version'),
                                'published': meta.get('publishedAt'), 'is_latest': bool(meta.get('isLatest'))})
        cursor = (d.get('metadata') or {}).get('nextCursor')
        pages += 1
        if pages % 50 == 0:
            print(f'  {pages} pages, {len(out)} npm-packaged servers', file=sys.stderr, flush=True)
        if not cursor:
            break
    return list(out.values())

def check(rec):
    name = rec['npm']
    if not name:
        rec['state'] = 'no-identifier'
        return rec
    d = get(f'https://registry.npmjs.org/{urllib.parse.quote(name, safe="@/")}', timeout=30)
    if d == 404:
        rec['state'] = 'missing'
    elif not isinstance(d, dict):
        rec['state'] = f'lookup-failed: {d}'
    else:
        versions = d.get('versions') or {}
        unpub = (d.get('time') or {}).get('unpublished')
        if unpub:
            rec['state'] = 'unpublished'
            rec['unpublished_at'] = unpub.get('time')
        elif not versions:
            rec['state'] = 'no-versions'
        elif rec.get('version') and rec['version'] not in versions:
            rec['state'] = 'version-missing'
            rec['npm_latest'] = (d.get('dist-tags') or {}).get('latest')
        else:
            rec['state'] = 'ok'
    return rec

if __name__ == '__main__':
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('out', help='path to write the per-server JSON results to')
    ap.add_argument('--workers', type=int, default=8,
                    help='concurrent npm metadata lookups (default: 8)')
    args = ap.parse_args()
    out_path = args.out
    recs = listings()
    print(f'{len(recs)} npm-packaged servers; checking npm', file=sys.stderr, flush=True)
    done = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, r in enumerate(ex.map(check, recs)):
            done.append(r)
            if (i + 1) % 500 == 0:
                print(f'  {i+1}/{len(recs)}', file=sys.stderr, flush=True)
    json.dump(done, open(out_path, 'w'), indent=1)
    from collections import Counter
    print(json.dumps(Counter(r['state'] for r in done), indent=1))
