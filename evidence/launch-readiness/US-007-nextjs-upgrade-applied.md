# US-007 Next.js/Auth0 Upgrade Applied

Date: 2026-06-09

## Scope

Owner approved the protected Auth0 v4 migration. The dashboard upgrade now clears the high-severity dependency audit gate.

## Dependency State

```bash
$ npm ls next react react-dom @auth0/nextjs-auth0 eslint eslint-config-next --depth=0
sigil-dashboard@0.1.0 /Users/reecefrazier/CascadeProjects/sigil/dashboard
├── @auth0/nextjs-auth0@4.22.0
├── eslint-config-next@16.2.7
├── eslint@9.39.4
├── next@16.2.7
├── react-dom@19.2.1
└── react@19.2.1
```

## Verification

```bash
$ npm ci
added 797 packages, and audited 798 packages
```

```bash
$ npm run lint
0 errors, 5 warnings
```

```bash
$ npx tsc --noEmit
exit 0
```

```bash
$ npm test -- --runInBand
Test Suites: 4 passed, 4 total
Tests: 43 passed, 43 total
```

```bash
$ npm run build
Next.js 16.2.7
Compiled successfully
Generating static pages ... 32/32
```

```bash
$ npm audit --audit-level=high --omit=dev
exit 0
```

## Residual Risk

Plain `npm audit` still reports 2 moderate PostCSS findings nested under Next.js 16.2.7. The suggested `npm audit fix --force` proposes an invalid downgrade to `next@9.3.3`; do not apply it.
