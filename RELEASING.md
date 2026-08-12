# Release process

Releases are maintainer-driven. Do not publish from an unreviewed or dirty checkout.

## 1. Prepare the repository

1. Confirm CI is green on `main`.
2. Update `version` in `package.json` and `SERVER_VERSION` in `src/config.ts` to the same semantic version.
3. Move relevant entries from `Unreleased` in [CHANGELOG.md](CHANGELOG.md) into a dated version section.
4. Install exactly what the lockfile records:

   ```bash
   pnpm install --frozen-lockfile
   ```

## 2. Run the release gate

```bash
pnpm release:check
```

This runs type checking, tests, the build and MCP smoke test, documentation build and link validation, a dependency audit at every severity, and an npm tarball dry run. Do not publish while any step fails. Inspect the tarball list and confirm it contains only compiled server files and public project documents—never local configuration, fixtures, source maps with private paths, or credentials. The published tarball includes `README.md` and `CHANGELOG.md`: confirm they still describe the npm install path, Security Advisories reporting, and which MCP SDK version this package version ships before you publish.

## 3. Publish

Verify the package name and authenticated npm account before the external action:

```bash
npm view @brdndon/secure-mcp
npm whoami
```

Publishing is irreversible for that exact version. Run it only after the version, changelog, and tarball have been reviewed.

Prefer publishing from GitHub Actions with npm provenance (the package then carries an OIDC attestation linking it to the tagged commit):

```bash
# CI (GitHub Actions) — provenance supported
npm publish --access public --provenance
```

`--provenance` requires an OIDC token from a supported CI provider and fails from a local machine. A local publish is still fine for a personal project, just without provenance:

```bash
# Local fallback — no provenance attestation
npm publish --access public
```

## 4. Tag and announce

1. Create an annotated `vX.Y.Z` tag on the exact published commit.
2. Push the tag.
3. Create a GitHub release whose notes match the changelog and include any security-relevant upgrade guidance.

```bash
git tag -a "vX.Y.Z" -m "vX.Y.Z"
git push origin "vX.Y.Z"
gh release create "vX.Y.Z" --title "vX.Y.Z" --notes-file - <<'EOF'
See CHANGELOG.md for this version.
EOF
```

Keep the GitHub release, git tag, `package.json` version, and npm publish on the same commit. After a security fix, publish the advisory from [Security Advisories](https://github.com/brbndon/secure-mcp/security/advisories) once the patched version is available.

Before a public release, confirm the repository is public, Issues and private vulnerability reporting work, and documentation hosting (if any) is live. Those are repository-owner actions and are intentionally not automated from a local checkout.
