# Release process

Releases are maintainer-only and run from GitHub Actions after the release PR is merged into `main`. Nothing in this repository publishes, tags, or creates releases from ordinary pushes, pull requests, or local checkouts.

## Before the 2.0.0 release

1. Configure npm trusted publishing for the exact workflow filename `.github/workflows/release.yml` in the npm package settings for `@brdndon/secure-mcp`. Use OIDC trusted publishing (no long-lived npm token) and bind it to the canonical `brbndon/secure-mcp` GitHub repository and `main` branch.
2. Configure the GitHub Actions `release` environment (used by the publish job) with the protection you want, for example required reviewers or a deployment branch rule on `main`.
3. Review `package.json`, `src/config.ts`, `server.json`, and `CHANGELOG.md`; all must name `2.0.0`. `pnpm release:check` validates this automatically.
4. Do not move, edit, or delete the historical `v1.0.0` tag or the `@brdndon/secure-mcp@1.0.0` npm artifact.

## Run the local release gate

```bash
pnpm install --frozen-lockfile
pnpm release:check
```

`release:check` runs type checking, unit and protocol tests, the build and MCP smoke test, documentation build/check/validate, a dependency audit at every severity, Unix installer integration tests, and a nonpublishing npm tarball E2E that installs the packed artifact in a temporary consumer directory. It also verifies that `package.json`, `server.json`, `SERVER_VERSION`, and the changelog all name `2.0.0`.

## Publish after merge

1. Merge the release PR into `main`.
2. Confirm the intended release changes are present on the exact `main` commit.
3. Manually dispatch the **Release** workflow (`.github/workflows/release.yml`) with input version `2.0.0`.
4. The workflow:
   - refuses to run unless it is a `workflow_dispatch` from the canonical `brbndon/secure-mcp` repository on merged `main`;
   - verifies the requested version, `package.json`, `SERVER_VERSION`, changelog, and `server.json`;
   - fails if tag `v2.0.0` already exists or npm already has `@brdndon/secure-mcp@2.0.0`;
   - captures the exact `main` commit SHA;
   - runs the complete release gate before any external mutation;
   - publishes with npm trusted publishing/OIDC and `--provenance`;
   - creates annotated tag `v2.0.0` on the exact published commit;
   - creates a GitHub release with notes extracted from the `2.0.0` changelog section.

## Verify after publishing

```bash
npm view @brdndon/secure-mcp@2.0.0 version
npm view @brdndon/secure-mcp@2.0.0 --json | grep -i provenance
git -C <clone> rev-parse v2.0.0
git -C <clone> show -s --format='%H %D' v2.0.0
```

Confirm:

- npm version is `2.0.0` and provenance is present;
- tag `v2.0.0` points at the same commit SHA that the workflow recorded and that the GitHub release references;
- the GitHub release notes come from the changelog, not a "See CHANGELOG" placeholder.

## Publish to the MCP Registry

Only after npm `2.0.0` exists, publish the repo's `server.json` metadata to the MCP Registry:

```bash
mcp-publisher login github
mcp-publisher validate
mcp-publisher publish
```

`server.json` uses the `io.github.brbndon/secure-mcp` namespace, references npm package `@brdndon/secure-mcp` version `2.0.0`, stdio transport, and the required `SECURE_MCP_ALLOWED_ROOTS` environment variable. The registry hosts metadata only; the npm artifact is the source of truth for the server binary.

## Future versions

For a future release, update every identity surface (`package.json`, `src/config.ts`, `server.json`, `CHANGELOG.md`), the release workflow's version guard and tag names, and the npm trusted publisher version scope as needed. Keep the historical `v1.0.0` tag and npm artifact untouched.
