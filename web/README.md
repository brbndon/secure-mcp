# secure-mcp — Marketing Site

Marketing site for the secure-mcp MCP server, in the calm, monochrome,
Apple-inspired style of the Group Trip Money landing page — adapted for a
developer tool: terminal-frame product visuals instead of phone screenshots.

## Stack

- Astro (static) + Tailwind CSS v4 (design tokens in `src/styles/global.css`)
- System fonts only; no analytics; no third-party scripts
- pnpm (matches the parent repo)

## Commands

```bash
pnpm install
pnpm dev        # http://localhost:4321
pnpm build      # emits dist/
pnpm preview    # serve the built site
```

## Routes

| Path | Page |
|------|------|
| `/` | Homepage |
| `/help/` | Getting Started (setup steps, workflow, coverage, defensive policy, FAQ) |
| `/support/` | Contact Support (`mailto:` draft form) |
| `/privacy/` | Privacy Policy |
| `/terms/` | Terms of Service |

## Layout

```text
src/layouts/BaseLayout.astro
src/components/   # Header, Footer, TerminalFrame, TerminalMockup, …
src/pages/        # file-based routes
src/captures/     # real output captured from the current server build
src/styles/global.css
```

## Real output captures

`src/captures/` holds output captured from a live stdio session of the current
server build against `fixtures/tiny-app` — the homepage “See it in action”
gallery renders these verbatim. Regenerate whenever the server output changes:

```bash
node scripts/capture-output.mjs   # writes src/captures/01–05 from a live session
```

The hero terminal and the finding-anatomy diagram are illustrative CSS
markup; only the gallery uses real captured output.

## Placeholders to replace before launch

- `astro.config.mjs` → `site` domain
- `src/components/SupportForm.astro` → `supportAddress`
- `src/pages/index.astro` → `testimonialPlaceholders` (real quotes after launch)
