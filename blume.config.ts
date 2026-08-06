import { defineConfig } from "blume";

const [environmentOwner, environmentRepo] = process.env.GITHUB_REPOSITORY?.split("/") ?? [];
const owner = process.env.BLUME_GITHUB_OWNER ?? environmentOwner;
const repo = process.env.BLUME_GITHUB_REPO ?? environmentRepo;
const site = process.env.BLUME_SITE ?? (owner ? `https://${owner}.github.io` : undefined);
const base = process.env.BLUME_BASE_PATH ?? (repo && !repo.endsWith(".github.io") ? `/${repo}` : undefined);

export default defineConfig({
  title: "secure-mcp",
  description: "Defensive, agent-first security audits over the Model Context Protocol.",
  logo: {
    // Brand mark in the header — dark tile for light mode, inverted for dark.
    image: { light: "/logo.svg", dark: "/logo-dark.svg", alt: "secure-mcp" },
  },
  theme: {
    accent: { light: "#0f8f85", dark: "#4de1c4" },
    action: "#f27745",
    background: { light: "#f4f7f5", dark: "#0d1311" },
    fonts: {
      display: "space-grotesk",
      body: "ibm-plex-sans",
      mono: "ibm-plex-mono",
    },
    mode: "system",
    radius: "sm",
  },
  navigation: {
    sidebar: { display: "group" },
    // Header tab: the marketing pages (pages/) sit outside the content tree,
    // so point the tab at the docs section. The site title links home.
    tabs: [{ label: "Docs", path: "/docs" }],
  },
  ai: {
    llmsTxt: true,
  },
  seo: {
    og: { enabled: true },
    robots: true,
    sitemap: true,
    structuredData: true,
  },
  ...(owner && repo
    ? {
        github: {
          owner,
          repo,
          branch: process.env.BLUME_GITHUB_BRANCH ?? "main",
        },
      }
    : {}),
  deployment: {
    output: "static",
    ...(base ? { base } : {}),
    ...(site ? { site } : {}),
  },
});
