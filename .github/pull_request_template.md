## What changed

Describe the focused change and the user or contributor problem it solves.

## Security and compatibility

Describe effects on trust boundaries, filesystem access, redaction, output safety, data handling, and existing MCP contracts. Write “None” when no material effect exists.

## Verification

- [ ] `pnpm verify`
- [ ] `pnpm docs:build && pnpm docs:check && pnpm docs:validate` (when docs or public behavior changed)
- [ ] New or changed behavior has focused test coverage
- [ ] Fixtures and logs contain no real credentials or sensitive source

## Checklist

- [ ] The change remains defensive and remediation-focused
- [ ] Documentation is updated where setup, configuration, or contracts changed
- [ ] The pull request contains no unrelated refactor or generated output
