# tiny\-app — secure code review \(remediation\)

> Defensive secure-code-review report. Goal: help the development team harden the codebase. Do not include exploit or attack PoC content.

**Project:** \/Users\/brandon\/Code\/secure\-mcp\/fixtures\/tiny\-app
**Total findings:** 3

## Summary by severity (remediation priority)
- **critical**: 0
- **high**: 2
- **medium**: 1
- **low**: 0
- **info**: 0

## Findings

### F\-001 — Possible secret\: \[REDACTED\:\*\*\*\*\] API key assignment

#### Classification
- **Severity:** high
- **Confidence:** high
- **Category:** secrets
- **CWE:** CWE\-798
- **Location:** ios\/Secrets\.swift\:5
- **Stable instance:** secrets\.secret\-patterns\:2cca61242a0d25b6
- **Rule family:** secrets\.secret\-patterns
- **Root control:** SECRET\-PATTERN\-GENERIC\-API\-KEY\-ASSIGNMENT
- **Disposition:** needs\_review
- **Disposition reason:** Heuristic or architecture candidate\; confirm source\-to\-sink reachability before reporting as confirmed\.

#### Evidence
Matched heuristic for Generic API key assignment\. Verify whether this is a real \[redacted\-secret\-file\] and whether it is still active\; if so\, remediate and rotate\.

`apiKey = "[REDACTED:****]"`

#### Proof context
- **Source:** Repository or configuration content matched a secret\-like pattern\.
- **Control:** Move secrets to environment variables or a secret manager\; rotate if committed\.
- **Sink:** ios\/Secrets\.swift

#### Counterevidence
- The detector does not prove reachability\, exploitability\, or runtime configuration\.

#### Proof gap
- Trace the relevant data flow and inspect runtime\/configuration context before confirmation\.

#### Validation
- Confirm rotation in the provider console\; re\-scan the repository and history\; ensure CI secrets are updated\.

#### Impact if unremediated
Hardcoded API \[redacted\-secret\-file\] can be reused by anyone with repository access\.

#### Remediation
Move secrets to environment variables or a secret manager\; rotate if committed\.

#### Residual risk
Secrets may remain in git history or secondary systems until rotated and purged\.

#### Verification suggestion
Confirm rotation in the provider console\; re\-scan the repository and history\; ensure CI secrets are updated\.

### F\-002 — Hardcoded password\-like assignment

#### Classification
- **Severity:** high
- **Confidence:** medium
- **Category:** secrets
- **CWE:** CWE\-798
- **Location:** ios\/Secrets\.swift\:5
- **Stable instance:** swift\-ios\.secret\-handling\:e66e4d0598418e80
- **Rule family:** swift\-ios\.secret\-handling
- **Root control:** SWIFT\-HARDCODED\-PASSWORD
- **Disposition:** needs\_review
- **Disposition reason:** Heuristic or architecture candidate\; confirm source\-to\-sink reachability before reporting as confirmed\.

#### Evidence
Swift secret\-handling heuristic SWIFT\-HARDCODED\-PASSWORD matched — review storage and remove hardcoded or weakly protected secrets\.

`…WEAKNESSES FOR FIXTURE / REMEDIATION SMOKE TESTS enum Secrets { static let apiKey = "[REDACTED:****]" } func storeToken(_ token: [REDACTED:****]`

#### Proof context
- **Source:** Swift source or Apple configuration matched a secret\-handling heuristic\.
- **Control:** Remove hardcoded secrets\; load from Keychain or secure configuration at runtime\.
- **Sink:** ios\/Secrets\.swift

#### Counterevidence
- The detector does not prove reachability\, exploitability\, or runtime configuration\.

#### Proof gap
- Trace the relevant data flow and inspect runtime\/configuration context before confirmation\.

#### Validation
- Audit Keychain migration paths and confirm no secrets remain in UserDefaults\, pasteboard\, or source\.

#### Impact if unremediated
Embedded secrets in binaries or source can grant unintended access if recovered\.

#### Remediation
Remove hardcoded secrets\; load from Keychain or secure configuration at runtime\.

#### Residual risk
Old app installs may retain secrets until users upgrade\.

#### Verification suggestion
Audit Keychain migration paths and confirm no secrets remain in UserDefaults\, pasteboard\, or source\.

### F\-003 — print of sensitive\-looking values

#### Classification
- **Severity:** medium
- **Confidence:** medium
- **Category:** privacy
- **CWE:** CWE\-532
- **Location:** ios\/Secrets\.swift\:13
- **Stable instance:** swift\-ios\.secret\-handling\:2d17ae49448d7d89
- **Rule family:** swift\-ios\.secret\-handling
- **Root control:** SWIFT\-PRINT\-SENSITIVE
- **Disposition:** needs\_review
- **Disposition reason:** Heuristic or architecture candidate\; confirm source\-to\-sink reachability before reporting as confirmed\.

#### Evidence
Swift secret\-handling heuristic SWIFT\-PRINT\-SENSITIVE matched — review storage and remove hardcoded or weakly protected secrets\.

`…andard.set(token, forKey: "authToken") } func debugAuth(_ token: [REDACTED:****] { print("token \(token)") } let insecure = "http://api.example.com/v1/login"`

#### Proof context
- **Source:** Swift source or Apple configuration matched a secret\-handling heuristic\.
- **Control:** Remove sensitive prints\; use privacy\-preserving os\_log\.
- **Sink:** ios\/Secrets\.swift

#### Counterevidence
- The detector does not prove reachability\, exploitability\, or runtime configuration\.

#### Proof gap
- Trace the relevant data flow and inspect runtime\/configuration context before confirmation\.

#### Validation
- Audit Keychain migration paths and confirm no secrets remain in UserDefaults\, pasteboard\, or source\.

#### Impact if unremediated
Logs may retain tokens or \[redacted\-secret\-file\] beyond the intended session lifetime\.

#### Remediation
Remove sensitive prints\; use privacy\-preserving os\_log\.

#### Residual risk
Old app installs may retain secrets until users upgrade\.

#### Verification suggestion
Audit Keychain migration paths and confirm no secrets remain in UserDefaults\, pasteboard\, or source\.