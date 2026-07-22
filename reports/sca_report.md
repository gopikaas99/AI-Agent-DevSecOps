# AI-Assisted SCA Security Report

## Scan summary

- **Scanner:** Snyk
- **Source file:** `scans/snyk.json`
- **Total vulnerability instances:** 2
- **Unique findings analyzed:** 1
- **Analysis model:** Ollama `llama3.1:8b`

---

**Snyk Software Composition Analysis Report**
=============================================

### Finding 1: Authorization Bypass Through User-Controlled Key
---------------------------------------------------------

#### Vulnerability Title
Authorization Bypass Through User-Controlled Key

#### Severity
Low

#### Affected Package and Installed Version
langgraph@1.2.9

#### Vulnerable Dependency Path
AIAgent DevSecOpS@0.0.0 > langgraph@1.2.9 (transitive dependency)

#### Technical Explanation
The vulnerability occurs due to a key collision in the `default_cache_key()` and `_freeze()` functions of `langgraph/_internal/_cache.py`. An attacker can poison the result cache or obtain another user's cached result by submitting a numpy array or PIL image keyword argument that matches a victim's input byte-for-byte but differs in the dropped metadata.

#### Potential Business Impact
An attacker could exploit this vulnerability to bypass authorization checks and access sensitive data or perform unauthorized actions.

#### CVE or CWE Information
CVE-2026-14742, CWE-639

#### Recommended Fixed Version
No direct upgrade is available. A fix was pushed into the `master` branch but not yet published.

#### Recommended Remediation Action
Wait for a new version of langgraph to be released that includes the fix.

#### Priority
Medium (due to low severity and lack of direct upgrade)

### Recommendation
Monitor the langgraph project for updates and plan to update as soon as a fixed version is available.