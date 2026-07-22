**Security Report**
====================

### High-Risk Findings

1. **Subprocess Popen with Shell=True**
	* Tools: Bandit, Semgrep
	* Affected file and line: `app/system.py`, line 12
	* Risk level: HIGH
	* Simple explanation: Using `shell=True` in subprocess calls can lead to security issues.
	* Potential impact: Unintended command execution.
	* Recommended secure fix: Use `shell=False` instead.
	* CWE/OWASP mapping: CWE-78, OWASP A04:2017 - Injection
2. **Weak Password Hashing**
	* Tools: Bandit, Semgrep
	* Affected file and line: `app/system.py`, line 22
	* Risk level: HIGH
	* Simple explanation: Using MD5 for password hashing is insecure.
	* Potential impact: Brute-force attacks on passwords.
	* Recommended secure fix: Use a suitable password hashing function like scrypt or bcrypt.

### Low-Risk Findings

1. **Hardcoded Password**
	* Tools: Bandit
	* Affected file and line: `app/auth.py`, line 6
	* Risk level: LOW
	* Simple explanation: Hardcoded passwords can be a security risk.
	* Potential impact: Unauthorized access to the system.
	* Recommended secure fix: Use environment variables or a secrets manager for sensitive data.

### Remediation Priority List

1. Fix subprocess Popen with Shell=True in `app/system.py`, line 12
2. Update password hashing function in `app/system.py`, line 22
3. Remove hardcoded passwords from the system