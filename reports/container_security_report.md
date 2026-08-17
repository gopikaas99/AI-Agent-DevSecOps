# Security Report for ai-devsecops-calculator Image

## Summary

The `ai-devsecops-calculator` image contains several vulnerabilities that need to be addressed.

### Vulnerability Count

* Critical: 4
* High: 19
* Medium: 0
* Low: 0

### Deployment Decision

Based on the deployment gate decision, the image should not be deployed as it contains critical vulnerabilities.

## Detailed Findings

### Critical Vulnerabilities

1. **CVE-2026-13221**: Perl versions through 5.43.9 produce silently incorrect regular expressions.
	* Package: perl-base
	* Version: 5.40.1-6
2. **CVE-2026-42496**: perl-archive-tar: Path traversal via crafted symlinks allows arbitrary file access
	* Package: perl-base
	* Version: 5.40.1-6
3. **CVE-2026-57433**: Storable versions before 3.41 for Perl have a signed integer overflow vulnerability.
	* Package: perl-base
	* Version: 5.40.1-6
4. **CVE-2026-8376**: perl: Heap buffer overflow when compiling regular expressions on 32-bit builds
	* Package: perl-base
	* Version: 5.40.1-6

### High Vulnerabilities

1. **CVE-2026-42497**: perl-Archive-Tar: Arbitrary file modification via crafted hardlinks during archive extraction
	* Package: perl-base
	* Version: 5.40.1-6
2. **CVE-2026-48962**: perl-IO-Compress: Arbitrary code execution via attacker-controlled output glob
	* Package: perl-base
	* Version: 5.40.1-6
3. **CVE-2026-57432**: Perl versions through 5.43.10 have an integer overflow in S_measure_st.
	* Package: perl-base
	* Version: 5.40.1-6
4. **CVE-2026-9538**: perl-Archive-Tar: Denial of Service via crafted tar header with large entry size
	* Package: perl-base
	* Version: 5.40.1-6

## Recommendations

1. Update the `perl-base` package to a version that is not vulnerable.
2. Review and update other packages as necessary.

## Deployment Decision

The deployment gate decision is to **BLOCK** the image due to critical vulnerabilities.

Note: This report only includes the vulnerabilities mentioned in the provided scan data. It is recommended to perform a thorough security audit of the image to identify any additional vulnerabilities.