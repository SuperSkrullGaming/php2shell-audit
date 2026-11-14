# PHP2Shell Audit Tool for Docker Containers

A lightweight Bash script for auditing PHP versions across running Docker containers to help identify potential exposure to the **PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619)**.

The script checks for PHP CLI and PHP-FPM executables, identifies their installed versions and compares them against the published upstream security-fixed releases.

## Features

- Scans all currently running Docker containers.
- Detects generic PHP executables (`php` and `php-fpm`).
- Detects version-specific executables for PHP 8.1 through 8.5.
- Reports the PHP version detected in each executable.
- Compares detected versions against PHP2Shell fixed release thresholds.
- Identifies potentially vulnerable installations.
- Flags unsupported PHP versions and versions requiring manual verification.
- Provides a colour-coded summary of the audit results.

## PHP2Shell vulnerability information

PHP2Shell refers to two critical PHP vulnerabilities:

- CVE-2026-109618
- CVE-2026-109619

These vulnerabilities can potentially allow remote code execution in affected PHP installations.

The PHP project published security fixes on 21 October 2026.

### Fixed PHP versions

The following table identifies the minimum upstream PHP versions containing the security fixes.

| PHP branch        | Minimum fixed version        |
| ----------------- | ---------------------------- |
| PHP 8.5           | 8.5.12                       |
| PHP 8.4           | 8.4.27                       |
| PHP 8.3           | 8.3.36                       |
| PHP 8.2           | 8.2.35                       |
| PHP 8.1 and older | Manual verification required |

PHP 8.1 and older are end-of-life branches. Some distributions and vendors may provide security backports without changing the reported PHP version.

For this reason, the script flags these versions for manual review rather than automatically classifying them as vulnerable.

For authoritative security information, consult:

- [PHP Security Advisories](https://github.com/php/php-src/security/advisories)
- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [NCSC-NL PHP2Shell Information](https://github.com/NCSC-NL/php2shell)

## Requirements

- Linux host with Bash.
- Docker Engine installed and running.
- Permission to execute Docker commands against the Docker daemon.
- GNU `sort` with version sorting support (`sort -V`).

The script does not require PHP to be installed on the Docker host.

## Installation

Clone the repository:

```bash
git clone https://github.com/SuperSkrullGaming/php2shell-audit.git
```

Enter the repository directory:

```bash
cd php2shell-audit
```

Make the script executable:

```bash
chmod +x php2shell-audit.sh
```

## Usage

Run the audit:

```bash
./php2shell-audit.sh
```

The script will automatically inspect all currently running Docker containers.

Depending on your Docker permissions, you may need to run it with elevated privileges:

```bash
sudo ./php2shell-audit.sh
```

### Example output

```text
============================================================
          PHP2Shell Docker Security Audit
============================================================

CONTAINER              EXECUTABLE                  PHP VERSION    STATUS
-------------------------------------------------------------------------------
nextcloud              php                         8.3.14         VULNERABLE
wordpress              php                         8.4.27         FIXED
wordpress              php-fpm                     8.4.27         FIXED
bookstack              php                         8.3.36         FIXED
custom-app             php8.2                      8.2.28         VULNERABLE
nginx                  -                           -              NO PHP DETECTED

============================================================
                    AUDIT SUMMARY
============================================================

Containers scanned:       5
PHP executables found:    5

Fixed:                    3
Vulnerable:               2
Manual review required:   0

WARNING: Vulnerable PHP installations detected!

Audit complete.
```

*Example output is illustrative.*

## Understanding the results

The audit uses three principal status classifications.

### FIXED

The detected PHP version meets or exceeds the published upstream fixed version for its PHP branch.

This is a version-based result and does not independently verify the security patch inside the installed binary.

### VULNERABLE

The detected PHP version is older than the published upstream fixed version for its branch.

The installation should be investigated and updated using a patched image or vendor-provided security update.

### REVIEW - EOL / BACKPORT

The detected PHP version belongs to PHP 8.1 or an older branch.

These branches are unsupported upstream, but some distributions and vendors may have backported the security fixes.

Check the relevant vendor security advisory before determining whether the installation is vulnerable.

### REVIEW - UNKNOWN BRANCH

The detected PHP version does not match a branch supported by the script's version comparison rules.

Manual investigation is required.

### NO PHP DETECTED

None of the recognised PHP executables were detected in the container.

This does not guarantee that the container does not contain PHP.

## Limitations

This script is intended as a lightweight inventory and initial security screening tool. It is not a definitive vulnerability scanner.

Be aware of the following limitations:

1. **Running containers only:** The script examines currently running containers. Stopped containers and locally stored images are not inspected.

2. **Executable detection:** The script checks a predefined list of executable names. PHP installations using non-standard paths, custom executable names or embedded runtimes may not be detected.

3. **PHP CLI and PHP-FPM:** The script checks the reported version of recognised CLI and FPM executables. It does not independently inspect the actual running worker processes or verify which PHP binary is serving web requests.

4. **Distribution security backports:** Some Linux distributions and image maintainers backport security patches without changing the upstream PHP version number. The script cannot identify these patches automatically.

5. **Image and package verification:** The script does not inspect Docker image digests, package changelogs, vendor advisories or the source code of installed PHP binaries.

6. **Other PHP implementations:** PHP installations using alternative execution environments, including FrankenPHP, custom CGI implementations or other non-standard configurations, may not be detected.

7. **Fixed status is not a security guarantee:** A FIXED result only means that the reported version meets the upstream version threshold. It does not establish that the application, image or entire container is secure.

Always consult the relevant PHP, operating system or container image maintainer's security advisories before making a final determination.

## Updating affected containers

If the audit identifies a potentially vulnerable installation:

1. Identify which Docker image provides the PHP runtime.
2. Check whether the image maintainer has published a patched release.
3. Pull the updated image.
4. Recreate the affected container.
5. Run the audit again to verify the reported PHP version.

For Docker Compose deployments:

```bash
docker compose pull
docker compose up -d --force-recreate
```

For custom-built images:

```bash
docker compose build --pull
docker compose up -d --force-recreate
```

Always check application release notes and back up persistent application data before updating production containers.

## Contributing

Contributions, bug reports and suggestions are welcome.

If you identify an issue, please open a GitHub Issue with:

- A description of the problem.
- The affected Docker image or PHP distribution.
- The relevant script output.
- Steps to reproduce the issue, where possible.

Please avoid sharing private container names, internal hostnames, IP addresses, credentials or other sensitive infrastructure information.

## Licence

This project is distributed under the MIT License.

See [LICENSE](LICENSE) for details.

## Disclaimer

This project is provided as-is, without warranty of any kind.

It is an independent community utility and is not affiliated with or endorsed by the PHP Group, Docker or any Linux distribution maintainer.

The script is intended to assist with identifying potentially affected PHP installations. It should not be relied upon as the sole means of determining whether a system is vulnerable or secure.
