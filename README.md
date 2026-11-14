# PHP2Shell Audit Script for Docker Containers

A lightweight Bash utility for auditing PHP installations across running Docker containers to help identify potential exposure to the **PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619)**.

The script identifies recognised PHP executables and runtime environments, reports their available version information and compares detected versions against the published upstream security-fixed releases.

It is designed as a simple first-line security inventory tool for Docker administrators and self-hosted environments.

## Features

- Scans all currently running Docker containers.
- Detects generic PHP CLI executables (`php`).
- Detects PHP-FPM (`php-fpm` and version-specific executables).
- Detects PHP-CGI (`php-cgi` and version-specific executables).
- Detects LiteSpeed PHP (`lsphp` and version-specific executables).
- Detects loaded Apache `mod_php` modules.
- Identifies the presence of FrankenPHP.
- Compares recognised PHP versions against upstream security-fixed releases.
- Provides colour-coded security assessment results.
- Flags unsupported PHP versions and environments requiring manual verification.
- Provides a summary of audit findings.
- Returns meaningful exit codes for automated monitoring and scripting.

## PHP2Shell vulnerability information

PHP2Shell refers to two critical PHP vulnerabilities:

- CVE-2026-109618
- CVE-2026-109619

Both vulnerabilities can potentially allow unauthenticated remote code execution in affected PHP installations serving web requests.

The PHP project published security fixes on 21 October 2026.

All PHP installations serving web requests are potentially affected, including:

- PHP-FPM
- Apache with mod_php
- PHP-CGI
- FrankenPHP
- LiteSpeed

### Fixed PHP versions

The following table identifies the minimum upstream PHP versions containing the security fixes.

| PHP branch | Minimum fixed version |
|---|---|
| PHP 8.5 | 8.5.12 |
| PHP 8.4 | 8.4.27 |
| PHP 8.3 | 8.3.36 |
| PHP 8.2 | 8.2.35 |
| PHP 8.1 and older | Manual verification required |

PHP 8.1 and older are no longer supported upstream by the PHP project. However, some Linux distributions and long-term support vendors provide security backports.

For this reason, older PHP versions are flagged for manual review rather than automatically classified as vulnerable.

### Related vulnerability: CVE-2026-115560

CVE-2026-115560 is a separate PHP vulnerability disclosed on 23 October 2026.

It is not covered by this audit script.

Consult the latest PHP security advisories and NCSC-NL guidance for information about this issue and its recommended temporary mitigations.

### Security references

For authoritative and up-to-date information, consult:

- [PHP Security Advisories](https://github.com/php/php-src/security/advisories)
- [NCSC-NL PHP2Shell Operational Information](https://github.com/NCSC-NL/php2shell)
- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [UK National Cyber Security Centre – Critical Security Issue Affecting PHP](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)

## Requirements

The script requires:

- Linux host with Bash.
- Docker Engine installed and running.
- Permission to execute Docker commands against the Docker daemon.
- GNU coreutils, including `sort` with version sorting support (`sort -V`).
- Containers must provide a compatible `sh` shell for executable detection.

The script does not require PHP to be installed on the Docker host.

**Note:** Access to the Docker daemon is highly privileged. Membership of the Docker group is effectively equivalent to root-level access on a conventional Linux Docker host.

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
                 PHP2Shell Docker Audit
============================================================

CONTAINER              RUNTIME / EXECUTABLE    PHP VERSION    ASSESSMENT
-----------------------------------------------------------------------------------------------
nextcloud              php                     8.3.14         BELOW FIXED VERSION
wordpress              php                     8.4.27         MEETS UPSTREAM FIX
wordpress              php-fpm                 8.4.27         MEETS UPSTREAM FIX
bookstack              php-cgi                 8.3.36         MEETS UPSTREAM FIX
custom-app             php8.2                  8.2.28         BELOW FIXED VERSION
legacy-app             Apache mod_php          UNKNOWN        REVIEW - MODULE LOADED
nginx                  -                       -              NO RECOGNISED PHP FOUND

============================================================
                       SUMMARY
============================================================

Running containers scanned: 7
Runtime/executable findings: 6

Meets upstream fixed version: 3
Below fixed version:          2
Manual review required:       1

ATTENTION: One or more detected versions are below the upstream fixed threshold.

Audit complete.
```

*Example output is illustrative.*

## Understanding the results

The script uses the following assessment classifications.

### MEETS UPSTREAM FIX

The detected PHP version meets or exceeds the published upstream security-fixed version for its PHP branch.

This is a version-based assessment and does not independently verify the security patch inside the installed binary.

### BELOW FIXED VERSION

The detected PHP version is older than the published upstream fixed version for its branch.

The installation should be investigated and updated using a patched image or vendor-provided security update.

A below-threshold version does not necessarily mean the installation is vulnerable: distributions and image maintainers may have backported security fixes without changing the upstream PHP version number.

### REVIEW - EOL/BACKPORT

The detected PHP version belongs to PHP 8.1 or an older branch.

These branches are no longer supported upstream, but some distributions and LTS vendors may provide backported security fixes.

Check the relevant vendor security advisory before determining whether the installation is vulnerable.

### REVIEW - UNKNOWN BRANCH

The detected PHP version does not match a supported branch in the script's version comparison rules.

Manual investigation is required.

### REVIEW - MODULE LOADED

An Apache PHP module has been detected using the available Apache control utilities.

The script confirms the module is loaded but cannot independently determine its PHP version. Check the Apache PHP module and corresponding package version.

### REVIEW - BUNDLED PHP

FrankenPHP has been detected.

FrankenPHP bundles its own PHP runtime, so the script flags it for manual version verification rather than assuming the host's or container's CLI version represents the bundled runtime.

### NO RECOGNISED PHP FOUND

None of the recognised PHP executables or runtime indicators were detected.

This does not guarantee that the container does not contain PHP.

## Exit codes

The script returns the following exit codes:

| Exit code | Meaning |
|---|---|
| `0` | No below-threshold versions or manual review findings |
| `1` | One or more versions below the upstream fixed threshold |
| `2` | Manual review required or an audit error |

These exit codes allow the script to be incorporated into automated monitoring and scheduled tasks.

For example:

```bash
./php2shell-audit.sh

echo "Audit exit code: $?"
```

## Detection methodology

The script uses Docker's `exec` functionality to inspect running containers.

It checks for the following executable names:

| Runtime | Executables checked |
|---|---|
| PHP CLI | `php`, `php8.1`–`php8.5` |
| PHP-FPM | `php-fpm`, `php-fpm8.1`–`php-fpm8.5` |
| PHP-CGI | `php-cgi`, `php-cgi8.1`–`php-cgi8.5` |
| LiteSpeed | `lsphp`, `lsphp81`–`lsphp85` |
| Apache | `apachectl`, `apache2ctl`, `httpd` module inspection |
| FrankenPHP | `frankenphp` executable presence |

Where an executable is found, the script attempts to retrieve its PHP version using the `-v` argument.

For Apache, it checks whether a PHP module is loaded using the available Apache control utility.

For FrankenPHP, it detects the executable but requires manual version verification.

## Limitations

This script is intended as a lightweight inventory and initial security screening tool. It is not a definitive vulnerability scanner.

Be aware of the following limitations:

1. **Running containers only:** The script examines currently running containers. Stopped containers and locally stored Docker images are not inspected.

2. **Executable detection:** The script checks a predefined list of executable names. PHP installations using non-standard paths, custom executable names or embedded runtimes may not be detected.

3. **Container shell requirement:** Executable detection uses `sh` inside the container. Minimal or distroless containers without a compatible shell may not be inspected successfully.

4. **PHP CLI versus web-serving runtime:** PHP CLI versions are useful indicators of the installed PHP build, but the CLI is not itself the web-serving execution environment. The script does not independently verify which binary is handling incoming web requests.

5. **PHP-FPM process verification:** The script checks the version reported by recognised PHP-FPM executables. It does not independently inspect running FPM worker processes or verify which binary is actively serving requests.

6. **Apache mod_php:** The script can detect a loaded PHP Apache module, but cannot reliably establish its version independently.

7. **FrankenPHP:** The script detects the presence of FrankenPHP but does not retrieve or verify its bundled PHP runtime version.

8. **Distribution security backports:** Some Linux distributions and image maintainers backport security patches without changing the upstream PHP version number. The script cannot identify these patches automatically.

9. **Image and package verification:** The script does not inspect Docker image digests, package changelogs, vendor advisories or the source code of installed PHP binaries.

10. **Fixed status is not a security guarantee:** A MEETS UPSTREAM FIX result only means that the reported version meets the upstream version threshold. It does not establish that the application, image or entire container is secure.

11. **Other vulnerabilities:** The script only assesses the upstream version thresholds for CVE-2026-109618 and CVE-2026-109619. It does not assess other PHP vulnerabilities, including CVE-2026-115560.

Always consult the relevant PHP, operating system or container image maintainer's security advisories before making a final determination.

## Updating affected containers

If the audit identifies a potentially affected installation:

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
