#!/usr/bin/env bash

# PHP2Shell Docker Audit
# Version: 1.0.1
#
# Audits recognised PHP runtimes and executables in running Docker
# containers against upstream fixed versions for:
# CVE-2026-109618 and CVE-2026-109619.
#
# This is a version-based screening tool, not a vulnerability scanner.

set -o pipefail

# --------------------------------------------------
# PHP2Shell upstream fixed versions
# --------------------------------------------------

fixed_version() {
    case "$1" in
        8.2) printf '%s' '8.2.35' ;;
        8.3) printf '%s' '8.3.36' ;;
        8.4) printf '%s' '8.4.27' ;;
        8.5) printf '%s' '8.5.12' ;;
        *) return 1 ;;
    esac
}

# --------------------------------------------------
# Version comparison
# --------------------------------------------------

version_ge() {
    local current="$1"
    local required="$2"

    [[ "$(printf '%s\n%s\n' "$required" "$current" |
        sort -V | head -n 1)" == "$required" ]]
}

# --------------------------------------------------
# Version classification
# --------------------------------------------------

classify_version() {
    local version="$1"
    local major_minor
    local fixed

    major_minor="$(printf '%s' "$version" |
        awk -F. '{print $1 "." $2}')"

    if fixed="$(fixed_version "$major_minor")"; then

        if version_ge "$version" "$fixed"; then
            printf '%s' 'MEETS UPSTREAM FIX'
        else
            printf '%s' 'BELOW FIXED VERSION'
        fi

    elif [[ "$major_minor" == "8.1" ]] ||
         version_ge '8.1.0' "$version"; then

        printf '%s' 'REVIEW - EOL/BACKPORT'

    else
        printf '%s' 'REVIEW - UNKNOWN BRANCH'
    fi
}

# --------------------------------------------------
# Prerequisite checks
# --------------------------------------------------

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker CLI was not found in PATH."
    exit 2
fi

if ! command -v sort >/dev/null 2>&1 ||
   ! sort -V </dev/null >/dev/null 2>&1; then
    echo "ERROR: GNU sort with version sorting (-V) is required."
    exit 2
fi

if ! containers="$(docker ps --quiet)"; then
    echo "ERROR: Unable to query Docker."
    echo "Check that Docker is running and you have permission."
    exit 2
fi

if [[ -z "$containers" ]]; then
    echo "No running Docker containers found."
    exit 0
fi

# --------------------------------------------------
# Terminal colours
# --------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --------------------------------------------------
# Audit counters
# --------------------------------------------------

container_count=0
checks_count=0
meets_count=0
below_count=0
review_count=0

# --------------------------------------------------
# Audit header
# --------------------------------------------------

printf '\n%b\n' "${CYAN}============================================================${NC}"
printf '%b\n' "${CYAN}                 PHP2Shell Docker Audit${NC}"
printf '%b\n\n' "${CYAN}============================================================${NC}"

printf '%-22s %-25s %-14s %s\n' \
    "CONTAINER" "RUNTIME / EXECUTABLE" "PHP VERSION" "ASSESSMENT"

printf '%s\n' "-----------------------------------------------------------------------------------------------"

# --------------------------------------------------
# Scan running Docker containers
# --------------------------------------------------

while IFS= read -r container; do

    [[ -z "$container" ]] && continue

    name="$(docker inspect --format '{{.Name}}' \
        "$container" 2>/dev/null | sed 's#^/##')"

    [[ -z "$name" ]] && name="$container"

    container_count=$((container_count + 1))
    found=0

    # --------------------------------------------------
    # PHP executable detection
    # --------------------------------------------------

    binaries=(
        php
        php-fpm
        php-cgi
        lsphp

        php8.1 php8.2 php8.3 php8.4 php8.5

        php-fpm8.1
        php-fpm8.2
        php-fpm8.3
        php-fpm8.4
        php-fpm8.5

        php-cgi8.1
        php-cgi8.2
        php-cgi8.3
        php-cgi8.4
        php-cgi8.5

        lsphp81
        lsphp82
        lsphp83
        lsphp84
        lsphp85
    )

    for binary in "${binaries[@]}"; do

        output="$(docker exec "$container" sh -c \
            'command -v "$1" >/dev/null 2>&1 && "$1" -v 2>&1' \
            sh "$binary" 2>/dev/null | head -n 1)"

        [[ -z "$output" ]] && continue

        if [[ "$output" =~ PHP[[:space:]]([0-9]+\.[0-9]+\.[0-9]+) ]]; then

            version="${BASH_REMATCH[1]}"
            assessment="$(classify_version "$version")"

            found=1
            checks_count=$((checks_count + 1))

            case "$assessment" in

                "MEETS UPSTREAM FIX")
                    colour="$GREEN"
                    meets_count=$((meets_count + 1))
                    ;;

                "BELOW FIXED VERSION")
                    colour="$RED"
                    below_count=$((below_count + 1))
                    ;;

                *)
                    colour="$YELLOW"
                    review_count=$((review_count + 1))
                    ;;

            esac

            printf '%-22s %-25s %-14s ' \
                "$name" "$binary" "$version"

            printf '%b\n' "${colour}${assessment}${NC}"

        fi

    done

    # --------------------------------------------------
    # Apache mod_php detection
    # --------------------------------------------------

    apache_modules=""

    for apache_ctl in apachectl apache2ctl httpd; do

        if docker exec "$container" sh -c \
            'command -v "$1" >/dev/null 2>&1' \
            sh "$apache_ctl" >/dev/null 2>&1; then

            apache_modules="$(docker exec "$container" sh -c \
                '"$1" -M 2>&1' \
                sh "$apache_ctl" 2>/dev/null || true)"

            if printf '%s\n' "$apache_modules" |
                grep -Eqi 'php[0-9]*_module'; then

                found=1
                checks_count=$((checks_count + 1))
                review_count=$((review_count + 1))

                printf '%-22s %-25s %-14s ' \
                    "$name" "Apache mod_php" "UNKNOWN"

                printf '%b\n' \
                    "${YELLOW}REVIEW - MODULE LOADED${NC}"

                break
            fi

        fi

    done

    # --------------------------------------------------
    # FrankenPHP detection
    # --------------------------------------------------

    if docker exec "$container" sh -c \
        'command -v frankenphp >/dev/null 2>&1' \
        >/dev/null 2>&1; then

        found=1
        checks_count=$((checks_count + 1))
        review_count=$((review_count + 1))

        printf '%-22s %-25s %-14s ' \
            "$name" "FrankenPHP" "UNKNOWN"

        printf '%b\n' \
            "${YELLOW}REVIEW - BUNDLED PHP${NC}"

    fi

    # --------------------------------------------------
    # No recognised PHP runtime
    # --------------------------------------------------

    if [[ "$found" -eq 0 ]]; then

        printf '%-22s %-25s %-14s ' \
            "$name" "-" "-"

        printf '%b\n' \
            "${YELLOW}NO RECOGNISED PHP FOUND${NC}"

    fi

done <<< "$containers"

# --------------------------------------------------
# Audit summary
# --------------------------------------------------

printf '\n%b\n' "${CYAN}============================================================${NC}"
printf '%b\n' "${CYAN}                       SUMMARY${NC}"
printf '%b\n\n' "${CYAN}============================================================${NC}"

printf "Running containers scanned: %s\n" "$container_count"
printf "Runtime/executable findings: %s\n\n" "$checks_count"

printf '%b\n' "${GREEN}Meets upstream fixed version: $meets_count${NC}"
printf '%b\n' "${RED}Below fixed version:          $below_count${NC}"
printf '%b\n\n' "${YELLOW}Manual review required:       $review_count${NC}"

if (( below_count > 0 )); then

    printf '%b\n' \
        "${RED}ATTENTION: One or more detected versions are below the upstream fixed threshold.${NC}"

elif (( review_count > 0 )); then

    printf '%b\n' \
        "${YELLOW}ATTENTION: Manual verification is required for one or more findings.${NC}"

else

    printf '%b\n' \
        "${GREEN}All recognised version findings meet the checked upstream thresholds.${NC}"

fi

printf '\nAudit complete. A clean result is not proof that every PHP runtime is patched.\n\n'

# --------------------------------------------------
# Exit codes
# --------------------------------------------------

# 0 = No below-threshold or review findings
# 1 = One or more versions below upstream fixed threshold
# 2 = Manual review required, or audit error

if (( below_count > 0 )); then
    exit 1
elif (( review_count > 0 )); then
    exit 2
fi

exit 0
