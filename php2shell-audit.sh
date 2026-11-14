#!/bin/bash

# PHP2Shell Docker Container Security Audit
# Checks PHP CLI and PHP-FPM versions in all running containers.

# Fixed versions for CVE-2026-109618 / CVE-2026-109619
declare -A FIXED_VERSIONS=(
    ["8.2"]="8.2.35"
    ["8.3"]="8.3.36"
    ["8.4"]="8.4.27"
    ["8.5"]="8.5.12"
)

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Compare version numbers using version-aware sorting.
version_ge() {
    local current="$1"
    local required="$2"

    [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n 1)" == "$required" ]]
}

# Determine vulnerability status.
check_status() {
    local version="$1"
    local branch="${version%.*}"
    local fixed="${FIXED_VERSIONS[$branch]}"

    if [[ -n "$fixed" ]]; then
        if version_ge "$version" "$fixed"; then
            echo "FIXED"
        else
            echo "VULNERABLE"
        fi
    elif [[ "$branch" == "8.1" ]] || version_ge "8.1.0" "$version"; then
        echo "REVIEW - EOL / BACKPORT"
    else
        echo "REVIEW - UNKNOWN BRANCH"
    fi
}

# Check for Docker.
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is not installed or not in PATH."
    exit 1
fi

# Check for running containers.
containers=$(docker ps -q)

if [[ -z "$containers" ]]; then
    echo "No running Docker containers found."
    exit 0
fi

# Counters
total=0
fixed_count=0
vulnerable_count=0
review_count=0
container_count=0

echo
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}          PHP2Shell Docker Security Audit${NC}"
echo -e "${CYAN}============================================================${NC}"
echo

printf "%-22s %-28s %-14s %-14s\n" \
    "CONTAINER" "EXECUTABLE" "PHP VERSION" "STATUS"

printf '%s\n' "-------------------------------------------------------------------------------"

for container in $containers; do

    name=$(docker inspect --format '{{.Name}}' "$container" | sed 's#^/##')

    container_count=$((container_count + 1))
    found=0

    # Generic and version-specific PHP executables.
    binaries=(
        php
        php-fpm
        php8.1 php8.2 php8.3 php8.4 php8.5
        php-fpm8.1 php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5
    )

    for binary in "${binaries[@]}"; do

        # Check whether executable exists and retrieve its version.
        output=$(docker exec "$container" sh -c \
            'command -v "$1" >/dev/null 2>&1 && "$1" -v 2>&1' \
            sh "$binary" 2>/dev/null | head -n 1)

        [[ -z "$output" ]] && continue

        # Extract PHP version.
        if [[ "$output" =~ PHP[[:space:]]([0-9]+\.[0-9]+\.[0-9]+) ]]; then

            version="${BASH_REMATCH[1]}"
            status=$(check_status "$version")

            total=$((total + 1))
            found=1

            case "$status" in
                FIXED)
                    colour="$GREEN"
                    fixed_count=$((fixed_count + 1))
                    ;;
                VULNERABLE)
                    colour="$RED"
                    vulnerable_count=$((vulnerable_count + 1))
                    ;;
                *)
                    colour="$YELLOW"
                    review_count=$((review_count + 1))
                    ;;
            esac

            printf "%-22s %-28s %-14s " \
                "$name" "$binary" "$version"

            echo -e "${colour}${status}${NC}"

        fi

    done

    if [[ "$found" -eq 0 ]]; then
        printf "%-22s %-28s %-14s " "$name" "-" "-"
        echo -e "${GREEN}NO PHP DETECTED${NC}"
    fi

done

echo
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}                    AUDIT SUMMARY${NC}"
echo -e "${CYAN}============================================================${NC}"

echo
printf "Containers scanned:       %s\n" "$container_count"
printf "PHP executables found:    %s\n" "$total"

echo
echo -e "${GREEN}Fixed:                    $fixed_count${NC}"
echo -e "${RED}Vulnerable:               $vulnerable_count${NC}"
echo -e "${YELLOW}Manual review required:   $review_count${NC}"

echo

if [[ "$vulnerable_count" -gt 0 ]]; then
    echo -e "${RED}WARNING: Vulnerable PHP installations detected!${NC}"
elif [[ "$review_count" -gt 0 ]]; then
    echo -e "${YELLOW}ATTENTION: Some PHP installations need manual verification.${NC}"
else
    echo -e "${GREEN}All detected PHP versions meet the checked thresholds.${NC}"
fi

echo
echo "Audit complete."
echo
