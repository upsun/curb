#!/usr/bin/env bash
# Cross-distro Docker smoke tests for curb.
# Validates CA bundle detection, default paths, proxy, and basic sandboxing
# across popular Linux distributions.
#
# Usage:
#   ./test/distro-smoke.sh                        # all distros (Landlock-only under Docker defaults)
#   ./test/distro-smoke.sh alpine fedora           # specific distros
#   CURB_TEST_TUN=1 ./test/distro-smoke.sh         # include TUN tests
#   CURB_TEST_NO_SECCOMP=1 ./test/distro-smoke.sh  # relax seccomp (enables user NS)
#   CURB_TEST_NO_APPARMOR=1 ./test/distro-smoke.sh # relax apparmor
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

declare -A DISTRO_SETUP
DISTRO_SETUP[alpine]="apk add --no-cache curl ca-certificates"
DISTRO_SETUP[debian]="apt-get update -qq && apt-get install -y -qq curl ca-certificates"
DISTRO_SETUP[fedora]=":"
DISTRO_SETUP[ubuntu]="apt-get update -qq && apt-get install -y -qq curl"
DISTRO_SETUP[archlinux]="pacman -Sy --noconfirm curl"

ALL_DISTROS=(alpine debian fedora ubuntu archlinux)

# Parse arguments: distro names, or all if none given.
if [ $# -gt 0 ]; then
	DISTROS=("$@")
	for d in "${DISTROS[@]}"; do
		if [ -z "${DISTRO_SETUP[$d]+x}" ]; then
			echo "unknown distro: $d" >&2
			echo "available: ${ALL_DISTROS[*]}" >&2
			exit 1
		fi
	done
else
	DISTROS=("${ALL_DISTROS[@]}")
fi

# Build the curb binary.
echo "Building curb..."
(cd "$PROJECT_DIR" && CGO_ENABLED=0 go build -o curb .)

# Docker run flags.
DOCKER_FLAGS=(--rm -v "$PROJECT_DIR/curb:/curb:ro")

if [ "${CURB_TEST_TUN:-}" = "1" ]; then
	DOCKER_FLAGS+=(--device /dev/net/tun)
fi

# Support both old CURB_TEST_RELAXED and new granular flags.
if [ "${CURB_TEST_RELAXED:-}" = "1" ]; then
	DOCKER_FLAGS+=(--security-opt seccomp=unconfined --security-opt apparmor=unconfined)
else
	if [ "${CURB_TEST_NO_SECCOMP:-}" = "1" ]; then
		DOCKER_FLAGS+=(--security-opt seccomp=unconfined)
	fi
	if [ "${CURB_TEST_NO_APPARMOR:-}" = "1" ]; then
		DOCKER_FLAGS+=(--security-opt apparmor=unconfined)
	fi
fi

# Counters for summary.
declare -A PASS_COUNTS
declare -A TOTAL_COUNTS
declare -A SKIP_REASONS
OVERALL_PASS=0
OVERALL_TOTAL=0

test_distro() {
	local distro="$1"
	local image="${distro}:latest"
	local setup="${DISTRO_SETUP[$distro]}"

	PASS_COUNTS[$distro]=0
	TOTAL_COUNTS[$distro]=0

	echo "=== $distro ==="

	# Run all tests in a single container to avoid per-test overhead.
	local results
	results=$(docker run "${DOCKER_FLAGS[@]}" "$image" sh -c "
		$setup >/dev/null 2>&1

		report() {
			if [ \$1 -eq 0 ]; then
				echo \"RESULT:PASS:\$2\"
			else
				echo \"RESULT:FAIL:\$2\"
			fi
		}

		# Detect Landlock-only mode: --dry-run without --unrestricted-net
		# will fail if user NS is unavailable but Landlock works.
		landlock_only=0
		probe=\$(/curb --dry-run 2>&1)
		if [ \$? -ne 0 ]; then
			if echo \"\$probe\" | grep -q -- '--unrestricted-net'; then
				landlock_only=1
				# Re-probe with --unrestricted-net.
				probe=\$(/curb --unrestricted-net --dry-run 2>&1)
				if [ \$? -ne 0 ]; then
					reason=\$(echo \"\$probe\" | grep -v '^\$' | tail -1)
					echo \"RESULT:ABORT:\$reason\"
					exit 0
				fi
			else
				reason=\$(echo \"\$probe\" | grep -v '^\$' | tail -1)
				echo \"RESULT:ABORT:\$reason\"
				exit 0
			fi
		fi
		report 0 'dry-run'

		# Set curb flags for Landlock-only mode.
		curb_flags=''
		if [ \$landlock_only -eq 1 ]; then
			curb_flags='--unrestricted-net'
		fi

		# Test 2: sandbox uid.
		out=\$(/curb \$curb_flags -- id 2>&1)
		if [ \$landlock_only -eq 1 ]; then
			# Landlock-only: uid is the real user, not 0.
			if echo \"\$out\" | grep -q 'uid='; then
				report 0 'sandbox runs (landlock-only)'
			else
				report 1 'sandbox runs (landlock-only)'
			fi
		else
			if echo \"\$out\" | grep -q 'uid=0'; then
				report 0 'sandbox uid=0'
			else
				report 1 'sandbox uid=0'
			fi
		fi

		# Test 3: exit code propagation.
		/curb \$curb_flags -- sh -c 'exit 42' 2>/dev/null
		if [ \$? -eq 42 ]; then
			report 0 'exit code propagation'
		else
			report 1 'exit code propagation'
		fi

		# Test 4: TMPDIR writable.
		out=\$(/curb \$curb_flags -- sh -c 'touch \${TMPDIR:-/tmp}/test && rm \${TMPDIR:-/tmp}/test' 2>&1)
		if [ \$? -eq 0 ]; then
			report 0 'tmpdir writable'
		else
			report 1 'tmpdir writable'
		fi

		# Test 5: system path read-only.
		out=\$(/curb \$curb_flags -- sh -c '! touch /usr/bin/test-escape' 2>&1)
		if [ \$? -eq 0 ]; then
			report 0 'system path read-only'
		else
			report 1 'system path read-only'
		fi

		# Test 6: default RO file accessible.
		out=\$(/curb \$curb_flags -- cat /etc/os-release 2>&1)
		if [ \$? -eq 0 ] && [ -n \"\$out\" ]; then
			report 0 '/etc/os-release readable'
		else
			report 1 '/etc/os-release readable'
		fi

		# Proxy tests require user NS (network namespaces).
		if [ \$landlock_only -eq 1 ]; then
			# Test 7: network is unrestricted in Landlock-only mode.
			if curl -sf https://httpbin.org/get >/dev/null 2>&1; then
				out=\$(/curb --unrestricted-net --write '*' --exec '*' -- curl -sf https://httpbin.org/get 2>&1)
				if [ \$? -eq 0 ] && echo \"\$out\" | grep -q '\"Host\"'; then
					report 0 'outbound HTTPS works (--unrestricted-net)'
				else
					report 1 'outbound HTTPS works (--unrestricted-net)'
				fi
			else
				echo 'RESULT:SKIP:network unrestricted (direct HTTPS failed — CA bundle issue)'
			fi
			echo 'RESULT:SKIP:proxy curl allowed domain (no user namespaces)'
			echo 'RESULT:SKIP:proxy blocks unlisted domain (no user namespaces)'
		elif curl -sf https://httpbin.org/get >/dev/null 2>&1; then
			# Test 7: proxy + CA bundle (curl to allowed domain).
			out=\$(/curb --domains httpbin.org --write '*' --exec '*' -- curl -sf https://httpbin.org/get 2>&1)
			if [ \$? -eq 0 ] && echo \"\$out\" | grep -q '\"Host\"'; then
				report 0 'proxy curl allowed domain'
			else
				report 1 'proxy curl allowed domain'
			fi

			# Test 8: proxy blocks unlisted domain.
			/curb --domains httpbin.org --write '*' --exec '*' -- curl -sf https://example.org/ 2>/dev/null
			if [ \$? -ne 0 ]; then
				report 0 'proxy blocks unlisted domain'
			else
				report 1 'proxy blocks unlisted domain'
			fi
		else
			echo 'RESULT:SKIP:proxy curl allowed domain (direct HTTPS failed — CA bundle issue)'
			echo 'RESULT:SKIP:proxy blocks unlisted domain (direct HTTPS failed — CA bundle issue)'
		fi
	" 2>&1)

	# Parse results from container output.
	while IFS= read -r line; do
		case "$line" in
			RESULT:ABORT:*)
				SKIP_REASONS[$distro]="${line#RESULT:ABORT:}"
				echo "  [SKIP] curb setup failed: ${SKIP_REASONS[$distro]}"
				echo "         Try CURB_TEST_NO_SECCOMP=1 or see docs/troubleshooting.md"
				;;
			RESULT:PASS:*)
				echo "  [PASS] ${line#RESULT:PASS:}"
				PASS_COUNTS[$distro]=$(( ${PASS_COUNTS[$distro]} + 1 ))
				OVERALL_PASS=$(( OVERALL_PASS + 1 ))
				TOTAL_COUNTS[$distro]=$(( ${TOTAL_COUNTS[$distro]} + 1 ))
				OVERALL_TOTAL=$(( OVERALL_TOTAL + 1 ))
				;;
			RESULT:FAIL:*)
				echo "  [FAIL] ${line#RESULT:FAIL:}"
				TOTAL_COUNTS[$distro]=$(( ${TOTAL_COUNTS[$distro]} + 1 ))
				OVERALL_TOTAL=$(( OVERALL_TOTAL + 1 ))
				;;
			RESULT:SKIP:*)
				echo "  [SKIP] ${line#RESULT:SKIP:}"
				;;
		esac
	done <<< "$results"
}

# Run tests for each distro.
for distro in "${DISTROS[@]}"; do
	test_distro "$distro"
	echo
done

# Summary.
echo "=== summary ==="
exit_code=0
for distro in "${DISTROS[@]}"; do
	if [ -n "${SKIP_REASONS[$distro]:-}" ]; then
		printf "%-12s skipped\n" "$distro:"
	else
		p=${PASS_COUNTS[$distro]:-0}
		t=${TOTAL_COUNTS[$distro]:-0}
		printf "%-12s %d/%d passed\n" "$distro:" "$p" "$t"
		if [ "$p" -ne "$t" ]; then
			exit_code=1
		fi
	fi
done
echo
printf "total:       %d/%d passed\n" "$OVERALL_PASS" "$OVERALL_TOTAL"

exit "$exit_code"
