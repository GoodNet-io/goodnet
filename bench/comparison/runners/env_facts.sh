#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Capture the environment a bench run executed on: CPU model, RAM,
# kernel version, CPU governor / scaling, ASLR / SMT / NUMA. The
# aggregator surfaces these in the report header so a reader scanning
# numbers a week later can tell whether the box was in `performance`
# or `schedutil` mode — bench rows mean different things across the
# two.

set -euo pipefail

cpu_model="$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo \
    2>/dev/null || echo unknown)"
cpu_cores="$(nproc 2>/dev/null || echo unknown)"
ram_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
ram_human="$(printf '%d MiB' "$(( ${ram_kb:-0} / 1024 ))")"
kernel="$(uname -r 2>/dev/null || echo unknown)"

# Governor — first online CPU's policy. `cpufreq-info` is gone on
# kernels with intel_pstate; fall back to the sysfs file.
governor="unknown"
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    governor="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
fi

# Scaling driver (intel_pstate vs acpi-cpufreq vs cppc_cpufreq etc.)
# Needed because intel_pstate "powersave" is NOT the same as
# acpi-cpufreq "powersave": with HWP the CPU still boosts to max
# under load regardless of the governor name.
scaling_driver="unknown"
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver ]]; then
    scaling_driver="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver)"
fi

# Detect "governor says powersave but CPU is actually running at max freq"
# — common on intel_pstate where HWP boosts to cpuinfo_max_freq under load.
# Report an explicit note so the aggregator does not mislead the reader.
governor_note=""
if [[ "${governor}" == "powersave" && "${scaling_driver}" == "intel_pstate" ]]; then
    max_freq="$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || echo 0)"
    smax_freq="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || echo 0)"
    if [[ "${max_freq}" -gt 0 && "${max_freq}" == "${smax_freq}" ]]; then
        governor_note="intel_pstate_at_max"
    else
        governor_note="intel_pstate_limited"
    fi
fi

# Turbo. intel_pstate exposes `no_turbo` (inverted boolean). AMD's
# cpufreq driver exposes `boost`. Default to "unknown" when neither
# path is readable so a reader notices the gap rather than getting a
# silently-wrong value.
turbo="unknown"
if [[ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
    if [[ "$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)" == "0" ]]; then
        turbo="enabled (intel_pstate)"
    else
        turbo="disabled (intel_pstate)"
    fi
elif [[ -r /sys/devices/system/cpu/cpufreq/boost ]]; then
    if [[ "$(cat /sys/devices/system/cpu/cpufreq/boost)" == "1" ]]; then
        turbo="enabled (cpufreq.boost)"
    else
        turbo="disabled (cpufreq.boost)"
    fi
fi

# SMT (hyperthreading). `/sys/devices/system/cpu/smt/active` reads
# 0 when SMT off, 1 when on. Missing on older kernels.
smt="unknown"
if [[ -r /sys/devices/system/cpu/smt/active ]]; then
    if [[ "$(cat /sys/devices/system/cpu/smt/active)" == "1" ]]; then
        smt="on"
    else
        smt="off"
    fi
fi

# ASLR. /proc/sys/kernel/randomize_va_space: 0=off, 1=stack only,
# 2=full. google-benchmark also pulls this but lands it inside the
# JSON; replicating here so the runner-side fact lines up with what
# the aggregator emits.
aslr="unknown"
if [[ -r /proc/sys/kernel/randomize_va_space ]]; then
    aslr="$(cat /proc/sys/kernel/randomize_va_space)"
fi

# NUMA nodes — relevant only on multi-socket machines; on a single-
# socket box this is always `1`. The bench harness pins to no CPU,
# so cross-NUMA-node memory traffic is possible whenever this is >1.
numa_nodes="1"
if [[ -r /sys/devices/system/node/online ]]; then
    last="$(cat /sys/devices/system/node/online | tr ',' ' ' | \
            awk '{n=split($NF,a,"-"); print a[n]}')"
    numa_nodes=$(( last + 1 ))
fi

cat <<JSON
{
  "metric": "env_facts",
  "cpu_model": "${cpu_model}",
  "cpu_cores": ${cpu_cores},
  "ram":       "${ram_human}",
  "kernel":    "${kernel}",
  "governor":  "${governor}",
  "scaling_driver": "${scaling_driver}",
  "governor_note":  "${governor_note}",
  "turbo":     "${turbo}",
  "smt":       "${smt}",
  "aslr":      "${aslr}",
  "numa_nodes": ${numa_nodes}
}
JSON
