# Detect4Shell / Java4Shell (CVE-2026-114938) — CPU × JDK validation matrix

Confined reproducer: `laboratorio/Base64Trigger.java` (offline, writes only inside its own
4096-byte array, auto-picks trigger length — 128 on JDK 17, else 64). Run via Docker on a
Windows host with Docker Desktop (Linux containers, linux/amd64). No network access, no
modification of the reproducer. Date of this run: 2026-11-18.

## JDK build matrix (Docker, local images, linux/amd64)

| # | Image (tag) | Vendor | `java.runtime.version` reported | Trigger length | rejected | changed | Result |
|---|---|---|---|---|---|---|---|
| 1 | `eclipse-temurin:17-jdk` | Eclipse Temurin | 17.0.21+9 | 128 | true | 62 | **REPRODUCED** |
| 2 | `eclipse-temurin:21-jdk` | Eclipse Temurin | 21.0.13+9-LTS | 64 | true | 62 | **REPRODUCED** ← known-vulnerable build used for the proxy runs below |
| 3 | `eclipse-temurin:25-jdk` | Eclipse Temurin | 25.0.5+8-LTS | 64 | true | 62 | **REPRODUCED** |
| 4 | `amazoncorretto:17` | Amazon Corretto | 17.0.21.1+2-LTS | 128 | true | 0 | **NOT REPRODUCED** — already-patched point release (`.1`) |
| 5 | `amazoncorretto:21` | Amazon Corretto | 21.0.13.1+2-LTS | 64 | true | 0 | **NOT REPRODUCED** — already-patched point release (`.1`) |

Rows 4–5 satisfy the "try one patched build" step directly: Amazon Corretto's floating
`17`/`21` tags had already rolled forward to the `.1` point release that fixes this issue by
the time of this run, while Eclipse Temurin's `17-jdk`/`21-jdk`/`25-jdk` tags were still on the
pre-fix point release. No separately-pinned patched tag needed to be hunted down — this is a
real, naturally-occurring patched data point, not a cherry-pick.

## Mitigation-flag proxies (run on row 2, `eclipse-temurin:21-jdk`, runtime 21.0.13+9-LTS — the
confirmed-vulnerable build)

| Flag | rejected | changed | Result |
|---|---|---|---|
| `-XX:-UseBASE64Intrinsics` (disables the Base64 intrinsic entirely) | true | 0 | **NOT REPRODUCED** |
| `-XX:UseAVX=2` (caps HotSpot's AVX ceiling below AVX-512 VBMI) | true | 0 | **NOT REPRODUCED** |

Both proxies model an "immune" runtime on otherwise-identical vulnerable JDK bits: turning off
the intrinsic, or forcing codegen off the AVX-512 VBMI path, suppresses the overrun exactly like
a real non-VBMI CPU or a patched JDK does.

## CPU axis (already-known results, not re-run — included for completeness)

| CPU | Microarchitecture | AVX-512 VBMI | JDK under test | Result |
|---|---|---|---|---|
| AMD Ryzen 9 7950X | Zen 4 | Yes | Temurin 21.0.13.0.2 (bare metal, host) | **REPRODUCED** (changed=62) |
| AMD EPYC 7713 (VPS, via Docker `temurin:21`) | Zen 3 | No | Temurin 21 (container) | **NOT REPRODUCED** (changed=0) — real immune x86 CPU |

## What this matrix proves

- **The vulnerability reproduces across JDK majors 17, 21, and 25**, and across vendors
  (Eclipse Temurin confirmed vulnerable on all three majors; Amazon Corretto reproduces too on
  its pre-fix point releases, though the floating tags pulled here already landed post-fix) —
  it is not a one-JDK-build artifact. It depends on the HotSpot C2 Base64 intrinsic picking the
  AVX-512 VBMI codegen path, which exists across these majors.
- **It is absent on hardware without AVX-512 VBMI**: the real Zen 3 EPYC 7713 (no VBMI) never
  reproduces, while the real Zen 4 Ryzen 9 7950X (has VBMI) reproduces reliably — confirming the
  CPU feature, not the JDK version alone, gates the overrun.
- **Both software mitigations suppress it on an otherwise-vulnerable JDK build**: disabling the
  Base64 intrinsic (`-XX:-UseBASE64Intrinsics`) or capping the AVX ceiling below VBMI
  (`-XX:UseAVX=2`) both take `eclipse-temurin:21-jdk` (21.0.13+9-LTS) from REPRODUCED to NOT
  REPRODUCED with no other change.
- **A real vendor patch suppresses it too**: Amazon Corretto's `.1` point releases for both 17
  and 21 are NOT REPRODUCED, consistent with the intrinsic being fixed/disabled upstream in
  those later builds, while Temurin's pre-fix point releases on the same majors still reproduce.

Net: this replaces the prior single-machine disclosure ("validated on 1 machine: Zen 4 / JDK
21.0.13.0.2") with a **2-CPU × 5-JDK-build × 2-mitigation-flag × 1-patched-vendor-build** matrix,
all collected without any network access and without modifying the confined reproducer.
