---
title: "DirtyAH6 — IPv6 AH routing-header out-of-bounds write"
description: "Linux kernel IPv6 AH6 routing-header out-of-bounds write (CVE-2026-80844, DirtyAH6) — unprivileged local root, and a remote crash/DoS on IPv6 AH-transport gateways — distro patch status tracker"
layout: "single"
date: 2026-09-18
lastmod: 2026-09-27
cover:
  image: "dirtyah6-tracker.png"
  alt: "DirtyAH6 — Linux kernel IPv6 AH6 routing-header out-of-bounds write tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-80844 |
| Alias | `DirtyAH6` (the name its [PoC][poc] uses) |
| Component | Kernel: IPv6 Authentication Header (AH6 / XFRM) routing-header rearrangement — `ipv6_rearrange_rthdr()` (`net/ipv6/ah6.c`) |
| Type | Out-of-bounds read/write. `ipv6_rearrange_rthdr()` trusts a routing header's `segments_left` without checking it against the address count `hdrlen` describes, moving an address pointer far outside the buffer and handing a ~4 KiB length to `memmove()` |
| Impact | Kernel heap out-of-bounds access. Unprivileged **local privilege escalation to root** (per the PoC), and — on a host applying AH in transport mode as an IPv6 router/gateway — a remotely reachable **crash/DoS**, theoretically groomable to remote root |
| Upstream fix | [`7bad4bda74dc`][fix] (*xfrm: ah6: validate routing header segments_left*); first in **v7.3-rc1** |
| Introduced | [`1da177e4c3f4`][intro] (`Linux-2.6.12-rc2`) — the `Fixes:` tag points at the start of the git era, so the flaw predates **v2.6.12** (2005) and every maintained line is in-window |
| Affected window | **2.6.12 through 7.2** without the backport |
| Discoverer | Asim Manizada |
| Public disclosure | 2026-09-18 ([oss-security][ossec], with a [write-up][writeup]) |
| Public PoC | [manizada/DirtyAH6][poc] (demonstrates the local-root chain) |
| KEV / EPSS / CVSS | Not in KEV · EPSS **0.20%** (9th percentile) · CVSS **8.3** (Red Hat) — no CNA or NVD score published |
| Related | One of four local-root bugs disclosed together by the same researcher: [TUNderflow (CVE-2026-81000)][tunderflow], [PPPoEject (CVE-2026-68121)][pppoeject], and [DiagSpill (CVE-2026-74469)][diagspill]. DirtyAH6 is the IPv6-AH bug of the set |
{.summary}

## How the exploitation chain works

The IPv6 Authentication Header (AH) protects a packet's immutable fields
with an ICV. Because a type-0 routing header is *mutable in transit*, AH6
must first rewrite it into the form it will have at its final destination
before the ICV is computed or verified. That rewrite is
`ipv6_rearrange_rthdr()` in `net/ipv6/ah6.c`.

The function derives the number of addresses in the routing header from its
`hdrlen` field, then walks a pointer using `segments - segments_left`. For
packets that arrive through the normal input path, `hdrlen` and
`segments_left` were already validated, so the code *assumed*
`segments_left <= segments`. That assumption does not hold for a raw IPv6
`HDRINCL` packet, where the sender supplies the header bytes directly. A
routing header with `hdrlen = 2` describes a single address but can carry
`segments_left = 255`.

With those values the pointer moves **4,064 bytes backwards**, and a
**4,064-byte length** is handed to `memmove()` — an out-of-bounds access
that reads and writes memory adjacent to the packet's `skb` head,
including the `skb_shared_info` that follows the linear data area. The
[PoC][poc] grooms that corruption into a controlled overwrite: it sources
data from `/etc/pam.d/su`, uses the corrupted metadata to decrypt chosen
bytes into the PAM configuration page, and swaps `pam_rootok.so` for
`pam_permit.so` so that `su` yields a root shell.

The fix, [`7bad4bda74dc`][fix], validates the invariant locally —
`if (segments_left > segments) return -EINVAL;` — before any pointer
arithmetic, and propagates the error through the existing AH6 input and
output paths.

> :information_source: **Only a patched kernel flips a verdict; the other
> conditions are reachability, not the fix.** The local-root path needs the
> AH6/XFRM code reachable *and* a way to inject a raw crafted packet:
> either unprivileged user + network namespaces, or `CAP_NET_ADMIN` plus
> `CAP_NET_RAW` over an attacker-controlled netns. A host that disables
> unprivileged user namespaces removes the ordinary-user route but not an
> appropriately-capable container or process. Separately, a host that acts
> as an **IPv6 router/gateway and applies AH in transport mode** can be
> driven into the same bug by a remote packet — a crash/DoS, and only with
> difficult on-target grooming anything more. These gates decide *exposure*;
> they never substitute for the backport, and they live in the prose below,
> not in the table.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`1da177e4c3f4`][intro] | Introduced | `Linux-2.6.12-rc2` — the fix's `Fixes:` tag points here, the first commit in the git era, so the mishandled `segments_left` predates **v2.6.12** (2005). |
| [`7bad4bda74dc`][fix] | Fixed | *xfrm: ah6: validate routing header segments_left* — rejects `segments_left > segments` before rearranging the header; first released in **v7.3-rc1**. |

The reachable lifetime is therefore **2.6.12 through 7.2** without the
backport.

## Patch status

A row is **Fixed** only if its kernel carries the [`7bad4bda74dc`][fix]
backport; every AH6-capable kernel without it is in-window and
**Vulnerable**. The first group is the upstream kernel; the rest are a
focused set of x86-64 distributions, with per-distribution detail in the
sections that follow. *First fixed* and *Fixed since* stay `—` until a row
is fixed.

Because the flaw predates the git era, there are **no "not affected"
kernel rows** — no maintained line is old enough to escape it, so a kernel
is safe only by carrying the fix. Every maintained upstream stable line
picked up the backport in its **2026-09-02** point release; the mainline
row carries it from **v7.3-rc1**.

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.3-rc4 | 7.3-rc1 | 2026-08-30 | :white_check_mark: Fixed — carries `7bad4bda74dc` |
| Linux kernel | 7.2.x | 7.2.8 | 7.2.3 | 2026-09-02 | :white_check_mark: Fixed |
| Linux kernel | 7.1.x | 7.1.13 | 7.1.13 | 2026-09-02 | :white_check_mark: Fixed — EOL |
| Linux kernel | 6.18.x | 6.18.54 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.111 | 6.12.108 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.157 | 6.6.156 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.188 | 6.1.187 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.221 | 5.15.220 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.270 | 5.10.269 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Debian | sid (unstable) | 7.2.8-1 | 7.1.13-1 | 2026-09-03 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.2.6-1 | 7.1.13-1 | 2026-09-11 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.107-1 | — | — | :x: Vulnerable |
| Debian | 12 (bookworm, LTS) | 6.1.187-1 | 6.1.187-1 | 2026-09-08 | :white_check_mark: Fixed — DLA-4777-1 |
| Debian | 12 (6.12 opt-in) | 6.12.107-1~deb12u1 | — | — | :x: Vulnerable |
| Proxmox VE | 9 (default) | 7.0.14-19-pve | 7.0.14-16-pve | 2026-08-28 | :white_check_mark: Fixed |
| NixOS | master | 6.18.54 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.54 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.54 | 6.18.49 | 2026-09-04 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.54 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.54 | 6.18.49 | 2026-09-04 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.54 | 6.18.49 | 2026-09-03 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.54 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.60.1.el10_2 | 6.12.0-211.60.1.el10_2 | 2026-09-25 | :white_check_mark: Fixed — RHSA-2026:71233 |
| Rocky Linux / RHEL | 9 | 5.14.0-687.52.1.el9_8 | 5.14.0-687.51.1.el9_8 | 2026-09-25 | :white_check_mark: Fixed — RHSA-2026:71232 |
| Rocky Linux / RHEL | 8 | 4.18.0-553.168.1.el8_10 | 4.18.0-553.168.1.el8_10 | 2026-09-24 | :white_check_mark: Fixed — RHSA-2026:71213 |
| Amazon Linux | 2023 (default) | 6.1.186-228.376 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.103-129.197 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.48-109.150 | — | — | :x: Vulnerable — no ALAS yet |
{.distros}

### Linux kernel

The fix reached mainline in **v7.3-rc1** and has been backported to
every maintained stable line.

**7.1.x is end of life.** Its last release, 7.1.13, is also the first to
carry the fix, but the line gets no further updates — move to 7.2.x or a
long-term line.

The mishandled `segments_left` dates to the start of the git era, so no
branch predates the bug. `AH6` itself is the `INET6_AH` module
(`ah6.ko`), built by every mainline configuration that enables IPv6 AH;
the vulnerable rearrangement runs whenever a packet takes the AH6 input
or output path.

### Debian

forky is testing, the future Debian 14. bookworm's opt-in 6.12 kernel is
the `linux-6.12` package, trixie's kernel rebuilt for bookworm.

**On bookworm, the opt-in and the default kernel can differ.** While the
opt-in is vulnerable and the default 6.1 kernel is fixed, a host that
opted in should fall back to the default until a fixed `linux-6.12`
ships.

**bullseye (Debian 11) left LTS support on 2026-08-31**, before the fix
reached any 5.10 point release. No fix is coming — upgrade to bookworm
or newer.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels, so Debian's status does
not carry over; Proxmox VE is x86-only. PVE 9's default
`proxmox-kernel-7.0` has carried the fix since a direct cherry-pick,
now folded into its Ubuntu base.

- **PVE 8 reached end of life in August 2026**, before any fix reached
  its kernels. Its default `proxmox-kernel-6.8` and the
  `bookworm-backports` opt-in `proxmox-kernel-6.14` stay vulnerable,
  and no fix is coming — upgrade to PVE 9.
- **Abandoned preview series** that PVE 9 still publishes,
  `proxmox-kernel-6.17` and `proxmox-kernel-6.14`, will never get the
  fix. A host booting one should switch to the default kernel.

### NixOS

Every NixOS channel and branch in the table defaults to
`linux_6_18` (`linuxPackages`), which carries the fix.
nixpkgs also pins `linux_6_1`, `linux_5_15` and
`linux_5_10` at fixed releases, so a host overriding the default to an
older long-term series is fixed too, as long as it tracks a
current-enough ref.

Kernel updates land on nixpkgs `master` first and reach each channel
once its Hydra jobset passes, so a channel can sit a few days behind
`master`. The `-small` channels (`nixos-unstable-small`,
`nixos-26.05-small`) run a reduced jobset and pick up kernel updates
fastest.

Which ref a flake input follows:

- `github:NixOS/nixpkgs/nixos-unstable` and
  `github:NixOS/nixpkgs/nixos-26.05` follow those channels — the GitHub
  channel branches are updated to exactly the published channel pins.
- A bare `github:NixOS/nixpkgs` with no ref follows `master`, and
  `github:NixOS/nixpkgs/release-26.05` follows that branch. Both are
  ungated development branches — they carry a kernel bump as soon as it
  lands, often a day or more before a channel publishes it.
- A bare `nixpkgs` registry input resolves by default to
  the `nixpkgs-unstable` channel: a separate channel aimed at
  Nix on other operating systems, not gated on the NixOS tests.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks that carry IPv6 AH, so all
three EL lines — EL10 (6.12-based), EL9 (5.14-based) and EL8
(4.18-based) — are in-window. Rocky 8 and 10 skipped the exact RHSA
build and shipped the next one.

- **RHEL 7 ELS:** fixed by RHSA-2026:71687 (`kernel-rt`
  RHSA-2026:71657). Rocky ships no EL7.
- **RHEL 8 `kernel-rt`** (NFV): fixed by RHSA-2026:71016.
- **RHEL 9 and 10 `kernel-rt`:** fixed by the same advisories as the
  regular kernel.

The usual route for an ordinary user to reach this bug is an
unprivileged user namespace. RHEL 8 disables those by default
(`user.max_user_namespaces = 0`); RHEL 9 and 10 enable them. The RHEL 8
default does not protect a suitably privileged container or a process
granted `CAP_NET_ADMIN` + `CAP_NET_RAW`, so treat it as an exposure
reducer, not a fix.

AlmaLinux, CloudLinux and Oracle Linux's Red Hat Compatible Kernel
rebuild RHEL's kernel, so they get the fix as they rebuild Red Hat's
advisories.

### Amazon Linux

The three AL2023 streams are the default `kernel` package (6.1 line) and
the opt-in `kernel6.12` and `kernel6.18` packages. Amazon routinely
backports a fix into a build numbered *below* the upstream first fix, so
judge an AL2023 kernel by its ALAS, not its version number.

## Detection

**Is the running kernel in the affected window and missing the fix?**
Every AH6-capable kernel is in-window; compare the running kernel against
the *Patch status* table's *First fixed* column for its series:

```bash
uname -r
```

**Is the `ah6` module available or loaded?**  The bug lives in the IPv6 AH
transform. `ah6` autoloads when an AH6 SA or an AH-bearing packet needs it:

```bash
lsmod | grep -E '^(ah6|xfrm)'
```

**Can this host reach the local-root path?**  The ordinary-user route needs
unprivileged user namespaces; without them an attacker needs
`CAP_NET_ADMIN` + `CAP_NET_RAW` over a network namespace instead. Check the
namespace policy:

```bash
sysctl kernel.unprivileged_userns_clone user.max_user_namespaces 2>/dev/null
```

**Is AH6 autoload blocked?**  Where AH6 is genuinely unused, a
`blacklist`/`install … /bin/false` entry stops the transform from
autoloading — though a capable caller can still request it:

```bash
modprobe -n -v ah6 2>&1; grep -rE '(^|[[:space:]])(install|blacklist)[[:space:]]+ah6' /etc/modprobe.d /usr/lib/modprobe.d 2>/dev/null
```

## Public PoC

The upstream PoC is in [manizada/DirtyAH6][poc]; it demonstrates the
unprivileged-local-user to root chain on specific targets (Fedora 43 and
Ubuntu 24.04 kernels) and is **destructive** — it overwrites `/etc/pam.d/su`
with no rollback. Do **not** run it on a system you are not authorised to
test; use a disposable VM.

## Mitigation

The real fix is a patched kernel (the [`7bad4bda74dc`][fix] backport).
Until one is installed, the exposure is narrowed by keeping the AH6
transform unreachable and closing the ordinary-user injection path — none
of these is a fix.

### Disable unprivileged user namespaces

This removes the standard ordinary-user route to the bug (it does not stop
an appropriately-capable container or process). For the current boot:

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=0
```

Persist it across reboots:

```bash
echo 'kernel.unprivileged_userns_clone = 0' | sudo tee /etc/sysctl.d/99-dirtyah6.conf
```

On kernels without that Debian/Ubuntu knob, cap the namespace count with
`user.max_user_namespaces = 0` instead.

### Block the `ah6` module (if AH6 is unused)

Most hosts never terminate IPv6 AH. Where it is genuinely unused, block the
transform so the vulnerable code cannot autoload; `install ah6 /bin/false`
is surer than a plain `blacklist ah6`:

```bash
echo 'install ah6 /bin/false' | sudo tee /etc/modprobe.d/dirtyah6.conf
```

Only do this where IPsec AH for IPv6 is genuinely unused.

### On an IPv6 router/gateway

A host that applies AH in transport mode while forwarding IPv6 is remotely
reachable for a crash/DoS. Until it is patched, restrict which peers can
send AH-protected traffic to it, and prefer ESP or a patched kernel before
exposing AH-transport processing to untrusted networks.

## Risk notes

- **Multi-tenant and container hosts are the primary exposure:** an
  unprivileged local user (via user namespaces) or a container/process with
  `CAP_NET_ADMIN` + `CAP_NET_RAW` can reach the bug and, per the PoC,
  escalate to root — even with no remote peer. Disabling unprivileged user
  namespaces closes the ordinary-user route but not the capable-caller one.
- **IPv6 AH-transport gateways add a remote surface:** a host adding AH in
  transport mode as an IPv6 router can be driven into the same
  out-of-bounds by a remote packet — a crash/DoS, and only with difficult
  on-target grooming anything worse.
- **No "too old to be affected":** the flaw predates the git era, so old
  LTS kernels are *not* safe by age. Every maintained upstream line now
  carries the fix, but distro kernels adopt it independently — check the
  *First fixed* column for the distro in question, not the kernel's age.
- **Backports available (CVE-2026-80844):** the fix has landed in mainline
  7.3-rc1 and stable 7.2.3, 7.1.13, 6.18.49, 6.12.108, 6.6.156, 6.1.187,
  5.15.220, and 5.10.269; distro kernels that have not adopted one of those
  remain vulnerable.

## Verification log

Every verdict in the table above is backed by a checkable source. This log
records the provenance — the git reference, advisory, or repository index
that established each fact — so any row can be audited or reproduced. Most
readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `7bad4bda74dc` (*xfrm: ah6: validate routing header
  segments_left*), first released in **v7.3-rc1** (tag date 2026-08-30, via
  `~/src/linux/stable` and the netdev `net` maintainer tree). It adds
  `if (segments_left > segments) return -EINVAL;` to
  `ipv6_rearrange_rthdr()` and propagates the error through the AH6 paths.
- The bug predates the git era: the fix's `Fixes:` tag is
  `1da177e4c3f4 ("Linux-2.6.12-rc2")`, the first commit in the history, so
  every maintained line is in-window and there are no not-affected rows.
- **CVE-2026-80844** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`, `cve/published/2026/CVE-2026-80844.{json,dyad}`; no
  `.cvss` file is published, so there is no CNA score). The `.dyad`'s
  vulnerable:fixed pairs key the fix to `2.6.12 → 5.10.269 / 5.15.220 /
  6.1.187 / 6.6.156 / 6.12.108 / 6.18.49 / 7.1.13 / 7.2.3 / 7.3-rc1`.
- **Stable backports** (fix cherry-picks confirmed by subject grep against
  `~/src/linux/stable`, each a new SHA; *Current kernel* from kernel.org's
  `finger_banner`):
  - All eight backports were tagged **2026-09-02**.
  - 7.2.3: `46640c814f25`.
  - 7.1.13: `0bf11081ad37`.
  - 6.18.49: `6733ae71268a`.
  - 6.12.108: `1516e31ac458`.
  - 6.6.156: `f00df8500e5a`.
  - 6.1.187: `1b7e066eabcc`.
  - 5.15.220: `48b0e36cf543`.
  - 5.10.269: `2dc650956e4e`.
- **7.1.x reached end of life** at `7.1.13`, per `finger_banner` (marked
  `(EOL)`), the same release that first carried the fix — so the row's
  *Current kernel* is final and its verdict settled.
- **Scoring** (kernel CNA record, NVD, Red Hat's security data API,
  api.first.org, KEV):
  - The kernel CNA record has no `.cvss` file.
  - NVD (record published 2026-09-04) carries no metrics.
  - Red Hat publishes a **verified** CVSS3 score of **8.3**
    (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`) alongside its `kernel`
    entries.
  - EPSS **0.20%** (9th percentile, 2026-09-23).
  - Not in KEV.

#### Distributions

- **Debian** (security tracker `data/json`, CVE-2026-80844):
  - sid resolved *fixed*; the tracker's first fixed version is `7.1.13-1`
    (7.1 branch's first-fixed release), accepted into unstable 2026-09-03;
    sid has since moved to `7.2.6-1`.
  - forky resolved *fixed*; `7.1.13-1` migrated to testing 2026-09-11 (per
    tracker.debian.org news), the first fixed kernel in the suite.
  - trixie *open*: `trixie` and `trixie-security` both at `6.12.107-1`,
    below the 6.12 branch's `6.12.108` first fix — vulnerable, no fixed
    build shipped.
  - bookworm resolved *fixed*; first fixed `6.1.187-1` via
    `bookworm-security`, shipped as **DLA-4777-1** (debian-lts-announce
    msg dated 2026-09-08). The `linux-6.12` opt-in source package is at
    `6.12.107-1~deb12u1` (ftp-master madison), below the 6.12 first fix, so
    the opt-in row is vulnerable by version compare (the tracker does not
    assess the opt-in package by name).
  - bullseye: no release entry for this CVE in the tracker JSON; standard
    LTS ended 2026-08-31 (wiki.debian.org/LTS schedule), before any 5.10
    fix shipped — retired, no row.
- **Proxmox VE** (`~/src/proxmox/pve-kernel`, `pve-no-subscription`
  `Packages.gz`):
  - `proxmox-default-kernel` depends on `proxmox-kernel-7.0` on trixie
    (PVE 9); *Current kernel* for the default row is read from
    `Packages.gz` each run.
  - The AH6 fix ships as a vendored patch file rather than a named
    cherry-pick commit, so it does not surface in a commit-subject
    grep — confirmed instead by walking `patches/kernel/` per version.
  - `proxmox-kernel-7.0` carries
    `patches/kernel/*-xfrm-ah6-validate-routing-header-segments_left.patch`
    (cherry-picked from stable's `0bf11081ad37`, the 7.1.13 backport
    SHA) starting at **7.0.14-16** (changelog-dated 2026-08-28).
  - The following rebase (7.0.14-18, "update submodules and patches to
    current Ubuntu resolute") drops the standalone patch file because
    the fix is part of the upstream base it rebases onto.
  - PVE 8 reached end of life in 2026-08 (Proxmox VE FAQ lifecycle
    table, pve.proxmox.com/wiki/FAQ), before this tracker existed.
  - Neither `bookworm-6.8` nor `bookworm-6.14` carried the patch at
    its final build.
  - Ubuntu's CVE tracker marks the 6.8 base (*noble*) *needed* and the
    HWE 6.14 base *end of life*.
  - Abandoned preview series carrying no fix: PVE 9's
    `proxmox-kernel-6.17` (`trixie-6.17`, last `6.17.13-21`,
    2026-07-28) and `proxmox-kernel-6.14` (`trixie-6.14`).
- **NixOS** (via `~/src/nixos/nixpkgs`; branch tips for `master` /
  `release-26.05`, channel `git-revision` pins for the other five refs):
  - `linux_default = packages.linux_6_18` at every tracked ref.
  - Every tracked ref resolves the `6.18` series from `kernels-org.json`
    above the `6.18.49` first-fixed release.
  - Each row's *Current kernel* is that pinned `6.18` version.
  - *Fixed since* for the branch rows is the commit date of the 6.18.49
    bump: `ab787beb39ad` on master and `1dcdedad8777` on release-26.05,
    both 2026-09-02.
  - *Fixed since* for the channel rows comes from
    `scripts/nixos-first-shipped`: nixos-unstable 2026-09-04,
    nixos-unstable-small 2026-09-02, nixpkgs-unstable 2026-09-04,
    nixos-26.05 2026-09-03, nixos-26.05-small 2026-09-02.
- **Rocky Linux / RHEL family**: Red Hat's security data API
  (`access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-80844.json`)
  `affected_release` carries fixes for the mainline `kernel` package on all
  three in-support lines:
  - **RHSA-2026:71233** (EL10, `kernel-0:6.12.0-211.59.1.el10_2`,
    2026-09-24).
  - **RHSA-2026:71232** (EL9, `kernel-0:5.14.0-687.51.1.el9_8`,
    2026-09-24).
  - **RHSA-2026:71213** (EL8, `kernel-0:4.18.0-553.167.1.el8_10`,
    2026-09-24).
  - CVSS3 **8.3** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:H`, status
    `verified`), threat_severity Important, public_date 2026-09-04.
  - *Current kernel* for each row is read from Rocky BaseOS repodata
    (`primary.xml.gz`, highest `rel` per release, ordered with
    `rpmsort`).
  - EL10's BaseOS build skipped the RHSA's own NVR (`211.59.1`) and
    shipped the fix in the next build, `kernel-6.12.0-211.60.1.el10_2`,
    on 2026-09-25 per the Rocky mirror directory listing — the
    changelog entry naming the CVE is attributed to `211.59.1`,
    confirming the skipped build carried it too.
  - EL9's BaseOS build reached the RHSA's exact NVR,
    `kernel-5.14.0-687.51.1.el9_8`, shipped 2026-09-25 per the Rocky
    mirror directory listing — confirmed carrying the fix by an
    `other.xml.gz` changelog entry naming the CVE.
  - EL8's BaseOS build skipped the RHSA's own NVR (`553.167.1`) and
    shipped the fix in the next build, `kernel-4.18.0-553.168.1.el8_10`,
    on 2026-09-24 per the Rocky mirror directory listing — the
    changelog entry naming the CVE is attributed to `553.167.1`,
    confirming the skipped build carried it too.
  - The API's `affected_release` also carries **RHSA-2026:71016**
    (2026-09-23), for `kernel-rt` on RHEL 8 NFV only — a niche variant this
    tracker gives no row.
  - Red Hat's CSAF/VEX record
    (`security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-80844.json`)
    lists RHSA-2026:71687 (RHEL 7 ELS `kernel`) and RHSA-2026:71657
    (its `kernel-rt`) among its `vendor_fix` remediations.
  - The same record lists RHEL 9 and 10 `kernel-rt` as `known_affected`,
    but RHSA-2026:71232 and RHSA-2026:71233 also cover the RHEL 9.8 and
    10.2 RT and NFV products.
- **Amazon Linux**: `scripts/alas-cve CVE-2026-80844` against the AL2023
  `updateinfo.xml.gz` returns no advisory (exit 1) for any kernel stream.
  Current builds queried from `primary.xml.gz`, highest `rel` per stream
  (`kernel`, `kernel6.12`, `kernel6.18`) — all vulnerable pending an ALAS.
{{< /details >}}

## References

| Source | URL |
|---|---|
| oss-security disclosure (quartet) | <https://www.openwall.com/lists/oss-security/2026/09/18/3> |
| Researcher write-up | <https://heyitsas.im/posts/lpe-quartet/> |
| Public PoC | <https://github.com/manizada/DirtyAH6> |
| Kernel fix (v7.3-rc1) | <https://github.com/torvalds/linux/commit/7bad4bda74dc4713f398d3b7624ff05478e3a568> |
| CVE-2026-80844 | <https://www.cve.org/CVERecord?id=CVE-2026-80844> |
| Companion tracker — TUNderflow (CVE-2026-81000) | <https://kimmo.cloud/tunderflow/> |
| Companion tracker — PPPoEject (CVE-2026-68121) | <https://kimmo.cloud/pppoeject/> |
| Companion tracker — DiagSpill (CVE-2026-74469) | <https://kimmo.cloud/diagspill/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-80844> |
| Red Hat security data | <https://access.redhat.com/security/cve/CVE-2026-80844> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
{.references}

[poc]: https://github.com/manizada/DirtyAH6
[ossec]: https://www.openwall.com/lists/oss-security/2026/09/18/3
[writeup]: https://heyitsas.im/posts/lpe-quartet/
[fix]: https://github.com/torvalds/linux/commit/7bad4bda74dc4713f398d3b7624ff05478e3a568
[intro]: https://github.com/torvalds/linux/commit/1da177e4c3f41524e886b7f1b8a0c1fc7321cac2
[tunderflow]: https://kimmo.cloud/tunderflow/
[pppoeject]: https://kimmo.cloud/pppoeject/
[diagspill]: https://kimmo.cloud/diagspill/
