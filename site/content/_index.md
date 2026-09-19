---
title: "DirtyAH6 — IPv6 AH routing-header out-of-bounds write"
description: "Linux kernel IPv6 AH6 routing-header out-of-bounds write (CVE-2026-80844, DirtyAH6) — unprivileged local root, and a remote crash/DoS on IPv6 AH-transport gateways — distro patch status tracker"
layout: "single"
date: 2026-09-18
lastmod: 2026-09-19
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
| KEV / EPSS / CVSS | Not in KEV · EPSS **0.20%** (9th percentile) · CVSS **pending** (no CNA or NVD score published) |
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
| Linux kernel | mainline | 7.3-rc3 | 7.3-rc1 | 2026-08-30 | :white_check_mark: Fixed — carries `7bad4bda74dc` |
| Linux kernel | 7.2.x | 7.2.6 | 7.2.3 | 2026-09-02 | :white_check_mark: Fixed |
| Linux kernel | 7.1.x | 7.1.13 | 7.1.13 | 2026-09-02 | :white_check_mark: Fixed — EOL |
| Linux kernel | 6.18.x | 6.18.52 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.110 | 6.12.108 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.157 | 6.6.156 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.188 | 6.1.187 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.15.x | 5.15.221 | 5.15.220 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Linux kernel | 5.10.x | 5.10.270 | 5.10.269 | 2026-09-02 | :white_check_mark: Fixed — LTS |
| Debian | sid (unstable) | 7.2.6-1 | 7.1.13-1 | 2026-09-03 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.13-1 | 7.1.13-1 | 2026-09-11 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.107-1 | — | — | :x: Vulnerable |
| Debian | 12 (bookworm, LTS) | 6.1.187-1 | 6.1.187-1 | 2026-09-08 | :white_check_mark: Fixed — DLA-4777-1 |
| Debian | 12 (6.12 opt-in) | 6.12.107-1~deb12u1 | — | — | :x: Vulnerable |
| Proxmox VE | 9 (default) | 7.0.14-17-pve | — | — | :x: Vulnerable |
| Proxmox VE | 8 (default) | 6.8.12-43-pve | — | — | :x: Vulnerable |
| Proxmox VE | 8 (6.14 opt-in) | 6.14.11-9~bpo12+1 | — | — | :x: Vulnerable |
| NixOS | master | 6.18.52 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| NixOS | release-26.05 | 6.18.52 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.52 | 6.18.49 | 2026-09-04 | :white_check_mark: Fixed |
| NixOS | Unstable (small) | 6.18.52 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| NixOS | Unstable (nixpkgs) | 6.18.52 | 6.18.49 | 2026-09-04 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.52 | 6.18.49 | 2026-09-03 | :white_check_mark: Fixed |
| NixOS | 26.05 (small) | 6.18.52 | 6.18.49 | 2026-09-02 | :white_check_mark: Fixed |
| Rocky Linux / RHEL | 10 | 6.12.0-211.55.1.el10_2 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 9 | 5.14.0-687.48.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux / RHEL | 8 | 4.18.0-553.163.1.el8_10 | — | — | :x: Vulnerable — no RHSA yet |
| Amazon Linux | 2023 (default) | 6.1.186-228.376 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.103-129.197 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.48-109.150 | — | — | :x: Vulnerable — no ALAS yet |
{.distros}

### Linux kernel

The fix reached Linus in **v7.3-rc1** (tagged 2026-08-30) and the kernel
CNA backported it across every maintained stable line in the **2026-09-02**
point releases: **7.2.3**, **7.1.13**, **6.18.49**, **6.12.108**,
**6.6.156**, **6.1.187**, **5.15.220**, and **5.10.269** — each the same
fix by subject, confirmed present on its `linux-*.y` branch, with
`finger_banner` current point releases at or above them.

The `7.1.x` line is marked **EOL** by `kernel.org`'s `finger_banner`: it
reached end of life at **7.1.13**, the same release that first carried the
fix, so its verdict is settled and its *Current kernel* simply stops
moving. Every other maintained line remains in support and carries the fix.

There is no not-affected upstream row: the mishandled `segments_left` dates
to the start of the git era, so no branch predates it. `AH6` itself is the
`INET6_AH` module (`ah6.ko`), built by every mainline configuration that
enables IPv6 AH; the vulnerable rearrangement runs whenever a packet takes
the AH6 input or output path.

### Debian

Debian's status splits on which upstream branch each suite tracks.
**sid** follows the 7.x line and is **fixed**: the fix first arrived with
the `7.1.13-1` upload (2026-09-03), and sid has since moved on to
`7.2.6-1`. **forky** (testing, the future Debian 14) became **fixed** when
`7.1.13-1` migrated to testing on 2026-09-11.

**trixie** (Debian 13, current stable) is **vulnerable**: its kernel is
`6.12.107-1`, one point release below the 6.12 branch's `6.12.108`
first-fixed version, and the security tracker still lists the CVE as *open*
for trixie — neither `trixie` nor `trixie-security` has shipped a fixed
build yet.

**bookworm** (Debian 12, now under LTS) is **fixed** via a
`bookworm-security` upload of `6.1.187-1`, shipped as **DLA-4777-1**
(2026-09-08) — exactly the 6.1 branch's first-fixed release. Note the
inversion below it: bookworm also offers the **`linux-6.12` opt-in**
kernel for newer hardware, and that package is still at
`6.12.107-1~deb12u1` — below the 6.12 first fix — so a bookworm host that
opted into the newer kernel is **vulnerable** while the default 6.1 kernel
is fixed. Upgrade the opt-in or fall back to the default.

**bullseye** (Debian 11) reached the end of its standard LTS window on
**2026-08-31**, before this tracker existed and before the fix shipped to
any 5.10 point release (the 5.10 branch was first fixed at `5.10.269` on
2026-09-02). It gets no row: the Debian security tracker carries no
bullseye entry for this CVE, and no fix is coming through standard LTS. A
host still on bullseye should upgrade.

### Proxmox VE

Proxmox ships its own Ubuntu-derived kernels, so Debian's status does not
carry over, and Proxmox VE is **x86-only**. Neither maintained default
series carries the fix yet. **PVE 9's `proxmox-kernel-7.0`** (at
`7.0.14-17-pve` in `pve-no-subscription`) tracks Ubuntu *resolute*, whose
`linux` update for this CVE is still *pending*, and no cherry-pick names
the AH6 fix in the changelog. **PVE 8's `proxmox-kernel-6.8`** (at
`6.8.12-43-pve`) tracks Ubuntu *noble*, marked *needed*; it too lacks the
fix. Both default rows are **vulnerable** until Proxmox rebases onto a
fixed Ubuntu source or cherry-picks the AH6 patch.

PVE 8 additionally offers **`proxmox-kernel-6.14`** as a
`bookworm-backports` opt-in (`6.14.11-9~bpo12+1`, last built 2026-05-15).
Its Ubuntu HWE 6.14 base on noble is marked *end of life* in Ubuntu's CVE
tracker, so no Ubuntu-side rebase will bring the fix and only a direct
Proxmox cherry-pick — none so far — would close the row. It is
**vulnerable**.

Both releases also still publish pre-GA preview kernel series that Proxmox
abandoned before this disclosure and that will not receive the fix — PVE
9's `proxmox-kernel-6.17` (last built 2026-07-28) and `proxmox-kernel-6.14`
(2026-05-15), and PVE 8's `proxmox-kernel-6.2`, `6.5`, and `6.11`. A host
still booting one of these preview kernels stays vulnerable until it
switches to its release's current default, which will carry the fix once
Proxmox ships it.

### NixOS

Every tracked ref's default `linuxPackages` is `linux_6_18`, and nixpkgs
currently pins the 6.18 series at `6.18.52` — above the 6.18 branch's
`6.18.49` first-fixed release — so **every tracked ref is fixed**; they
differ only in which point release each has reached and when it published.
Kernel bumps land on nixpkgs `master` first, and each channel republishes
them once its Hydra jobset passes, so a channel can sit a few days behind
`master`, and an unstable channel is not necessarily ahead of a release
channel. The `-small` channels are gated on a reduced jobset and pick up
kernel updates fastest.

The `master` and `release-26.05` rows are the git branches the bump lands
on directly (not Hydra-gated), so they carry the fixed kernel from the
moment the commit lands — the 2026-09-02 dates down the group. nixpkgs
also pins `linux_6_1` / `linux_5_15` / `linux_5_10` at or above their
branches' first-fixed releases, so a host overriding the default to an
older LTS is fixed too, as long as it tracks a current-enough ref.

### Rocky Linux / RHEL family

RHEL-family kernels are long-lived forks that carry IPv6 AH, so all three
in-support lines — EL10 (6.12-based), EL9 (5.14-based), EL8 (4.18-based) —
are in-window regardless of their base version. As of this writing Red Hat
has published **no advisory and no CVE assessment** reachable through the
security data API for CVE-2026-80844, so there is no fixed NVR to confirm
and every stream is **vulnerable pending an advisory**. Rocky rebuilds
RHEL's kernels unchanged, so its fixes track Red Hat's; AlmaLinux is
typically the fastest rebuild and the leading indicator, and neither has an
erratum for this CVE yet.

The standard ordinary-user path to this bug goes through unprivileged user
namespaces. RHEL 8 ships with unprivileged user namespaces disabled by
default (`user.max_user_namespaces = 0`), which removes that route on a
stock host — though it does not protect an appropriately-capable container
or a process granted `CAP_NET_ADMIN` + `CAP_NET_RAW`, and RHEL 9 and 10
enable unprivileged user namespaces by default. Treat the module posture
and namespace settings as exposure reducers, not a fix.

### Amazon Linux

All three AL2023 kernel streams are **vulnerable**: the repodata
`updateinfo.xml` carries no advisory naming CVE-2026-80844 for any of
`kernel` (6.1 line), `kernel6.12`, or `kernel6.18`. The `kernel6.18`
stream is one point release below the 6.18 branch's `6.18.49` first fix,
and no version threshold could confirm the other two even once a fix ships
— Amazon routinely backports into a build below the upstream first-fixed
release — so only an ALAS naming this CVE will flip these rows. None has
appeared yet.

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
  `~/src/linux/stable`, each a new SHA): 5.10.269 (`2dc650956e4e`),
  5.15.220 (`48b0e36cf543`), 6.1.187 (`1b7e066eabcc`), 6.6.156
  (`f00df8500e5a`), 6.12.108 (`1516e31ac458`), 6.18.49 (`6733ae71268a`),
  7.1.13 (`0bf11081ad37`), 7.2.3 (`46640c814f25`) — all tagged
  **2026-09-02**. The `Linux kernel` rows' *Current kernel* cells are read
  from kernel.org's `finger_banner`.
- **7.1.x reached end of life** at `7.1.13`, per `finger_banner` (marked
  `(EOL)`), the same release that first carried the fix — so the row's
  *Current kernel* is final and its verdict settled.
- **Scoring:** no CVSS is published — the kernel CNA record has no `.cvss`
  file and NVD (record published 2026-09-04) carries no metrics. EPSS
  **0.20%** (9th percentile, via api.first.org, 2026-09-16); not in KEV.

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
  `Packages.gz`): no changelog entry or `patches/kernel/*` names the AH6
  fix (`segments_left` / CVE-2026-80844) on any branch. `proxmox-default-kernel`
  depends on `proxmox-kernel-7.0` on trixie (PVE 9, current build
  `7.0.14-17-pve`) and `proxmox-kernel-6.8` on bookworm (PVE 8,
  `6.8.12-43-pve`). Ubuntu's CVE tracker
  (`ubuntu.com/security/cves/CVE-2026-80844.json`) marks `linux` *resolute*
  (7.0 base) *pending* and *noble* (6.8 base) *needed*, so neither PVE
  default has the fix via rebase either. PVE 8's `proxmox-kernel-6.14`
  opt-in (`6.14.11-9~bpo12+1`, `bookworm-6.14`) has no cherry-pick and its
  Ubuntu HWE 6.14 base on noble is *end of life* per Ubuntu's tracker.
  Abandoned preview series carrying no fix: PVE 9's `proxmox-kernel-6.17`
  (`trixie-6.17`, last `6.17.13-21`, 2026-07-28) and `proxmox-kernel-6.14`
  (`trixie-6.14`); PVE 8's `proxmox-kernel-6.2` / `6.5` / `6.11`.
- **NixOS** (`~/src/nixos/nixpkgs`): `linux_default = packages.linux_6_18`;
  every tracked ref resolves `6.18` at `6.18.52` from `kernels-org.json`,
  above the `6.18.49` first-fixed release, so all seven rows are fixed.
  Each row's *Current kernel* is that pinned `6.18` version. *Fixed since*:
  the branch rows use the commit date of the 6.18.49 bump (`ab787beb39ad`
  on master, `1dcdedad8777` on release-26.05, both 2026-09-02); the channel
  rows use `scripts/nixos-first-shipped` (nixos-unstable 2026-09-04,
  nixos-unstable-small 2026-09-02, nixpkgs-unstable 2026-09-04, nixos-26.05
  2026-09-03, nixos-26.05-small 2026-09-02).
- **Rocky Linux / RHEL family**: no Red Hat record reachable via the
  security data API (`access.redhat.com/hydra/rest/securitydata/cve/CVE-2026-80844.json`
  → 404) and no AlmaLinux/OSV erratum, so no fixed NVR exists yet; all
  three in-support lines carry IPv6 AH and are in-window. Rocky BaseOS
  repodata (`primary.xml.gz`, highest `rel`) current builds:
  EL10 `6.12.0-211.55.1.el10_2`, EL9 `5.14.0-687.48.1.el9_8`, EL8
  `4.18.0-553.163.1.el8_10`.
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
