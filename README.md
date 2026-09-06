# Quest 3 root exploit — CVE-2026-43499 ("GhostLock")

Userspace-only Android LPE for the **Meta Quest 3** (codename `eureka`,
kernel `5.10.240-g69827d40d782`), plus a wider target matrix of Pixel /
Tensor and Meta builds. The payload is shipped as an `LD_PRELOAD` library
that gains root in-process and installs a root daemon.

## Vulnerability

**CVE-2026-43499 — Futex PI (Priority Inheritance) use-after-free.**

The syscall layer copies user-controlled data onto the calling thread's
kernel stack. Combined with the futex-PI waiter machinery, a stale
`struct rt_mutex_waiter` frame on that stack is overwritten with forged
state. When the PI chain walker (`rt_mutex_adjust_prio_chain`) later
`rb_erase`s the forged node, the red-black tree rotation writes
`child->__rb_parent_color` to an attacker-chosen address. That write is
used to redirect the **ashmem fops table** (`ashmem_misc_fops`) to a
forged table, hijacking file operations into an arbitrary kernel write.

No kernel driver, no privileged service and no persistent boot payload is
required — everything runs as `uid 2000` (`shell`).

## Pipeline

1. **KASLR leak** — `perf_event_open` ring sampling of kernel IPs
   (`perf_event_paranoid=-1` on these builds), lowest-IP vote → kernel
   image base. Reliable single-shot.
2. **Heap leak** — KernelSnitch futex-hash collision correlates an
   `mm_struct` slab page (`stride=400`, `order=2`) and the freed slab
   object that the skb `sendmsg` groom later reclaims.
3. **Forge + reclaim** — `io_uring_setup(4)` (MAP_POPULATE) + an
   `IORING_OP_MADVISE` submission whose address range covers the reclaimed
   ring page, planting the forged `rt_mutex_waiter` / rb-node page.
4. **Punch** — a raised-priority consumer walks the forged waiter:
   `rb_erase` writes `fake_fops` into the `ashmem_misc_fops` slot.
5. **Root** — hijacked fops dispatch into the forged table, `cred` is
   overwritten (uid/caps/SELinux sid), and a `su` daemon is spawned.

## Supported builds

| Target               | Device            | Kernel / build              | Status   |
|----------------------|-------------------|-----------------------------|----------|
| `eureka-52168470052900520` | Meta Quest 3 | `5.10.240-g69827d40d782` | **primary** |
| `blazer-CP2A.260605.012`      | Google Tensor (Pixel) | `CP2A.260605.012`     | working  |
| `blazer-CP2A.260605.012.C1`   | Google Tensor (Pixel) | `CP2A.260605.012.C1`  | working  |
| `caiman/comet/frankel/komodo/mustang/oriole/rango/tokay` `-CP2A.260605.012(.C1)` | Pixel family | `CP2A.260605.012(.C1)` | configured |
| `blazer/frankel/mustang/rango` `-CP1A.*` | Pixel family | `CP1A.260305..260505` | configured |

Offsets are pre-extracted per build from the OTA `kernel.elf` (see
`src/targets/<target>/target.h`); new builds are added with
`gen_target_config.py` and measured against
`kernel.elf-offset-finder.py`.

## Build

Requires an Android NDK toolchain (auto-detected via `NDK_CC` or
`android-ndk-cache`, else `TARGET_CC`).

```sh
make PROJECT=eureka-52168470052900520
# -> build/eureka-52168470052900520/bin/preload.so
```

Use `make PROJECT=blazer-CP2A.260605.012` for the Pixel build.

## Run

```sh
adb push build/eureka-52168470052900520/bin/preload.so /data/local/tmp/preload.so
adb shell chmod 755 /data/local/tmp/preload.so
adb shell "LD_PRELOAD=/data/local/tmp/preload.so MAIN_IOURING_ROUTE=1 \
  /system/bin/sh -c 'sleep 120'"
```

The io_uring installer route is the primary delivery path on `eureka`.
Run on a freshly booted, **awake** device — the exploit is single-shot and
each attempt permanently consumes one boot (reboots re-randomize KASLR and
heap layout).

## Environment knobs

| Variable            | Meaning                                                    |
|---------------------|------------------------------------------------------------|
| `MAIN_IOURING_ROUTE=1` | Use the io_uring/MADVISE installer route (primary).      |
| `MAIN_TCP_ROUTE`    | TCP-route fallback; set `=0` to disable.                   |
| `LANE`              | Stamp vehicle: `1` = MCAST socket, `2` = pselect (default).|
| `WORDS_SHIFT`       | Manual waiter-word placement shift (debug).                |
| `PSELECT_TMO`       | pselect timeout for the stamp.                             |
| `NFDS_CAP`          | Cap on `nfds` used by fd-set stamps.                       |
| `MODE`              | Select alternate payload modes.                            |
| `PUNCH_*`           | Punch tuning: `PUNCH_TARGET`, `PUNCH_MASK`, `PUNCH_NICE`, `PUNCH_POLICY`, `PUNCH_SINGLE`, `PUNCH_OWNER`, `PUNCH_ONLY`, `PUNCH_NONE`, `PUNCH_TID`. |
| `ROUTE_SKIP`        | Skip parts of the route (debug).                           |
| `WAITER_CLEAN_EXIT` | Cleanly acquire/release the PI futex before exiting.       |

## Source layout

```
src/
  main.c          entry, futex-PI setup, route dispatch
  fops.c          forged rt_waiter layout, lane stamps, io_uring route
  slide.c         perf-ring KASLR leak
  q3slide.c       Quest 3 slide variant
  kernelsnitch/   futex-hash heap address leak + slab groom
  util.c          payload shaping (fake_lock/fake_w0/fake_task)
  root.c          cred patch, SELinux, su daemon
  preload.c       LD_PRELOAD entry
  targets/        per-build offset tables
```

## References

- GhostLock writeup (NebuSec IonStack part II): https://nebusec.ai/research/ionstack-part-2
- Working-reference profile for this device:
  `ghostlock/tools/reference/pancake_quest3_eureka.txt`
- Kernel ground truth: OTA-extracted `kernel.elf` for
  `52168470052900520` (sha `53b0a65f…ecbc`).
-note this was INSPIRED by the pancake exploit although absolutely NO code was stolen/skidded of the pancake project 
