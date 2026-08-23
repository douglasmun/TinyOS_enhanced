# Audit log persistence — decided: NOT NOW

Status: **decided, not deferred.** The audit log stays volatile. This file records
why, because "the audit log should survive a reboot" is an obviously-good idea that
is wrong in this tree for two specific reasons, and without them written down it
will be proposed again.

The question came out of the Check Point BTR Reforged write-up: a threat actor with
root access disables or blinds the EDR. The natural follow-up is "would our audit
log even show it afterwards?" — and the answer is no, because `reboot` erases it.
That makes persistence look like the fix. It is not, yet.

## What exists today

`src/audit.c` is a 1000-entry in-memory ring (`AUDIT_BUFFER_SIZE`, audit.c:25).
Each record carries an HMAC-SHA512 chained over the previous record's HMAC
(`audit_event_t::hmac`, audit.h:134), so `auditlog -v` can detect a record edited
in place. Nothing is written to any backing store, and the whole ring is `memset`
to zero by `audit_init()` on every boot.

## Reason 1 — the HMAC key is regenerated every boot

`audit_init()` (`src/audit.c:81`) opens with:

```c
csprng_random_bytes(&global_csprng, audit_hmac_key, sizeof(audit_hmac_key));
```

The key is fresh CSPRNG output on each boot and is never stored anywhere. So
records persisted from a previous boot **cannot be authenticated after that boot** —
the key that signed them no longer exists. `audit_verify_integrity()` would fail
against them, or, worse, would be "fixed" by re-signing the loaded records with the
new key, which is not verification at all: it would stamp attacker-supplied records
as genuine.

This is the load-bearing objection. Persistence without a stable key ships a
**tamper-evident log whose tamper-evidence is void exactly across the boundary that
persistence exists to cross**. The reboot is the event you most want covered, and it
is the one event the chain cannot span. A log that looks verified and is not is
worse than one that is honestly volatile — this is the status-surface lie class
again (`doc/SECURITY_HARDENING.md`): ask what the surface would print if the
mechanism were absent, and here `[OK] integrity verified` would print either way.

Doing this properly needs a key that outlives the boot *and* that root cannot read —
i.e. sealed storage. There is no TPM and no sealing primitive here.

## Reason 2 — the one persistence precedent in the tree has never persisted anything

`src/entropy.c:442` defines `SEED_FILE_PATH "/boot/entropy.seed"` and saves through
`ramfs_open`. Nothing in the tree creates `/boot`, and nothing mounts a persistent
filesystem there — ramfs is RAM. Verified from three live boot logs; every boot
prints:

```
[ENTROPY] No persistent seed file found
[ENTROPY] ERROR: Cannot create seed file
[ENTROPY] WARNING: Could not save persistent seed
[ENTROPY] Entropy will reset on next reboot
```

So the existing model for "persist a security-critical blob across reboots" has been
failing on every boot since it was written, and announcing it. Copying that model
for the audit log reproduces the bug with a quieter failure mode. A real
implementation must target FAT32 (which has a live `.write` — see the `edit`
discussion in `CLAUDE.md`), not ramfs.

## What was done instead

Neither reason is fixable by a small change, so the honest interim fix is to stop
the volatility being a *surprise* rather than to half-build the durable version:

- `auditlog -s` reports `Total events logged`, which reads as an all-time total and
  is actually since-boot. It now says so.
- The log's volatility is stated where a reader would look for it, rather than being
  something you learn by rebooting.

## What would have to be true to revisit this

1. A key that survives reboot and is **not readable by root** — otherwise the root
   attacker in the threat model above simply re-signs the log after editing it, and
   persistence has bought nothing against the adversary that motivated it.
2. A backing store that actually persists (FAT32, not ramfs) with a write path that
   tolerates power loss mid-record.
3. A decision on what happens when the store is unavailable or fails verification at
   load — silently continuing is the failure mode of Reason 2.

Until (1) has an answer, persistence adds attack surface and a false assurance, and
removes nothing an attacker cares about. Item (1) is the hard one and it is a
hardware question, not a software one.
