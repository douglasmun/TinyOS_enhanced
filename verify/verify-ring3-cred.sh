#!/usr/bin/env bash
#
# verify-ring3-cred.sh — FULLY AUTOMATED check of RING-3 CREDENTIALS (SYS_CRED).
#
# passwd/useradd/userdel from the ring-3 shell. The syscall carries an operation
# and a username and NOTHING else: the kernel prints the prompts, reads the
# password into its own buffer, applies the euid checks and zeroes the buffer
# before returning. Ring 3 never holds a plaintext password, so it cannot leak
# or log one.
#
# That design is exactly what makes the harness worth writing: the interesting
# assertions are all REFUSALS, and a refusal is what a naive "expose the command
# to ring 3" change gets wrong while every success path still looks fine.
#
# The run does two logins on purpose. Everything up to `exit` runs as ROOT; the
# second login is as the just-created UNPRIVILEGED user, which is the only way
# to prove that the euid check is enforced on the kernel side of the syscall
# rather than by the shell choosing not to offer the command. A shell-side check
# would pass every root-side assertion here and still leave useradd reachable by
# anyone who called the syscall directly.
#
# Each check is chosen so a plausible bug fails it:
#
#   - useradd creates a user     — the success path. Proves the whole chain: the
#                                  ring-3 builtin, the bounded copy of the
#                                  username out of user memory, the kernel-side
#                                  prompt, and the write to the user database.
#
#   - the password PROMPT is     — the prompts are printed by the KERNEL, into
#     visible on the session       the calling process's stream. If SYS_CRED
#                                  routed them to the kernel console instead
#                                  (kprintf, as this code did before), a ring-3
#                                  user would face a silent shell that appears
#                                  hung while something invisible waits for a
#                                  password. Seeing the prompt IS the check that
#                                  output routing works.
#
#   - `userdel root` REFUSED     — refused by UID, not by the name "root". The
#                                  old check compared the argument to the string
#                                  "root", so any other name for uid 0 deleted
#                                  the system's only privileged account.
#
# Deliberately NOT asserted: the self-deletion refusal. userdel is root-only, so
# reaching it requires a session whose euid is 0 and whose uid names a deletable
# account — which no path in the current shell produces (root hits the uid-0
# branch first, and a non-root caller is stopped by the root-only gate). It is
# defense-in-depth for an su-elevated session, and claiming a check the run does
# not perform would be worse than leaving it out.
#
#   - useradd as NON-ROOT is     — THE decisive check, and the reason for the
#     REFUSED                      second login. Everything above runs as root
#                                  and would pass even if the euid check were
#                                  dropped entirely.
#
#   - passwd on ANOTHER user is  — the second half of the privilege model: an
#     REFUSED for non-root         unprivileged user may change their own
#                                  password, but not somebody else's.
#
#   - passwd on THEMSELVES is    — the case that gate must not catch, checked
#     ALLOWED                      alongside it so a blanket root-only "fix"
#                                  cannot satisfy the refusal above. It is also
#                                  the only path reading three passwords in a
#                                  row, so it proves the kernel's prompt loop
#                                  returns control cleanly between reads.
#
#   - a REDIRECTED credential    — `passwd > f` must be refused, not run. The
#     command is REFUSED           prompts are printed by the KERNEL into this
#                                  process's stdout, so redirecting them puts
#                                  "Enter new password:" in the file while the
#                                  kernel blocks on the keyboard: the user faces
#                                  an apparently-hung shell and types a password
#                                  blind. This is checked immediately before the
#                                  self-service passwd, so a refusal that also
#                                  broke the ordinary case fails the next check.
#
#   - no plaintext password on   — a sweep, not a behaviour: the kernel echoes
#     the console                  '*' and never prints its buffer, so any hit
#                                  is a password that reached an output path.
#
#   - the shell SURVIVES each    — every refusal is followed by a command whose
#     refusal                      output we wait on, so a refusal that killed
#                                  or wedged the session fails the NEXT check.
#                                  A kernel-side prompt reads the keyboard
#                                  directly, so a command that returned early
#                                  while the kernel was still in read_password
#                                  would eat the following line's keystrokes.
#
# Note the '!' prefix on the password lines below: it tells the typist to send
# them WITHOUT the usual echo check, because a password prompt echoes '*' per
# keystroke and verifying the characters back would always fail.
#
# Exit 0 = PASS, non-zero = FAIL/INCONCLUSIVE.  Logs: ring3-cred.log (serial),
# ring3-cred-trace.log (int/cpu_reset trace).
set -uo pipefail
cd "$(dirname "$0")/.."

PASSWORD="${TINYOS_TEST_PASSWORD:-rootpass1}"
# The account this run creates and then logs in as. Its password is deliberately
# DIFFERENT from root's: if both were the same string, a bug that authenticated
# the second login against root's credentials would still succeed, and the
# non-root refusals would then be tested against a root session that passes them
# for the wrong reason.
NEWUSER=tester
NEWPASS=testpass1
# What the self-service passwd changes it to. Distinct from NEWPASS so the
# "no plaintext on the console" sweep at the end covers both the password that
# was typed at a prompt and the one that was verified against the database.
NEWPASS2=testpass2

ISO=dist/tinyos.iso
SERIAL=ring3-cred.log
TRACE=ring3-cred-trace.log
RUN_DISK=/tmp/tinyos-ring3-cred-disk.img
MON_SOCK=/tmp/tinyos-ring3-cred-mon.sock

echo "==> Building kernel + ISO..."
make >/dev/null || exit 1
cp kernel.elf iso/boot/kernel.elf
i686-elf-grub-mkrescue -o "$ISO" iso >/dev/null 2>&1

echo "==> Copying pristine disk.img -> $RUN_DISK"
rm -f "$RUN_DISK" "$SERIAL" "$TRACE" "$MON_SOCK"
if [ ! -f disk.img ]; then
    echo "ERROR: disk.img not found"
    exit 1
fi
cp disk.img "$RUN_DISK"

echo "==> Launching headless QEMU (monitor on $MON_SOCK)"
qemu-system-i386 -cpu Broadwell,+rdrand,+rdseed -cdrom "$ISO" \
    -boot d -m 256M \
    -drive file="$RUN_DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -serial "file:$SERIAL" \
    -monitor "unix:$MON_SOCK,server,nowait" \
    -no-reboot -d int,cpu_reset -D "$TRACE" -display none &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; rm -f "$MON_SOCK"; }
trap cleanup EXIT

echo "==> Driving the boot flow (slow under TCG; be patient)..."
# `id` is the first command purely as a barrier: it is cheap, it echoes, and it
# proves the ring-3 shell is up and running as root (uid=0) before anything that
# depends on being root is attempted.
#
# The ordering below is load-bearing. useradd must precede the login as that
# user, and the self-deletion refusal must be attempted while logged in AS
# someone — as root, `userdel root` covers both that case and the uid-0 case at
# once, so the two are separated by creating `tester` first and having root try
# to delete the account it is not.
#
# Each password line is a follow-up of its own rather than being appended to the
# command, because it is answering a KERNEL prompt, not the shell's readline.
TINYOS_PASSWORD="$PASSWORD" \
TINYOS_SERIAL="$SERIAL" \
TINYOS_MON_SOCK="$MON_SOCK" \
TINYOS_STAY_IN_RING3=1 \
TINYOS_EXEC_CMD="id" \
TINYOS_EXPECT="uid=0" \
TINYOS_FOLLOWUP_CMDS="\
useradd $NEWUSER=>Enter password for new user;\
!$NEWPASS=>created;\
userdel root=>cannot delete root user;\
useradd $NEWUSER=>already exists;\
exit=>TinyOS login:;\
$NEWUSER=>Password:;\
!$NEWPASS=>Login successful;\
id=>uid=1002;\
useradd second=>permission denied;\
userdel root=>permission denied;\
passwd root=>only root can change;\
passwd > D:/pw.txt=>cannot be redirected;\
passwd=>(current);\
!$NEWPASS=>Enter new password;\
!$NEWPASS2=>Retype new password;\
!$NEWPASS2=>password updated successfully;\
pwd=>D:/" \
python3 tools/qemu_typist.py
TYPIST_RC=$?

sleep 3
cleanup

echo ""
echo "================ VERDICT ================"

if [ ! -s "$SERIAL" ]; then
    echo "RESULT: FAIL — no serial output at all (typist rc=$TYPIST_RC)"
    exit 2
fi

fail_with() {
    echo "RESULT: FAIL — $1"
    shift
    for line in "$@"; do echo "  $line"; done
    grep -v "Suspicious" "$SERIAL" | tail -30
    exit 2
}

# --- The success path, as root -------------------------------------------

# The kernel printed its prompt into the RING-3 session's stream. If this is
# missing but the user was still created, output routing regressed to kprintf
# and an interactive user would see a shell that looks hung.
n_prompt=$(grep -c "Enter password for new user" "$SERIAL" 2>/dev/null)
[ "$n_prompt" -ge 1 ] || fail_with \
    "the kernel's password prompt never reached the ring-3 session" \
    "SYS_CRED must print through the caller's stream, not kprintf: an" \
    "interactive user would otherwise face a silent, apparently-hung shell."

grep -q "useradd: user '$NEWUSER' created" "$SERIAL" 2>/dev/null || fail_with \
    "useradd did not create the user from ring 3" \
    "The success path is the whole chain: builtin -> SYS_CRED -> bounded" \
    "username copy -> kernel prompt -> user database write."

# --- The refusals, as root -----------------------------------------------

grep -q "userdel: cannot delete root user" "$SERIAL" 2>/dev/null || fail_with \
    "root deletion was not refused" \
    "The refusal must be by UID, not by the name 'root' — an account created" \
    "with uid 0 is root in every way that matters."

grep -q "useradd: user '$NEWUSER' already exists" "$SERIAL" 2>/dev/null || fail_with \
    "a duplicate useradd was not refused" \
    "A second account under one name makes every later lookup ambiguous."

# --- The decisive part: the same commands as an UNPRIVILEGED user ---------

# Proof the second login actually happened AND landed unprivileged. Without
# this, every "permission denied" below could be a root session refusing for
# some unrelated reason.
grep -q "uid=1002" "$SERIAL" 2>/dev/null || fail_with \
    "the second login did not reach ring 3 as the new unprivileged user" \
    "Every non-root assertion below depends on this; without it they would" \
    "be checking a root session and could pass for the wrong reason."

n_denied=$(grep -c "permission denied (must be root)" "$SERIAL" 2>/dev/null)
[ "$n_denied" -ge 2 ] || fail_with \
    "useradd/userdel were not refused for a non-root caller (saw $n_denied of 2)" \
    "THE check this harness exists for. The euid gate must live on the kernel" \
    "side of SYS_CRED: a shell that merely declines to offer the command still" \
    "leaves the syscall reachable by anything that calls it directly."

grep -q "only root can change other users' passwords" "$SERIAL" 2>/dev/null || fail_with \
    "a non-root user was not refused another user's password" \
    "The other half of the model: self-service passwd must stay allowed, so a" \
    "blanket root-only gate is the wrong fix and this check rejects it."

grep -q "passwd: cannot be redirected" "$SERIAL" 2>/dev/null || fail_with \
    "a redirected credential command was not refused" \
    "'passwd > f' must be refused: the kernel prints its prompts into this" \
    "process's stdout, so redirecting them hides the prompt in a file while" \
    "the kernel blocks on the keyboard and the user types a password blind."

# ...and the case that gate must NOT catch. This is the one credential operation
# an unprivileged user is entitled to, and it is also the only path that reads
# THREE passwords in a row (current, new, retype) — so it proves the kernel's
# prompt loop hands control back to the shell cleanly between reads rather than
# leaving stray keystrokes queued.
grep -q "passwd: password updated successfully" "$SERIAL" 2>/dev/null || fail_with \
    "an unprivileged user could not change their OWN password" \
    "Self-service passwd must remain allowed; a refusal here means the euid" \
    "check is a blanket root-only gate rather than the intended policy."

# --- The session survived it all -----------------------------------------

# The trailing pwd is a barrier as much as a check: a kernel-side prompt reads
# the keyboard directly, so a command that returned while the kernel was still
# inside read_password would swallow this line instead of echoing it.
grep -q "D:/" "$SERIAL" 2>/dev/null || fail_with \
    "the shell did not survive the refusals" \
    "Nothing echoed after the last refusal, so the session was left wedged —" \
    "most likely a path that returned while the kernel still held the keyboard."

if grep -q "Triple fault\|PANIC\|triple fault" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — kernel panic/triple fault during the run"
    grep -n "Triple fault\|PANIC\|triple fault" "$SERIAL" | head -5
    exit 2
fi

# A plaintext password must never appear on the serial console. The kernel echoes
# '*' per keystroke and never prints the buffer, so a hit here means a password
# reached a printf somewhere it should not have.
if grep -qE "$NEWPASS|$NEWPASS2" "$SERIAL" 2>/dev/null; then
    echo "RESULT: FAIL — a plaintext password appeared in the serial log"
    echo "  The kernel echoes '*' and never prints the buffer; a hit means a"
    echo "  password reached an output path it should never touch."
    grep -nE "$NEWPASS|$NEWPASS2" "$SERIAL" | head -5
    exit 2
fi

echo "RESULT: PASS — ring 3 administered credentials through SYS_CRED:" \
     "useradd created a user with the password read kernel-side; deleting" \
     "root and a duplicate useradd were refused; and after logging in as the" \
     "unprivileged account, useradd/userdel/passwd-for-another were all" \
     "refused by the kernel's euid check while that user's OWN passwd still" \
     "succeeded; a redirected passwd was refused; no plaintext reached the" \
     "console and the session was still alive at the end"
grep -E "created \(uid|cannot delete root|already exists|permission denied|only root can change|cannot be redirected|password updated successfully|uid=1002" \
     "$SERIAL" | head -12
exit 0
