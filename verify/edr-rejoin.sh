# edr-rejoin.sh -- shared repair for command echoes torn by the EDR bursts.
#
# Source this, then use rejoin_edr (filter, stdin->stdout) or rejoin_serial
# (file -> file). Both strip CR themselves, so callers must not tr -d '\r'
# again. Unit tests: verify/edr-rejoin-test.sh.
#
# WHY THIS EXISTS AS ONE FILE
# ---------------------------
# Five harnesses each grew their own copy of this awk, independently, and the
# copies drifted in three ways that each produce a FALSE non-PASS on a
# CORRECT kernel -- the worst possible failure mode for a test harness:
#
#   1. Four of the five matched only "[EDR DAEMON]", not "[EDR ADVANCED]".
#      The ADVANCED "Suspicious memory" line is the HIGH-FREQUENCY one, so
#      those copies left the commonest tear unrepaired.
#   2. All five flushed the splice buffer on a blank line. The 60s status
#      report is BRACKETED by blank lines (edr_daemon.c:217 opens with
#      kprintf("\n[EDR DAEMON] ===...") and the closing rule is followed by
#      another newline), so an echo torn across the report lost its head.
#   3. All five emitted a CONTINUATION line as if it were finished output.
#      When the shell resumes between two bursts the continuation lands on a
#      line of its own containing no marker at all -- indistinguishable from
#      real output by content. See "the two-burst tear" below.
#
# THE TEAR, AS MEASURED
# ---------------------
# The burst interrupts at an ARBITRARY character, including inside the first
# token, so no token-based match can ever be made correct -- only splicing:
#
#     $ w[EDR DAEMON] Starting threat scan...
#     rite /secret.txt ROO[EDR DAEMON] Starting threat scan...
#     TONLYDATA
#
# THE TWO-BURST TEAR (defect 3 above)
# -----------------------------------
# When the echo spans the 60s status report, the middle fragment has no
# marker on it and the report's blank lines sit between the halves:
#
#     $ e[EDR DAEMON] Starting threat scan...
#     [EDR DAEMON] Scan complete: ...
#     cho                                    <-- fragment, NO marker
#     [EDR DAEMON] ========== STATUS REPORT ==========
#     ... 8 report lines ...
#     [EDR DAEMON] ===================================
#                                            <-- blank, part of the burst
#     MARKREDIR > /root[EDR DAEMON] Starting threat scan...
#     only/redir.txt
#
# "cho " cannot be told from real output by looking at it. It is told by
# POSITION: a line arriving while a tear is open, whose successor is another
# burst line, is itself a fragment. That is the lookahead below, and it only
# ever fires while a tear is open, so untorn output is never glued.
#
# THE LONE-PROMPT LINE (defect 4)
# -------------------------------
# The shell writes its prompt with NO trailing newline, so when the status
# report's leading "\n" arrives the prompt becomes a line of its own -- with
# no marker on it at all -- and the command echo lands after the report:
#
#     D:/ $                                  <-- complete line, no marker
#     [EDR DAEMON] ========== STATUS REPORT ==========
#     ... 8 report lines ...
#     [EDR DAEMON] ===================================
#
#     cat /t1.txt
#     KEEPME
#
# Nothing is pending when "cat /t1.txt" arrives, so no buffer rule can fix
# this: a line that is ONLY a prompt has to be recognised as unterminated and
# held. verify-ring3-fileops.sh anchors after() on "$ cmd" -- deliberately,
# since a bare command match would also hit the harness'"'"'s own typed input --
# so without this its cat lookups return empty and the leg reports a ramfs
# that dropped the file. It did not: the same log shows KEEPME on the next
# line.
#
# The two hold rules are disjoint and BOTH are needed: the prompt rule fires
# only when the buffer is EMPTY, the lookahead only when it is NON-empty. The
# lookahead additionally excludes a buffer already ending in a prompt, or it
# runs away and glues whole commands together (measured: 13 spurious joins in
# one capture, producing lines like "write /t1.txt KEEPMED:/ $ touch").
#
# Lines that START with a marker are pure noise, dropped whole; lines that
# merely CONTAIN one carry real output before it, so that prefix is kept and
# joined to what follows. The END flush recovers a torn line with nothing
# after it.

_EDR_REJOIN_AWK='
{ lines[NR] = $0 }
END {
  buf = ""
  for (i = 1; i <= NR; i++) {
    l = lines[i]
    if (l ~ /^\[EDR (DAEMON|ADVANCED)\]/) { inburst = 1; continue }
    if (l ~ /\[EDR (DAEMON|ADVANCED)\]/) {
      sub(/\[EDR (DAEMON|ADVANCED)\].*$/, "", l)
      buf = buf l; inburst = 1; continue
    }
    if (l == "" && (inburst || buf != "")) continue
    if (buf == "" && l ~ /^[A-Za-z]:\/[^ ]* \$ $/) { buf = l; inburst = 1; continue }
    if (buf != "" && i < NR && lines[i+1] ~ /\[EDR (DAEMON|ADVANCED)\]/ && buf !~ /\$ $/) {
      buf = buf l; inburst = 0; continue
    }
    print buf l; buf = ""; inburst = 0
  }
  if (buf != "") print buf
}'

rejoin_edr() {
    tr -d '\r' | awk "$_EDR_REJOIN_AWK"
}

rejoin_serial() {
    rejoin_edr < "$1" > "$2"
}
