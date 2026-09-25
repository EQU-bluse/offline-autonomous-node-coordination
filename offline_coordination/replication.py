"""Read-only audit replication batches.

A batch is a single UTF-8 compact JSON object (non-ASCII preserved, no
whitespace) terminated by exactly one ``\\n``::

    {"after":...,"complete":...,"next":...,"records":[...],"version":1}

The top-level keys are fixed in the order ``after``, ``complete``,
``next``, ``records``, ``version`` and ``version`` is always the integer
1.  ``after`` echoes the request's ``after`` argument.  ``records`` holds
up to ``limit`` (at most 1000) audit records whose ``seq`` is greater
than ``after``, in audit order, each preserving the audit record key
order ``detail, hash, kind, prev, seq, source`` and its original values.
``next`` is the seq of the last record in the batch, or ``after`` itself
when the batch is empty; ``complete`` is true when no record follows the
batch, and an empty ``records`` list is only valid when ``complete`` is
true.  Batches are generated solely through :func:`audit.read`, so the
audit log is never modified and :class:`~offline_coordination.audit.
CorruptAuditError` and :class:`OSError` propagate unchanged.

:func:`import_batch` validates a batch against this byte contract and
appends its records to the local log.  It returns a dict with the fixed
key order ``need``, ``next``, ``status``.  When the batch starts beyond
the local log (``after`` greater than the local last seq ``L``) nothing is
written and ``status`` is ``"missing"`` with ``need`` holding the gap
``[L + 1, after]`` and ``next`` set to ``L``.  Otherwise records already
present locally must match field by field (a mismatch raises
:class:`ValueError`); the matching prefix is skipped idempotently and
only the contiguous suffix past ``L`` is appended, linked to the local
last hash.  ``need`` is then ``None``, ``next`` is ``max(L, batch.next)``
and ``status`` is ``"applied"`` when records were appended, else
``"duplicate"``.  Any failure leaves the log untouched.

Batches are checked only against the byte contract: canonical encoding, key
order, the seq/prev/hash chain and the stored values.  Value-domain rules
enforced by :func:`audit.append` on event input (the kind enum, non-empty
string fields) are *not* re-enforced here, so every log :func:`audit.read`
accepts round-trips through :func:`export_batch`/:func:`import_batch`.  The
append itself is atomic: when the write, flush or fsync step raises
:class:`OSError` the error propagates unchanged and the log is left
byte-identical to its pre-call state (still missing when it was missing).

:func:`apply_remote` persists remote state applications in a version-1
*ledger*: one UTF-8 compact JSON object (keys sorted lexicographically,
exactly one trailing ``\\n``) with the top-level keys ``audit``,
``requests``, ``state`` and ``version`` (``version`` is the integer 1).
``state`` holds the current :mod:`~offline_coordination.merge` state,
``requests`` binds each accepted request id to the digest of its request,
and ``audit`` lists one entry per successful application in order; each
entry carries ``after``/``before`` state digests, the request ``id`` and
``source`` and a contiguous ``seq`` starting at 1, every entry after the
first chaining its ``before`` to the previous entry's ``after`` and the
last ``after`` hashing the stored state.  A missing ledger stands for the
request's ``base`` state with empty indexes; any existing file that fails
the byte, structure, state or index rules is rejected with
:class:`ValueError` and left untouched.

Replaying a request whose ``id`` is already bound to exactly the same
request digest always yields ``duplicate`` from the saved binding alone,
immediately or after other commits: one item per remote record in
ascending key order, each already duplicate with an empty ``need`` map,
and no receipt; the ledger is never read for modification on a replay.
A bound ``id`` presented with a different request raises
:class:`ValueError`.  Every successful commit is one durable transaction:
write, flush, file sync, replacement and directory sync all lie inside
its boundary, and an :class:`OSError` at any stage propagates unchanged
with the file system restored to its pre-call state.

Each commit is additionally backed by a *recovery intent* so a crash of
the committing process itself can be reconciled later, across processes.
Before anything is replaced, the commit publishes an intent at ``path +
".txn"``: one UTF-8 compact JSON object (keys recursively sorted,
exactly one trailing ``\n``) recording only ``version`` (the integer 1),
``phase``, the lowercase hex SHA-256 digests of the new and old ledger
bytes (``newDigest``/``oldDigest``) and the safe base names of the
candidate and predecessor transaction files, all confined to the
ledger's own directory; when the ledger did not exist, ``oldDigest`` and
``predecessor`` are both ``null``.  The intent starts in phase
``prepared`` and is republished as ``installed`` only after the new
ledger has replaced the old one and the directory has synced; the
intent's own creation and phase change each sync the file and the
directory.  A crash before the ``installed`` intent is durable leaves
the commit unconfirmed: :func:`recover_ledger` keeps or restores the old
bytes (byte-for-byte, and missing again when the path was missing) and
deletes the referenced candidate.  A crash afterwards lets
:func:`recover_ledger` verify the new bytes against ``newDigest`` and
finish the cleanup.  Only files the intent references are removed, the
intent itself is deleted last and the directory is synced, and a
repeated call reports ``clean`` without scanning random artifacts.

:func:`recover_ledger` returns a fresh dict with the key order
``digest``, ``status``: ``clean`` when no intent exists, ``rolled-back``
or ``completed`` after a recovery, with ``digest`` holding the digest of
the resulting ledger bytes (``None`` when the path is missing).  A
``path`` that is not a str raises :class:`TypeError`; an intent that
fails to parse, or whose fields, phase, names, digests or necessary
artifacts are invalid, raises :class:`CorruptRecoveryError` (a
:class:`ValueError`) without touching the ledger or any unrelated file;
an :class:`OSError` while reading, replacing, deleting or syncing
propagates unchanged with enough intent and artifacts left for a retry.
The ledger write entry points run this recovery automatically after
their input validation, before the ledger is read.

:func:`inspect_recovery` diagnoses an explicit, non-empty list of ledger
paths without modifying anything: only each listed ledger, its intent
and the artifacts the intent references are read.  Each report carries
``path``, ``status``, ``phase``, ``digest``, ``artifacts``, ``action``
and ``error`` -- ``clean`` with a null phase and action when no intent
exists (the digest still summarizes the ledger bytes, or is null when
the path is missing), ``pending`` with the intent's phase and the
suggested action (``rollback``/``complete``) plus the candidate and
predecessor existence, digest match and completeness when an intent is
valid, ``blocked``/``corrupt`` when the intent or a necessary artifact
is invalid, and ``failed``/``os-error`` when reading fails.
:func:`recover_many` is the controlled batch form of
:func:`recover_ledger` over the same kind of list: every path is
recovered in order, one ledger's failure never stops or rolls back the
others, a :class:`CorruptRecoveryError` becomes a ``blocked``/``corrupt``
item and an :class:`OSError` a ``failed``/``os-error`` item, and failed
ledgers keep their intent and artifacts so a re-run retries them
independently.  Both validate the whole list (a non-empty list of
non-empty, distinct strings) before any file is read or modified.

:func:`apply_signed_remote` adds an offline-verifiable authentication
boundary in front of the same application flow.  It receives the ledger
path, a keyring, an envelope and the current moment.  The envelope
carries exactly ``node``, ``keyVersion``, ``request`` and ``signature``;
the request follows the :func:`apply_remote` contract and its ``source``
must equal the envelope's ``node``.  The keyring maps node names to
credential entries, each holding exactly ``version`` (a positive integer,
unique per node), ``secret`` (64 lowercase hex characters decoding to the
32-byte HMAC key), ``notBefore``/``notAfter`` (non-negative integers
bounding the validity period, both bounds inclusive) and ``revoked``.
The signed payload is the canonical compact UTF-8 JSON encoding of
``node``, ``keyVersion`` and ``request`` with every object key
recursively sorted lexicographically and non-ASCII preserved; the
signature is the lowercase hex HMAC-SHA256 computed with the selected key
and compared in constant time.  Keys are selected by exact node and
version with no fallback: unknown credentials, a revoked, not-yet-valid
or expired key, a source/node identity mismatch and a signature mismatch
all raise :class:`AuthenticationError` (a :class:`ValueError`) before the
ledger is ever read, so a failed verification creates no file.  Replays
are authenticated against the *current* keyring, so a later revocation or
expiry cannot be bypassed through a historical request binding.  Audit
entries committed through :func:`apply_signed_remote` record the verified
credentials under ``auth``; entries without ``auth`` remain readable and
:func:`apply_remote` keeps its public behaviour and ledger format.

:func:`export_proof` and :func:`verify_proof` add offline audit-proof
exchange over the same ledger.  A proof is one version-1 UTF-8 compact
JSON object -- every object key recursively sorted lexicographically,
non-ASCII preserved, exactly one trailing ``\\n`` -- with the top-level
keys ``digest``, ``endSeq``, ``entries``, ``firstBefore``, ``lastAfter``,
``startSeq`` and ``version``.  ``startSeq``/``endSeq`` name the covered
audit range, ``firstBefore`` is the state digest before the first covered
entry and ``lastAfter`` the state digest after the last one; ``entries``
hold the ledger entries in range unchanged, each carrying ``after``/
``before`` state digests, ``id``, ``seq`` and ``source`` with the optional
``auth`` binding.  ``digest`` is the lowercase hex SHA-256 of the compact
canonical encoding (with no trailing newline) of the proof object with
the ``digest`` key itself removed.  :func:`verify_proof` is purely
offline: it reads neither the ledger nor the keyring.

:func:`compare_proofs` relates two proofs offline, on top of that same
purely local verification.  Both arguments are :class:`bytes`; they are
first independently checked against the exact :func:`verify_proof`
contract, so a non-bytes argument raises :class:`TypeError` and either
proof being invalid raises :class:`InvalidProofError` before any
comparison.  The ledger, the keyring and the filesystem are never read
and neither input is modified.  The result is one version-1 UTF-8
compact JSON object -- every object key sorted lexicographically,
non-ASCII preserved, exactly one trailing ``\\n`` -- with the fixed
top-level keys ``common``, ``conflictSeq``, ``left``, ``overlap``,
``relation``, ``right`` and ``version`` (``version`` is the integer 1).
``left``/``right`` each carry the proof ``digest`` and its
``startSeq``/``endSeq``.  ``overlap`` is the closed shared seq interval
``[start, end]`` or ``null`` when the two ranges are disjoint; disjoint
ranges never raise and keep both sides' ranges.  With an overlap, the
complete entries at every shared seq are compared in ascending seq
order -- boundary and proof digests alone are never enough.  If every
shared entry matches, ``relation`` is ``"same"`` (identical ranges),
``"left-prefix"``/``"right-prefix"`` (same start and the shorter side
matches in full, named for the shorter side) or ``"overlap"``
otherwise; ``common`` then names the last shared boundary as
``{"after", "seq"}`` -- the last common entry's seq and after digest.
The first shared seq whose complete entry differs makes ``relation``
``"fork"`` with ``conflictSeq`` that earliest seq (never skipped past);
``common`` is the last equal entry when an equal entry precedes it, the
prior boundary ``{"after", "seq"}`` when the first shared entry already
conflicts but its ``before`` digests agree (its seq may be 0), and
``null`` when those ``before`` digests differ.  ``conflictSeq`` is
``null`` for every non-fork relation.  The bytes are deterministic for
equal inputs; swapping the inputs only exchanges ``left``/``right`` and
mirrors the prefix direction.

:func:`plan_merge` turns that read-only comparison into a read-only merge
plan.  It takes both proof byte strings and a conflict ``policy`` --
``"left"``, ``"right"`` or ``"manual"``; any other value raises
:class:`ValueError` -- and validates every argument type before parsing
either proof, so a malformed proof never masks a :class:`TypeError` and an
invalid proof still raises :class:`InvalidProofError`.  Disjoint ranges,
or a fork whose common boundary cannot be confirmed, raise
:class:`ValueError` instead of producing a speculative plan.  Only
complete entries strictly after the common boundary become steps: an
unforked history accepts the longer side's tail as an ``extension``; a
fork accepts the selected side's tail (``selected``) and rejects the
other (``rejected``), while ``manual`` marks both tails ``manual`` and
references them from ``unresolved``.  The plan is one version-1 UTF-8
compact JSON object -- keys recursively sorted, non-ASCII preserved,
exactly one trailing ``\\n`` -- with the top-level keys ``common``,
``left``, ``policy``, ``relation``, ``right``, ``steps``, ``unresolved``
and ``version``; steps carry the original entries unchanged and are
ordered by ascending seq with the left side first on ties.  The plan is
byte-stable for equal inputs, mirrors left/right when the proofs are
swapped together with a ``left``/``right`` policy, and never touches the
filesystem or the inputs.

:func:`resolve_merge` closes a ``manual`` plan read-only.  It takes the
plan byte string, the same two proofs and a list of decisions; only a
``manual`` plan produced by :func:`plan_merge` for exactly those proofs
may be resolved -- a plan from any other policy is a structurally valid
version-1 plan whose steps differ from the regenerated manual plan and
is therefore rejected as stale before any decision is considered.
A structurally invalid plan (encoding, duplicate keys, version-1
structure) raises :class:`InvalidPlanError`; a structurally valid plan
that is not byte-for-byte the manual plan regenerated from the proofs
(digest, relation, common boundary, side summaries, steps or unresolved
references) raises :class:`StalePlanError`; both are
:class:`ValueError` subclasses.  Each decision carries only ``side``,
``seq`` and ``action`` (``"accept"`` or ``"reject"``), resolving one
unresolved reference; missing, duplicate, extra or out-of-range
references and illegal choices raise :class:`InvalidResolutionError`
(a :class:`ValueError`).  Accepted entries must chain contiguously from
the common boundary -- at most one accepted side per seq, no acceptance
past a rejected seq, an unbroken seq and digest chain.  The result is
one version-1 compact JSON object with the top-level keys ``common``,
``left``, ``planDigest``, ``relation``, ``right``, ``steps``,
``unresolved`` and ``version``; manual steps become
``accept``/``reject`` with the fixed reasons ``manual-accepted``/
``manual-rejected``, non-manual steps, carried audit entries and ``auth``
bindings are unchanged, ``unresolved`` is empty and ``planDigest`` is the
lowercase hex SHA-256 of the complete source plan bytes.  Resolution is
deterministic, mirrors under a left/right swap with matching decisions,
and never touches the filesystem or the inputs.

:func:`commit_resolution` is the write entry point that lands a manual
resolution in the ledger.  It takes the ledger path, the canonical
resolution bytes, the original plan bytes, both proofs and the landing
material -- the final ``state`` plus ``requests`` binding every accepted
entry id to its request digest.  Both proofs are verified offline and
the plan and resolution are checked against the freshly regenerated
manual plan (:class:`StalePlanError` otherwise, without touching the
ledger); the ledger itself must still sit at the resolution's common
boundary (:class:`StaleLedgerError`, a :class:`ValueError`).  A fully
identical replay is recognized before that staleness check and returns
``duplicate``; a resolution accepting nothing returns ``unchanged`` and
writes nothing.  Otherwise the final state, the request bindings and
the contiguous accepted entries -- rejected entries never enter the
audit -- are written in one fail-safe replacement, returning
``applied``.  The result carries only ``next``, ``resolutionDigest``
and ``status``.

:func:`recover_authorized` puts an offline-verifiable authorization
boundary and a durable operation audit around the same batch recovery.
It takes the ledger path list, a keyring, a ticket, the current moment
and the recovery audit path.  The ticket is one UTF-8 compact JSON
object -- every object key recursively sorted lexicographically,
non-ASCII preserved, no trailing newline or any other trailing byte --
carrying exactly ``payload`` and ``signature``.  The payload holds exactly ``issuer``,
``keyVersion``, ``nonce``, ``notBefore``, ``notAfter`` and the ordered
``paths``; the signature is the lowercase hex HMAC-SHA256 of the
canonical compact payload encoding, computed with the key the keyring
binds to the exact issuer and version (the
:func:`apply_signed_remote` keyring rules) and compared in constant
time.  The command paths must equal the ticket paths item for item --
never expanded, reordered or implicitly normalized.  Unknown
credentials, a revoked, not-yet-valid or expired key or ticket, a path
mismatch and a signature mismatch all raise :class:`AuthenticationError`
before any ledger is read, so a failed authorization creates no audit
record, consumes no nonce and leaves no temporary file.  Type faults in
the arguments raise :class:`TypeError` (a :class:`bool` never poses as
``moment``); a malformed ticket key set, nonce, validity interval,
encoding or signature format raises :class:`ValueError`.

Once authorized, the batch runs in the :func:`recover_many` order with
the same per-ledger isolation and the same public item structure, and
every step is recorded in an append-only recovery audit at the given
path: a canonical JSONL hash chain (recursively sorted keys, one
trailing ``\\n`` per record, each record chaining the previous record's
SHA-256) where every record is written, flushed and synced before the
step it gates.  The first use of a nonce persists a ``batch`` header
binding the ticket digest, the issuer and the ordered paths; each
ledger then gets a ``before`` record (original digest, recovery phase,
planned action) and an ``after`` record (new digest, status, failure
category).  An :class:`OSError` while reading the audit or writing,
flushing or syncing a record propagates unchanged and leaves a
consistent, retryable chain prefix.  Re-entering with the same nonce
and the same ticket reuses the recorded results and only continues the
paths not yet settled; a process interrupted after a recovery but
before its result record is completed from the recorded action and
digests, without repeating side effects.  The same nonce bound to a
different ticket raises :class:`ReplayError` (a :class:`ValueError`)
without modifying any file, and a corrupt chain raises
:class:`CorruptRecoveryAuditError` (a :class:`ValueError`).

:func:`export_recovery_audit` pages the recovery audit read-only:
``after``/``limit`` select the window, the whole chain is validated
and a missing audit is treated as an empty chain.

:func:`export_recovery_checkpoint` adds an offline signature anchor
over the same chain.  It takes the audit path, a keyring, an issuer,
a key version and a moment, reads and validates the whole chain
read-only and returns one canonical compact UTF-8 JSON object -- keys
recursively sorted, non-ASCII preserved, no trailing newline or any
other trailing byte -- carrying exactly ``payload`` and ``signature``.
The payload binds exactly ``issuer``, ``keyVersion``, ``lastSeq``,
``moment``, ``tail`` and ``version`` (the integer 1); ``lastSeq`` is
the chain's last seq (0 for a missing audit) and ``tail`` the last
record hash (the zero hash for an empty chain).  The signature is the
lowercase hex HMAC-SHA256 of the canonical compact payload bytes under
the key the keyring binds to the exact issuer and version, with no
fallback; unknown credentials and a revoked, not-yet-valid or expired
key raise :class:`AuthenticationError`, a corrupt chain raises
:class:`CorruptRecoveryAuditError` and an :class:`OSError` while
reading propagates unchanged.

:func:`verify_recovery_page` verifies a paging dict against such a
checkpoint entirely offline: it reads no file.  The checkpoint is
parsed and its HMAC is verified against the current keyring (exact
issuer/version, usable at the given moment, so a later revocation or
expiry rejects the checkpoint as it does a replay); the moment bound
into the payload is part of the signed anchor itself and needs no
equality with the verification time.  The first round passes no cursor
and the page's ``after`` must be zero; every later round passes the
``{"digest", "next", "tail"}`` cursor built from the previous result,
requiring ``after`` to equal the cursor's ``next``, the first record
to chain to the cursor's ``tail`` and the cursor ``digest`` to equal
this checkpoint's SHA-256 digest, so a cursor can never resume
another checkpoint.  Every page's records must be contiguous from
``after + 1`` (no gap, reordering or duplicate), hash-correct and
chained inside the page and across its boundaries, and verification
never crosses the signed ``lastSeq``; before that seq an empty page
or a wrong ``complete`` flag is rejected as an invalid page.  The
result carries the fixed keys ``digest``, ``lastSeq``, ``status`` and
``tail``: reaching the signed tail yields ``"verified"``, every
earlier page ``"continue"``.  An empty checkpoint accepts only an
empty page starting at zero and reports seq 0, the zero hash and
``"verified"``.  Type faults raise :class:`TypeError` (a bool never
poses as an int), keyring faults raise :class:`ValueError`,
checkpoint faults raise :class:`InvalidRecoveryCheckpointError` and
page or cursor faults raise :class:`InvalidRecoveryPageError`; both
format errors subclass :class:`ValueError`.  No input or file is
modified.

:func:`verify_recovery_checkpoints` verifies a whole batch of
checkpoints offline, in input order, and never reads a file.  Each
item carries exactly a non-empty, batch-unique ``id``, the
``checkpoint`` bytes and the ordered, non-empty ``pages`` exported
for that checkpoint; the batch is validated in full before any item
is verified, so a container, field or element type fault raises
:class:`TypeError` and an empty list, an empty or duplicate id or an
empty page list raises :class:`ValueError` without producing any
result.  Every item is then verified in isolation from a zero cursor
through the exact :func:`verify_recovery_page` paging rules, each
round resuming from a cursor bound to the same checkpoint digest and
the previous page's chain tail, and one item's failure never stops
the later items.  Each checkpoint selects its key by its own exact
issuer and version with no fallback, so checkpoints signed before
and after a key rotation verify independently in the same batch as
long as the keyring retains both versions.  An item that reaches the
signed ``lastSeq`` must have no further pages; an item whose pages
run out earlier is ``incomplete`` and keeps its verified boundary.
Every item reports ``id``, the checkpoint ``digest``, the signed
``issuer`` and ``keyVersion`` (both ``None`` when the checkpoint
does not parse), the verified ``boundary`` (``None`` when nothing
was verified), a ``status`` of ``verified``, ``incomplete``,
``invalid-checkpoint``, ``invalid-page`` or ``unauthenticated`` and
an ``error`` (``None`` exactly when the item verified).  The result
is a fresh dict with the fixed key order ``items``, ``version``
(the integer 1); only batch-level or keyring-level faults raise,
never one item's verification failure.

:func:`adjudicate_recovery` turns those per-site verification results
into one offline aggregate verdict, still reading no file.  It takes a
non-empty ``items`` list, a ``policy``, a ``keyring`` and ``moment``.
Each item contains exactly a non-empty, batch-unique ``id`` and
``attestation`` bytes -- one canonical compact UTF-8 JSON object with
recursively sorted keys, non-ASCII preserved and no trailing newline
or any other trailing byte, carrying exactly ``payload`` and
``signature``.  The payload binds exactly ``batch``, ``site``,
``keyVersion`` and ``result`` with no extra fields; ``result`` follows
the public single-item :func:`verify_recovery_checkpoints` report
shape (``boundary``, ``digest``, ``error``, ``id``, ``issuer``,
``keyVersion``, ``status``).  Every legal single-item result is
accepted: a ``verified`` result always carries the checkpoint
identity, positive key version and signed boundary, while a
non-verified result may carry null ``issuer``/``keyVersion`` (when the
checkpoint did not parse) or a null boundary -- its identity, digest,
boundary and status are preserved on the report -- and only a
``verified`` result may count.
The policy binds the authorized ``batch``, a positive ``threshold`` no
greater than the number of its sites and, per non-empty site, the
non-empty set of positive key versions that site may use; the keyring
and moment keep their existing structure, validity and revocation
rules.  The signature is the lowercase hex HMAC-SHA256 of the
canonical compact payload bytes under the key selected by the exact
site and version with no fallback.  A wrong batch or unauthorized
site/version, unavailable, revoked, not-yet-valid or expired
credentials, a bad signature and a non-verified result each reject the
packet with a fixed reason and never count; a single packet with
illegal encoding, key sets or fields is rejected on its own as
``invalid-attestation`` and never blocks the other packets.  For one
site an identical valid packet -- the complete embedded result
(``boundary``, ``digest``, ``error``, ``id``, ``issuer``,
``keyVersion`` and ``status``) equal on every field -- counts once
and further copies are ``duplicate``, while any differing valid
result (even one sharing digest and boundary) is a
self-``contradiction``; valid packets from different sites must
agree on both digest and boundary, since any disagreement is a fork a
majority cannot mask.  The result is one canonical compact UTF-8 JSON
object (sorted keys, non-ASCII preserved, no trailing byte) with the
top-level keys ``boundary``, ``digest``, ``items``, ``status``,
``threshold`` and ``version`` (the integer 1): any contradiction or
cross-site fork yields ``conflicted`` with a null digest and boundary,
a unique agreed result from at least the threshold of distinct sites
yields ``accepted``, and every other case ``insufficient``.  Every
packet is reported -- sorted stably by site then id -- with its
identity, conclusion, fixed reason and verified boundary, and the
verdict is independent of input order.

:func:`export_recovery_verdict` and :func:`verify_recovery_verdict`
hand that aggregate verdict to a verifier that never sees the original
attestations, entirely offline.  :func:`export_recovery_verdict` takes
the verdict :func:`adjudicate_recovery` returned (canonical compact
JSON bytes), the signing ``policy``, a ``keyring``, the signing
``issuer``, key ``version`` and ``moment``; it reads and writes no
file.  It returns one canonical compact UTF-8 JSON object -- every
object key recursively sorted, non-ASCII preserved, no trailing
newline or any other trailing byte -- carrying exactly ``payload`` and
``signature``.  The payload binds exactly ``batch``, ``issuer``,
``keyVersion``, ``signedAt``, ``policyDigest`` and the complete
``verdict``.  ``policyDigest`` is the lowercase hex SHA-256 of one
canonical compact encoding of the policy: sites in ascending order and
each site's allowed versions as an ascending array, all object keys
recursively sorted; ``signature`` is the lowercase hex HMAC-SHA256 of
the canonical compact payload bytes under the key the keyring binds to
the exact issuer and version, with no fallback.  Unknown credentials
and a revoked, not-yet-valid or expired key raise
:class:`AuthenticationError`; a verdict that fails its canonical
contract raises :class:`InvalidRecoveryVerdictError`.

:func:`verify_recovery_verdict` takes only the proof bytes, the
expected policy, the current keyring and the verification moment; it
reads and writes no file and modifies no argument.  It recomputes the
policy digest and the verdict digest (the SHA-256 of the canonical
compact encoding of the verdict bound into the payload), checks the
payload batch and the verdict threshold against the policy, the
signing moment against the verification moment and the proof and
verdict structure, and verifies the HMAC against the key the *current*
keyring binds to the payload's exact issuer and version, usable at the
verification moment, so a later revocation or expiry rejects the proof
as it does a replay.  It returns a fresh dict with the fixed keys
``batch``, ``issuer``, ``keyVersion``, ``signedAt``, ``policyDigest``,
``verdictDigest``, ``status``, ``digest``, ``boundary``, ``items`` and
``version`` (the integer 1).  A non-bytes argument or a field of the
wrong type raises :class:`TypeError` (a :class:`bool` never poses as
an int); an invalid policy, identifier, version or moment raises
:class:`ValueError`; a bound verdict that fails its canonical contract
raises :class:`InvalidRecoveryVerdictError`; a proof with a bad
structure, a recomputed digest mismatch or a wrong batch/threshold
binding raises :class:`InvalidRecoveryVerdictProofError` (both format
errors subclass :class:`ValueError`); unknown, revoked, not-yet-valid
or expired credentials or a signature mismatch raise
:class:`AuthenticationError`.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
from typing import BinaryIO

from offline_coordination import audit, merge, storage

AFTER = "after"
COMPLETE = "complete"
NEED = "need"
NEXT = "next"
RECORDS = "records"
STATUS = "status"
VERSION = "version"

STATUS_MISSING = "missing"
STATUS_APPLIED = "applied"
STATUS_DUPLICATE = "duplicate"

_BATCH_KEYS = (AFTER, COMPLETE, NEXT, RECORDS, VERSION)
_RESULT_KEYS = (NEED, NEXT, STATUS)
_RECORD_KEYS = (
    audit.DETAIL,
    audit.HASH,
    audit.KIND,
    audit.PREV,
    audit.SEQ,
    audit.SOURCE,
)
_BATCH_VERSION = 1
_MIN_LIMIT = 1
_MAX_LIMIT = 1000
_HEX64 = re.compile(r"[0-9a-f]{64}")


def export_batch(path: str, after: int = 0, limit: int = 100) -> bytes:
    """Return one replication batch of audit records as UTF-8 JSON bytes.

    Selects the first ``limit`` records whose ``seq`` is greater than
    ``after``.  ``after`` must not exceed the log's last seq (an empty or
    missing log has last seq 0); otherwise :class:`ValueError` is raised.

    Type violations raise :class:`TypeError` (``bool`` is not accepted as
    an int); ``after < 0`` or a ``limit`` outside ``[1, 1000]`` raises
    :class:`ValueError`.  A corrupt log raises
    :class:`~offline_coordination.audit.CorruptAuditError` and filesystem
    errors propagate as :class:`OSError`.  The log is never modified.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(after, bool) or not isinstance(after, int):
        raise TypeError("after must be an int")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an int")
    if after < 0:
        raise ValueError("after must be >= 0")
    if limit < _MIN_LIMIT or limit > _MAX_LIMIT:
        raise ValueError("limit must be in [1, 1000]")

    all_records = audit.read(path)
    last_seq = all_records[-1][audit.SEQ] if all_records else 0
    if after > last_seq:
        raise ValueError("after must not exceed the last audit seq")

    selected = [record for record in all_records if record[audit.SEQ] > after]
    selected = selected[:limit]
    batch_records = [
        {key: record[key] for key in _RECORD_KEYS} for record in selected
    ]

    next_seq = batch_records[-1][audit.SEQ] if batch_records else after
    batch = {
        AFTER: after,
        COMPLETE: next_seq == last_seq,
        NEXT: next_seq,
        RECORDS: batch_records,
        VERSION: _BATCH_VERSION,
    }
    ordered = {key: batch[key] for key in _BATCH_KEYS}
    text = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"
    return text.encode("utf-8")


def _invalid_batch(message: str) -> ValueError:
    return ValueError(f"invalid replication batch: {message}")


def _compact(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _parse_batch(batch: bytes) -> dict:
    """Validate a batch against the export byte contract and decode it."""
    if not batch.endswith(b"\n") or batch.endswith(b"\n\n"):
        raise _invalid_batch("must be a single JSON object terminated by one LF")
    try:
        data = json.loads(batch[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid_batch("is not valid UTF-8 JSON") from exc

    if not isinstance(data, dict) or tuple(data.keys()) != _BATCH_KEYS:
        raise _invalid_batch(
            "top-level object must have exactly the keys "
            "'after', 'complete', 'next', 'records', 'version' in order"
        )
    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int) or version != _BATCH_VERSION:
        raise _invalid_batch("version must be the integer 1")
    for key in (AFTER, NEXT):
        if isinstance(data[key], bool) or not isinstance(data[key], int):
            raise _invalid_batch(f"{key} must be an int")
        if data[key] < 0:
            raise _invalid_batch(f"{key} must be >= 0")
    if not isinstance(data[COMPLETE], bool):
        raise _invalid_batch("complete must be a bool")
    records = data[RECORDS]
    if not isinstance(records, list):
        raise _invalid_batch("records must be a list")
    if len(records) > _MAX_LIMIT:
        raise _invalid_batch("records must contain at most 1000 items")
    if not records and not data[COMPLETE]:
        raise _invalid_batch("empty records require complete to be true")

    expected_seq = data[AFTER]
    expected_prev = audit._ZERO_HASH if data[AFTER] == 0 else None
    for index, record in enumerate(records):
        if not isinstance(record, dict) or tuple(record.keys()) != _RECORD_KEYS:
            raise _invalid_batch(
                f"record {index} must have exactly the keys "
                "'detail', 'hash', 'kind', 'prev', 'seq', 'source' in order"
            )
        # Only the byte contract is enforced here: key order, the
        # seq/prev/hash chain and the stored values.  Value-domain rules
        # (non-empty fields, the kind enum) belong to audit.append's event
        # input, so records from any log audit.read accepts stay importable.
        prev = record[audit.PREV]
        digest = record[audit.HASH]
        if expected_prev is not None:
            if prev != expected_prev:
                raise _invalid_batch(
                    f"record {index} prev does not match the previous record hash"
                )
        elif not isinstance(prev, str) or not _HEX64.fullmatch(prev):
            # The first record's prev refers to the exporter's log and
            # cannot be checked against local state; require hash shape.
            raise _invalid_batch(f"record {index} prev must be 64 lowercase hex chars")
        seq = record[audit.SEQ]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _invalid_batch(f"record {index} seq must be an int")
        expected_seq += 1
        if seq != expected_seq:
            raise _invalid_batch(
                f"record {index} seq is {seq}, expected {expected_seq}"
            )
        without_hash = {
            audit.DETAIL: record[audit.DETAIL],
            audit.KIND: record[audit.KIND],
            audit.PREV: prev,
            audit.SEQ: seq,
            audit.SOURCE: record[audit.SOURCE],
        }
        if digest != audit._record_hash(without_hash):
            raise _invalid_batch(f"record {index} hash does not match its contents")
        expected_prev = digest

    expected_next = expected_seq if records else data[AFTER]
    if data[NEXT] != expected_next:
        raise _invalid_batch("next must be the last record seq, or after when empty")

    # The bytes must be the exact canonical compact encoding export_batch
    # produces: no whitespace, no non-canonical escapes, fixed key order.
    if _compact(data) + b"\n" != batch:
        raise _invalid_batch("encoding is not the canonical compact form")
    return data


def _restore_log(path: str, existed: bool, size: int) -> None:
    """Best-effort rollback of a failed append.

    Append-mode writes only ever extend the file, so truncating back to
    the pre-call size restores the exact prior bytes; a file the failed
    call newly created is unlinked again.  Rollback errors are swallowed
    so the original :class:`OSError` propagates unchanged.
    """
    try:
        if existed:
            with open(path, "r+b") as handle:
                handle.truncate(size)
                handle.flush()
                os.fsync(handle.fileno())
        else:
            os.unlink(path)
    except OSError:
        pass


def import_batch(path: str, batch: bytes) -> dict:
    """Validate a replication batch and append its suffix to the local log.

    See the module docstring for the byte contract.  A ``path`` that is not
    a str or a ``batch`` that is not bytes raises :class:`TypeError`; any
    contract violation raises :class:`ValueError`.  The local log is read
    solely through :func:`audit.read`, and a corrupt log or filesystem
    error propagates as :class:`~offline_coordination.audit.
    CorruptAuditError` or :class:`OSError`.  Any failure leaves the log
    byte-identical to its pre-call state (still missing when it was
    missing).
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if not isinstance(batch, bytes):
        raise TypeError("batch must be bytes")

    data = _parse_batch(batch)
    after = data[AFTER]
    batch_records = data[RECORDS]

    local_records = audit.read(path)
    last_seq = local_records[-1][audit.SEQ] if local_records else 0

    if after > last_seq:
        return {NEED: [last_seq + 1, after], NEXT: last_seq, STATUS: STATUS_MISSING}

    # Records with seq <= last_seq must already exist locally and match the
    # batch record field by field; everything past last_seq is appended.
    suffix: list[dict] = []
    for record in batch_records:
        seq = record[audit.SEQ]
        if seq <= last_seq:
            local = local_records[seq - 1]
            if any(record[key] != local[key] for key in _RECORD_KEYS):
                raise _invalid_batch(
                    f"record {seq} conflicts with the local record of the same seq"
                )
        else:
            if seq != last_seq + 1 + len(suffix):
                raise _invalid_batch("records past the local last seq must be contiguous")
            suffix.append(record)

    if not suffix:
        return {NEED: None, NEXT: max(last_seq, data[NEXT]), STATUS: STATUS_DUPLICATE}

    # The first appended record must chain onto the local log's last hash
    # (or the zero hash for an empty log).
    local_last_hash = local_records[-1][audit.HASH] if local_records else audit._ZERO_HASH
    if suffix[0][audit.PREV] != local_last_hash:
        raise _invalid_batch(
            "first new record prev must match the local last record hash"
        )

    lines = b"".join(
        audit._encode_line({key: record[key] for key in _RECORD_KEYS})
        for record in suffix
    )
    existed = os.path.exists(path)
    original_size = os.path.getsize(path) if existed else 0
    dir_fd: int | None = None
    try:
        with open(path, "ab") as handle:
            handle.write(lines)
            handle.flush()
            os.fsync(handle.fileno())
        if not existed:
            dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
            os.fsync(dir_fd)
    except OSError:
        _restore_log(path, existed, original_size)
        raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)

    return {NEED: None, NEXT: max(last_seq, data[NEXT]), STATUS: STATUS_APPLIED}



# --- Persistent remote-state application (version-1 ledger) ----------------

APPLY = "apply"
CONFLICT = "conflict"
DECISION = "decision"
ITEMS = "items"
KEY = "key"
RECEIPT = "receipt"
STALE = "stale"

AUDIT = "audit"
AUTH = "auth"
BASE = "base"
BEFORE = "before"
ID = "id"
KEY_VERSION = "keyVersion"
NODE = "node"
REMOTE = "remote"
REQUESTS = "requests"
SOURCE = "source"
STATE_KEY = "state"

LEDGER_VERSION = 1
_LEDGER_TOP_KEYS = (AUDIT, REQUESTS, STATE_KEY, "version")
_LEDGER_ENTRY_KEY_ORDER = (AFTER, BEFORE, ID, "seq", SOURCE)
_LEDGER_ENTRY_KEY_SET = frozenset(_LEDGER_ENTRY_KEY_ORDER)
_LEDGER_ENTRY_AUTHED_SET = _LEDGER_ENTRY_KEY_SET | {AUTH}
_LEDGER_AUTH_KEYS = frozenset((KEY_VERSION, NODE))
_REQUEST_KEYS = (ID, SOURCE, BASE, REMOTE)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


def _ledger_invalid(message: str) -> ValueError:
    return ValueError(f"invalid replication ledger: {message}")


def _state_bytes(state: dict) -> bytes:
    """Canonical compact UTF-8 bytes (with one trailing LF) of a state."""
    clock, records = merge._validated_state(state)
    return storage._serialize(clock, records)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validated_apply_request(
    request: object,
) -> tuple[str, str, dict, dict]:
    """Validate an apply_remote request into (id, source, base, remote).

    The states come back as fresh copies obeying the merge state contract,
    so type errors raised while validating them stay :class:`TypeError`.
    """
    if not isinstance(request, dict):
        raise TypeError("request must be a dict")
    if set(request.keys()) != set(_REQUEST_KEYS):
        raise ValueError(
            "request must contain exactly the keys 'id', 'source', 'base' "
            "and 'remote'"
        )
    request_id = request[ID]
    source = request[SOURCE]
    if not isinstance(request_id, str):
        raise TypeError("request id must be a str")
    if request_id == "":
        raise ValueError("request id must be non-empty")
    if not isinstance(source, str):
        raise TypeError("request source must be a str")
    if source == "":
        raise ValueError("request source must be non-empty")
    base_clock, base_records = merge._validated_state(request[BASE])
    remote_clock, remote_records = merge._validated_state(request[REMOTE])
    base = {merge.CLOCK: base_clock, merge.RECORDS: base_records}
    remote = {merge.CLOCK: remote_clock, merge.RECORDS: remote_records}
    return request_id, source, base, remote


def _request_digest(request_id: str, source: str, base: dict, remote: dict) -> str:
    """SHA-256 of the canonical compact encoding of the logical request."""
    ordered = {
        BASE: {merge.CLOCK: base[merge.CLOCK], merge.RECORDS: base[merge.RECORDS]},
        ID: request_id,
        REMOTE: {
            merge.CLOCK: remote[merge.CLOCK],
            merge.RECORDS: remote[merge.RECORDS],
        },
        SOURCE: source,
    }
    payload = json.dumps(
        ordered, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _digest(payload)


def _serialize_entry(entry: dict) -> dict:
    """One audit entry as stored: the fixed keys plus ``auth`` when present."""
    out = {key: entry[key] for key in _LEDGER_ENTRY_KEY_ORDER}
    if AUTH in entry:
        out[AUTH] = {KEY_VERSION: entry[AUTH][KEY_VERSION], NODE: entry[AUTH][NODE]}
    return out


def _serialize_ledger(
    state: dict, requests: dict[str, str], entries: list[dict]
) -> bytes:
    """Canonical ledger bytes: compact JSON, sorted keys, one trailing LF."""
    ledger = {
        AUDIT: [_serialize_entry(entry) for entry in entries],
        REQUESTS: dict(requests),
        STATE_KEY: {
            merge.CLOCK: state[merge.CLOCK],
            merge.RECORDS: state[merge.RECORDS],
        },
        "version": LEDGER_VERSION,
    }
    text = json.dumps(
        ledger, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ) + "\n"
    return text.encode("utf-8")


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _parse_ledger(raw: bytes) -> tuple[dict, dict[str, str], list[dict]]:
    """Validate every byte of a ledger into (state, requests, audit).

    Any decoding, structural, state, index or chain violation raises
    :class:`ValueError`; in particular a type fault in the stored state is
    an on-disk corruption, not a :class:`TypeError`.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ledger_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _ledger_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _ledger_invalid("must be a JSON object")
    if set(data.keys()) != set(_LEDGER_TOP_KEYS):
        raise _ledger_invalid(
            "must contain exactly the keys 'audit', 'requests', 'state' "
            "and 'version'"
        )
    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _ledger_invalid("version must be an int")
    if version != LEDGER_VERSION:
        raise _ledger_invalid("version must be the integer 1")

    try:
        clock, records = merge._validated_state(data[STATE_KEY])
    except (TypeError, ValueError) as exc:
        raise _ledger_invalid(f"state is invalid: {exc}") from exc
    state = {merge.CLOCK: clock, merge.RECORDS: records}

    raw_requests = data[REQUESTS]
    if not isinstance(raw_requests, dict):
        raise _ledger_invalid("requests must be a JSON object")
    requests: dict[str, str] = {}
    for bound_id, bound_digest in raw_requests.items():
        if not isinstance(bound_id, str) or bound_id == "":
            raise _ledger_invalid("requests keys must be non-empty str")
        if not _is_digest(bound_digest):
            raise _ledger_invalid(
                "requests values must be 64 lowercase hex characters"
            )
        requests[bound_id] = bound_digest

    raw_entries = data[AUDIT]
    if not isinstance(raw_entries, list):
        raise _ledger_invalid("audit must be an array")
    entries: list[dict] = []
    seen_ids: set[str] = set()
    expected_seq = 1
    expected_before: str | None = None
    for position, entry in enumerate(raw_entries):
        if not isinstance(entry, dict):
            raise _ledger_invalid(f"audit entry {position} must be an object")
        entry_keys = set(entry.keys())
        if entry_keys != _LEDGER_ENTRY_KEY_SET and entry_keys != _LEDGER_ENTRY_AUTHED_SET:
            raise _ledger_invalid(
                f"audit entry {position} must contain exactly the keys "
                "'after', 'before', 'id', 'seq' and 'source' with "
                "optional 'auth'"
            )
        after_digest = entry[AFTER]
        before_digest = entry[BEFORE]
        entry_id = entry[ID]
        seq = entry["seq"]
        entry_source = entry[SOURCE]
        if not _is_digest(after_digest):
            raise _ledger_invalid(
                f"audit entry {position} after must be 64 lowercase hex characters"
            )
        if not _is_digest(before_digest):
            raise _ledger_invalid(
                f"audit entry {position} before must be 64 lowercase hex characters"
            )
        if not isinstance(entry_id, str) or entry_id == "":
            raise _ledger_invalid(f"audit entry {position} id must be a non-empty str")
        if not isinstance(entry_source, str) or entry_source == "":
            raise _ledger_invalid(
                f"audit entry {position} source must be a non-empty str"
            )
        parsed_auth = None
        if AUTH in entry:
            # Entries committed through apply_signed_remote carry the
            # credentials they were verified against; entries written by
            # plain apply_remote have none and stay readable.
            auth = entry[AUTH]
            if not isinstance(auth, dict) or set(auth.keys()) != _LEDGER_AUTH_KEYS:
                raise _ledger_invalid(
                    f"audit entry {position} auth must contain exactly the "
                    "keys 'keyVersion' and 'node'"
                )
            auth_node = auth[NODE]
            auth_version = auth[KEY_VERSION]
            if not isinstance(auth_node, str) or auth_node == "":
                raise _ledger_invalid(
                    f"audit entry {position} auth node must be a non-empty str"
                )
            if (
                isinstance(auth_version, bool)
                or not isinstance(auth_version, int)
                or auth_version <= 0
            ):
                raise _ledger_invalid(
                    f"audit entry {position} auth keyVersion must be a "
                    "positive int"
                )
            parsed_auth = {KEY_VERSION: auth_version, NODE: auth_node}
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _ledger_invalid(f"audit entry {position} seq must be an int")
        if seq != expected_seq:
            raise _ledger_invalid(
                f"audit entry {position} seq is {seq}, expected {expected_seq}"
            )
        if entry_id in seen_ids:
            raise _ledger_invalid(
                f"audit entry {position} repeats the already applied id {entry_id!r}"
            )
        if entry_id not in requests:
            raise _ledger_invalid(
                f"audit entry {position} id {entry_id!r} is missing from requests"
            )
        if expected_before is not None and before_digest != expected_before:
            raise _ledger_invalid(
                f"audit entry {position} before does not chain to the previous after"
            )
        parsed_entry = {
            AFTER: after_digest,
            BEFORE: before_digest,
            ID: entry_id,
            "seq": seq,
            SOURCE: entry_source,
        }
        if parsed_auth is not None:
            parsed_entry[AUTH] = parsed_auth
        entries.append(parsed_entry)
        seen_ids.add(entry_id)
        expected_seq += 1
        expected_before = after_digest

    if seen_ids != set(requests):
        raise _ledger_invalid("requests and audit must bind the same ids")
    if entries and entries[-1][AFTER] != _digest(_state_bytes(state)):
        raise _ledger_invalid("last audit after must hash the stored state")

    # The bytes must be the single canonical compact encoding with sorted
    # keys and exactly one trailing newline.
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _ledger_invalid("must end with exactly one newline")
    if _serialize_ledger(state, requests, entries) != raw:
        raise _ledger_invalid("encoding is not the canonical compact form")
    return state, requests, entries


def _read_ledger(
    path: str, base: dict
) -> tuple[dict, dict[str, str], list[dict]]:
    """Load the ledger at ``path``; a missing file stands for ``base``."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        clock, records = merge._validated_state(base)
        return {merge.CLOCK: clock, merge.RECORDS: records}, {}, []
    return _parse_ledger(raw)


def _record_decision(
    local_clock: dict,
    local_record: list | None,
    remote_record: list,
) -> tuple[str, dict | None]:
    """Classify one remote record against the current local state."""
    need = merge._remote_need(remote_record, local_clock)
    if need:
        return STATUS_MISSING, need
    if local_record is None:
        return APPLY, None
    if local_record == remote_record:
        return STATUS_DUPLICATE, None
    if merge._dominates(remote_record[2], local_record[2]):
        return APPLY, None
    if merge._dominates(local_record[2], remote_record[2]):
        return STALE, None
    return CONFLICT, None


def _overall_status(decisions: list[str]) -> str:
    """Overall outcome with missing > conflict > stale > applied > duplicate.

    Any ``missing``/``conflict``/``stale`` item dominates; otherwise the
    request applies as soon as at least one item applies (the rest being
    apply or duplicate), and a batch with nothing to do is duplicate.
    """
    for status in (STATUS_MISSING, CONFLICT, STALE):
        if status in decisions:
            return status
    return STATUS_APPLIED if APPLY in decisions else STATUS_DUPLICATE


def _restore_bytes_quietly(path: str, payload: bytes) -> None:
    """Best-effort rewrite of ``payload`` to ``path`` as one replacement.

    Used when the retained predecessor link is already gone and the
    pre-call bytes survive only in memory.  Every error is swallowed so
    the original exception propagates unchanged.
    """
    tmp_path: str | None = None
    try:
        handle, tmp_path = _reserve_tmp_file(path)
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
        storage._fsync_dir(path)
    except OSError:
        pass
    finally:
        if tmp_path is not None:
            _remove_quietly(tmp_path)


def _rollback_ledger_write(
    path: str,
    tmp_path: str | None,
    backup_path: str | None,
    existed: bool,
    stage: str,
    original: bytes | None,
) -> None:
    """Best-effort rollback of a failed :func:`_atomic_write`.

    ``stage`` records how far the transaction got: ``write`` (temporary
    file written), ``link`` (predecessor hard-linked aside), ``intent``
    (the prepared recovery intent published), ``install`` (temporary
    moved into place), ``sync`` (the directory sync after install),
    ``confirm`` (the installed intent published), ``cleanup`` (the
    predecessor link removed) or ``final`` (the intent removed, its
    directory sync failed).  The predecessor is retained as a hard link
    rather than rewritten, so renaming it back restores the original
    file byte-for-byte (indeed as the same inode) even with no working
    fsync or free space left; once that link is already gone, the
    captured pre-call bytes are rewritten from memory instead.  The
    recovery intent at ``path + ".txn"`` only ever belongs to the failed
    call and is removed as well.  The directory is synced last so the
    recovery is durable.  Every recovery error is swallowed so the
    original exception propagates unchanged.
    """
    try:
        if stage in ("cleanup", "final"):
            # The new ledger was installed and the install synced; only
            # the backup removal, the intent removal or a directory sync
            # failed.  The commit still must not stand: rename the
            # retained link back when it survives, otherwise rewrite the
            # captured pre-call bytes from memory.
            _remove_quietly(tmp_path)
            if backup_path is not None and os.path.exists(backup_path):
                os.replace(backup_path, path)
            elif original is not None:
                _restore_bytes_quietly(path, original)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        elif stage in ("sync", "confirm"):
            _remove_quietly(tmp_path)
            if existed:
                os.replace(backup_path, path)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        elif stage in ("install", "intent"):
            # The replacement did not run: the predecessor at path is
            # untouched; the backup link and temporary file are internal
            # artifacts to remove.
            if backup_path is not None:
                try:
                    os.unlink(backup_path)
                except FileNotFoundError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
        else:
            # write/link stages leave the predecessor in place; the link
            # stage additionally leaves a backup link to remove.
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
            if stage == "link" and backup_path is not None:
                try:
                    os.unlink(backup_path)
                except FileNotFoundError:
                    pass
        # The recovery intent only ever belongs to this transaction.
        _remove_quietly(path + ".txn")
        try:
            storage._fsync_dir(path)
        except OSError:
            pass
    except OSError:
        pass


def _remove_quietly(target: str) -> None:
    """Best-effort unlink that never lets cleanup block the caller."""
    try:
        os.unlink(target)
    except OSError:
        pass


def _reserve_unique_file(prefix: str) -> tuple[BinaryIO, str]:
    """Open a fresh file named ``prefix + <random hex>``, exclusively."""
    last_error: OSError | None = None
    for _ in range(128):
        tmp_path = f"{prefix}{os.urandom(8).hex()}"
        try:
            return open(tmp_path, "xb"), tmp_path
        except FileExistsError as exc:
            last_error = exc
    raise last_error if last_error is not None else OSError(
        "could not reserve a unique transaction file name"
    )


def _reserve_tmp_file(path: str) -> tuple[BinaryIO, str]:
    """Open a fresh, uniquely named transaction file next to ``path``.

    Exclusive binary create (``"xb"``) atomically reserves a random name
    and gives the file the same mode a plain create would; a collision
    simply retries.  The returned open binary handle owns the file until
    the caller closes it.
    """
    return _reserve_unique_file(f"{path}.tmp.")


def _link_predecessor_aside(path: str) -> str:
    """Hard-link the existing ledger to a unique backup name.

    ``os.link`` is atomic and fails with :class:`FileExistsError` when the
    candidate name already exists (for example as a leftover of a killed
    transaction), so the name can be reserved by the link itself without
    any create-then-link window.
    """
    last_error: OSError | None = None
    for _ in range(128):
        backup_path = f"{path}.old.{os.urandom(8).hex()}"
        try:
            os.link(path, backup_path)
        except FileExistsError as exc:
            last_error = exc
            continue
        return backup_path
    # Practically unreachable: 128 random 64-bit name collisions in a row.
    raise last_error if last_error is not None else OSError(
        "could not reserve a ledger backup file name"
    )


# --- Cross-process crash recovery for ledger replacement ---------------------

RECOVERY_VERSION = 1

PHASE_PREPARED = "prepared"
PHASE_INSTALLED = "installed"

STATUS_CLEAN = "clean"
STATUS_ROLLED_BACK = "rolled-back"
STATUS_COMPLETED = "completed"

INTENT_CANDIDATE = "candidate"
INTENT_NEW_DIGEST = "newDigest"
INTENT_OLD_DIGEST = "oldDigest"
INTENT_PHASE = "phase"
INTENT_PREDECESSOR = "predecessor"

_INTENT_KEYS = frozenset((
    INTENT_CANDIDATE,
    INTENT_NEW_DIGEST,
    INTENT_OLD_DIGEST,
    INTENT_PHASE,
    INTENT_PREDECESSOR,
    VERSION,
))


class CorruptRecoveryError(ValueError):
    """A recovery intent or one of its referenced artifacts is corrupt."""


def _recovery_invalid(message: str) -> CorruptRecoveryError:
    return CorruptRecoveryError(f"invalid recovery intent: {message}")


def _intent_compact(obj: object) -> bytes:
    """Canonical compact sorted-key UTF-8 JSON of intent content."""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _intent_payload(
    phase: str,
    new_digest: str,
    old_digest: str | None,
    candidate_name: str,
    predecessor_name: str | None,
) -> bytes:
    """Canonical intent bytes: compact JSON, sorted keys, one trailing LF."""
    intent = {
        INTENT_CANDIDATE: candidate_name,
        INTENT_NEW_DIGEST: new_digest,
        INTENT_OLD_DIGEST: old_digest,
        INTENT_PHASE: phase,
        INTENT_PREDECESSOR: predecessor_name,
        VERSION: RECOVERY_VERSION,
    }
    return _intent_compact(intent) + b"\n"


def _publish_intent(path: str, payload: bytes) -> None:
    """Atomically publish the recovery intent at ``path + ".txn"``.

    The intent is written to a uniquely named temporary in the same
    directory, flushed and synced, then renamed into place and the
    directory synced, so a crash leaves either no intent or the complete
    intent; the intent's own creation and phase change are as durable as
    the transaction steps they record.
    """
    handle, tmp_path = _reserve_unique_file(f"{path}.txn.")
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path + ".txn")
        tmp_path = None
    finally:
        if tmp_path is not None:
            _remove_quietly(tmp_path)
    storage._fsync_dir(path)


def _validated_artifact_name(name: object, key: str, ledger_base: str) -> None:
    """Require a safe base name confined to the ledger's own directory."""
    if not isinstance(name, str) or name == "":
        raise _recovery_invalid(f"{key} must be a non-empty str")
    if (
        name in (".", "..")
        or os.path.basename(name) != name
        or os.sep in name
        or (os.altsep is not None and os.altsep in name)
    ):
        raise _recovery_invalid(f"{key} must be a plain base name")
    if name == ledger_base or name == ledger_base + ".txn":
        raise _recovery_invalid(
            f"{key} must not name the ledger or the intent itself"
        )


def _parse_intent(raw: bytes, ledger_base: str) -> dict:
    """Validate every byte of a recovery intent and return its decoded form.

    Any decoding, structural, phase, name or digest violation raises
    :class:`CorruptRecoveryError`.
    """
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _recovery_invalid("must be a single JSON object ending in one LF")
    try:
        text = raw[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _recovery_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _recovery_invalid("is not valid JSON") from exc

    if not isinstance(data, dict) or set(data.keys()) != _INTENT_KEYS:
        raise _recovery_invalid(
            "must contain exactly the keys 'candidate', 'newDigest', "
            "'oldDigest', 'phase', 'predecessor' and 'version'"
        )
    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _recovery_invalid("version must be an int")
    if version != RECOVERY_VERSION:
        raise _recovery_invalid("version must be the integer 1")
    phase = data[INTENT_PHASE]
    if phase not in (PHASE_PREPARED, PHASE_INSTALLED):
        raise _recovery_invalid("phase must be 'prepared' or 'installed'")
    if not _is_digest(data[INTENT_NEW_DIGEST]):
        raise _recovery_invalid("newDigest must be 64 lowercase hex characters")
    old_digest = data[INTENT_OLD_DIGEST]
    if old_digest is not None and not _is_digest(old_digest):
        raise _recovery_invalid(
            "oldDigest must be null or 64 lowercase hex characters"
        )
    _validated_artifact_name(data[INTENT_CANDIDATE], "candidate", ledger_base)
    predecessor = data[INTENT_PREDECESSOR]
    if predecessor is not None:
        _validated_artifact_name(predecessor, "predecessor", ledger_base)
    if (old_digest is None) != (predecessor is None):
        raise _recovery_invalid(
            "oldDigest and predecessor must both be null or both be set"
        )

    # The bytes must be the single canonical compact encoding with
    # recursively sorted keys and exactly one trailing newline.
    if _intent_compact(data) + b"\n" != raw:
        raise _recovery_invalid("encoding is not the canonical compact form")
    return data


def recover_ledger(path: str) -> dict:
    """Reconcile an interrupted ledger transaction at ``path``.

    When no recovery intent exists at ``path + ".txn"`` the result is
    ``clean`` and no random artifacts are scanned.  Otherwise the intent
    is fully validated -- a parse, field, phase, name, digest or
    necessary-artifact violation raises :class:`CorruptRecoveryError` (a
    :class:`ValueError`) without touching the ledger or any unrelated
    file -- and the interrupted transaction is settled by its phase:

    - ``prepared``: the commit was never confirmed.  The old bytes are
      kept or restored byte-for-byte from the retained predecessor (the
      path stays missing when it was missing) and the referenced new
      candidate is deleted; the status is ``rolled-back``.
    - ``installed``: the new ledger already replaced the old one and the
      directory synced.  The current bytes must hash to ``newDigest``;
      the remaining referenced artifacts are cleaned and the status is
      ``completed``.

    Only files the intent references are removed, the intent itself is
    deleted last and the directory is synced, so a repeated call reports
    ``clean``.  The result is a fresh dict with the key order ``digest``,
    ``status``; ``digest`` is the digest of the resulting ledger bytes,
    or ``None`` when the path is missing.  A ``path`` that is not a str
    raises :class:`TypeError`; an :class:`OSError` while reading,
    replacing, deleting or syncing propagates unchanged with enough
    intent and artifacts left in place for a retry.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    try:
        with open(path + ".txn", "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        # No intent: nothing to settle, and random leftover artifacts
        # are never scanned.  The digest still summarizes the ledger
        # bytes currently at the path (None when the path is missing).
        try:
            with open(path, "rb") as handle:
                current = handle.read()
        except FileNotFoundError:
            current = None
        return {
            "digest": _digest(current) if current is not None else None,
            STATUS: STATUS_CLEAN,
        }

    ledger_base = os.path.basename(path)
    intent = _parse_intent(raw, ledger_base)
    phase = intent[INTENT_PHASE]
    new_digest = intent[INTENT_NEW_DIGEST]
    old_digest = intent[INTENT_OLD_DIGEST]
    directory = os.path.dirname(os.path.abspath(path))
    candidate_path = os.path.join(directory, intent[INTENT_CANDIDATE])
    predecessor_path = (
        os.path.join(directory, intent[INTENT_PREDECESSOR])
        if intent[INTENT_PREDECESSOR] is not None
        else None
    )

    try:
        with open(path, "rb") as handle:
            current = handle.read()
    except FileNotFoundError:
        current = None

    # Every validation finishes before the first mutation, so a
    # CorruptRecoveryError never changes the ledger or any other file.
    restore = False
    remove_path = False
    if phase == PHASE_PREPARED:
        current_digest = _digest(current) if current is not None else None
        if old_digest is None:
            # The path was missing: it may only hold the unconfirmed new
            # bytes (the replacement already ran) and must be missing
            # again after the rollback.
            if current is not None:
                if current_digest != new_digest:
                    raise _recovery_invalid(
                        "ledger bytes do not match newDigest"
                    )
                remove_path = True
        elif current_digest != old_digest:
            if current_digest is not None and current_digest != new_digest:
                raise _recovery_invalid(
                    "ledger bytes match neither oldDigest nor newDigest"
                )
            # The old bytes must come back byte-for-byte from the
            # retained predecessor (also when the path vanished).
            try:
                with open(predecessor_path, "rb") as handle:
                    predecessor = handle.read()
            except FileNotFoundError as exc:
                raise _recovery_invalid(
                    "predecessor artifact is missing"
                ) from exc
            if _digest(predecessor) != old_digest:
                raise _recovery_invalid(
                    "predecessor artifact does not match oldDigest"
                )
            restore = True
    else:
        # installed: the new ledger is the durable content and must
        # still hash to the confirmed digest.
        if current is None:
            raise _recovery_invalid("ledger is missing the installed bytes")
        if _digest(current) != new_digest:
            raise _recovery_invalid(
                "ledger bytes do not match the installed newDigest"
            )

    # Settle the transaction.  The intent survives every failure here
    # (it is deleted last), so an OSError leaves enough state to retry.
    if restore:
        os.replace(predecessor_path, path)
        predecessor_path = None
    elif remove_path:
        os.unlink(path)
    for artifact in (candidate_path, predecessor_path):
        if artifact is None:
            continue
        try:
            os.unlink(artifact)
        except FileNotFoundError:
            pass
    storage._fsync_dir(path)
    os.unlink(path + ".txn")
    storage._fsync_dir(path)

    if phase == PHASE_PREPARED:
        return {"digest": old_digest, STATUS: STATUS_ROLLED_BACK}
    return {"digest": new_digest, STATUS: STATUS_COMPLETED}


# --- Read-only recovery diagnostics and controlled batch recovery ------------

STATUS_PENDING = "pending"
STATUS_BLOCKED = "blocked"
STATUS_FAILED = "failed"

ACTION_ROLLBACK = "rollback"
ACTION_COMPLETE = "complete"

ERROR_CORRUPT = "corrupt"
ERROR_OS_ERROR = "os-error"


def _validated_path_list(paths: object) -> list[str]:
    """Validate an explicit ledger path list before any file is touched.

    The argument must be a non-empty list of non-empty, distinct strings:
    a non-list container or a non-str element raises :class:`TypeError`,
    an empty list, an empty path or a duplicate path raises
    :class:`ValueError`.  Only a fully validated list comes back, so a
    rejected argument guarantees no file was read or modified.
    """
    if not isinstance(paths, list):
        raise TypeError("paths must be a list")
    for path in paths:
        if not isinstance(path, str):
            raise TypeError("paths elements must be str")
    if not paths:
        raise ValueError("paths must be a non-empty list")
    validated: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path == "":
            raise ValueError("paths elements must be non-empty")
        if path in seen:
            raise ValueError(f"duplicate path {path!r}")
        seen.add(path)
        validated.append(path)
    return validated


def _read_bytes_or_none(path: str) -> bytes | None:
    """Return the bytes at ``path``, or None when the path is missing."""
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def _inspect_item(
    path: str,
    status: str,
    phase: str | None,
    digest: str | None,
    artifacts: dict | None,
    action: str | None,
    error: str | None,
) -> dict:
    """One diagnostics report entry with the fixed key order."""
    return {
        "path": path,
        STATUS: status,
        "phase": phase,
        "digest": digest,
        "artifacts": artifacts,
        "action": action,
        "error": error,
    }


def _inspect_one(path: str) -> dict:
    """Diagnose one ledger path without modifying any file.

    Mirrors the validation :func:`recover_ledger` performs, read-only:
    only the ledger, its intent and the artifacts the intent references
    are ever read.
    """
    try:
        raw_intent = _read_bytes_or_none(path + ".txn")
        current = _read_bytes_or_none(path)
        if raw_intent is None:
            # No intent: clean, and random artifacts are never scanned.
            return _inspect_item(
                path,
                STATUS_CLEAN,
                None,
                _digest(current) if current is not None else None,
                None,
                None,
                None,
            )
        try:
            intent = _parse_intent(raw_intent, os.path.basename(path))
        except CorruptRecoveryError:
            return _inspect_item(
                path,
                STATUS_BLOCKED,
                None,
                _digest(current) if current is not None else None,
                None,
                None,
                ERROR_CORRUPT,
            )

        phase = intent[INTENT_PHASE]
        new_digest = intent[INTENT_NEW_DIGEST]
        old_digest = intent[INTENT_OLD_DIGEST]
        directory = os.path.dirname(os.path.abspath(path))
        candidate = _read_bytes_or_none(
            os.path.join(directory, intent[INTENT_CANDIDATE])
        )
        predecessor_name = intent[INTENT_PREDECESSOR]
        predecessor = (
            _read_bytes_or_none(os.path.join(directory, predecessor_name))
            if predecessor_name is not None
            else None
        )
    except OSError:
        return _inspect_item(path, STATUS_FAILED, None, None, None, None, ERROR_OS_ERROR)

    current_digest = _digest(current) if current is not None else None
    artifacts = {
        INTENT_CANDIDATE: {
            "exists": candidate is not None,
            "matches": (
                _digest(candidate) == new_digest if candidate is not None else None
            ),
        },
        INTENT_PREDECESSOR: (
            None
            if predecessor_name is None
            else {
                "exists": predecessor is not None,
                "matches": (
                    _digest(predecessor) == old_digest
                    if predecessor is not None
                    else None
                ),
            }
        ),
        COMPLETE: True,
    }

    # The same necessary-artifact and digest rules recover_ledger
    # enforces, evaluated without settling anything.
    corrupt = False
    if phase == PHASE_PREPARED:
        if old_digest is None:
            if current is not None and current_digest != new_digest:
                corrupt = True
        elif current_digest != old_digest:
            if current_digest is not None and current_digest != new_digest:
                corrupt = True
            elif predecessor is None or _digest(predecessor) != old_digest:
                corrupt = True
    else:
        if current is None or current_digest != new_digest:
            corrupt = True

    action = ACTION_ROLLBACK if phase == PHASE_PREPARED else ACTION_COMPLETE
    if corrupt:
        artifacts[COMPLETE] = False
        return _inspect_item(
            path, STATUS_BLOCKED, phase, current_digest, artifacts, action,
            ERROR_CORRUPT,
        )
    return _inspect_item(
        path, STATUS_PENDING, phase, current_digest, artifacts, action, None
    )


def inspect_recovery(paths: list[str]) -> list[dict]:
    """Read-only recovery diagnostics for an explicit list of ledgers.

    ``paths`` must be a non-empty list of non-empty, distinct strings;
    the whole list is validated before any file is read, so a
    :class:`TypeError` (container or element type) or :class:`ValueError`
    (empty list, empty path, duplicate path) guarantees nothing was
    touched.  Only the listed ledgers, their intents and the artifacts
    those intents reference are ever read -- random leftover artifacts
    are never scanned -- and no file is created, modified or deleted.

    The result is one fresh report dict per path, in the given order,
    with the fixed key order ``path``, ``status``, ``phase``, ``digest``,
    ``artifacts``, ``action``, ``error``.  ``digest`` is the lowercase
    hex SHA-256 of the current ledger bytes, or ``None`` when the path
    is missing.  Without an intent the status is ``clean`` and ``phase``,
    ``artifacts``, ``action`` and ``error`` are all ``None``.  A valid
    intent reports ``pending`` with its ``phase`` and the suggested
    ``action`` (``rollback`` for ``prepared``, ``complete`` for
    ``installed``); ``artifacts`` then tells for the candidate and the
    predecessor whether each exists and matches its recorded digest and
    whether every necessary artifact is complete.  An intent or a
    necessary artifact that fails validation yields ``blocked`` with
    error ``corrupt`` instead of raising, and an :class:`OSError` while
    reading yields ``failed`` with error ``os-error``; either way the
    remaining paths are still diagnosed.
    """
    return [_inspect_one(path) for path in _validated_path_list(paths)]


def recover_many(paths: list[str]) -> list[dict]:
    """Recover every ledger in an explicit path list, in order.

    ``paths`` is validated exactly as in :func:`inspect_recovery` before
    anything is read or modified.  Each path is then settled through
    :func:`recover_ledger` in the given order; one ledger's failure never
    stops the later ones, and ledgers already recovered are never rolled
    back because a later one failed.

    The result is one fresh report dict per path, in the given order,
    with the fixed key order ``path``, ``status``, ``digest``, ``error``.
    A successful recovery keeps the :func:`recover_ledger` status
    (``clean``, ``rolled-back`` or ``completed``) and its digest, with
    ``error`` ``None``.  A :class:`CorruptRecoveryError` becomes a
    ``blocked`` item with error ``corrupt`` and an :class:`OSError` a
    ``failed`` item with error ``os-error``; both carry a ``None``
    digest, and the intent and artifacts the failing recovery left
    behind stay in place, so re-running the call retries each failed
    ledger independently.
    """
    items: list[dict] = []
    for path in _validated_path_list(paths):
        try:
            result = recover_ledger(path)
        except CorruptRecoveryError:
            items.append(
                {
                    "path": path,
                    STATUS: STATUS_BLOCKED,
                    "digest": None,
                    "error": ERROR_CORRUPT,
                }
            )
        except OSError:
            items.append(
                {
                    "path": path,
                    STATUS: STATUS_FAILED,
                    "digest": None,
                    "error": ERROR_OS_ERROR,
                }
            )
        else:
            items.append(
                {
                    "path": path,
                    STATUS: result[STATUS],
                    "digest": result["digest"],
                    "error": None,
                }
            )
    return items


def _atomic_write(path: str, payload: bytes) -> None:
    """Durably replace ``path`` with ``payload`` as a single transaction.

    Every transaction uses *unique* file names (an exclusively created
    ``path + ".tmp.<random>"`` temporary and a random-suffixed hard link
    for the predecessor), so a fixed ``path + ".tmp"``/``path + ".old"``
    leftover from an older interrupted process never collides with a
    fresh commit.  Such fixed leftovers are internal artifacts: they are
    never read as a ledger and are swept best-effort before the
    transaction starts -- a sweep failure cannot block the commit, which
    never depends on those names.

    Before anything is replaced, a recovery intent is published at
    ``path + ".txn"`` (see :func:`recover_ledger`) in phase ``prepared``,
    recording both ledger digests and the base names of the candidate
    and predecessor; after the replacement and its directory sync the
    intent is republished in phase ``installed`` and only then are the
    predecessor link and the intent removed.  A crash of the process at
    any point leaves a state a later :func:`recover_ledger` settles.

    The temporary file's write, flush and file sync, the intent
    publications, the replacement, the directory sync after the install
    and the directory sync after the cleanup all lie inside the
    boundary.  An existing predecessor is retained as a hard link --
    without ever removing ``path`` -- until the new file is installed
    and the directory has synced, and its pre-call bytes are
    additionally held in memory until the cleanup completes, so an
    :class:`OSError` at any stage rolls the whole transaction back: the
    prior file returns byte-for-byte (renamed back as the same inode
    while the retained link survives, rewritten from the captured bytes
    once the link was already removed), and a path the call created is
    removed again.  The rollback syncs the directory as well, and the
    original :class:`OSError` propagates unchanged.  On success both the
    file and the directory have been synced and neither a temporary
    file, a predecessor link nor a recovery intent remains.
    """
    existed = os.path.exists(path)
    # Retained fixed-name artifacts from earlier interrupted calls are
    # internal, never read as a ledger, and must never stand in the way of
    # a fresh transaction; the transaction itself uses unique names.
    _remove_quietly(path + ".tmp")
    _remove_quietly(path + ".old")

    # The pre-call bytes are captured up front so the transaction can
    # still be rolled back byte-for-byte after the retained predecessor
    # link is gone.
    original: bytes | None = None
    if existed:
        with open(path, "rb") as handle:
            original = handle.read()

    new_digest = _digest(payload)
    old_digest = _digest(original) if original is not None else None

    tmp_handle, tmp_path = _reserve_tmp_file(path)
    backup_path: str | None = None
    stage = "write"
    try:
        with tmp_handle as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if existed:
            backup_path = _link_predecessor_aside(path)
            stage = "link"
        # The prepared intent makes the unconfirmed transaction visible
        # to a later recover_ledger before anything is replaced.
        _publish_intent(
            path,
            _intent_payload(
                PHASE_PREPARED,
                new_digest,
                old_digest,
                os.path.basename(tmp_path),
                os.path.basename(backup_path)
                if backup_path is not None
                else None,
            ),
        )
        stage = "install"
        os.replace(tmp_path, path)
        stage = "sync"
        storage._fsync_dir(path)
        # Only now is the commit confirmed: the installed intent tells a
        # later recover_ledger that the new bytes are the durable ones.
        stage = "confirm"
        _publish_intent(
            path,
            _intent_payload(
                PHASE_INSTALLED,
                new_digest,
                old_digest,
                os.path.basename(tmp_path),
                os.path.basename(backup_path)
                if backup_path is not None
                else None,
            ),
        )
        if backup_path is not None:
            # The backup link's removal itself is best-effort (a
            # leftover is internal and swept by the next commit), but
            # the directory sync persisting the cleanup belongs to the
            # same transaction boundary: its failure still rolls the
            # commit back instead of standing as a success.
            stage = "cleanup"
            _remove_quietly(backup_path)
        # The intent is deleted last; only then is the transaction over.
        # Its removal is best-effort like the backup link's: a leftover
        # installed intent is internal, never read as a ledger, and is
        # settled by the next recover_ledger, but the directory sync
        # persisting the cleanup stays inside the transaction boundary.
        stage = "final"
        _remove_quietly(path + ".txn")
        storage._fsync_dir(path)
    except BaseException:
        _rollback_ledger_write(
            path, tmp_path, backup_path, existed, stage, original
        )
        raise


def apply_remote(path: str, request: dict) -> dict:
    """Persistently apply one remote state request to the ledger at ``path``.

    ``request`` must contain exactly the keys ``id`` and ``source`` (both
    non-empty str) and ``base`` and ``remote`` (states obeying the
    :mod:`~offline_coordination.merge` contract).  ``path`` is a version-1
    ledger; when it is missing the current state is taken to be ``base``
    with empty request/audit indexes, otherwise the stored ``state``,
    ``requests`` and ``audit`` are fully validated before anything else.

    An unknown ``id`` whose current state differs from ``base`` returns
    ``stale`` without touching the filesystem.  A known ``id`` whose bound
    request digest matches replays as ``duplicate``: the verdict comes from
    the saved binding alone, so the result is the same immediately or after
    later successful commits.  Its items list every remote record in
    ascending key order, each already ``duplicate`` with ``need`` an empty
    mapping, ``receipt`` is ``None`` and the ledger bytes are unchanged.  A
    known ``id`` presented with different contents raises
    :class:`ValueError`.

    Otherwise the remote records are examined in ascending key order.  A
    record whose prerequisite (its clock with the ``writer`` component
    decremented by one) is not covered by the local outer clock is
    ``missing`` and its item's ``need`` lists the closed intervals still
    required per node.  With prerequisites satisfied, an equal record is
    ``duplicate``, a remote-dominating record ``apply``, a local-dominating
    record ``stale`` and a concurrent record ``conflict``.

    The overall status follows the precedence ``missing``, ``conflict``,
    ``stale``, ``duplicate``, ``applied``; only an outcome of at least one
    ``apply`` with every other item ``apply`` or ``duplicate`` commits:
    those records are updated, the outer clock is raised per node, one
    chained audit entry (id, source, before/after state digests, seq) is
    appended and the request digest is bound in ``requests``, via one
    atomic replacement.

    The result has the key order ``items``, ``receipt``, ``status``; items
    have ``key``, ``decision``, ``need`` (``need`` is ``None`` except for
    ``missing`` items, which map the still-required intervals, and
    replayed duplicates, which carry an empty mapping) and ``receipt`` is
    ``None`` unless committed.  Type violations raise :class:`TypeError`
    without creating any file; every other contract or ledger violation
    raises :class:`ValueError` and an invalid existing ledger is never
    written.  A failure while writing, flushing, syncing, replacing or
    syncing the directory propagates unchanged as :class:`OSError` and the
    file system is restored to its pre-call state: an existing ledger keeps
    its exact prior bytes, a missing ledger stays missing (with no
    recognizable file or temporary artifact left behind), and the rollback
    syncs the directory itself.
    """
    return _apply(path, request, None)


def _apply(path: str, request: dict, auth: dict | None) -> dict:
    """Shared body of :func:`apply_remote` and :func:`apply_signed_remote`.

    ``auth`` is ``None`` for an unsigned application; otherwise it holds
    the verified ``node``/``keyVersion`` pair to record on the committed
    audit entry.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")

    request_id, source, base, remote = _validated_apply_request(request)

    # Settle any interrupted earlier commit before the ledger is read.
    recover_ledger(path)

    state, requests, entries = _read_ledger(path, base)

    if request_id in requests:
        if requests[request_id] != _request_digest(request_id, source, base, remote):
            raise ValueError(
                f"request id {request_id!r} is already bound to a different request"
            )
        # The saved request binding is the whole replay verdict: regardless
        # of how far the ledger state has advanced since the original
        # commit, every record the replayed request carries is reported
        # already duplicate, with no receipt and no filesystem change.
        items = [
            {KEY: key, DECISION: STATUS_DUPLICATE, NEED: {}}
            for key in sorted(remote[merge.RECORDS])
        ]
        return {ITEMS: items, RECEIPT: None, STATUS: STATUS_DUPLICATE}

    current_bytes = _state_bytes(state)
    if current_bytes != _state_bytes(base):
        # An unseen id must be offered against exactly the state it claims
        # as its base; per-record examination happens only past this gate.
        return {ITEMS: [], RECEIPT: None, STATUS: STALE}

    remote_records = remote[merge.RECORDS]
    items: list[dict] = []
    decisions: list[str] = []
    for key in sorted(remote_records):
        remote_record = remote_records[key]
        decision, need = _record_decision(
            state[merge.CLOCK], state[merge.RECORDS].get(key), remote_record
        )
        items.append({KEY: key, DECISION: decision, NEED: need})
        decisions.append(decision)

    status = _overall_status(decisions)
    if status != STATUS_APPLIED:
        return {ITEMS: items, RECEIPT: None, STATUS: status}

    before_digest = _digest(current_bytes)
    new_clock = dict(state[merge.CLOCK])
    new_records = {
        key: [value, deleted, dict(clock), writer]
        for key, (value, deleted, clock, writer) in state[merge.RECORDS].items()
    }
    for item in items:
        if item[DECISION] != APPLY:
            continue
        value, deleted, clock, writer = remote_records[item[KEY]]
        new_records[item[KEY]] = [value, deleted, dict(clock), writer]
        for node, count in clock.items():
            if count > new_clock.get(node, 0):
                new_clock[node] = count
    new_state = {merge.CLOCK: new_clock, merge.RECORDS: new_records}

    after_digest = _digest(_state_bytes(new_state))
    seq = len(entries) + 1
    new_entry = {
        AFTER: after_digest,
        BEFORE: before_digest,
        ID: request_id,
        "seq": seq,
        SOURCE: source,
    }
    if auth is not None:
        new_entry[AUTH] = {KEY_VERSION: auth[KEY_VERSION], NODE: auth[NODE]}
    new_entries = entries + [new_entry]
    new_requests = dict(requests)
    new_requests[request_id] = _request_digest(request_id, source, base, remote)

    _atomic_write(path, _serialize_ledger(new_state, new_requests, new_entries))

    return {
        ITEMS: items,
        RECEIPT: {
            ID: request_id,
            SOURCE: source,
            BEFORE: before_digest,
            AFTER: after_digest,
            "seq": seq,
        },
        STATUS: STATUS_APPLIED,
    }


# --- Authenticated remote-state application (signed envelopes) --------------

REQUEST = "request"
REVOKED = "revoked"
SECRET = "secret"
SIGNATURE = "signature"
NOT_BEFORE = "notBefore"
NOT_AFTER = "notAfter"

_ENVELOPE_KEYS = frozenset((NODE, KEY_VERSION, REQUEST, SIGNATURE))
_KEYRING_ENTRY_KEYS = frozenset((VERSION, SECRET, NOT_BEFORE, NOT_AFTER, REVOKED))


class AuthenticationError(ValueError):
    """A signed replication envelope failed authentication."""


def _validated_keyring(keyring: object) -> dict[str, list[dict]]:
    """Validate a keyring into a fresh ``{node: [entry]}`` mapping.

    Type faults raise :class:`TypeError`; key sets, ranges, duplicate
    versions, secret formats and validity periods raise
    :class:`ValueError`.
    """
    if not isinstance(keyring, dict):
        raise TypeError("keyring must be a dict")
    result: dict[str, list[dict]] = {}
    for node, entries in keyring.items():
        if not isinstance(node, str):
            raise TypeError("keyring node names must be str")
        if node == "":
            raise ValueError("keyring node names must be non-empty")
        if not isinstance(entries, list):
            raise TypeError(f"keyring entries for node {node!r} must be a list")
        validated: list[dict] = []
        seen_versions: set[int] = set()
        for position, entry in enumerate(entries):
            where = f"keyring entry {position} for node {node!r}"
            if not isinstance(entry, dict):
                raise TypeError(f"{where} must be a dict")
            if set(entry.keys()) != _KEYRING_ENTRY_KEYS:
                raise ValueError(
                    f"{where} must contain exactly the keys 'version', "
                    "'secret', 'notBefore', 'notAfter' and 'revoked'"
                )
            version = entry[VERSION]
            if isinstance(version, bool) or not isinstance(version, int):
                raise TypeError(f"{where} version must be an int")
            if version <= 0:
                raise ValueError(f"{where} version must be positive")
            if version in seen_versions:
                raise ValueError(
                    f"{where} repeats key version {version} for node {node!r}"
                )
            seen_versions.add(version)
            secret = entry[SECRET]
            if not isinstance(secret, str):
                raise TypeError(f"{where} secret must be a str")
            if _HEX64.fullmatch(secret) is None:
                raise ValueError(
                    f"{where} secret must be 64 lowercase hex characters"
                )
            bounds: dict[str, int] = {}
            for bound_key in (NOT_BEFORE, NOT_AFTER):
                bound = entry[bound_key]
                if isinstance(bound, bool) or not isinstance(bound, int):
                    raise TypeError(f"{where} {bound_key} must be an int")
                if bound < 0:
                    raise ValueError(f"{where} {bound_key} must be non-negative")
                bounds[bound_key] = bound
            if bounds[NOT_BEFORE] > bounds[NOT_AFTER]:
                raise ValueError(
                    f"{where} notBefore must not exceed notAfter"
                )
            revoked = entry[REVOKED]
            if not isinstance(revoked, bool):
                raise TypeError(f"{where} revoked must be a bool")
            validated.append(
                {
                    VERSION: version,
                    SECRET: secret,
                    NOT_BEFORE: bounds[NOT_BEFORE],
                    NOT_AFTER: bounds[NOT_AFTER],
                    REVOKED: revoked,
                }
            )
        result[node] = validated
    return result


def _validated_envelope(envelope: object) -> tuple[str, int, object, str]:
    """Validate an envelope into (node, key_version, request, signature)."""
    if not isinstance(envelope, dict):
        raise TypeError("envelope must be a dict")
    if set(envelope.keys()) != _ENVELOPE_KEYS:
        raise ValueError(
            "envelope must contain exactly the keys 'node', 'keyVersion', "
            "'request' and 'signature'"
        )
    node = envelope[NODE]
    if not isinstance(node, str):
        raise TypeError("envelope node must be a str")
    if node == "":
        raise ValueError("envelope node must be non-empty")
    key_version = envelope[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("envelope keyVersion must be an int")
    if key_version <= 0:
        raise ValueError("envelope keyVersion must be positive")
    signature = envelope[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("envelope signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise ValueError(
            "envelope signature must be 64 lowercase hex characters"
        )
    return node, key_version, envelope[REQUEST], signature


def _signed_payload(node: str, key_version: int, request: object) -> bytes:
    """The signed bytes: canonical compact JSON of node/keyVersion/request."""
    ordered = {KEY_VERSION: key_version, NODE: node, REQUEST: request}
    return json.dumps(
        ordered, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _authenticate(
    keyring: dict[str, list[dict]],
    node: str,
    key_version: int,
    request: object,
    source: str,
    signature: str,
    moment: int,
) -> None:
    """Verify the envelope against the current keyring.

    The key is selected by exact node and version with no fallback and
    must be usable *now*: unknown credentials, a revoked, not-yet-valid or
    expired key, a request source other than the envelope node and a
    signature mismatch all raise :class:`AuthenticationError`.
    """
    entry = None
    for candidate in keyring.get(node, ()):
        if candidate[VERSION] == key_version:
            entry = candidate
            break
    if entry is None:
        raise AuthenticationError(
            f"no credentials for node {node!r} and key version {key_version}"
        )
    if entry[REVOKED]:
        raise AuthenticationError(
            f"credentials for node {node!r} key version {key_version} "
            "are revoked"
        )
    if moment < entry[NOT_BEFORE]:
        raise AuthenticationError(
            f"credentials for node {node!r} key version {key_version} "
            "are not yet valid"
        )
    if moment > entry[NOT_AFTER]:
        raise AuthenticationError(
            f"credentials for node {node!r} key version {key_version} "
            "have expired"
        )
    if source != node:
        raise AuthenticationError(
            f"request source {source!r} does not match envelope node {node!r}"
        )
    expected = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _signed_payload(node, key_version, request),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise AuthenticationError("signature does not match the envelope")


def apply_signed_remote(
    path: str, keyring: dict, envelope: dict, moment: int
) -> dict:
    """Verify a signed envelope, then apply it like :func:`apply_remote`.

    ``keyring`` maps node names to credential entries (see the module
    docstring), ``envelope`` carries exactly ``node``, ``keyVersion``,
    ``request`` and ``signature``, and ``moment`` is the current time as a
    non-negative integer.  The request inside the envelope follows the
    :func:`apply_remote` contract and its ``source`` must equal the
    envelope's ``node``.

    Authentication runs before the ledger is ever read, so a failed
    verification raises :class:`AuthenticationError` (a
    :class:`ValueError`) without creating or modifying any file; replays
    are authenticated against the current keyring, so a key revoked or
    expired since the original commit rejects the replay instead of
    serving the historical binding.  A verified envelope is applied by the
    exact :func:`apply_remote` flow with the same result shape; a commit
    additionally records the verified ``node`` and ``keyVersion`` under
    ``auth`` in the new audit entry.

    Type violations in any argument or field raise :class:`TypeError`;
    key sets, ranges, duplicate key versions, secret/signature formats
    and validity periods raise :class:`ValueError`.  Ledger corruption
    raises :class:`ValueError`, and a write, flush, sync or replacement
    failure propagates unchanged as :class:`OSError` with the file system
    restored to its pre-call state.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    validated_keyring = _validated_keyring(keyring)
    node, key_version, request, signature = _validated_envelope(envelope)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    _, source, _, _ = _validated_apply_request(request)
    _authenticate(
        validated_keyring, node, key_version, request, source, signature, moment
    )
    return _apply(path, request, {KEY_VERSION: key_version, NODE: node})


# --- Offline audit-range proofs ----------------------------------------------

PROOF_DIGEST = "digest"
PROOF_END_SEQ = "endSeq"
PROOF_ENTRIES = "entries"
PROOF_FIRST_BEFORE = "firstBefore"
PROOF_LAST_AFTER = "lastAfter"
PROOF_START_SEQ = "startSeq"

PROOF_VERSION = 1
_PROOF_TOP_KEYS = frozenset((
    PROOF_DIGEST,
    PROOF_END_SEQ,
    PROOF_ENTRIES,
    PROOF_FIRST_BEFORE,
    PROOF_LAST_AFTER,
    PROOF_START_SEQ,
    VERSION,
))
_PROOF_RESULT_KEYS = (
    PROOF_START_SEQ,
    PROOF_END_SEQ,
    PROOF_FIRST_BEFORE,
    PROOF_LAST_AFTER,
    "signedEntries",
    "unsignedEntries",
)


class InvalidProofError(ValueError):
    """An audit proof fails its offline byte, chain or digest contract."""


def _proof_invalid(message: str) -> InvalidProofError:
    return InvalidProofError(f"invalid audit proof: {message}")


def _proof_compact(obj: object) -> bytes:
    """Canonical compact sorted-key UTF-8 JSON of proof content."""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate object keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _proof_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def export_proof(path: str, start_seq: int, end_seq: int | None = None) -> bytes:
    """Export a self-certifying audit-range proof from the ledger at ``path``.

    The proof covers the ledger's audit entries with ``startSeq <= seq <=
    endSeq``.  ``start_seq`` must be at least 1; when ``end_seq`` is
    omitted the range runs through the ledger's last entry.  The range
    must lie completely inside the existing, non-empty audit sequence.

    The result is canonical version-1 proof bytes: one compact UTF-8 JSON
    object with every object key recursively sorted lexicographically,
    non-ASCII preserved unescaped and exactly one trailing ``\\n``.  It
    declares ``version`` (the integer 1), the range, ``firstBefore`` (the
    before-digest of the first entry) and ``lastAfter`` (the after-digest
    of the last one), carries the unchanged ledger entries, and binds the
    whole content with ``digest``, the lowercase hex SHA-256 of the
    canonical encoding of the proof with its ``digest`` key removed.

    The ledger is opened read-only and never modified.  Type violations
    (including a :class:`bool` posing as an int or as ``path``) raise
    :class:`TypeError`; an inverted or out-of-range request, an empty
    audit and a corrupt ledger raise :class:`ValueError`; a missing
    ledger raises :class:`FileNotFoundError` and every other read failure
    propagates unchanged as :class:`OSError`.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(start_seq, bool) or not isinstance(start_seq, int):
        raise TypeError("start_seq must be an int")
    if end_seq is not None and (
        isinstance(end_seq, bool) or not isinstance(end_seq, int)
    ):
        raise TypeError("end_seq must be an int or None")
    if start_seq < 1:
        raise ValueError("start_seq must be >= 1")
    if end_seq is not None and end_seq < start_seq:
        raise ValueError("end_seq must not be less than start_seq")

    with open(path, "rb") as handle:
        raw = handle.read()
    # A missing file propagates as FileNotFoundError; a corrupt ledger as
    # ValueError; any other read failure already propagated as OSError.
    _state, _requests, entries = _parse_ledger(raw)

    total = len(entries)
    if total == 0:
        raise ValueError("cannot export a proof from an empty audit")
    if start_seq > total:
        raise ValueError("start_seq must not exceed the last audit seq")
    if end_seq is None:
        end_seq = total
    elif end_seq > total:
        raise ValueError("end_seq must not exceed the last audit seq")

    selected = entries[start_seq - 1:end_seq]
    body = {
        PROOF_END_SEQ: end_seq,
        PROOF_ENTRIES: [_serialize_entry(entry) for entry in selected],
        PROOF_FIRST_BEFORE: selected[0][BEFORE],
        PROOF_LAST_AFTER: selected[-1][AFTER],
        PROOF_START_SEQ: start_seq,
        VERSION: PROOF_VERSION,
    }
    digest = hashlib.sha256(_proof_compact(body)).hexdigest()
    proof = dict(body)
    proof[PROOF_DIGEST] = digest
    return _proof_compact(proof) + b"\n"


def _parse_proof(raw: bytes) -> dict:
    """Validate every byte and link of a proof and return its decoded form."""
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _proof_invalid("must be a single JSON object ending in one LF")
    try:
        text = raw[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _proof_invalid("is not valid UTF-8") from exc
    try:
        # The pairs hook raises directly on duplicate object keys, so a
        # ValueError raised here means that contract fault, not bad JSON.
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise _proof_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _proof_invalid("must be a JSON object")
    if set(data.keys()) != _PROOF_TOP_KEYS:
        raise _proof_invalid(
            "top-level object must contain exactly the keys 'digest', "
            "'endSeq', 'entries', 'firstBefore', 'lastAfter', 'startSeq' "
            "and 'version'"
        )
    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _proof_invalid("version must be an int")
    if version != PROOF_VERSION:
        raise _proof_invalid("version must be the integer 1")

    start = data[PROOF_START_SEQ]
    end = data[PROOF_END_SEQ]
    if isinstance(start, bool) or not isinstance(start, int):
        raise _proof_invalid("startSeq must be an int")
    if isinstance(end, bool) or not isinstance(end, int):
        raise _proof_invalid("endSeq must be an int")
    if start < 1:
        raise _proof_invalid("startSeq must be >= 1")
    if end < start:
        raise _proof_invalid("endSeq must not be less than startSeq")

    first_before = data[PROOF_FIRST_BEFORE]
    last_after = data[PROOF_LAST_AFTER]
    if not _is_digest(first_before):
        raise _proof_invalid("firstBefore must be 64 lowercase hex characters")
    if not _is_digest(last_after):
        raise _proof_invalid("lastAfter must be 64 lowercase hex characters")

    raw_entries = data[PROOF_ENTRIES]
    if not isinstance(raw_entries, list):
        raise _proof_invalid("entries must be an array")
    expected_count = end - start + 1
    if len(raw_entries) != expected_count:
        raise _proof_invalid(
            f"entries must contain exactly the {expected_count} items of the "
            "declared range"
        )

    signed = 0
    parsed_entries: list[dict] = []
    previous_after: str | None = None
    for position, entry in enumerate(raw_entries):
        where = f"entry {position}"
        if not isinstance(entry, dict):
            raise _proof_invalid(f"{where} must be a JSON object")
        keys = set(entry.keys())
        if keys != _LEDGER_ENTRY_KEY_SET and keys != _LEDGER_ENTRY_AUTHED_SET:
            raise _proof_invalid(
                f"{where} must contain exactly the keys 'after', 'before', "
                "'id', 'seq' and 'source' with optional 'auth'"
            )
        before = entry[BEFORE]
        after = entry[AFTER]
        entry_id = entry[ID]
        source = entry[SOURCE]
        seq = entry["seq"]
        if not _is_digest(before):
            raise _proof_invalid(f"{where} before must be 64 lowercase hex chars")
        if not _is_digest(after):
            raise _proof_invalid(f"{where} after must be 64 lowercase hex chars")
        if not isinstance(entry_id, str) or entry_id == "":
            raise _proof_invalid(f"{where} id must be a non-empty str")
        if not isinstance(source, str) or source == "":
            raise _proof_invalid(f"{where} source must be a non-empty str")
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _proof_invalid(f"{where} seq must be an int")
        expected_seq = start + position
        if seq != expected_seq:
            raise _proof_invalid(
                f"{where} seq is {seq}, expected {expected_seq}"
            )
        expected_before = first_before if position == 0 else previous_after
        if before != expected_before:
            raise _proof_invalid(
                f"{where} before does not chain to the previous after"
            )
        if AUTH in entry:
            auth = entry[AUTH]
            if not isinstance(auth, dict) or set(auth.keys()) != _LEDGER_AUTH_KEYS:
                raise _proof_invalid(
                    f"{where} auth must contain exactly the keys "
                    "'keyVersion' and 'node'"
                )
            node = auth[NODE]
            key_version = auth[KEY_VERSION]
            if not isinstance(node, str) or node == "":
                raise _proof_invalid(f"{where} auth node must be a non-empty str")
            if (
                isinstance(key_version, bool)
                or not isinstance(key_version, int)
                or key_version <= 0
            ):
                raise _proof_invalid(
                    f"{where} auth keyVersion must be a positive non-bool int"
                )
            signed += 1
        parsed_entry = {
            AFTER: after,
            BEFORE: before,
            ID: entry_id,
            "seq": expected_seq,
            SOURCE: source,
        }
        if AUTH in entry:
            parsed_entry[AUTH] = {
                KEY_VERSION: entry[AUTH][KEY_VERSION],
                NODE: entry[AUTH][NODE],
            }
        parsed_entries.append(parsed_entry)
        previous_after = after

    if previous_after != last_after:
        raise _proof_invalid("lastAfter must equal the last entry's after")

    claimed = data[PROOF_DIGEST]
    if not _is_digest(claimed):
        raise _proof_invalid("digest must be 64 lowercase hex characters")
    unsigned = expected_count - signed
    body = {key: value for key, value in data.items() if key != PROOF_DIGEST}
    actual = hashlib.sha256(_proof_compact(body)).hexdigest()
    if not hmac.compare_digest(actual, claimed):
        raise _proof_invalid("digest does not match the proof contents")

    # The bytes must be the single canonical compact form with sorted keys
    # and exactly one trailing newline: no whitespace, no non-canonical
    # escapes, no permuted keys, no escaped non-ASCII.
    if _proof_compact(data) + b"\n" != raw:
        raise _proof_invalid("encoding is not the canonical compact form")

    return {
        PROOF_START_SEQ: start,
        PROOF_END_SEQ: end,
        PROOF_FIRST_BEFORE: first_before,
        PROOF_LAST_AFTER: last_after,
        PROOF_DIGEST: claimed,
        PROOF_ENTRIES: parsed_entries,
        "signedEntries": signed,
        "unsignedEntries": unsigned,
    }


def verify_proof(proof: bytes) -> dict:
    """Verify an audit proof without consulting the ledger or any keyring.

    ``proof`` must be :class:`bytes` produced by :func:`export_proof`.
    Verification checks the canonical encoding, the unique key set, the
    integer version 1, the overall digest, the contiguous unique entry
    sequence and the before/after state-digest chain, and matches the
    declared range boundaries.

    On success a fresh dict is returned with the key order ``startSeq``,
    ``endSeq``, ``firstBefore``, ``lastAfter``, ``signedEntries`` and
    ``unsignedEntries``: the covered range, its boundary state digests and
    the counts of entries with and without an ``auth`` binding.  Any
    encoding, key-set, version, digest, gap, duplicate, reordering, chain,
    tamper or auth-binding fault raises :class:`InvalidProofError` (a
    :class:`ValueError`); a non-bytes argument raises :class:`TypeError`.
    """
    if not isinstance(proof, bytes):
        raise TypeError("proof must be bytes")
    result = _parse_proof(proof)
    return {key: result[key] for key in _PROOF_RESULT_KEYS}


# --- Offline comparison of two audit-range proofs ----------------------------

COMPARE_VERSION = 1
RELATION_DISJOINT = "disjoint"
RELATION_SAME = "same"
RELATION_LEFT_PREFIX = "left-prefix"
RELATION_RIGHT_PREFIX = "right-prefix"
RELATION_OVERLAP = "overlap"
RELATION_FORK = "fork"

COMMON_AFTER = AFTER
COMMON_SEQ = "seq"
_SIDE_KEYS = (PROOF_START_SEQ, PROOF_END_SEQ, PROOF_DIGEST)


def _side_info(parsed: dict) -> dict:
    """One side of the report: the proof digest and its covered range."""
    return {key: parsed[key] for key in _SIDE_KEYS}


def _boundary(after: str, seq: int) -> dict:
    """A shared-boundary marker ``{"after", "seq"}`` in sorted key order."""
    return {COMMON_AFTER: after, COMMON_SEQ: seq}


def compare_proofs(left: bytes, right: bytes) -> bytes:
    """Compare two offline audit proofs and return a canonical JSON report.

    Both arguments are :class:`bytes` produced by :func:`export_proof`;
    each is independently validated against the exact
    :func:`verify_proof` contract before anything is compared, so a
    non-bytes argument raises :class:`TypeError` and an invalid proof
    raises :class:`InvalidProofError`.  The ledger, the keyring and the
    filesystem are never consulted and the inputs are never modified.

    See the module docstring for the report contract: fixed top-level
    keys ``common``, ``conflictSeq``, ``left``, ``overlap``, ``relation``,
    ``right`` and ``version``, compact UTF-8 JSON with sorted keys,
    non-ASCII unescaped and one trailing ``\\n``.  Disjoint ranges give
    relation ``"disjoint"`` with ``overlap`` and ``common`` both ``null``;
    overlapping ranges are compared entry by complete entry in ascending
    seq order and classified as ``"same"``, ``"left-prefix"``,
    ``"right-prefix"``, ``"overlap"`` or ``"fork"``.  Reports are
    byte-for-byte stable; swapping the inputs swaps ``left``/``right``
    and mirrors a prefix relation.
    """
    # Type faults precede any InvalidProofError: check both arguments
    # before parsing either, so no malformed input can mask a TypeError.
    if not isinstance(left, bytes):
        raise TypeError("left proof must be bytes")
    if not isinstance(right, bytes):
        raise TypeError("right proof must be bytes")

    left_parsed = _parse_proof(left)
    right_parsed = _parse_proof(right)
    relation, overlap, conflict_seq, common = _compare_parsed(
        left_parsed, right_parsed
    )
    report = {
        "common": common,
        "conflictSeq": conflict_seq,
        "left": _side_info(left_parsed),
        "overlap": overlap,
        "relation": relation,
        "right": _side_info(right_parsed),
        "version": COMPARE_VERSION,
    }
    return _proof_compact(report) + b"\n"


def _compare_parsed(
    left_parsed: dict, right_parsed: dict
) -> tuple[str, list | None, int | None, dict | None]:
    """The read-only comparison core shared by compare_proofs/plan_merge.

    Both arguments are already validated :func:`_parse_proof` results.  The
    return value is ``(relation, overlap, conflictSeq, common)`` exactly as
    the compare_proofs report carries them: ``overlap`` is the closed shared
    seq interval or ``None`` for disjoint ranges, ``common`` is the shared
    boundary ``{"after", "seq"}`` or ``None`` and ``conflictSeq`` is the
    earliest conflicting shared seq or ``None`` for every non-fork relation.
    """
    left_start = left_parsed[PROOF_START_SEQ]
    left_end = left_parsed[PROOF_END_SEQ]
    right_start = right_parsed[PROOF_START_SEQ]
    right_end = right_parsed[PROOF_END_SEQ]

    overlap_start = max(left_start, right_start)
    overlap_end = min(left_end, right_end)

    if overlap_start > overlap_end:
        return RELATION_DISJOINT, None, None, None

    overlap = [overlap_start, overlap_end]
    left_entries = left_parsed[PROOF_ENTRIES]
    right_entries = right_parsed[PROOF_ENTRIES]

    # Compare the complete entries at every shared seq in ascending
    # order.  Boundary or proof digests alone are never consulted here.
    fork_seq: int | None = None
    for seq in range(overlap_start, overlap_end + 1):
        if left_entries[seq - left_start] != right_entries[seq - right_start]:
            fork_seq = seq
            break

    if fork_seq is not None:
        left_at = left_entries[fork_seq - left_start]
        right_at = right_entries[fork_seq - right_start]
        if fork_seq > overlap_start:
            # Equal entries precede the conflict: the last one defines
            # the common boundary, on either side (they match there).
            previous = left_entries[fork_seq - left_start - 1]
            common = _boundary(previous[AFTER], fork_seq - 1)
        elif left_at[BEFORE] == right_at[BEFORE]:
            # The first shared entry already conflicts, but both chains
            # start from the same state digest: that prior boundary is
            # still common (its seq may be 0, outside both ranges).
            common = _boundary(left_at[BEFORE], fork_seq - 1)
        else:
            common = None
        relation = RELATION_FORK
        conflict_seq: int | None = fork_seq
    else:
        conflict_seq = None
        if left_start == right_start and left_end == right_end:
            relation = RELATION_SAME
        else:
            left_is_shorter = (left_end - left_start) < (right_end - right_start)
            right_is_shorter = (right_end - right_start) < (left_end - left_start)
            same_start = left_start == right_start
            if same_start and (left_is_shorter or right_is_shorter):
                # Same start and the shorter side matches in full; the
                # relation is named for the shorter (prefix) side.
                relation = (
                    RELATION_LEFT_PREFIX if left_is_shorter
                    else RELATION_RIGHT_PREFIX
                )
            else:
                relation = RELATION_OVERLAP
        # All shared entries agree: the common boundary is the last
        # shared entry's seq together with its after digest.
        last_shared = left_entries[overlap_end - left_start]
        common = _boundary(last_shared[AFTER], overlap_end)

    return relation, overlap, conflict_seq, common


# --- Read-only merge planning over two audit proofs --------------------------

PLAN_VERSION = 1

POLICY_LEFT = "left"
POLICY_RIGHT = "right"
POLICY_MANUAL = "manual"
_PLAN_POLICIES = (POLICY_LEFT, POLICY_RIGHT, POLICY_MANUAL)

ACTION_ACCEPT = "accept"
ACTION_REJECT = "reject"
ACTION_MANUAL = "manual"

REASON_EXTENSION = "extension"
REASON_SELECTED = "selected"
REASON_REJECTED = "rejected"
REASON_MANUAL = "manual"

_SIDE_LEFT = "left"
_SIDE_RIGHT = "right"


def _tail_entries(parsed: dict, boundary_seq: int) -> list[dict]:
    """The proof's complete entries strictly past the common boundary."""
    return [
        entry for entry in parsed[PROOF_ENTRIES] if entry["seq"] > boundary_seq
    ]


def _plan_step(side: str, action: str, reason: str, entry: dict) -> dict:
    """One plan step; the entry is carried unchanged, never rewritten."""
    return {
        "action": action,
        "entry": entry,
        "reason": reason,
        "side": side,
    }


def plan_merge(left: bytes, right: bytes, policy: str) -> bytes:
    """Plan a read-only merge of two offline audit proofs.

    Both proofs are :class:`bytes` produced by :func:`export_proof` and are
    independently validated against the exact :func:`verify_proof` contract
    before anything is planned, so a non-bytes proof raises
    :class:`TypeError` and an invalid proof raises
    :class:`InvalidProofError`.  ``policy`` must be the str ``"left"``,
    ``"right"`` or ``"manual"``; any other value raises :class:`ValueError`.
    All argument types are checked before either proof is parsed, so a
    malformed proof can never mask a :class:`TypeError`.  The ledger, the
    keyring and the filesystem are never consulted and the inputs are never
    modified.

    The relation, common boundary and both side summaries are exactly the
    read-only conclusions of :func:`compare_proofs`.  Disjoint ranges, or a
    fork whose common boundary cannot be confirmed, raise
    :class:`ValueError` -- no speculative plan is ever produced.

    Only complete audit entries strictly after the common boundary become
    candidate operations; entries at or before the boundary are never
    listed again.  For an unforked history (``same``, a prefix relation or
    ``overlap``) the longer side's following entries are marked ``accept``
    with reason ``extension`` in audit order.  For a fork, policy ``left``
    accepts the left tail (reason ``selected``) and rejects the right tail
    (reason ``rejected``); ``right`` is fully symmetric.  Policy ``manual``
    selects neither branch: both tails are marked ``manual`` and referenced
    by ``{"side", "seq"}`` in ``unresolved``.

    The result is one version-1 UTF-8 compact JSON object -- every object
    key recursively sorted lexicographically, non-ASCII preserved, exactly
    one trailing ``\\n`` -- with the top-level keys ``common``, ``left``,
    ``policy``, ``relation``, ``right``, ``steps``, ``unresolved`` and
    ``version`` (the integer 1).  ``left``/``right`` carry the proof digest
    and its ``startSeq``/``endSeq``; ``common`` keeps the compare_proofs
    boundary shape.  Every step carries ``action``, the original ``entry``,
    ``reason`` and ``side``; steps are ordered by ascending ``seq`` with
    the left side first on ties, and ``unresolved`` follows the same order
    without duplicates.  The bytes are deterministic for equal inputs, and
    swapping the proofs while mirroring a ``left``/``right`` policy mirrors
    the left/right semantics.
    """
    # Type faults precede any InvalidProofError or policy ValueError: all
    # argument types are checked before either proof is parsed.
    if not isinstance(left, bytes):
        raise TypeError("left proof must be bytes")
    if not isinstance(right, bytes):
        raise TypeError("right proof must be bytes")
    if not isinstance(policy, str):
        raise TypeError("policy must be a str")

    left_parsed = _parse_proof(left)
    right_parsed = _parse_proof(right)

    if policy not in _PLAN_POLICIES:
        raise ValueError("policy must be one of 'left', 'right' or 'manual'")

    relation, _overlap, _conflict_seq, common = _compare_parsed(
        left_parsed, right_parsed
    )
    if relation == RELATION_DISJOINT:
        raise ValueError("cannot plan a merge of disjoint proof ranges")
    if common is None:
        raise ValueError(
            "cannot plan a merge without a confirmed common boundary"
        )

    left_tail = _tail_entries(left_parsed, common[COMMON_SEQ])
    right_tail = _tail_entries(right_parsed, common[COMMON_SEQ])

    steps: list[dict] = []
    if relation == RELATION_FORK:
        if policy == POLICY_LEFT:
            for entry in left_tail:
                steps.append(
                    _plan_step(_SIDE_LEFT, ACTION_ACCEPT, REASON_SELECTED, entry)
                )
            for entry in right_tail:
                steps.append(
                    _plan_step(_SIDE_RIGHT, ACTION_REJECT, REASON_REJECTED, entry)
                )
        elif policy == POLICY_RIGHT:
            for entry in left_tail:
                steps.append(
                    _plan_step(_SIDE_LEFT, ACTION_REJECT, REASON_REJECTED, entry)
                )
            for entry in right_tail:
                steps.append(
                    _plan_step(_SIDE_RIGHT, ACTION_ACCEPT, REASON_SELECTED, entry)
                )
        else:
            for entry in left_tail:
                steps.append(
                    _plan_step(_SIDE_LEFT, ACTION_MANUAL, REASON_MANUAL, entry)
                )
            for entry in right_tail:
                steps.append(
                    _plan_step(_SIDE_RIGHT, ACTION_MANUAL, REASON_MANUAL, entry)
                )
    else:
        # Unforked history: only the longer side extends past the common
        # boundary, and its tail is accepted as a plain extension.
        for entry in left_tail:
            steps.append(
                _plan_step(_SIDE_LEFT, ACTION_ACCEPT, REASON_EXTENSION, entry)
            )
        for entry in right_tail:
            steps.append(
                _plan_step(_SIDE_RIGHT, ACTION_ACCEPT, REASON_EXTENSION, entry)
            )

    # Ascending seq with the left side first on ties.
    steps.sort(key=lambda step: (step["entry"]["seq"], step["side"] != _SIDE_LEFT))

    unresolved = [
        {"side": step["side"], "seq": step["entry"]["seq"]}
        for step in steps
        if step["action"] == ACTION_MANUAL
    ]

    plan = {
        "common": common,
        "left": _side_info(left_parsed),
        "policy": policy,
        "relation": relation,
        "right": _side_info(right_parsed),
        "steps": steps,
        "unresolved": unresolved,
        "version": PLAN_VERSION,
    }
    return _proof_compact(plan) + b"\n"


# --- Read-only manual merge resolution ---------------------------------------

RESOLVE_VERSION = 1

RESOLVE_ACTION_ACCEPT = "accept"
RESOLVE_ACTION_REJECT = "reject"
_RESOLVE_ACTIONS = (RESOLVE_ACTION_ACCEPT, RESOLVE_ACTION_REJECT)

REASON_MANUAL_ACCEPTED = "manual-accepted"
REASON_MANUAL_REJECTED = "manual-rejected"

_RESOLUTION_KEYS = frozenset(("side", "seq", "action"))
_PLAN_TOP_KEYS = frozenset((
    "common",
    "left",
    "policy",
    "relation",
    "right",
    "steps",
    "unresolved",
    "version",
))
_PLAN_STEP_KEYS = frozenset(("action", "entry", "reason", "side"))
_PLAN_REF_KEYS = frozenset(("side", "seq"))
_PLAN_SIDE_KEYS = frozenset((PROOF_START_SEQ, PROOF_END_SEQ, PROOF_DIGEST))
_PLAN_COMMON_KEYS = frozenset((COMMON_AFTER, COMMON_SEQ))
_PLAN_ACTIONS = (ACTION_ACCEPT, ACTION_REJECT, ACTION_MANUAL)
_PLAN_REASONS = (
    REASON_EXTENSION,
    REASON_SELECTED,
    REASON_REJECTED,
    REASON_MANUAL,
)
_PLAN_RELATIONS = (
    RELATION_SAME,
    RELATION_LEFT_PREFIX,
    RELATION_RIGHT_PREFIX,
    RELATION_OVERLAP,
    RELATION_FORK,
)
_PLAN_SIDES = (_SIDE_LEFT, _SIDE_RIGHT)


class InvalidPlanError(ValueError):
    """A merge plan fails its byte, structure or version-1 contract."""


class StalePlanError(ValueError):
    """A merge plan no longer matches the proofs it claims to describe."""


class InvalidResolutionError(ValueError):
    """A manual merge resolution set is incomplete, invalid or broken."""


def _plan_invalid(message: str) -> InvalidPlanError:
    return InvalidPlanError(f"invalid merge plan: {message}")


def _reject_duplicate_plan_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate plan object keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _plan_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _validated_plan_entry(entry: object, where: str) -> None:
    """Structural check of one plan step's carried audit entry."""
    if not isinstance(entry, dict):
        raise _plan_invalid(f"{where} entry must be a JSON object")
    keys = set(entry.keys())
    if keys != _LEDGER_ENTRY_KEY_SET and keys != _LEDGER_ENTRY_AUTHED_SET:
        raise _plan_invalid(
            f"{where} entry must contain exactly the keys 'after', 'before', "
            "'id', 'seq' and 'source' with optional 'auth'"
        )
    if not _is_digest(entry[BEFORE]):
        raise _plan_invalid(f"{where} entry before must be 64 lowercase hex chars")
    if not _is_digest(entry[AFTER]):
        raise _plan_invalid(f"{where} entry after must be 64 lowercase hex chars")
    if not isinstance(entry[ID], str) or entry[ID] == "":
        raise _plan_invalid(f"{where} entry id must be a non-empty str")
    if not isinstance(entry[SOURCE], str) or entry[SOURCE] == "":
        raise _plan_invalid(f"{where} entry source must be a non-empty str")
    if isinstance(entry["seq"], bool) or not isinstance(entry["seq"], int):
        raise _plan_invalid(f"{where} entry seq must be an int")
    if AUTH in entry:
        auth = entry[AUTH]
        if not isinstance(auth, dict) or set(auth.keys()) != _LEDGER_AUTH_KEYS:
            raise _plan_invalid(
                f"{where} entry auth must contain exactly the keys "
                "'keyVersion' and 'node'"
            )
        if not isinstance(auth[NODE], str) or auth[NODE] == "":
            raise _plan_invalid(f"{where} entry auth node must be a non-empty str")
        if (
            isinstance(auth[KEY_VERSION], bool)
            or not isinstance(auth[KEY_VERSION], int)
            or auth[KEY_VERSION] <= 0
        ):
            raise _plan_invalid(
                f"{where} entry auth keyVersion must be a positive non-bool int"
            )


def _parse_plan(raw: bytes) -> dict:
    """Validate a merge plan against the version-1 plan byte contract.

    Only the structural contract is enforced here: canonical encoding,
    unique keys, the fixed key sets, the integer version 1 and the value
    domains of every field.  Whether the plan still matches the proofs it
    describes is decided separately by :func:`resolve_merge`.
    """
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _plan_invalid("must be a single JSON object ending in one LF")
    try:
        text = raw[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _plan_invalid("is not valid UTF-8") from exc
    try:
        # The pairs hook raises directly on duplicate object keys, so a
        # ValueError raised here means that contract fault, not bad JSON.
        data = json.loads(text, object_pairs_hook=_reject_duplicate_plan_keys)
    except json.JSONDecodeError as exc:
        raise _plan_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _plan_invalid("must be a JSON object")
    if set(data.keys()) != _PLAN_TOP_KEYS:
        raise _plan_invalid(
            "top-level object must contain exactly the keys 'common', "
            "'left', 'policy', 'relation', 'right', 'steps', 'unresolved' "
            "and 'version'"
        )
    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _plan_invalid("version must be an int")
    if version != PLAN_VERSION:
        raise _plan_invalid("version must be the integer 1")

    policy = data["policy"]
    if not isinstance(policy, str) or policy not in _PLAN_POLICIES:
        raise _plan_invalid("policy must be one of 'left', 'right' or 'manual'")
    relation = data["relation"]
    if not isinstance(relation, str) or relation not in _PLAN_RELATIONS:
        raise _plan_invalid("relation must be a known proof relation")

    common = data["common"]
    if not isinstance(common, dict) or set(common.keys()) != _PLAN_COMMON_KEYS:
        raise _plan_invalid("common must contain exactly the keys 'after' and 'seq'")
    if not _is_digest(common[COMMON_AFTER]):
        raise _plan_invalid("common after must be 64 lowercase hex characters")
    if isinstance(common[COMMON_SEQ], bool) or not isinstance(common[COMMON_SEQ], int):
        raise _plan_invalid("common seq must be an int")

    for side_key in (_SIDE_LEFT, _SIDE_RIGHT):
        side = data[side_key]
        if not isinstance(side, dict) or set(side.keys()) != _PLAN_SIDE_KEYS:
            raise _plan_invalid(
                f"{side_key} must contain exactly the keys 'digest', "
                "'endSeq' and 'startSeq'"
            )
        if not _is_digest(side[PROOF_DIGEST]):
            raise _plan_invalid(
                f"{side_key} digest must be 64 lowercase hex characters"
            )
        for seq_key in (PROOF_START_SEQ, PROOF_END_SEQ):
            if isinstance(side[seq_key], bool) or not isinstance(side[seq_key], int):
                raise _plan_invalid(f"{side_key} {seq_key} must be an int")

    steps = data["steps"]
    if not isinstance(steps, list):
        raise _plan_invalid("steps must be an array")
    for position, step in enumerate(steps):
        where = f"step {position}"
        if not isinstance(step, dict) or set(step.keys()) != _PLAN_STEP_KEYS:
            raise _plan_invalid(
                f"{where} must contain exactly the keys 'action', 'entry', "
                "'reason' and 'side'"
            )
        if step["side"] not in _PLAN_SIDES:
            raise _plan_invalid(f"{where} side must be 'left' or 'right'")
        if step["action"] not in _PLAN_ACTIONS:
            raise _plan_invalid(f"{where} action must be a known plan action")
        if step["reason"] not in _PLAN_REASONS:
            raise _plan_invalid(f"{where} reason must be a known plan reason")
        _validated_plan_entry(step["entry"], where)

    unresolved = data["unresolved"]
    if not isinstance(unresolved, list):
        raise _plan_invalid("unresolved must be an array")
    for position, ref in enumerate(unresolved):
        where = f"unresolved item {position}"
        if not isinstance(ref, dict) or set(ref.keys()) != _PLAN_REF_KEYS:
            raise _plan_invalid(
                f"{where} must contain exactly the keys 'side' and 'seq'"
            )
        if ref["side"] not in _PLAN_SIDES:
            raise _plan_invalid(f"{where} side must be 'left' or 'right'")
        if isinstance(ref["seq"], bool) or not isinstance(ref["seq"], int):
            raise _plan_invalid(f"{where} seq must be an int")

    # The bytes must be the single canonical compact form with sorted keys
    # and exactly one trailing newline.
    if _proof_compact(data) + b"\n" != raw:
        raise _plan_invalid("encoding is not the canonical compact form")
    return data


def _validate_resolution_types(decisions: object) -> None:
    """Type-check the decisions argument before any proof or plan is parsed."""
    if not isinstance(decisions, list):
        raise TypeError("decisions must be a list")
    for position, decision in enumerate(decisions):
        where = f"decision {position}"
        if not isinstance(decision, dict):
            raise TypeError(f"{where} must be a dict")
        if "side" in decision and not isinstance(decision["side"], str):
            raise TypeError(f"{where} side must be a str")
        if "seq" in decision and (
            isinstance(decision["seq"], bool)
            or not isinstance(decision["seq"], int)
        ):
            raise TypeError(f"{where} seq must be an int")
        if "action" in decision and not isinstance(decision["action"], str):
            raise TypeError(f"{where} action must be a str")


def resolve_merge(plan: bytes, left: bytes, right: bytes, decisions: list) -> bytes:
    """Resolve a manual merge plan into a final, auditable merge result.

    ``plan`` must be :class:`bytes` produced by :func:`plan_merge` with
    policy ``"manual"`` for exactly the same ``left`` and ``right`` proofs;
    plans from any other policy never enter resolution.  Both proofs are
    independently validated against the exact :func:`verify_proof`
    contract.  ``decisions`` resolves every ``unresolved`` reference of the
    plan exactly once: each item carries only ``side``, ``seq`` and
    ``action`` (``"accept"`` or ``"reject"``), in any input order.

    All argument and decision field types are checked before either proof
    or the plan is parsed, so a malformed input never masks a
    :class:`TypeError` (a :class:`bool` never poses as a ``seq``).  An
    invalid proof raises :class:`InvalidProofError`; a plan whose encoding,
    key sets or version-1 structure is invalid raises
    :class:`InvalidPlanError` (a :class:`ValueError`); a structurally valid
    plan that differs byte-for-byte from the manual plan freshly generated
    for the same proofs -- digest, relation, common boundary, side
    summaries, steps or unresolved references -- raises
    :class:`StalePlanError` (a :class:`ValueError`).

    A missing, duplicate, extra or out-of-range reference and any action
    other than ``"accept"``/``"reject"`` raises
    :class:`InvalidResolutionError` (a :class:`ValueError`).  The accepted
    entries must chain contiguously from the common boundary: at most one
    side may be accepted per seq, acceptance may not resume past a seq
    where every side was rejected, and a break in the seq or before/after
    digest chain raises :class:`InvalidResolutionError` as well.

    On success the result is one version-1 UTF-8 compact JSON object --
    every object key recursively sorted lexicographically, non-ASCII
    preserved, exactly one trailing ``\\n`` -- with the top-level keys
    ``common``, ``left``, ``planDigest``, ``relation``, ``right``,
    ``steps``, ``unresolved`` and ``version`` (the integer 1).  Manual
    steps are relabelled ``accept``/``reject`` with the fixed reasons
    ``manual-accepted``/``manual-rejected`` in the plan's original step
    order; non-manual steps, the carried audit entries and their ``auth``
    bindings are unchanged and ``unresolved`` is empty.  ``relation``,
    ``common`` and both side summaries are taken from the plan and
    ``planDigest`` is the lowercase hex SHA-256 of the complete source
    plan bytes.  The bytes are deterministic for equal inputs, swapping
    the proofs together with the matching decision sides mirrors the
    left/right semantics, and the ledger, the keyring and the filesystem
    are never consulted and the inputs are never modified.
    """
    # Type faults precede every other error: all argument and decision
    # field types are checked before either proof or the plan is parsed.
    if not isinstance(plan, bytes):
        raise TypeError("plan must be bytes")
    if not isinstance(left, bytes):
        raise TypeError("left proof must be bytes")
    if not isinstance(right, bytes):
        raise TypeError("right proof must be bytes")
    _validate_resolution_types(decisions)

    _parse_proof(left)
    _parse_proof(right)
    parsed_plan = _parse_plan(plan)

    # Staleness: the plan must be byte-for-byte the manual plan freshly
    # generated for these very proofs.  A plan that no longer regenerates
    # at all (disjoint ranges, an unconfirmed boundary) is equally stale.
    try:
        expected = plan_merge(left, right, POLICY_MANUAL)
    except ValueError as exc:
        raise StalePlanError(
            "plan does not match a manual plan for these proofs"
        ) from exc
    if plan != expected:
        raise StalePlanError(
            "plan does not match the manual plan regenerated from these proofs"
        )

    # Every unresolved reference must be resolved exactly once; anything
    # missing, duplicated, extra or out of range is an invalid resolution.
    pending = {(ref["side"], ref["seq"]) for ref in parsed_plan["unresolved"]}
    seen: set[tuple[str, int]] = set()
    choices: dict[tuple[str, int], str] = {}
    for position, decision in enumerate(decisions):
        where = f"decision {position}"
        if set(decision.keys()) != _RESOLUTION_KEYS:
            raise InvalidResolutionError(
                f"{where} must contain exactly the keys 'side', 'seq' "
                "and 'action'"
            )
        side = decision["side"]
        if side not in _PLAN_SIDES:
            raise InvalidResolutionError(f"{where} side must be 'left' or 'right'")
        action = decision["action"]
        if action not in _RESOLVE_ACTIONS:
            raise InvalidResolutionError(
                f"{where} action must be 'accept' or 'reject'"
            )
        ref = (side, decision["seq"])
        if ref not in pending:
            raise InvalidResolutionError(
                f"{where} references no unresolved plan item"
            )
        if ref in seen:
            raise InvalidResolutionError(
                f"{where} resolves the same plan item twice"
            )
        seen.add(ref)
        choices[ref] = action
    if seen != pending:
        raise InvalidResolutionError(
            "every unresolved plan item must be resolved exactly once"
        )

    # The accepted entries must chain contiguously from the common
    # boundary: one side per seq, no resumption past an all-rejected seq
    # and an unbroken seq and before/after digest chain.
    manual_steps = [step for step in parsed_plan["steps"] if step["action"] == ACTION_MANUAL]
    accepted: dict[int, dict] = {}
    for step in manual_steps:
        seq = step["entry"]["seq"]
        if choices[(step["side"], seq)] == RESOLVE_ACTION_ACCEPT:
            if seq in accepted:
                raise InvalidResolutionError(
                    f"at most one side may be accepted at seq {seq}"
                )
            accepted[seq] = step["entry"]
    expected_seq = parsed_plan["common"][COMMON_SEQ] + 1
    expected_before = parsed_plan["common"][COMMON_AFTER]
    for seq in sorted({step["entry"]["seq"] for step in manual_steps}):
        entry = accepted.get(seq)
        if entry is None:
            if any(later > seq for later in accepted):
                raise InvalidResolutionError(
                    f"acceptance may not resume past the rejected seq {seq}"
                )
            continue
        if seq != expected_seq or entry[BEFORE] != expected_before:
            raise InvalidResolutionError(
                f"accepted entry at seq {seq} does not chain from the "
                "common boundary"
            )
        expected_seq = seq + 1
        expected_before = entry[AFTER]

    steps: list[dict] = []
    for step in parsed_plan["steps"]:
        if step["action"] != ACTION_MANUAL:
            # Non-manual steps are carried through unchanged.
            steps.append(step)
            continue
        seq = step["entry"]["seq"]
        if choices[(step["side"], seq)] == RESOLVE_ACTION_ACCEPT:
            action, reason = RESOLVE_ACTION_ACCEPT, REASON_MANUAL_ACCEPTED
        else:
            action, reason = RESOLVE_ACTION_REJECT, REASON_MANUAL_REJECTED
        steps.append(
            {
                "action": action,
                "entry": step["entry"],
                "reason": reason,
                "side": step["side"],
            }
        )

    result = {
        "common": parsed_plan["common"],
        "left": parsed_plan["left"],
        "planDigest": hashlib.sha256(plan).hexdigest(),
        "relation": parsed_plan["relation"],
        "right": parsed_plan["right"],
        "steps": steps,
        "unresolved": [],
        "version": RESOLVE_VERSION,
    }
    return _proof_compact(result) + b"\n"


# --- Landing a manual merge resolution in the ledger -------------------------

RESOLUTION_DIGEST = "resolutionDigest"
STATUS_UNCHANGED = "unchanged"

_PLAN_DIGEST = "planDigest"
_RESOLUTION_TOP_KEYS = frozenset((
    "common",
    "left",
    _PLAN_DIGEST,
    "relation",
    "right",
    "steps",
    "unresolved",
    VERSION,
))
_RESOLUTION_ACCEPT_REASONS = (
    REASON_EXTENSION,
    REASON_SELECTED,
    REASON_MANUAL_ACCEPTED,
)
_RESOLUTION_REJECT_REASONS = (REASON_REJECTED, REASON_MANUAL_REJECTED)
_MATERIAL_KEYS = frozenset((STATE_KEY, REQUESTS))


class StaleLedgerError(ValueError):
    """The ledger tip no longer matches the resolution's common boundary."""


def _resolution_invalid(message: str) -> InvalidResolutionError:
    return InvalidResolutionError(f"invalid merge resolution: {message}")


def _reject_duplicate_resolution_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate resolution keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _resolution_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _validated_resolution_entry(entry: object, where: str) -> None:
    """Structural check of one resolution step's carried audit entry."""
    if not isinstance(entry, dict):
        raise _resolution_invalid(f"{where} entry must be a JSON object")
    keys = set(entry.keys())
    if keys != _LEDGER_ENTRY_KEY_SET and keys != _LEDGER_ENTRY_AUTHED_SET:
        raise _resolution_invalid(
            f"{where} entry must contain exactly the keys 'after', 'before', "
            "'id', 'seq' and 'source' with optional 'auth'"
        )
    if not _is_digest(entry[BEFORE]):
        raise _resolution_invalid(
            f"{where} entry before must be 64 lowercase hex chars"
        )
    if not _is_digest(entry[AFTER]):
        raise _resolution_invalid(
            f"{where} entry after must be 64 lowercase hex chars"
        )
    if not isinstance(entry[ID], str) or entry[ID] == "":
        raise _resolution_invalid(f"{where} entry id must be a non-empty str")
    if not isinstance(entry[SOURCE], str) or entry[SOURCE] == "":
        raise _resolution_invalid(f"{where} entry source must be a non-empty str")
    if isinstance(entry["seq"], bool) or not isinstance(entry["seq"], int):
        raise _resolution_invalid(f"{where} entry seq must be an int")
    if AUTH in entry:
        auth = entry[AUTH]
        if not isinstance(auth, dict) or set(auth.keys()) != _LEDGER_AUTH_KEYS:
            raise _resolution_invalid(
                f"{where} entry auth must contain exactly the keys "
                "'keyVersion' and 'node'"
            )
        if not isinstance(auth[NODE], str) or auth[NODE] == "":
            raise _resolution_invalid(
                f"{where} entry auth node must be a non-empty str"
            )
        if (
            isinstance(auth[KEY_VERSION], bool)
            or not isinstance(auth[KEY_VERSION], int)
            or auth[KEY_VERSION] <= 0
        ):
            raise _resolution_invalid(
                f"{where} entry auth keyVersion must be a positive non-bool int"
            )


def _parse_resolution(raw: bytes) -> dict:
    """Validate resolution bytes against the version-1 resolution contract.

    Only the structural contract is enforced here: canonical encoding,
    unique keys, the fixed key sets, the integer version 1 and the value
    domains of every field.  Whether the resolution binds the manual plan
    for the given proofs is decided separately by
    :func:`commit_resolution`.
    """
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise _resolution_invalid("must be a single JSON object ending in one LF")
    try:
        text = raw[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _resolution_invalid("is not valid UTF-8") from exc
    try:
        # The pairs hook raises directly on duplicate object keys, so a
        # ValueError raised here means that contract fault, not bad JSON.
        data = json.loads(text, object_pairs_hook=_reject_duplicate_resolution_keys)
    except json.JSONDecodeError as exc:
        raise _resolution_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _resolution_invalid("must be a JSON object")
    if set(data.keys()) != _RESOLUTION_TOP_KEYS:
        raise _resolution_invalid(
            "top-level object must contain exactly the keys 'common', "
            "'left', 'planDigest', 'relation', 'right', 'steps', "
            "'unresolved' and 'version'"
        )
    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _resolution_invalid("version must be an int")
    if version != RESOLVE_VERSION:
        raise _resolution_invalid("version must be the integer 1")

    if not _is_digest(data[_PLAN_DIGEST]):
        raise _resolution_invalid("planDigest must be 64 lowercase hex characters")
    relation = data["relation"]
    if not isinstance(relation, str) or relation not in _PLAN_RELATIONS:
        raise _resolution_invalid("relation must be a known proof relation")

    common = data["common"]
    if not isinstance(common, dict) or set(common.keys()) != _PLAN_COMMON_KEYS:
        raise _resolution_invalid(
            "common must contain exactly the keys 'after' and 'seq'"
        )
    if not _is_digest(common[COMMON_AFTER]):
        raise _resolution_invalid("common after must be 64 lowercase hex characters")
    if isinstance(common[COMMON_SEQ], bool) or not isinstance(common[COMMON_SEQ], int):
        raise _resolution_invalid("common seq must be an int")

    for side_key in (_SIDE_LEFT, _SIDE_RIGHT):
        side = data[side_key]
        if not isinstance(side, dict) or set(side.keys()) != _PLAN_SIDE_KEYS:
            raise _resolution_invalid(
                f"{side_key} must contain exactly the keys 'digest', "
                "'endSeq' and 'startSeq'"
            )
        if not _is_digest(side[PROOF_DIGEST]):
            raise _resolution_invalid(
                f"{side_key} digest must be 64 lowercase hex characters"
            )
        for seq_key in (PROOF_START_SEQ, PROOF_END_SEQ):
            if isinstance(side[seq_key], bool) or not isinstance(side[seq_key], int):
                raise _resolution_invalid(f"{side_key} {seq_key} must be an int")

    unresolved = data["unresolved"]
    if not isinstance(unresolved, list):
        raise _resolution_invalid("unresolved must be an array")
    if unresolved:
        raise _resolution_invalid("unresolved must be empty in a final resolution")

    steps = data["steps"]
    if not isinstance(steps, list):
        raise _resolution_invalid("steps must be an array")
    for position, step in enumerate(steps):
        where = f"step {position}"
        if not isinstance(step, dict) or set(step.keys()) != _PLAN_STEP_KEYS:
            raise _resolution_invalid(
                f"{where} must contain exactly the keys 'action', 'entry', "
                "'reason' and 'side'"
            )
        if step["side"] not in _PLAN_SIDES:
            raise _resolution_invalid(f"{where} side must be 'left' or 'right'")
        action = step["action"]
        reason = step["reason"]
        if action == RESOLVE_ACTION_ACCEPT:
            if reason not in _RESOLUTION_ACCEPT_REASONS:
                raise _resolution_invalid(
                    f"{where} reason is not a valid accept reason"
                )
        elif action == RESOLVE_ACTION_REJECT:
            if reason not in _RESOLUTION_REJECT_REASONS:
                raise _resolution_invalid(
                    f"{where} reason is not a valid reject reason"
                )
        else:
            raise _resolution_invalid(
                f"{where} action must be 'accept' or 'reject'"
            )
        _validated_resolution_entry(step["entry"], where)

    # The bytes must be the single canonical compact form with sorted keys
    # and exactly one trailing newline.
    if _proof_compact(data) + b"\n" != raw:
        raise _resolution_invalid("encoding is not the canonical compact form")
    return data


def _validated_commit_material(material: object) -> tuple[dict, dict[str, str]]:
    """Validate the landing material into (final state, request bindings).

    Type faults raise :class:`TypeError`; a bad key set, a malformed
    request digest or an invalid state value raises :class:`ValueError`.
    The state comes back as a fresh copy obeying the merge state contract.
    """
    if not isinstance(material, dict):
        raise TypeError("material must be a dict")
    if set(material.keys()) != _MATERIAL_KEYS:
        raise ValueError(
            "material must contain exactly the keys 'state' and 'requests'"
        )
    clock, records = merge._validated_state(material[STATE_KEY])
    state = {merge.CLOCK: clock, merge.RECORDS: records}

    raw_requests = material[REQUESTS]
    if not isinstance(raw_requests, dict):
        raise TypeError("material requests must be a dict")
    requests: dict[str, str] = {}
    for bound_id, bound_digest in raw_requests.items():
        if not isinstance(bound_id, str):
            raise TypeError("material requests keys must be str")
        if bound_id == "":
            raise ValueError("material requests keys must be non-empty")
        if not isinstance(bound_digest, str):
            raise TypeError("material requests values must be str")
        if not _is_digest(bound_digest):
            raise ValueError(
                "material requests values must be 64 lowercase hex characters"
            )
        requests[bound_id] = bound_digest
    return state, requests


def _assert_resolution_binds_plan(
    parsed_resolution: dict, parsed_plan: dict, plan: bytes
) -> None:
    """Require the resolution to bind the manual plan byte-for-byte.

    The ``planDigest`` must hash the complete plan bytes, the boundary,
    relation and side summaries must equal the plan's, and every step
    must carry the plan step's entry and side -- relabelled
    ``accept``/``reject`` with the fixed manual reasons for a manual plan
    step, identical to the plan step otherwise.  Any deviation raises
    :class:`StalePlanError`.
    """
    if parsed_resolution[_PLAN_DIGEST] != hashlib.sha256(plan).hexdigest():
        raise StalePlanError("resolution planDigest does not match the plan")
    for key in ("common", "left", "relation", "right"):
        if parsed_resolution[key] != parsed_plan[key]:
            raise StalePlanError(
                f"resolution {key} does not match the manual plan"
            )
    plan_steps = parsed_plan["steps"]
    resolution_steps = parsed_resolution["steps"]
    if len(resolution_steps) != len(plan_steps):
        raise StalePlanError("resolution steps do not match the manual plan")
    for resolution_step, plan_step in zip(resolution_steps, plan_steps):
        if (
            resolution_step["side"] != plan_step["side"]
            or resolution_step["entry"] != plan_step["entry"]
        ):
            raise StalePlanError("resolution steps do not match the manual plan")
        if plan_step["action"] == ACTION_MANUAL:
            if (resolution_step["action"], resolution_step["reason"]) not in (
                (RESOLVE_ACTION_ACCEPT, REASON_MANUAL_ACCEPTED),
                (RESOLVE_ACTION_REJECT, REASON_MANUAL_REJECTED),
            ):
                raise StalePlanError(
                    "resolution steps do not match the manual plan"
                )
        elif (
            resolution_step["action"] != plan_step["action"]
            or resolution_step["reason"] != plan_step["reason"]
        ):
            raise StalePlanError("resolution steps do not match the manual plan")


def _commit_result(next_seq: int, resolution_digest: str, status: str) -> dict:
    """The commit_resolution result, keys in lexicographic order."""
    return {NEXT: next_seq, RESOLUTION_DIGEST: resolution_digest, STATUS: status}


def commit_resolution(
    path: str,
    resolution: bytes,
    plan: bytes,
    left: bytes,
    right: bytes,
    material: dict,
) -> dict:
    """Land one manual merge resolution in the ledger at ``path``.

    ``resolution`` must be the canonical bytes produced by
    :func:`resolve_merge` for the manual ``plan`` of exactly the ``left``
    and ``right`` proofs.  ``material`` must be a dict with exactly the
    keys ``state`` -- the final state, obeying the
    :mod:`~offline_coordination.merge` contract -- and ``requests``,
    binding every accepted entry id to its 64-character lowercase hex
    request digest.

    Every input is validated before the ledger is touched: a non-str
    ``path``, non-bytes canonical arguments or ill-typed material fields
    raise :class:`TypeError`; material structure, digest or state value
    faults raise :class:`ValueError`; both proofs are independently
    verified against the exact :func:`verify_proof` contract
    (:class:`InvalidProofError`); the plan structure is checked
    (:class:`InvalidPlanError`) and so is the resolution structure
    (:class:`InvalidResolutionError`).  The plan must be byte-for-byte
    the manual plan regenerated from the proofs and the resolution must
    bind that plan -- ``planDigest``, boundary, relation, side summaries
    and steps -- otherwise :class:`StalePlanError` is raised without
    reading or writing the ledger.  The accepted entries must chain
    contiguously from the common boundary
    (:class:`InvalidResolutionError`), the material ``requests`` must
    bind exactly the accepted ids and the final state must hash to the
    last accepted entry's ``after`` (:class:`ValueError`).

    A missing ledger raises :class:`FileNotFoundError` and a corrupt one
    :class:`ValueError`.  Replaying a fully identical resolution -- every
    accepted entry already sits at its resolution position with the same
    request binding -- is recognized before the staleness check and
    returns ``duplicate`` without touching the ledger.  Otherwise the
    ledger tip's seq and state digest must equal the resolution's common
    boundary: a ledger that moved on, holds only some of the accepted
    entries, binds a conflicting digest or carries a changed ``auth``
    binding raises :class:`StaleLedgerError` (a :class:`ValueError`) and
    nothing is written.  A resolution with no accepted entries returns
    ``unchanged`` with the ledger bytes untouched (its ``requests`` must
    be empty).  Otherwise the final state, the request bindings and the
    contiguous accepted entries -- rejected entries never enter the
    audit, carried entries and ``auth`` bindings stay unchanged -- are
    written in one fail-safe replacement and the status is ``applied``;
    an :class:`OSError` at any write, flush, file-sync, replace or
    directory-sync step propagates unchanged with the pre-call bytes
    restored.

    The result is a fresh dict with the keys ``next`` (the last accepted
    seq, or the common boundary seq when nothing is applied),
    ``resolutionDigest`` (the lowercase hex SHA-256 of the complete
    resolution bytes) and ``status``, in lexicographic key order.
    """
    # Type faults precede every other check: all argument types and the
    # material are validated before any proof, plan or resolution bytes
    # are parsed, so a malformed input never masks a TypeError.
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if not isinstance(resolution, bytes):
        raise TypeError("resolution must be bytes")
    if not isinstance(plan, bytes):
        raise TypeError("plan must be bytes")
    if not isinstance(left, bytes):
        raise TypeError("left proof must be bytes")
    if not isinstance(right, bytes):
        raise TypeError("right proof must be bytes")
    final_state, material_requests = _validated_commit_material(material)

    # Offline verification: both proofs independently, then the plan and
    # resolution structures -- all before the ledger is ever touched.
    _parse_proof(left)
    _parse_proof(right)
    parsed_plan = _parse_plan(plan)
    parsed_resolution = _parse_resolution(resolution)

    # The plan must be byte-for-byte the manual plan freshly regenerated
    # for these very proofs, and the resolution must bind that plan.  A
    # plan that no longer regenerates at all is equally stale.  None of
    # this reads or writes the ledger.
    try:
        expected_plan = plan_merge(left, right, POLICY_MANUAL)
    except ValueError as exc:
        raise StalePlanError(
            "plan does not match a manual plan for these proofs"
        ) from exc
    if plan != expected_plan:
        raise StalePlanError(
            "plan does not match the manual plan regenerated from these proofs"
        )
    _assert_resolution_binds_plan(parsed_resolution, parsed_plan, plan)

    # Only the contiguous accept items are committed; rejected entries
    # never enter the audit.  The accepted entries must chain
    # contiguously from the common boundary, one unbroken seq and
    # before/after digest chain with distinct request ids.
    common = parsed_resolution["common"]
    accepted = [
        step["entry"]
        for step in parsed_resolution["steps"]
        if step["action"] == RESOLVE_ACTION_ACCEPT
    ]
    expected_seq = common[COMMON_SEQ] + 1
    expected_before = common[COMMON_AFTER]
    accepted_ids: set[str] = set()
    for entry in accepted:
        if entry["seq"] != expected_seq or entry[BEFORE] != expected_before:
            raise InvalidResolutionError(
                "accepted entries do not chain contiguously from the "
                "common boundary"
            )
        if entry[ID] in accepted_ids:
            raise InvalidResolutionError("accepted entries repeat a request id")
        accepted_ids.add(entry[ID])
        expected_seq += 1
        expected_before = entry[AFTER]

    # The material must match the resolution: one request binding per
    # accepted id (none at all when nothing is accepted) and a final
    # state hashing to the last accepted entry's after -- the common
    # boundary itself when no entry is accepted.
    if set(material_requests) != accepted_ids:
        raise ValueError(
            "material requests must bind exactly the accepted entry ids"
        )
    expected_after = accepted[-1][AFTER] if accepted else common[COMMON_AFTER]
    if _digest(_state_bytes(final_state)) != expected_after:
        raise ValueError(
            "material state does not hash to the last accepted entry's after"
        )

    # Only now is the ledger read: any interrupted earlier commit is
    # settled first, a missing ledger propagates FileNotFoundError, a
    # corrupt one ValueError, and any other read failure propagates as
    # OSError.
    recover_ledger(path)
    with open(path, "rb") as handle:
        raw = handle.read()
    stored_state, stored_requests, stored_entries = _parse_ledger(raw)

    resolution_digest = hashlib.sha256(resolution).hexdigest()
    common_seq = common[COMMON_SEQ]

    # A fully identical replay is recognized before the staleness check:
    # every accepted entry already sits at its resolution position with
    # the same request binding, so the verdict comes from the saved
    # artifacts alone and the ledger is never modified.
    if accepted:
        final_seq = accepted[-1]["seq"]
        if (
            len(stored_entries) >= final_seq
            and stored_entries[common_seq:final_seq] == accepted
            and all(
                stored_requests.get(entry[ID]) == material_requests[entry[ID]]
                for entry in accepted
            )
        ):
            return _commit_result(final_seq, resolution_digest, STATUS_DUPLICATE)

    # The ledger tip must still be the resolution's common boundary: a
    # ledger that moved on, holds only some of the accepted entries or
    # carries them with conflicting digests or changed auth bindings is
    # stale, and nothing is written.
    last_seq = stored_entries[-1]["seq"] if stored_entries else 0
    if (
        last_seq != common_seq
        or _digest(_state_bytes(stored_state)) != common[COMMON_AFTER]
    ):
        raise StaleLedgerError(
            "ledger tip does not match the resolution's common boundary"
        )

    # Nothing to commit: the resolution accepts no entries, so the
    # ledger bytes stay untouched.
    if not accepted:
        return _commit_result(common_seq, resolution_digest, STATUS_UNCHANGED)

    # An accepted id already bound before the boundary can never be
    # committed again without corrupting the ledger's id uniqueness.
    for entry in accepted:
        if entry[ID] in stored_requests:
            raise StaleLedgerError(
                f"accepted id {entry[ID]!r} is already bound in the ledger"
            )

    # One fail-safe replacement writes the final state, the request
    # bindings and the accepted entries; an OSError at any step
    # propagates unchanged with the pre-call bytes restored.
    new_entries = stored_entries + accepted
    new_requests = dict(stored_requests)
    new_requests.update(material_requests)
    _atomic_write(path, _serialize_ledger(final_state, new_requests, new_entries))
    return _commit_result(accepted[-1]["seq"], resolution_digest, STATUS_APPLIED)


# --- Authorized batch recovery with tickets and a recovery audit -------------

TICKET_PAYLOAD = "payload"
TICKET_ISSUER = "issuer"
TICKET_NONCE = "nonce"
TICKET_PATHS = "paths"
TICKET_DIGEST = "ticketDigest"

AUDIT_KIND_BATCH = "batch"
AUDIT_KIND_BEFORE = "before"
AUDIT_KIND_AFTER = "after"

_TICKET_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_TICKET_PAYLOAD_KEYS = frozenset((
    TICKET_ISSUER,
    KEY_VERSION,
    TICKET_NONCE,
    NOT_AFTER,
    NOT_BEFORE,
    TICKET_PATHS,
))

_RECOVERY_AUDIT_ZERO_HASH = "0" * 64
_RECOVERY_AUDIT_KIND_KEYS = {
    AUDIT_KIND_BATCH: frozenset((
        "hash", TICKET_ISSUER, "kind", TICKET_NONCE, TICKET_PATHS, "prev",
        "seq", TICKET_DIGEST,
    )),
    AUDIT_KIND_BEFORE: frozenset((
        "action", "digest", "hash", "kind", TICKET_NONCE, "path", "phase",
        "prev", "seq",
    )),
    AUDIT_KIND_AFTER: frozenset((
        "digest", "error", "hash", "kind", TICKET_NONCE, "path", "prev",
        "seq", "status",
    )),
}
_RECOVERY_AUDIT_PHASES = (PHASE_PREPARED, PHASE_INSTALLED)
_RECOVERY_AUDIT_ACTIONS = (ACTION_ROLLBACK, ACTION_COMPLETE)
_RECOVERY_AUDIT_STATUSES = (
    STATUS_CLEAN,
    STATUS_ROLLED_BACK,
    STATUS_COMPLETED,
    STATUS_BLOCKED,
    STATUS_FAILED,
)
_RECOVERY_AUDIT_ERRORS = (ERROR_CORRUPT, ERROR_OS_ERROR)


class ReplayError(ValueError):
    """A recovery nonce is already bound to a different ticket."""


class CorruptRecoveryAuditError(ValueError):
    """The recovery audit exists but is not a valid recovery audit chain."""


def _ticket_invalid(message: str) -> ValueError:
    return ValueError(f"invalid recovery ticket: {message}")


def _reject_duplicate_ticket_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate ticket keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _ticket_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _parse_ticket(raw: bytes) -> tuple[dict, str]:
    """Validate ticket bytes against the ticket contract.

    Returns ``(payload, signature)``.  Type faults raise
    :class:`TypeError`; key-set, nonce, validity-interval, encoding and
    signature-format faults raise :class:`ValueError`.
    """
    # The ticket carries no terminator of any kind: no trailing newline
    # and no other byte past the closing brace.
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _ticket_invalid("must end with the closing brace, no LF")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ticket_invalid("is not valid UTF-8") from exc
    try:
        # The pairs hook raises directly on duplicate object keys, so a
        # ValueError raised here means that contract fault, not bad JSON.
        data = json.loads(text, object_pairs_hook=_reject_duplicate_ticket_keys)
    except json.JSONDecodeError as exc:
        raise _ticket_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise TypeError("ticket must be a JSON object")
    if set(data.keys()) != _TICKET_TOP_KEYS:
        raise _ticket_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("ticket signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _ticket_invalid("signature must be 64 lowercase hex characters")

    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("ticket payload must be a dict")
    if set(payload.keys()) != _TICKET_PAYLOAD_KEYS:
        raise _ticket_invalid(
            "payload must contain exactly the keys 'issuer', 'keyVersion', "
            "'nonce', 'notAfter', 'notBefore' and 'paths'"
        )
    issuer = payload[TICKET_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("ticket issuer must be a str")
    if issuer == "":
        raise _ticket_invalid("issuer must be non-empty")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("ticket keyVersion must be an int")
    if key_version <= 0:
        raise _ticket_invalid("keyVersion must be positive")
    nonce = payload[TICKET_NONCE]
    if not isinstance(nonce, str) or nonce == "":
        raise _ticket_invalid("nonce must be a non-empty str")
    bounds: dict[str, int] = {}
    for bound_key in (NOT_BEFORE, NOT_AFTER):
        bound = payload[bound_key]
        if isinstance(bound, bool) or not isinstance(bound, int):
            raise TypeError(f"ticket {bound_key} must be an int")
        if bound < 0:
            raise _ticket_invalid(f"{bound_key} must be non-negative")
        bounds[bound_key] = bound
    if bounds[NOT_BEFORE] > bounds[NOT_AFTER]:
        raise _ticket_invalid("notBefore must not exceed notAfter")
    # The ticket paths obey the same list contract as the command paths:
    # a non-empty list of non-empty, distinct strings.
    _validated_path_list(payload[TICKET_PATHS])

    # The bytes must be the single canonical compact encoding with
    # recursively sorted keys and no trailing byte whatsoever.
    if _proof_compact(data) != raw:
        raise _ticket_invalid("encoding is not the canonical compact form")
    return payload, signature


def _authenticate_ticket(
    keyring: dict[str, list[dict]],
    payload: dict,
    signature: str,
    paths: list[str],
    moment: int,
) -> None:
    """Verify a parsed ticket against the current keyring, paths and moment.

    The key is selected by exact issuer and version with no fallback and
    both the key and the ticket must be usable *now*: unknown
    credentials, a revoked, not-yet-valid or expired key or ticket, a
    path list other than the ticket's and a signature mismatch all raise
    :class:`AuthenticationError`.
    """
    issuer = payload[TICKET_ISSUER]
    key_version = payload[KEY_VERSION]
    entry = None
    for candidate in keyring.get(issuer, ()):
        if candidate[VERSION] == key_version:
            entry = candidate
            break
    if entry is None:
        raise AuthenticationError(
            f"no credentials for issuer {issuer!r} and key version {key_version}"
        )
    if entry[REVOKED]:
        raise AuthenticationError(
            f"credentials for issuer {issuer!r} key version {key_version} "
            "are revoked"
        )
    if moment < entry[NOT_BEFORE]:
        raise AuthenticationError(
            f"credentials for issuer {issuer!r} key version {key_version} "
            "are not yet valid"
        )
    if moment > entry[NOT_AFTER]:
        raise AuthenticationError(
            f"credentials for issuer {issuer!r} key version {key_version} "
            "have expired"
        )
    if moment < payload[NOT_BEFORE]:
        raise AuthenticationError("the ticket is not yet valid")
    if moment > payload[NOT_AFTER]:
        raise AuthenticationError("the ticket has expired")
    if list(paths) != list(payload[TICKET_PATHS]):
        raise AuthenticationError("paths do not match the ticket")
    expected = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _proof_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise AuthenticationError("signature does not match the ticket")


def _recovery_audit_invalid(message: str) -> CorruptRecoveryAuditError:
    return CorruptRecoveryAuditError(f"invalid recovery audit: {message}")


def _audit_record_hash(record_without_hash: dict) -> str:
    """SHA-256 of the canonical compact encoding of one audit record."""
    return hashlib.sha256(_proof_compact(record_without_hash)).hexdigest()


def _validated_audit_record_paths(value: object, where: str) -> None:
    """Require a non-empty list of non-empty, distinct path strings."""
    if not isinstance(value, list) or not value:
        raise _recovery_audit_invalid(
            f"{where} paths must be a non-empty array"
        )
    seen: set[str] = set()
    for element in value:
        if not isinstance(element, str) or element == "":
            raise _recovery_audit_invalid(
                f"{where} paths must hold non-empty str"
            )
        if element in seen:
            raise _recovery_audit_invalid(f"{where} paths must be distinct")
        seen.add(element)


def _parse_recovery_audit(raw: bytes) -> list[dict]:
    """Validate every byte of a recovery audit chain into its records.

    Any decoding, structural, domain, chain or canonical-encoding
    violation raises :class:`CorruptRecoveryAuditError`.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _recovery_audit_invalid("is not valid UTF-8") from exc

    records: list[dict] = []
    if text == "":
        return records
    # Every record, including the last one, must be newline-terminated.
    lines = text.split("\n")
    if lines[-1] != "":
        raise _recovery_audit_invalid(
            "the last line is not terminated by a newline"
        )
    expected_seq = 1
    expected_prev = _RECOVERY_AUDIT_ZERO_HASH
    for line_no, line in enumerate(lines[:-1], start=1):
        where = f"line {line_no}"
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise _recovery_audit_invalid(f"{where} is not valid JSON") from exc
        if not isinstance(data, dict):
            raise _recovery_audit_invalid(f"{where} must be a JSON object")
        kind = data.get("kind")
        if kind not in _RECOVERY_AUDIT_KIND_KEYS:
            raise _recovery_audit_invalid(
                f"{where} kind must be 'batch', 'before' or 'after'"
            )
        if set(data.keys()) != _RECOVERY_AUDIT_KIND_KEYS[kind]:
            raise _recovery_audit_invalid(
                f"{where} has the wrong keys for kind {kind!r}"
            )
        seq = data["seq"]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _recovery_audit_invalid(f"{where} seq must be an int")
        if seq != expected_seq:
            raise _recovery_audit_invalid(
                f"{where} seq is {seq}, expected {expected_seq}"
            )
        if data["prev"] != expected_prev:
            raise _recovery_audit_invalid(
                f"{where} prev does not match the previous hash"
            )
        nonce = data[TICKET_NONCE]
        if not isinstance(nonce, str) or nonce == "":
            raise _recovery_audit_invalid(
                f"{where} nonce must be a non-empty str"
            )
        if kind == AUDIT_KIND_BATCH:
            issuer = data[TICKET_ISSUER]
            if not isinstance(issuer, str) or issuer == "":
                raise _recovery_audit_invalid(
                    f"{where} issuer must be a non-empty str"
                )
            if not _is_digest(data[TICKET_DIGEST]):
                raise _recovery_audit_invalid(
                    f"{where} ticketDigest must be 64 lowercase hex characters"
                )
            _validated_audit_record_paths(data[TICKET_PATHS], where)
        else:
            path = data["path"]
            if not isinstance(path, str) or path == "":
                raise _recovery_audit_invalid(
                    f"{where} path must be a non-empty str"
                )
            digest = data["digest"]
            if digest is not None and not _is_digest(digest):
                raise _recovery_audit_invalid(
                    f"{where} digest must be null or 64 lowercase hex characters"
                )
            if kind == AUDIT_KIND_BEFORE:
                if data["phase"] is not None and data["phase"] not in (
                    _RECOVERY_AUDIT_PHASES
                ):
                    raise _recovery_audit_invalid(
                        f"{where} phase must be null, 'prepared' or 'installed'"
                    )
                if data["action"] is not None and data["action"] not in (
                    _RECOVERY_AUDIT_ACTIONS
                ):
                    raise _recovery_audit_invalid(
                        f"{where} action must be null, 'rollback' or 'complete'"
                    )
            else:
                if data["status"] not in _RECOVERY_AUDIT_STATUSES:
                    raise _recovery_audit_invalid(
                        f"{where} status is not a known recovery status"
                    )
                if data["error"] is not None and data["error"] not in (
                    _RECOVERY_AUDIT_ERRORS
                ):
                    raise _recovery_audit_invalid(
                        f"{where} error must be null, 'corrupt' or 'os-error'"
                    )
        without_hash = {key: value for key, value in data.items() if key != "hash"}
        if data["hash"] != _audit_record_hash(without_hash):
            raise _recovery_audit_invalid(
                f"{where} hash does not match its contents"
            )
        # The line must be the single canonical compact encoding with
        # recursively sorted keys: no whitespace, no non-canonical
        # escapes, no permuted keys, no escaped non-ASCII.
        if _proof_compact(data) != line.encode("utf-8"):
            raise _recovery_audit_invalid(
                f"{where} is not canonically encoded"
            )
        records.append(data)
        expected_seq += 1
        expected_prev = data["hash"]
    return records


def _read_recovery_audit(path: str) -> list[dict]:
    """Load the recovery audit chain; a missing file is an empty chain."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    return _parse_recovery_audit(raw)


def _append_recovery_audit_record(path: str, chain: dict, fields: dict) -> None:
    """Append one record to the recovery audit chain and sync it.

    ``chain`` tracks the next ``seq`` and the last ``hash`` and is
    advanced only after the record is durable.  The line is written,
    flushed and fsynced before the call returns (a newly created file
    also syncs its directory), so every record is durable before the
    recovery step it gates.  An :class:`OSError` propagates unchanged
    with the chain restored to its pre-call prefix: the partial line is
    truncated away, or the file unlinked when this append created it.
    """
    record = dict(fields)
    record["prev"] = chain["prev"]
    record["seq"] = chain["seq"]
    record["hash"] = _audit_record_hash(record)
    line = _proof_compact(record) + b"\n"
    existed = os.path.exists(path)
    original_size = os.path.getsize(path) if existed else 0
    dir_fd: int | None = None
    try:
        with open(path, "ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        if not existed:
            dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
            os.fsync(dir_fd)
    except OSError:
        _restore_log(path, existed, original_size)
        raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    chain["prev"] = record["hash"]
    chain["seq"] += 1


def _recover_one_isolated(path: str) -> tuple[str, str | None, str | None]:
    """Settle one ledger, mapping failures to (status, digest, error)."""
    try:
        result = recover_ledger(path)
    except CorruptRecoveryError:
        return STATUS_BLOCKED, None, ERROR_CORRUPT
    except OSError:
        return STATUS_FAILED, None, ERROR_OS_ERROR
    return result[STATUS], result["digest"], None


def recover_authorized(
    paths: list[str],
    keyring: dict,
    ticket: bytes,
    moment: int,
    audit: str,
) -> list[dict]:
    """Recover every ledger in an authorized, audited batch, in order.

    ``paths`` is the explicit ledger path list, validated exactly as in
    :func:`recover_many`.  ``keyring`` follows the
    :func:`apply_signed_remote` rules, ``ticket`` is the canonical
    ticket bytes (see the module docstring), ``moment`` is the current
    time as a non-negative integer and ``audit`` is the path of the
    append-only recovery audit chain.

    Every argument is validated and the whole ticket is verified before
    any ledger is read: type faults raise :class:`TypeError` (a
    :class:`bool` never poses as ``moment``), a malformed ticket key
    set, nonce, validity interval, encoding or signature format raises
    :class:`ValueError`, and unknown credentials, a revoked,
    not-yet-valid or expired key or ticket, a command path list that is
    not item-for-item the ticket's and a signature mismatch raise
    :class:`AuthenticationError`.  A failed authorization creates no
    audit record, consumes no nonce and leaves no temporary file.

    Once authorized, the first use of the nonce persists a ``batch``
    header binding the ticket digest, the issuer and the ordered paths;
    each ledger then gets a ``before`` record (original digest, phase,
    planned action) and, after it settles, an ``after`` record (new
    digest, status, failure category), every record written, flushed
    and synced before the step it gates.  The same nonce bound to a
    different ticket raises :class:`ReplayError` (a :class:`ValueError`)
    without modifying any file; a corrupt audit chain raises
    :class:`CorruptRecoveryAuditError` (a :class:`ValueError`).  An
    :class:`OSError` while reading the audit or writing, flushing or
    syncing a record propagates unchanged and leaves a consistent,
    retryable chain prefix.

    Re-entering with the same nonce and the same ticket reuses the
    recorded results and only continues the paths not yet settled; a
    process interrupted after a recovery but before its result record
    is completed from the recorded action and digests, without
    repeating side effects.  The result is one fresh report dict per
    path, in the given order, with the :func:`recover_many` key order
    ``path``, ``status``, ``digest``, ``error``; a blocked or failed
    ledger never stops the later ones.
    """
    validated_paths = _validated_path_list(paths)
    validated_keyring = _validated_keyring(keyring)
    if not isinstance(ticket, bytes):
        raise TypeError("ticket must be bytes")
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    if not isinstance(audit, str):
        raise TypeError("audit must be a str")

    payload, signature = _parse_ticket(ticket)
    # The whole ticket is verified before any ledger is read, so a
    # failed authorization creates no audit record, consumes no nonce
    # and leaves no temporary file behind.
    _authenticate_ticket(
        validated_keyring, payload, signature, validated_paths, moment
    )

    records = _read_recovery_audit(audit)
    nonce = payload[TICKET_NONCE]
    ticket_digest = _digest(ticket)
    batch = None
    before_map: dict[str, dict] = {}
    after_map: dict[str, dict] = {}
    for record in records:
        if record[TICKET_NONCE] != nonce:
            continue
        if record["kind"] == AUDIT_KIND_BATCH:
            batch = record
        elif record["kind"] == AUDIT_KIND_BEFORE:
            before_map[record["path"]] = record
        else:
            after_map[record["path"]] = record
    if batch is not None and batch[TICKET_DIGEST] != ticket_digest:
        raise ReplayError(
            f"nonce {nonce!r} is already bound to a different ticket"
        )

    chain = {
        "seq": len(records) + 1,
        "prev": records[-1]["hash"] if records else _RECOVERY_AUDIT_ZERO_HASH,
    }
    if batch is None:
        # First use of the nonce: the batch header binds the ticket
        # digest, the issuer and the ordered paths before any ledger
        # is settled.
        _append_recovery_audit_record(
            audit,
            chain,
            {
                "kind": AUDIT_KIND_BATCH,
                TICKET_ISSUER: payload[TICKET_ISSUER],
                TICKET_NONCE: nonce,
                TICKET_PATHS: list(validated_paths),
                TICKET_DIGEST: ticket_digest,
            },
        )

    items: list[dict] = []
    for path in validated_paths:
        settled = after_map.get(path)
        if settled is not None:
            # A completed result is reused as recorded; the path is
            # neither read nor settled again.
            items.append(
                {
                    "path": path,
                    STATUS: settled["status"],
                    "digest": settled["digest"],
                    "error": settled["error"],
                }
            )
            continue
        pending = before_map.get(path)
        if pending is None:
            report = _inspect_one(path)
            _append_recovery_audit_record(
                audit,
                chain,
                {
                    "kind": AUDIT_KIND_BEFORE,
                    TICKET_NONCE: nonce,
                    "path": path,
                    "digest": report["digest"],
                    "phase": report["phase"],
                    "action": report["action"],
                },
            )
            planned_action = report["action"]
        else:
            planned_action = pending["action"]
        status, digest, error = _recover_one_isolated(path)
        if status == STATUS_CLEAN and planned_action is not None:
            # The earlier process recovered the ledger but was
            # interrupted before the result record landed; the recorded
            # action and the idempotent recovery fill the result in
            # without repeating any side effect.
            status = (
                STATUS_ROLLED_BACK
                if planned_action == ACTION_ROLLBACK
                else STATUS_COMPLETED
            )
        _append_recovery_audit_record(
            audit,
            chain,
            {
                "kind": AUDIT_KIND_AFTER,
                TICKET_NONCE: nonce,
                "path": path,
                "digest": digest,
                "status": status,
                "error": error,
            },
        )
        items.append(
            {"path": path, STATUS: status, "digest": digest, "error": error}
        )
    return items


def export_recovery_audit(path: str, after: int = 0, limit: int = 100) -> dict:
    """Page the recovery audit chain at ``path``, read-only.

    Selects the first ``limit`` records whose ``seq`` is greater than
    ``after``.  The whole chain is validated first: a corrupt chain
    raises :class:`CorruptRecoveryAuditError` (a :class:`ValueError`),
    a missing audit file is treated as an empty chain and an
    :class:`OSError` while reading propagates unchanged.  ``after``
    must not exceed the chain's last seq (an empty chain has last seq
    0).

    Type violations raise :class:`TypeError` (``bool`` is not accepted
    as an int); ``after < 0`` or a ``limit`` outside ``[1, 1000]``
    raises :class:`ValueError`.  The result is a fresh dict with the
    key order ``after``, ``complete``, ``next``, ``records``: ``after``
    echoes the argument, ``records`` holds the selected records as
    stored, ``next`` is the seq of the last record in the page (or
    ``after`` itself when the page is empty) and ``complete`` is true
    when no record follows the page.  The audit is never modified.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if isinstance(after, bool) or not isinstance(after, int):
        raise TypeError("after must be an int")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an int")
    if after < 0:
        raise ValueError("after must be >= 0")
    if limit < _MIN_LIMIT or limit > _MAX_LIMIT:
        raise ValueError("limit must be in [1, 1000]")

    records = _read_recovery_audit(path)
    last_seq = records[-1]["seq"] if records else 0
    if after > last_seq:
        raise ValueError("after must not exceed the last audit seq")

    selected = [record for record in records if record["seq"] > after]
    selected = selected[:limit]
    next_seq = selected[-1]["seq"] if selected else after
    return {
        AFTER: after,
        COMPLETE: next_seq == last_seq,
        NEXT: next_seq,
        RECORDS: [dict(record) for record in selected],
    }


# --- Signed recovery checkpoints and offline page verification --------------

CHECKPOINT_VERSION = 1

CP_DIGEST = "digest"
CP_ISSUER = TICKET_ISSUER
CP_KEY_VERSION = KEY_VERSION
CP_MOMENT = "moment"
CP_LAST_SEQ = "lastSeq"
CP_TAIL = "tail"

_CHECKPOINT_TOP_KEYS = frozenset((
    TICKET_PAYLOAD,
    SIGNATURE,
))
_CHECKPOINT_PAYLOAD_KEYS = frozenset((
    CP_ISSUER,
    CP_KEY_VERSION,
    CP_LAST_SEQ,
    CP_MOMENT,
    CP_TAIL,
    VERSION,
))
_PAGE_KEYS = frozenset((AFTER, COMPLETE, NEXT, RECORDS))
_CURSOR_KEYS = frozenset((CP_DIGEST, NEXT, CP_TAIL))

_VERIFY_CONTINUE = "continue"
_VERIFY_VERIFIED = "verified"


class InvalidRecoveryCheckpointError(ValueError):
    """Recovery checkpoint bytes fail their format or anchor contract."""


class InvalidRecoveryPageError(ValueError):
    """A recovery page or cursor fails its format or continuity contract."""


def _checkpoint_invalid(message: str) -> InvalidRecoveryCheckpointError:
    return InvalidRecoveryCheckpointError(f"invalid recovery checkpoint: {message}")


def _page_invalid(message: str) -> InvalidRecoveryPageError:
    return InvalidRecoveryPageError(f"invalid recovery page: {message}")


def _reject_duplicate_checkpoint_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate checkpoint keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _checkpoint_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _checkpoint_compact(obj: object) -> bytes:
    """Canonical compact sorted-key UTF-8 JSON of checkpoint content."""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _select_checkpoint_key(
    keyring: dict[str, list[dict]], issuer: str, key_version: int
) -> dict:
    """Pick the key bound to exactly ``issuer`` and ``key_version``.

    Selection is exact with no fallback; missing credentials raise
    :class:`AuthenticationError`.
    """
    for candidate in keyring.get(issuer, ()):
        if candidate[VERSION] == key_version:
            return candidate
    raise AuthenticationError(
        f"no credentials for issuer {issuer!r} and key version {key_version}"
    )


def _usable_checkpoint_key(
    keyring: dict[str, list[dict]],
    issuer: str,
    key_version: int,
    moment: int,
) -> dict:
    """Select the exact key and require it to be usable at ``moment``.

    Unknown credentials and a revoked, not-yet-valid or expired key
    raise :class:`AuthenticationError`; selection never falls back to
    another version.
    """
    entry = _select_checkpoint_key(keyring, issuer, key_version)
    if entry[REVOKED]:
        raise AuthenticationError(
            f"credentials for issuer {issuer!r} key version {key_version} "
            "are revoked"
        )
    if moment < entry[NOT_BEFORE]:
        raise AuthenticationError(
            f"credentials for issuer {issuer!r} key version {key_version} "
            "are not yet valid"
        )
    if moment > entry[NOT_AFTER]:
        raise AuthenticationError(
            f"credentials for issuer {issuer!r} key version {key_version} "
            "have expired"
        )
    return entry


def _checkpoint_payload_bytes(payload: dict) -> bytes:
    """The signed canonical bytes: the payload alone, compact and sorted."""
    return _checkpoint_compact(payload)


def _parse_checkpoint(raw: object) -> tuple[dict, str]:
    """Validate checkpoint bytes structurally into ``(payload, signature)``.

    A non-bytes argument or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, range, shape or canonical-format fault raises
    :class:`InvalidRecoveryCheckpointError`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("checkpoint must be bytes")
    # The checkpoint carries no terminator of any kind: no trailing
    # newline and no other byte past the closing brace.
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _checkpoint_invalid("must end with the closing brace, no LF")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _checkpoint_invalid("is not valid UTF-8") from exc
    try:
        # The pairs hook raises directly on duplicate object keys.
        data = json.loads(text, object_pairs_hook=_reject_duplicate_checkpoint_keys)
    except json.JSONDecodeError as exc:
        raise _checkpoint_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise TypeError("checkpoint must be a JSON object")
    if set(data.keys()) != _CHECKPOINT_TOP_KEYS:
        raise _checkpoint_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("checkpoint signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _checkpoint_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("checkpoint payload must be a dict")
    if set(payload.keys()) != _CHECKPOINT_PAYLOAD_KEYS:
        raise _checkpoint_invalid(
            "payload must contain exactly the keys 'issuer', 'keyVersion', "
            "'lastSeq', 'moment', 'tail' and 'version'"
        )
    issuer = payload[CP_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("checkpoint issuer must be a str")
    if issuer == "":
        raise _checkpoint_invalid("issuer must be non-empty")
    key_version = payload[CP_KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("checkpoint keyVersion must be an int")
    if key_version <= 0:
        raise _checkpoint_invalid("keyVersion must be positive")
    moment = payload[CP_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("checkpoint moment must be an int")
    if moment < 0:
        raise _checkpoint_invalid("moment must be non-negative")
    last_seq = payload[CP_LAST_SEQ]
    if isinstance(last_seq, bool) or not isinstance(last_seq, int):
        raise TypeError("checkpoint lastSeq must be an int")
    if last_seq < 0:
        raise _checkpoint_invalid("lastSeq must be >= 0")
    tail = payload[CP_TAIL]
    if not isinstance(tail, str):
        raise TypeError("checkpoint tail must be a str")
    if not _is_digest(tail):
        raise _checkpoint_invalid(
            "tail must be 64 lowercase hex characters"
        )
    if last_seq == 0 and tail != _RECOVERY_AUDIT_ZERO_HASH:
        raise _checkpoint_invalid(
            "tail must be the zero hash when lastSeq is 0"
        )
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("checkpoint version must be an int")
    if version != CHECKPOINT_VERSION:
        raise _checkpoint_invalid("version must be the integer 1")

    # The bytes must be the single canonical compact form with sorted
    # keys and no trailing byte whatsoever.
    if _checkpoint_compact(data) != raw:
        raise _checkpoint_invalid("encoding is not the canonical compact form")
    return payload, signature


def export_recovery_checkpoint(
    audit: str,
    keyring: dict,
    issuer: str,
    version: int,
    moment: int,
) -> bytes:
    """Export a signed checkpoint anchoring the recovery audit prefix.

    The recovery audit at ``audit`` is read and validated in full but
    never modified; a missing audit file stands for the empty chain
    (last seq 0, zero tail hash).  The checkpoint binds the checkpoint
    format ``version``, the signing ``issuer``, the selected key
    version, the ``moment``, the chain's last seq and the chain tail
    (the last record hash, or the zero hash for an empty chain), and
    carries the lowercase hex HMAC-SHA256 of the canonical compact
    payload bytes under the key the keyring binds to the exact issuer
    and version -- with no fallback.

    The result is one canonical compact UTF-8 JSON object -- every
    object key recursively sorted lexicographically, non-ASCII
    preserved -- carrying exactly ``payload`` and ``signature``, with
    no trailing newline or any other trailing byte.

    Type faults in the arguments raise :class:`TypeError` (a
    :class:`bool` never poses as an int); keyring structure or format
    faults raise :class:`ValueError`.  Unknown credentials and a
    revoked, not-yet-valid or expired key at ``moment`` raise
    :class:`AuthenticationError` (a :class:`ValueError`); a corrupt
    audit chain raises :class:`CorruptRecoveryAuditError` and an
    :class:`OSError` while reading propagates unchanged.
    """
    if not isinstance(audit, str):
        raise TypeError("audit must be a str")
    validated_keyring = _validated_keyring(keyring)
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")

    entry = _usable_checkpoint_key(validated_keyring, issuer, version, moment)

    records = _read_recovery_audit(audit)
    last_seq = records[-1]["seq"] if records else 0
    tail = records[-1]["hash"] if records else _RECOVERY_AUDIT_ZERO_HASH

    payload = {
        CP_ISSUER: issuer,
        CP_KEY_VERSION: version,
        CP_LAST_SEQ: last_seq,
        CP_MOMENT: moment,
        CP_TAIL: tail,
        VERSION: CHECKPOINT_VERSION,
    }
    payload_bytes = _checkpoint_payload_bytes(payload)
    signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


def _page_field_type_error(message: str) -> TypeError:
    return TypeError(f"invalid recovery page: {message}")


def _validated_page_records(
    records: list, start_seq: int, opening_prev: str | None
) -> str:
    """Validate every record of a page and its full hash chain.

    Records must occupy the contiguous seqs ``start_seq + 1`` through
    ``start_seq + len(records)``; the first record's ``prev`` must equal
    ``opening_prev`` when one is supplied (the zero hash on the first
    page or the cursor tail on later pages) and is only shape-checked
    when it is ``None``.  Every later record chains to its predecessor's
    hash and every stored hash is recomputed.

    Field type faults raise :class:`TypeError` (a :class:`bool` never
    poses as an int); key-set, domain, gap, reordering, duplicate, hash
    and chain faults raise :class:`InvalidRecoveryPageError`.  Returns
    the tail hash of the page's last record.
    """
    expected_seq = start_seq
    expected_prev = opening_prev
    for index, record in enumerate(records):
        where = f"record {index}"
        if not isinstance(record, dict):
            raise _page_field_type_error(f"{where} must be a dict")
        kind = record.get("kind")
        if "kind" not in record:
            raise _page_invalid(f"{where} is missing its kind")
        if not isinstance(kind, str):
            raise _page_field_type_error(f"{where} kind must be a str")
        if kind not in _RECOVERY_AUDIT_KIND_KEYS:
            raise _page_invalid(
                f"{where} kind must be 'batch', 'before' or 'after'"
            )
        if set(record.keys()) != _RECOVERY_AUDIT_KIND_KEYS[kind]:
            raise _page_invalid(f"{where} has the wrong keys for its kind")
        seq = record["seq"]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _page_field_type_error(f"{where} seq must be an int")
        prev = record["prev"]
        digest = record["hash"]
        if not isinstance(prev, str):
            raise _page_field_type_error(f"{where} prev must be a str")
        if not _is_digest(prev):
            raise _page_invalid(
                f"{where} prev must be 64 lowercase hex characters"
            )
        if not isinstance(digest, str):
            raise _page_field_type_error(f"{where} hash must be a str")
        if not _is_digest(digest):
            raise _page_invalid(
                f"{where} hash must be 64 lowercase hex characters"
            )
        expected_seq += 1
        if seq != expected_seq:
            raise _page_invalid(
                f"{where} seq is {seq}, expected {expected_seq}"
            )
        if expected_prev is not None and prev != expected_prev:
            raise _page_invalid(
                f"{where} prev does not chain to the previous record hash"
            )
        nonce = record[TICKET_NONCE]
        if not isinstance(nonce, str):
            raise _page_field_type_error(f"{where} nonce must be a str")
        if nonce == "":
            raise _page_invalid(f"{where} nonce must be non-empty")
        if kind == AUDIT_KIND_BATCH:
            issuer_value = record[TICKET_ISSUER]
            if not isinstance(issuer_value, str):
                raise _page_field_type_error(f"{where} issuer must be a str")
            if issuer_value == "":
                raise _page_invalid(f"{where} issuer must be non-empty")
            ticket_digest = record[TICKET_DIGEST]
            if not isinstance(ticket_digest, str):
                raise _page_field_type_error(
                    f"{where} ticketDigest must be a str"
                )
            if not _is_digest(ticket_digest):
                raise _page_invalid(
                    f"{where} ticketDigest must be 64 lowercase hex characters"
                )
            paths_value = record[TICKET_PATHS]
            if not isinstance(paths_value, list):
                raise _page_field_type_error(f"{where} paths must be an array")
            if not paths_value:
                raise _page_invalid(f"{where} paths must be a non-empty array")
            seen_paths: set[str] = set()
            for element in paths_value:
                if not isinstance(element, str):
                    raise _page_field_type_error(
                        f"{where} paths must hold str"
                    )
                if element == "":
                    raise _page_invalid(
                        f"{where} paths must hold non-empty str"
                    )
                if element in seen_paths:
                    raise _page_invalid(f"{where} paths must be distinct")
                seen_paths.add(element)
        else:
            path_value = record["path"]
            if not isinstance(path_value, str):
                raise _page_field_type_error(f"{where} path must be a str")
            if path_value == "":
                raise _page_invalid(f"{where} path must be non-empty")
            digest_value = record["digest"]
            if digest_value is not None:
                if not isinstance(digest_value, str):
                    raise _page_field_type_error(
                        f"{where} digest must be a str or null"
                    )
                if not _is_digest(digest_value):
                    raise _page_invalid(
                        f"{where} digest must be null or 64 lowercase hex "
                        "characters"
                    )
            if kind == AUDIT_KIND_BEFORE:
                phase = record["phase"]
                action = record["action"]
                if phase is not None and not isinstance(phase, str):
                    raise _page_field_type_error(f"{where} phase must be a str")
                if action is not None and not isinstance(action, str):
                    raise _page_field_type_error(f"{where} action must be a str")
                if phase is not None and phase not in _RECOVERY_AUDIT_PHASES:
                    raise _page_invalid(
                        f"{where} phase must be null, 'prepared' or 'installed'"
                    )
                if action is not None and action not in _RECOVERY_AUDIT_ACTIONS:
                    raise _page_invalid(
                        f"{where} action must be null, 'rollback' or 'complete'"
                    )
            else:
                status_value = record["status"]
                error_value = record["error"]
                if not isinstance(status_value, str):
                    raise _page_field_type_error(f"{where} status must be a str")
                if status_value not in _RECOVERY_AUDIT_STATUSES:
                    raise _page_invalid(
                        f"{where} status is not a known recovery status"
                    )
                if error_value is not None and not isinstance(error_value, str):
                    raise _page_field_type_error(f"{where} error must be a str")
                if (
                    error_value is not None
                    and error_value not in _RECOVERY_AUDIT_ERRORS
                ):
                    raise _page_invalid(
                        f"{where} error must be null, 'corrupt' or 'os-error'"
                    )
        without_hash = {
            key: value for key, value in record.items() if key != "hash"
        }
        if digest != _audit_record_hash(without_hash):
            raise _page_invalid(f"{where} hash does not match its contents")
        expected_prev = digest
    return expected_prev if records else (opening_prev or _RECOVERY_AUDIT_ZERO_HASH)


def _parse_page(
    page: dict, start_seq: int, opening_prev: str | None
) -> tuple[int, int, bool, list, str]:
    """Validate one offline page against its expected opening position.

    Returns ``(after, next, complete, records, tail)``.  Field type
    faults raise :class:`TypeError`; key-set, range, gap, reordering,
    duplicate, boundary and chain faults raise
    :class:`InvalidRecoveryPageError`.
    """
    if set(page.keys()) != _PAGE_KEYS:
        raise _page_invalid(
            "page must contain exactly the keys 'after', 'complete', "
            "'next' and 'records'"
        )
    after = page[AFTER]
    next_seq = page[NEXT]
    complete = page[COMPLETE]
    records = page[RECORDS]
    for key, value in ((AFTER, after), (NEXT, next_seq)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise _page_field_type_error(f"{key} must be an int")
        if value < 0:
            raise _page_invalid(f"{key} must be >= 0")
    if not isinstance(complete, bool):
        raise _page_field_type_error("complete must be a bool")
    if not isinstance(records, list):
        raise _page_field_type_error("records must be an array")
    if after != start_seq:
        raise _page_invalid(
            "page after does not match the expected resume position"
        )

    tail = _validated_page_records(records, start_seq, opening_prev)
    expected_next = records[-1]["seq"] if records else after
    if next_seq != expected_next:
        raise _page_invalid(
            "next must be the last record seq, or after when the page is empty"
        )
    return after, next_seq, complete, records, tail


def _parse_cursor(cursor: dict) -> tuple[str, int, str]:
    """Validate a resume cursor into ``(checkpoint_digest, next, tail)``."""
    if set(cursor.keys()) != _CURSOR_KEYS:
        raise _page_invalid(
            "cursor must contain exactly the keys 'digest', 'next' and 'tail'"
        )
    cursor_digest = cursor[CP_DIGEST]
    cursor_next = cursor[NEXT]
    cursor_tail = cursor[CP_TAIL]
    if not isinstance(cursor_digest, str):
        raise _page_field_type_error("cursor digest must be a str")
    if not _is_digest(cursor_digest):
        raise _page_invalid(
            "cursor digest must be 64 lowercase hex characters"
        )
    if isinstance(cursor_next, bool) or not isinstance(cursor_next, int):
        raise _page_field_type_error("cursor next must be an int")
    if cursor_next < 0:
        raise _page_invalid("cursor next must be >= 0")
    if not isinstance(cursor_tail, str):
        raise _page_field_type_error("cursor tail must be a str")
    if not _is_digest(cursor_tail):
        raise _page_invalid(
            "cursor tail must be 64 lowercase hex characters"
        )
    return cursor_digest, cursor_next, cursor_tail


def verify_recovery_page(
    checkpoint: bytes,
    page: dict,
    keyring: dict,
    moment: int,
    cursor: dict | None = None,
) -> dict:
    """Verify one recovery audit page against a signed checkpoint, offline.

    Neither the audit nor any other file is read: only the checkpoint
    bytes, the page dict, the keyring, the current ``moment`` and the
    optional resume ``cursor`` are consulted.  The checkpoint is parsed
    and its HMAC-SHA256 is verified against the key the keyring binds
    to the exact issuer and version named in its payload, with no
    fallback and authenticated against the *current* keyring: the key
    must be usable at ``moment``, so a later revocation or expiry
    rejects a checkpoint just as it does a replay.  The ``moment``
    bound into the payload is part of the signed anchor itself and
    needs no equality with the verification time.

    The first call passes no cursor, and the page's ``after`` must be
    zero.  Every later call passes a cursor built from the previous
    result -- ``{"digest", "next", "tail"}``: the page's ``after``
    must equal the cursor's ``next``, its first record must chain to
    the cursor's ``tail`` and the cursor's ``digest`` must equal this
    checkpoint's digest, so a cursor can never resume a different
    checkpoint.  Each page's records must then be contiguous from
    ``after + 1`` -- a gap, reordering or duplicate is rejected --
    correctly hash-chained within the page and across the paging
    boundary, and verification never crosses the signed ``lastSeq``.
    Before that last seq is reached an empty page or a page whose
    ``complete`` flag disagrees with the boundary is rejected.

    On success a fresh dict is returned with the key order ``digest``,
    ``lastSeq``, ``status`` and ``tail``: the checkpoint digest (the
    lowercase hex SHA-256 of the checkpoint bytes), the seq the
    verified prefix ends at, its tail hash and the status.  Reaching
    the signed chain tail yields ``"verified"``; every earlier page
    yields ``"continue"``.  An empty page presented again once the
    tail is reached restates the anchored boundary and reports the
    signed tail.  An empty checkpoint (last seq 0, zero tail) accepts
    only an empty page starting at zero and directly reports seq 0,
    the zero hash and ``"verified"``.

    Type faults in the arguments or fields raise :class:`TypeError`
    (a :class:`bool` never poses as an int); keyring structure or
    format faults raise :class:`ValueError`.  Checkpoint format
    faults raise :class:`InvalidRecoveryCheckpointError`; unknown
    credentials, a revoked, not-yet-valid or expired key at
    ``moment`` and a signature mismatch raise
    :class:`AuthenticationError`; page or cursor format and
    continuity faults raise :class:`InvalidRecoveryPageError`.  The
    two format errors are :class:`ValueError` subclasses.  No input
    is modified and no file is read or written.
    """
    if not isinstance(checkpoint, bytes):
        raise TypeError("checkpoint must be bytes")
    if not isinstance(page, dict):
        raise TypeError("page must be a dict")
    if cursor is not None and not isinstance(cursor, dict):
        raise TypeError("cursor must be a dict or None")
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")

    cursor_digest: str | None = None
    cursor_next: int | None = None
    cursor_tail: str | None = None
    if cursor is not None:
        cursor_digest, cursor_next, cursor_tail = _parse_cursor(cursor)

    payload, signature = _parse_checkpoint(checkpoint)
    checkpoint_digest = hashlib.sha256(checkpoint).hexdigest()
    issuer = payload[CP_ISSUER]
    key_version = payload[CP_KEY_VERSION]
    entry = _usable_checkpoint_key(
        validated_keyring, issuer, key_version, moment
    )
    expected_signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_payload_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError("checkpoint signature does not match")

    if cursor_digest is not None and cursor_digest != checkpoint_digest:
        raise _page_invalid("cursor is bound to a different checkpoint")

    start_seq = 0 if cursor is None else cursor_next
    opening_prev = (
        _RECOVERY_AUDIT_ZERO_HASH if cursor is None else cursor_tail
    )
    _after, next_seq, complete, records, page_tail = _parse_page(
        page, start_seq, opening_prev
    )

    signed_last_seq = payload[CP_LAST_SEQ]
    signed_tail = payload[CP_TAIL]
    if next_seq > signed_last_seq:
        raise _page_invalid("page must not cross the signed lastSeq")

    at_tail = next_seq == signed_last_seq
    if complete != at_tail:
        raise _page_invalid(
            "complete must be true exactly when the page reaches the "
            "signed lastSeq"
        )
    if not at_tail:
        # Before the signed tail is reached an empty page is a gap, not
        # a legitimate boundary: nothing may silently truncate the chain.
        if not records:
            raise _page_invalid(
                "an empty page is not valid before the signed lastSeq"
            )
        return {
            CP_DIGEST: checkpoint_digest,
            CP_LAST_SEQ: next_seq,
            STATUS: _VERIFY_CONTINUE,
            CP_TAIL: page_tail,
        }

    if records:
        if page_tail != signed_tail:
            raise _page_invalid(
                "the final record hash does not match the signed tail"
            )
        current_tail = page_tail
    else:
        # An empty page at the tail (after already equals lastSeq) only
        # restates the anchored boundary; its tail comes from the
        # checkpoint.  This is also the only form an empty checkpoint
        # accepts: first round, after zero, no records.
        if cursor is not None and start_seq != signed_last_seq:
            raise _page_invalid(
                "an empty final page must start at the signed lastSeq"
            )
        current_tail = signed_tail
    return {
        CP_DIGEST: checkpoint_digest,
        CP_LAST_SEQ: signed_last_seq,
        STATUS: _VERIFY_VERIFIED,
        CP_TAIL: current_tail,
    }


# --- Offline batch verification of signed recovery checkpoints ---------------

CHECKPOINTS_VERSION = 1

VERIFY_INCOMPLETE = "incomplete"
VERIFY_INVALID_CHECKPOINT = "invalid-checkpoint"
VERIFY_INVALID_PAGE = "invalid-page"
VERIFY_UNAUTHENTICATED = "unauthenticated"

CHECKPOINT_ITEM_CHECKPOINT = "checkpoint"
CHECKPOINT_ITEM_PAGES = "pages"
CHECKPOINT_ITEM_BOUNDARY = "boundary"
CHECKPOINT_ITEM_ERROR = "error"

_CHECKPOINT_ITEM_KEYS = frozenset((
    CHECKPOINT_ITEM_CHECKPOINT,
    ID,
    CHECKPOINT_ITEM_PAGES,
))


def _validated_checkpoint_items(items: object) -> list[dict]:
    """Validate the batch structure before any checkpoint is verified.

    The argument must be a non-empty list of dicts each holding exactly
    ``id`` (a non-empty str, unique across the batch), ``checkpoint``
    (bytes) and ``pages`` (a non-empty list of page dicts).  Container,
    field and element type faults raise :class:`TypeError`; an empty
    list, an empty or duplicate id, a wrong key set or an empty page
    list raises :class:`ValueError`.  Only a fully validated batch
    comes back -- as fresh item dicts with a copied page list, so the
    verification below never mutates the caller's objects.
    """
    if not isinstance(items, list):
        raise TypeError("items must be a list")
    if not items:
        raise ValueError("items must be a non-empty list")
    validated: list[dict] = []
    seen_ids: set[str] = set()
    for position, item in enumerate(items):
        where = f"item {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{where} must be a dict")
        if set(item.keys()) != _CHECKPOINT_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'checkpoint', "
                "'id' and 'pages'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        checkpoint = item[CHECKPOINT_ITEM_CHECKPOINT]
        if not isinstance(checkpoint, bytes):
            raise TypeError(f"{where} checkpoint must be bytes")
        pages = item[CHECKPOINT_ITEM_PAGES]
        if not isinstance(pages, list):
            raise TypeError(f"{where} pages must be a list")
        if not pages:
            raise ValueError(f"{where} pages must be a non-empty list")
        for page in pages:
            if not isinstance(page, dict):
                raise TypeError(f"{where} pages elements must be dict")
        validated.append(
            {
                ID: item_id,
                CHECKPOINT_ITEM_CHECKPOINT: checkpoint,
                CHECKPOINT_ITEM_PAGES: list(pages),
            }
        )
    return validated


def _checkpoint_item_result(
    item_id: str,
    digest: str,
    issuer: str | None,
    key_version: int | None,
    boundary: dict | None,
    status: str,
    error: str | None,
) -> dict:
    """One batch report entry with the fixed key order."""
    return {
        ID: item_id,
        CP_DIGEST: digest,
        CP_ISSUER: issuer,
        CP_KEY_VERSION: key_version,
        CHECKPOINT_ITEM_BOUNDARY: boundary,
        STATUS: status,
        CHECKPOINT_ITEM_ERROR: error,
    }


def _verify_checkpoint_item(
    item: dict, keyring: dict[str, list[dict]], moment: int
) -> dict:
    """Verify one batch item in isolation and report its outcome.

    The checkpoint is parsed and authenticated against the current
    keyring (exact issuer and version, usable at ``moment``, no
    fallback); the pages are then walked from a zero cursor through
    the exact :func:`verify_recovery_page` rules, each round resuming
    from a cursor bound to this checkpoint's digest and the previous
    page's chain tail.  No file is ever read and no input is modified.
    """
    item_id = item[ID]
    checkpoint = item[CHECKPOINT_ITEM_CHECKPOINT]
    digest = hashlib.sha256(checkpoint).hexdigest()
    try:
        payload, signature = _parse_checkpoint(checkpoint)
    except (InvalidRecoveryCheckpointError, TypeError) as exc:
        return _checkpoint_item_result(
            item_id, digest, None, None, None,
            VERIFY_INVALID_CHECKPOINT, str(exc),
        )
    issuer = payload[CP_ISSUER]
    key_version = payload[CP_KEY_VERSION]
    try:
        entry = _usable_checkpoint_key(keyring, issuer, key_version, moment)
        expected_signature = hmac.new(
            bytes.fromhex(entry[SECRET]),
            _checkpoint_payload_bytes(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            raise AuthenticationError("checkpoint signature does not match")
    except AuthenticationError as exc:
        return _checkpoint_item_result(
            item_id, digest, issuer, key_version, None,
            VERIFY_UNAUTHENTICATED, str(exc),
        )

    boundary: dict | None = None
    cursor: dict | None = None
    pages = item[CHECKPOINT_ITEM_PAGES]
    last_index = len(pages) - 1
    for index, page in enumerate(pages):
        try:
            result = verify_recovery_page(
                checkpoint, page, keyring, moment, cursor
            )
        except (InvalidRecoveryPageError, TypeError) as exc:
            return _checkpoint_item_result(
                item_id, digest, issuer, key_version, boundary,
                VERIFY_INVALID_PAGE, str(exc),
            )
        boundary = {
            CP_LAST_SEQ: result[CP_LAST_SEQ],
            CP_TAIL: result[CP_TAIL],
        }
        if result[STATUS] == _VERIFY_VERIFIED:
            if index != last_index:
                # The signed tail is final: no page may follow it.
                return _checkpoint_item_result(
                    item_id, digest, issuer, key_version, boundary,
                    VERIFY_INVALID_PAGE,
                    "pages continue past the signed lastSeq",
                )
            return _checkpoint_item_result(
                item_id, digest, issuer, key_version, boundary,
                _VERIFY_VERIFIED, None,
            )
        cursor = {
            CP_DIGEST: result[CP_DIGEST],
            NEXT: result[CP_LAST_SEQ],
            CP_TAIL: result[CP_TAIL],
        }
    # The pages ran out before the signed chain tail was reached.
    return _checkpoint_item_result(
        item_id, digest, issuer, key_version, boundary,
        VERIFY_INCOMPLETE,
        "pages exhausted before the signed lastSeq",
    )


def verify_recovery_checkpoints(
    items: list, keyring: dict, moment: int
) -> dict:
    """Verify a batch of signed recovery checkpoints, entirely offline.

    ``items`` is a non-empty list of batch items, each a dict with
    exactly the keys ``id`` (a non-empty str, unique across the batch),
    ``checkpoint`` (the checkpoint bytes produced by
    :func:`export_recovery_checkpoint`) and ``pages`` (a non-empty list
    of page dicts as exported by :func:`export_recovery_audit`, in
    export order, covering one chain prefix).  ``keyring`` follows the
    :func:`apply_signed_remote` rules and ``moment`` is the current
    time as a non-negative integer.  No file is ever read and no input
    is modified.

    The whole batch structure is validated before any item is
    verified: container, field or element type faults raise
    :class:`TypeError` (a :class:`bool` never poses as an int) and an
    empty list, an empty or duplicate id, a wrong item key set or an
    empty page list raises :class:`ValueError`; keyring and ``moment``
    faults follow the :func:`verify_recovery_page` classification.
    Only these batch-level faults raise -- one item's verification
    failure never stops or rolls back the other items.

    Each item is then verified in isolation, in input order: its
    checkpoint is parsed and authenticated against the current keyring
    with the key bound to the checkpoint's own exact issuer and
    version (no fallback, so checkpoints signed before and after a key
    rotation verify independently in the same batch), and its pages
    are walked from a zero cursor through the exact
    :func:`verify_recovery_page` paging rules, every cursor bound to
    the same checkpoint digest and the previous page's chain tail.
    Reaching the signed ``lastSeq`` ends the walk -- further pages are
    a page fault -- and pages that run out earlier leave the item
    ``incomplete`` with its verified boundary kept.

    The result is a fresh dict with the fixed key order ``items``,
    ``version`` (the integer 1).  Every item reports, in this key
    order, ``id``, the checkpoint ``digest`` (the lowercase hex
    SHA-256 of the checkpoint bytes), the signed ``issuer`` and
    ``keyVersion`` (both ``None`` when the checkpoint does not parse),
    the verified ``boundary`` ``{"lastSeq", "tail"}`` (``None`` when
    nothing was verified), a ``status`` of ``verified``,
    ``incomplete``, ``invalid-checkpoint``, ``invalid-page`` or
    ``unauthenticated`` and an ``error`` message (``None`` exactly
    when the item verified).
    """
    validated_items = _validated_checkpoint_items(items)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return {
        ITEMS: [
            _verify_checkpoint_item(item, validated_keyring, moment)
            for item in validated_items
        ],
        VERSION: CHECKPOINTS_VERSION,
    }


# --- Offline multi-site adjudication of recovery attestations ----------------

ADJUDICATE_VERSION = 1

ADJ_BATCH = "batch"
ADJ_THRESHOLD = "threshold"
ADJ_SITES = "sites"
ADJ_SITE = "site"
ADJ_RESULT = "result"
ADJ_ATTESTATION = "attestation"
ADJ_CONCLUSION = "conclusion"
ADJ_REASON = "reason"

ADJ_STATUS_ACCEPTED = "accepted"
ADJ_STATUS_CONFLICTED = "conflicted"
ADJ_STATUS_INSUFFICIENT = "insufficient"

ADJ_CONCLUSION_VALID = "valid"
ADJ_CONCLUSION_INVALID = "invalid"
ADJ_CONCLUSION_DUPLICATE = "duplicate"
REASON_DUPLICATE = "duplicate"
ADJ_CONCLUSION_CONTRADICTION = "contradiction"
REASON_CONTRADICTION = "contradiction"

REASON_UNAUTHORIZED_BATCH = "unauthorized-batch"
REASON_UNAUTHORIZED_SITE = "unauthorized-site"
REASON_UNAUTHORIZED_VERSION = "unauthorized-version"
REASON_CREDENTIAL_UNAVAILABLE = "credential-unavailable"
REASON_REVOKED = "revoked"
REASON_NOT_YET_VALID = "not-yet-valid"
REASON_EXPIRED = "expired"
REASON_BAD_SIGNATURE = "bad-signature"
REASON_NOT_VERIFIED = "not-verified"
REASON_INVALID_ATTESTATION = "invalid-attestation"

_ADJ_POLICY_KEYS = frozenset((ADJ_BATCH, ADJ_THRESHOLD, ADJ_SITES))
_ADJ_ITEM_KEYS = frozenset((ID, ADJ_ATTESTATION))
_ADJ_ATTESTATION_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_ADJ_PAYLOAD_KEYS = frozenset((
    ADJ_BATCH,
    KEY_VERSION,
    ADJ_RESULT,
    ADJ_SITE,
))
_ADJ_RESULT_KEYS = frozenset((
    CHECKPOINT_ITEM_BOUNDARY,
    CP_DIGEST,
    CHECKPOINT_ITEM_ERROR,
    ID,
    CP_ISSUER,
    CP_KEY_VERSION,
    STATUS,
))
_ADJ_RESULT_STATUSES = frozenset((
    _VERIFY_VERIFIED,
    VERIFY_INCOMPLETE,
    VERIFY_INVALID_CHECKPOINT,
    VERIFY_INVALID_PAGE,
    VERIFY_UNAUTHENTICATED,
))
_ADJ_BOUNDARY_KEYS = frozenset((CP_LAST_SEQ, CP_TAIL))


def _adjudication_invalid(message: str) -> ValueError:
    return ValueError(f"invalid recovery attestation: {message}")


def _reject_duplicate_adjudication_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate attestation keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _adjudication_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _validated_embedded_result(result: object) -> dict:
    """Validate the embedded single-item batch verification result.

    The result must follow the public
    :func:`verify_recovery_checkpoints` item shape: ``boundary``,
    ``digest``, ``error``, ``id``, ``issuer``, ``keyVersion`` and
    ``status``, with ``error`` null exactly when ``status`` is
    ``verified``.  A ``verified`` result always carries the checkpoint
    identity (a non-empty ``issuer``, a positive ``keyVersion``) and the
    signed ``{"lastSeq", "tail"}`` boundary.  Every non-verified result
    keeps its ``id``, ``digest`` and ``status``; when the checkpoint did
    not parse its ``issuer``, ``keyVersion`` and ``boundary`` are all
    null, otherwise the signed identity and the verified boundary (which
    may itself be null) are preserved.  Any fault is an invalid
    attestation.
    """
    if not isinstance(result, dict):
        raise _adjudication_invalid("result must be an object")
    if set(result.keys()) != _ADJ_RESULT_KEYS:
        raise _adjudication_invalid(
            "result must contain exactly the keys 'boundary', 'digest', "
            "'error', 'id', 'issuer', 'keyVersion' and 'status'"
        )
    result_id = result[ID]
    if not isinstance(result_id, str) or result_id == "":
        raise _adjudication_invalid("result id must be a non-empty str")
    if not _is_digest(result[CP_DIGEST]):
        raise _adjudication_invalid(
            "result digest must be 64 lowercase hex characters"
        )
    issuer = result[CP_ISSUER]
    if not isinstance(issuer, str) and issuer is not None:
        raise _adjudication_invalid("result issuer must be a str or null")
    key_version = result[CP_KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        if key_version is not None:
            raise _adjudication_invalid(
                "result keyVersion must be an int or null"
            )
    elif key_version <= 0:
        raise _adjudication_invalid("result keyVersion must be positive")
    status = result[STATUS]
    if not isinstance(status, str) or status not in _ADJ_RESULT_STATUSES:
        raise _adjudication_invalid("result status is not a known status")
    error = result[CHECKPOINT_ITEM_ERROR]
    if status == _VERIFY_VERIFIED:
        if error is not None:
            raise _adjudication_invalid(
                "result error must be null when status is verified"
            )
        if not isinstance(issuer, str) or issuer == "":
            raise _adjudication_invalid(
                "result issuer must be a non-empty str when status is verified"
            )
        if key_version is None or key_version <= 0:
            raise _adjudication_invalid(
                "result keyVersion must be positive when status is verified"
            )
    elif not isinstance(error, str) or error == "":
        raise _adjudication_invalid(
            "result error must be a non-empty str for a non-verified status"
        )
    boundary = result[CHECKPOINT_ITEM_BOUNDARY]
    if boundary is not None:
        if not isinstance(boundary, dict) or set(boundary.keys()) != _ADJ_BOUNDARY_KEYS:
            raise _adjudication_invalid(
                "result boundary must be null or {'lastSeq', 'tail'}"
            )
        last_seq = boundary[CP_LAST_SEQ]
        if isinstance(last_seq, bool) or not isinstance(last_seq, int):
            raise _adjudication_invalid("boundary lastSeq must be an int")
        if last_seq < 0:
            raise _adjudication_invalid("boundary lastSeq must be >= 0")
        if not _is_digest(boundary[CP_TAIL]):
            raise _adjudication_invalid(
                "boundary tail must be 64 lowercase hex characters"
            )
    if status == _VERIFY_VERIFIED and boundary is None:
        raise _adjudication_invalid(
            "result boundary must be present when status is verified"
        )
    # Identity and version are null exactly together: a report only
    # drops them when the checkpoint itself does not parse, in which
    # case the boundary is null as well.
    if (issuer is None) != (key_version is None):
        raise _adjudication_invalid(
            "result issuer and keyVersion must be null together"
        )
    if issuer is None and boundary is not None:
        raise _adjudication_invalid(
            "result boundary must be null when issuer is null"
        )
    return {
        CHECKPOINT_ITEM_BOUNDARY: (
            None
            if boundary is None
            else {CP_LAST_SEQ: boundary[CP_LAST_SEQ], CP_TAIL: boundary[CP_TAIL]}
        ),
        CP_DIGEST: result[CP_DIGEST],
        CHECKPOINT_ITEM_ERROR: error,
        ID: result_id,
        CP_ISSUER: issuer,
        CP_KEY_VERSION: key_version,
        STATUS: status,
    }


def _parse_adjudication_attestation(raw: object) -> tuple[dict, str]:
    """Validate one attestation packet into ``(payload, signature)``.

    The packet must be canonical compact UTF-8 JSON with recursively
    sorted keys and no trailing byte, carrying exactly ``payload`` and
    ``signature``; the payload carries exactly ``batch``,
    ``keyVersion``, ``result`` and ``site``, with ``result`` following
    the public single-item batch verification shape.  A non-bytes
    argument or any encoding, key-set, field or canonical-form fault
    raises :class:`ValueError`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("attestation must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _adjudication_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _adjudication_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_adjudication_keys
        )
    except json.JSONDecodeError as exc:
        raise _adjudication_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _adjudication_invalid("must be a JSON object")
    if set(data.keys()) != _ADJ_ATTESTATION_TOP_KEYS:
        raise _adjudication_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise _adjudication_invalid("signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _adjudication_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise _adjudication_invalid("payload must be an object")
    if set(payload.keys()) != _ADJ_PAYLOAD_KEYS:
        raise _adjudication_invalid(
            "payload must contain exactly the keys 'batch', 'keyVersion', "
            "'result' and 'site'"
        )
    batch = payload[ADJ_BATCH]
    if not isinstance(batch, str) or batch == "":
        raise _adjudication_invalid("payload batch must be a non-empty str")
    site = payload[ADJ_SITE]
    if not isinstance(site, str) or site == "":
        raise _adjudication_invalid("payload site must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise _adjudication_invalid("payload keyVersion must be an int")
    if key_version <= 0:
        raise _adjudication_invalid("payload keyVersion must be positive")
    _validated_embedded_result(payload[ADJ_RESULT])

    if _checkpoint_compact(data) != raw:
        raise _adjudication_invalid("encoding is not the canonical compact form")
    return payload, signature


def _validated_adjudication_items(items: object) -> list[dict]:
    """Validate the adjudication item container before any packet is read.

    A non-list container or a non-dict element, non-str id or non-bytes
    attestation raises :class:`TypeError`; an empty list, an empty or
    duplicate id or a wrong item key set raises :class:`ValueError`.
    """
    if not isinstance(items, list):
        raise TypeError("items must be a list")
    if not items:
        raise ValueError("items must be a non-empty list")
    validated: list[dict] = []
    seen_ids: set[str] = set()
    for position, item in enumerate(items):
        where = f"item {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{where} must be a dict")
        if set(item.keys()) != _ADJ_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'attestation' and 'id'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        attestation = item[ADJ_ATTESTATION]
        if not isinstance(attestation, bytes):
            raise TypeError(f"{where} attestation must be bytes")
        validated.append({ID: item_id, ADJ_ATTESTATION: attestation})
    return validated


def _validated_adjudication_policy(policy: object) -> dict:
    """Validate the adjudication policy into a fresh normalized dict.

    Type faults raise :class:`TypeError` (a :class:`bool` never poses as
    an int); key-set, batch, threshold, site or version-set faults raise
    :class:`ValueError`.
    """
    if not isinstance(policy, dict):
        raise TypeError("policy must be a dict")
    if set(policy.keys()) != _ADJ_POLICY_KEYS:
        raise ValueError(
            "policy must contain exactly the keys 'batch', 'sites' and "
            "'threshold'"
        )
    batch = policy[ADJ_BATCH]
    if not isinstance(batch, str):
        raise TypeError("policy batch must be a str")
    if batch == "":
        raise ValueError("policy batch must be non-empty")
    threshold = policy[ADJ_THRESHOLD]
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise TypeError("policy threshold must be an int")
    if threshold <= 0:
        raise ValueError("policy threshold must be a positive integer")
    sites = policy[ADJ_SITES]
    if not isinstance(sites, dict):
        raise TypeError("policy sites must be a dict")
    if not sites:
        raise ValueError("policy sites must be non-empty")
    allowed: dict[str, frozenset[int]] = {}
    for site, versions in sites.items():
        if not isinstance(site, str):
            raise TypeError("policy site names must be str")
        if site == "":
            raise ValueError("policy site names must be non-empty")
        if not isinstance(versions, set):
            raise TypeError(
                f"allowed versions for site {site!r} must be a set"
            )
        site_versions: set[int] = set()
        for version in versions:
            if isinstance(version, bool) or not isinstance(version, int):
                raise TypeError(
                    f"allowed versions for site {site!r} must be ints"
                )
            if version <= 0:
                raise ValueError(
                    f"allowed versions for site {site!r} must be positive"
                )
            site_versions.add(version)
        if not site_versions:
            raise ValueError(
                f"site {site!r} must allow at least one key version"
            )
        allowed[site] = frozenset(site_versions)
    if threshold > len(allowed):
        raise ValueError(
            "policy threshold must not exceed the number of policy sites"
        )
    return {
        ADJ_BATCH: batch,
        ADJ_THRESHOLD: threshold,
        ADJ_SITES: allowed,
    }


def _adjudication_item_report(
    item_id: str,
    site: str | None,
    key_version: int | None,
    digest: str | None,
    boundary: dict | None,
    status: str | None,
    conclusion: str,
    reason: str | None,
) -> dict:
    """One per-item adjudication report with a fixed key order."""
    return {
        CHECKPOINT_ITEM_BOUNDARY: boundary,
        ADJ_CONCLUSION: conclusion,
        CP_DIGEST: digest,
        ID: item_id,
        CP_KEY_VERSION: key_version,
        ADJ_REASON: reason,
        ADJ_SITE: site,
        STATUS: status,
    }


def _adjudicate_one(
    item: dict,
    policy: dict,
    keyring: dict[str, list[dict]],
    moment: int,
) -> tuple[dict, tuple[str, str, dict, dict] | None]:
    """Adjudicate one packet in isolation.

    Returns ``(report, vote)`` where ``vote`` is
    ``(site, digest, boundary, result)`` for a packet that counts and
    ``None`` otherwise.  ``result`` is the full authenticated embedded
    single-item result, so two same-site packets count as duplicates only
    when every result field is identical.  A malformed packet is rejected
    on its own and never affects the other packets.
    """
    item_id = item[ID]
    attestation = item[ADJ_ATTESTATION]
    invalid = lambda reason: (
        _adjudication_item_report(
            item_id, None, None, None, None, None,
            ADJ_CONCLUSION_INVALID, reason,
        ),
        None,
    )
    try:
        payload, signature = _parse_adjudication_attestation(attestation)
    except (TypeError, ValueError):
        return invalid(REASON_INVALID_ATTESTATION)

    site = payload[ADJ_SITE]
    key_version = payload[KEY_VERSION]
    result = _validated_embedded_result(payload[ADJ_RESULT])
    digest = result[CP_DIGEST]
    boundary = result[CHECKPOINT_ITEM_BOUNDARY]
    status = result[STATUS]

    def reject(reason: str) -> tuple[dict, None]:
        return (
            _adjudication_item_report(
                item_id, site, key_version, digest, boundary, status,
                ADJ_CONCLUSION_INVALID, reason,
            ),
            None,
        )

    if payload[ADJ_BATCH] != policy[ADJ_BATCH]:
        return reject(REASON_UNAUTHORIZED_BATCH)
    allowed_versions = policy[ADJ_SITES].get(site)
    if allowed_versions is None:
        return reject(REASON_UNAUTHORIZED_SITE)
    if key_version not in allowed_versions:
        return reject(REASON_UNAUTHORIZED_VERSION)

    entry = None
    for candidate in keyring.get(site, ()):
        if candidate[VERSION] == key_version:
            entry = candidate
            break
    if entry is None:
        return reject(REASON_CREDENTIAL_UNAVAILABLE)
    if entry[REVOKED]:
        return reject(REASON_REVOKED)
    if moment < entry[NOT_BEFORE]:
        return reject(REASON_NOT_YET_VALID)
    if moment > entry[NOT_AFTER]:
        return reject(REASON_EXPIRED)

    expected_signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        return reject(REASON_BAD_SIGNATURE)

    # Only a verified single-item result may cast a vote; every other
    # authenticated result is rejected with its fixed reason.
    if status != _VERIFY_VERIFIED:
        return reject(REASON_NOT_VERIFIED)

    report = _adjudication_item_report(
        item_id, site, key_version, digest, boundary, status,
        ADJ_CONCLUSION_VALID, None,
    )
    return report, (site, digest, boundary, result)


def adjudicate_recovery(
    items: list, policy: dict, keyring: dict, moment: int
) -> bytes:
    """Adjudicate multi-site recovery attestations offline into JSON bytes.

    ``items`` is a non-empty list; each item is a dict with exactly the
    keys ``id`` (a non-empty str, unique across the batch) and
    ``attestation`` (bytes).  The attestation is one canonical compact
    UTF-8 JSON object -- every object key recursively sorted, non-ASCII
    preserved, no trailing newline or any other trailing byte --
    carrying exactly ``payload`` and ``signature``.  The payload binds
    exactly ``batch``, ``site``, ``keyVersion`` and ``result`` with no
    extra fields; ``result`` follows the public single-item
    :func:`verify_recovery_checkpoints` shape (``boundary``, ``digest``,
    ``error``, ``id``, ``issuer``, ``keyVersion``, ``status``).  The
    signature is the lowercase hex HMAC-SHA256 of the canonical compact
    payload bytes under the key the keyring binds to the exact site and
    version, with no fallback.

    ``policy`` is a dict with exactly ``batch`` (the authorized batch
    id), ``threshold`` (a positive integer no greater than the number
    of sites) and ``sites`` (a non-empty mapping of each authorized
    non-empty site name to its non-empty set of allowed positive key
    versions).  ``keyring`` follows the :func:`apply_signed_remote`
    rules and ``moment`` is the current time as a non-negative integer.
    No file is ever read and no input is modified.

    The item container, policy and keyring are validated in full before
    any attestation is examined: parameter, container or public field
    type faults raise :class:`TypeError` (a :class:`bool` never poses as
    an int) and an empty list, a duplicate id or an illegal threshold,
    site or version rule raises :class:`ValueError`.  A single packet
    with illegal encoding, key sets or fields is rejected on its own as
    ``invalid-attestation`` and never blocks the other packets.

    Packets are authenticated against the *current* keyring with exact
    site/version selection and no fallback, so the fixed reasons
    ``unauthorized-batch``, ``unauthorized-site``,
    ``unauthorized-version``, ``credential-unavailable``, ``revoked``,
    ``not-yet-valid``, ``expired``, ``bad-signature`` and
    ``not-verified`` each reject (and never count) their packet.  For
    one site the same valid packet -- an identical embedded result on
    every field -- counts once; later identical packets are
    ``duplicate``, while a different valid result from the same site
    (even one sharing digest and boundary) is a ``contradiction``.
    Valid packets from different sites must agree on both digest and
    boundary: any disagreement is a cross-site conflict that no majority
    can outvote.

    The returned bytes are one canonical compact UTF-8 JSON object with
    recursively sorted keys, non-ASCII preserved and no trailing byte,
    with the top-level keys ``boundary``, ``digest``, ``items``,
    ``status``, ``threshold`` and ``version`` (the integer 1).  Any
    contradiction or cross-site disagreement makes ``status``
    ``conflicted`` with ``digest`` and ``boundary`` null; otherwise the
    one agreed digest and ``{"lastSeq", "tail"}`` boundary are reported
    as ``accepted`` once the distinct agreeing sites reach the
    threshold, and all other cases are ``insufficient`` with both null.
    Every packet is kept in ``items`` -- sorted stably by site then id
    -- carrying its ``id``, ``site``, ``keyVersion``, ``digest``,
    ``boundary``, single-item ``status``, ``conclusion`` (``valid``,
    ``invalid``, ``duplicate`` or ``contradiction``) and fixed
    ``reason`` (null only for a valid packet).  The conclusion never
    depends on input order.
    """
    validated_items = _validated_adjudication_items(items)
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")

    reports: list[dict] = []
    accepted: list[dict] = []
    for item in validated_items:
        report, vote = _adjudicate_one(
            item, validated_policy, validated_keyring, moment
        )
        reports.append(report)
        if vote is not None:
            site, digest, boundary, result = vote
            accepted.append(
                {
                    "site": site,
                    "digest": digest,
                    "boundary": boundary,
                    "result": result,
                    ID: report[ID],
                    "report": report,
                }
            )

    # Per-site accounting is derived from the authenticated, verified
    # packets keyed by their unique ids, never from input order.  Two
    # packets from one site are the same attestation only when their
    # complete embedded results agree field for field: the smallest-id
    # packet of one identical group is the vote and every exact repeat a
    # duplicate, while any two distinct full results are a
    # self-contradiction whose representatives each contradict and whose
    # exact repeats stay duplicates.
    by_site: dict[str, list[dict]] = {}
    for packet in accepted:
        by_site.setdefault(packet["site"], []).append(packet)

    votes: list[tuple[str, str, dict]] = []
    contradicted = False
    for site, packets in by_site.items():
        groups: dict[str, list[dict]] = {}
        for packet in packets:
            content = _checkpoint_compact(packet["result"]).decode("utf-8")
            groups.setdefault(content, []).append(packet)
        ordered = sorted(
            groups.items(), key=lambda kv: min(member[ID] for member in kv[1])
        )
        if len(ordered) == 1:
            members = sorted(ordered[0][1], key=lambda member: member[ID])
            votes.append((site, members[0]["digest"], members[0]["boundary"]))
            extras = members[1:]
        else:
            contradicted = True
            extras = []
            for _content, members in ordered:
                members = sorted(members, key=lambda member: member[ID])
                members[0]["report"][ADJ_CONCLUSION] = (
                    ADJ_CONCLUSION_CONTRADICTION
                )
                members[0]["report"][ADJ_REASON] = REASON_CONTRADICTION
                extras.extend(members[1:])
        for extra in extras:
            extra["report"][ADJ_CONCLUSION] = ADJ_CONCLUSION_DUPLICATE
            extra["report"][ADJ_REASON] = REASON_DUPLICATE

    # Cross-site agreement: every counted vote must name the same digest
    # and boundary, regardless of how many sites back either side.  Sites
    # that already self-contradicted cast no vote.
    contents = {(digest, _checkpoint_compact(boundary).decode("utf-8"))
                for _site, digest, boundary in votes}
    conflicted = contradicted or len(contents) > 1

    if conflicted:
        overall_status = ADJ_STATUS_CONFLICTED
        agreed_digest: str | None = None
        agreed_boundary: dict | None = None
    elif len(contents) == 1:
        agreeing_sites = {site for site, _digest, _boundary in votes}
        if len(agreeing_sites) >= validated_policy[ADJ_THRESHOLD]:
            overall_status = ADJ_STATUS_ACCEPTED
            agreed_digest, agreed_boundary = votes[0][1], votes[0][2]
        else:
            overall_status = ADJ_STATUS_INSUFFICIENT
            agreed_digest, agreed_boundary = None, None
    else:
        overall_status = ADJ_STATUS_INSUFFICIENT
        agreed_digest, agreed_boundary = None, None

    reports.sort(
        key=lambda report: (
            report[ADJ_SITE] is not None,
            report[ADJ_SITE] or "",
            report[ID],
        )
    )
    result = {
        CHECKPOINT_ITEM_BOUNDARY: agreed_boundary,
        ITEMS: reports,
        STATUS: overall_status,
        ADJ_THRESHOLD: validated_policy[ADJ_THRESHOLD],
        VERSION: ADJUDICATE_VERSION,
        "digest": agreed_digest,
    }
    return _checkpoint_compact(result)


# --- Offline signed handover of the aggregate recovery verdict ----------------

RECOVERY_VERDICT_VERSION = 1

VD_ISSUER = TICKET_ISSUER
VD_SIGNED_AT = "signedAt"
VD_POLICY_DIGEST = "policyDigest"
VD_VERDICT = "verdict"
VD_VERDICT_DIGEST = "verdictDigest"

_VERDICT_PROOF_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_VERDICT_PAYLOAD_KEYS = frozenset((
    ADJ_BATCH,
    VD_ISSUER,
    KEY_VERSION,
    VD_SIGNED_AT,
    VD_POLICY_DIGEST,
    VD_VERDICT,
))
_VERDICT_RESULT_KEYS = (
    ADJ_BATCH,
    VD_ISSUER,
    KEY_VERSION,
    VD_SIGNED_AT,
    VD_POLICY_DIGEST,
    VD_VERDICT_DIGEST,
    STATUS,
    CP_DIGEST,
    CHECKPOINT_ITEM_BOUNDARY,
    ITEMS,
    VERSION,
)
_VERDICT_TOP_KEYS = frozenset((
    CHECKPOINT_ITEM_BOUNDARY,
    ITEMS,
    STATUS,
    ADJ_THRESHOLD,
    VERSION,
    CP_DIGEST,
))
_ADJ_ITEM_REPORT_KEYS = frozenset((
    CHECKPOINT_ITEM_BOUNDARY,
    ADJ_CONCLUSION,
    CP_DIGEST,
    ID,
    CP_KEY_VERSION,
    ADJ_REASON,
    ADJ_SITE,
    STATUS,
))


class InvalidRecoveryVerdictError(ValueError):
    """The signed-off recovery verdict bytes fail their canonical contract."""


class InvalidRecoveryVerdictProofError(ValueError):
    """A recovery verdict proof is structurally invalid or binds wrong data."""


def _verdict_invalid(message: str) -> InvalidRecoveryVerdictError:
    return InvalidRecoveryVerdictError(f"invalid recovery verdict: {message}")


def _verdict_proof_invalid(message: str) -> InvalidRecoveryVerdictProofError:
    return InvalidRecoveryVerdictProofError(
        f"invalid recovery verdict proof: {message}"
    )


def _reject_duplicate_verdict_keys(
    pairs: list[tuple], invalid=_verdict_invalid
) -> dict:
    """``object_pairs_hook`` turning duplicate verdict keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _verdict_policy_bytes(policy: dict) -> bytes:
    """Canonical compact bytes of the normalized adjudication policy.

    Sites are listed in ascending site order and each site's allowed
    versions are an ascending array; every object key is recursively
    sorted lexicographically and non-ASCII is preserved.  These bytes are
    the sole representation :func:`export_recovery_verdict` signs and
    :func:`verify_recovery_verdict` rehashes, so both sides agree on the
    digest without sharing an encoding of the input sets.
    """
    ordered_sites = {
        site: sorted(policy[ADJ_SITES][site])
        for site in sorted(policy[ADJ_SITES])
    }
    canonical = {
        ADJ_BATCH: policy[ADJ_BATCH],
        ADJ_SITES: ordered_sites,
        ADJ_THRESHOLD: policy[ADJ_THRESHOLD],
    }
    return _checkpoint_compact(canonical)


def _verdict_payload_bytes(payload: dict) -> bytes:
    """The signed canonical bytes: the proof payload alone, compact."""
    return _checkpoint_compact(payload)


def _parse_verdict(
    raw: object,
    invalid=_verdict_invalid,
    type_invalid=TypeError,
) -> dict:
    """Validate verdict bytes structurally into a fresh dict.

    The verdict must be the exact canonical compact UTF-8 JSON object
    :func:`adjudicate_recovery` returns.  A non-bytes argument or a
    field of the wrong JSON type raises ``type_invalid`` (a
    :class:`bool` never poses as an int); every encoding, key-set,
    range, shape or canonical-form fault raises ``invalid``.

    The standalone export path keeps ``InvalidRecoveryVerdictError``
    and :class:`TypeError`; a verdict bound inside a proof is part of
    the proof payload, so the verification path passes
    :class:`InvalidRecoveryVerdictProofError` factories and every fault
    is attributed to the proof.
    """
    if not isinstance(raw, bytes):
        raise type_invalid("verdict must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise invalid("is not valid UTF-8") from exc

    def reject_pairs(pairs: list[tuple]) -> dict:
        return _reject_duplicate_verdict_keys(pairs, invalid=invalid)

    try:
        data = json.loads(text, object_pairs_hook=reject_pairs)
    except json.JSONDecodeError as exc:
        raise invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise type_invalid("verdict must be a JSON object")
    if set(data.keys()) != _VERDICT_TOP_KEYS:
        raise invalid(
            "must contain exactly the keys 'boundary', 'digest', 'items', "
            "'status', 'threshold' and 'version'"
        )
    version = data[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise type_invalid("verdict version must be an int")
    if version != ADJUDICATE_VERSION:
        raise invalid("version must be the integer 1")
    status = data[STATUS]
    if not isinstance(status, str):
        raise type_invalid("verdict status must be a str")
    if status not in (
        ADJ_STATUS_ACCEPTED,
        ADJ_STATUS_CONFLICTED,
        ADJ_STATUS_INSUFFICIENT,
    ):
        raise invalid("status is not a known verdict status")
    threshold = data[ADJ_THRESHOLD]
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise type_invalid("verdict threshold must be an int")
    if threshold <= 0:
        raise invalid("threshold must be positive")
    digest = data[CP_DIGEST]
    if digest is not None:
        if not isinstance(digest, str):
            raise type_invalid("verdict digest must be a str or null")
        if not _is_digest(digest):
            raise invalid(
                "digest must be null or 64 lowercase hex characters"
            )
    if status == ADJ_STATUS_ACCEPTED and digest is None:
        raise invalid("an accepted verdict must carry its digest")
    if status != ADJ_STATUS_ACCEPTED and digest is not None:
        raise invalid(
            "digest must be null unless the verdict is accepted"
        )
    boundary = data[CHECKPOINT_ITEM_BOUNDARY]
    if boundary is not None:
        if not isinstance(boundary, dict):
            raise type_invalid("verdict boundary must be an object or null")
        if set(boundary.keys()) != _ADJ_BOUNDARY_KEYS:
            raise invalid(
                "boundary must be null or {'lastSeq', 'tail'}"
            )
        last_seq = boundary[CP_LAST_SEQ]
        if isinstance(last_seq, bool) or not isinstance(last_seq, int):
            raise type_invalid("boundary lastSeq must be an int")
        if last_seq < 0:
            raise invalid("boundary lastSeq must be >= 0")
        tail = boundary[CP_TAIL]
        if not isinstance(tail, str):
            raise type_invalid("boundary tail must be a str")
        if not _is_digest(tail):
            raise invalid(
                "boundary tail must be 64 lowercase hex characters"
            )
    if status == ADJ_STATUS_ACCEPTED and boundary is None:
        raise invalid("an accepted verdict must carry its boundary")
    if status != ADJ_STATUS_ACCEPTED and boundary is not None:
        raise invalid(
            "boundary must be null unless the verdict is accepted"
        )
    items = data[ITEMS]
    if not isinstance(items, list):
        raise type_invalid("verdict items must be a list")
    for position, item in enumerate(items):
        where = f"item {position}"
        if not isinstance(item, dict):
            raise type_invalid(f"{where} must be an object")
        if set(item.keys()) != _ADJ_ITEM_REPORT_KEYS:
            raise invalid(
                f"{where} must contain exactly the keys 'boundary', "
                "'conclusion', 'digest', 'id', 'keyVersion', 'reason', "
                "'site' and 'status'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise type_invalid(f"{where} id must be a str")
        if item_id == "":
            raise invalid(f"{where} id must be non-empty")
        site = item[ADJ_SITE]
        if site is not None:
            if not isinstance(site, str):
                raise type_invalid(f"{where} site must be a str or null")
            if site == "":
                raise invalid(f"{where} site must be non-empty")
        key_version = item[CP_KEY_VERSION]
        if isinstance(key_version, bool) or not isinstance(key_version, int):
            if key_version is not None:
                raise type_invalid(
                    f"{where} keyVersion must be an int or null"
                )
        elif key_version <= 0:
            raise invalid(f"{where} keyVersion must be positive")
        item_digest = item[CP_DIGEST]
        if item_digest is not None:
            if not isinstance(item_digest, str):
                raise type_invalid(f"{where} digest must be a str or null")
            if not _is_digest(item_digest):
                raise invalid(
                    f"{where} digest must be 64 lowercase hex characters"
                )
        item_status = item[STATUS]
        if item_status is not None:
            if not isinstance(item_status, str):
                raise type_invalid(f"{where} status must be a str or null")
            if item_status not in _ADJ_RESULT_STATUSES:
                raise invalid(
                    f"{where} status is not a known result status"
                )
        item_boundary = item[CHECKPOINT_ITEM_BOUNDARY]
        if item_boundary is not None:
            if not isinstance(item_boundary, dict):
                raise type_invalid(
                    f"{where} boundary must be an object or null"
                )
            if set(item_boundary.keys()) != _ADJ_BOUNDARY_KEYS:
                raise invalid(
                    f"{where} boundary must be null or "
                    "{'lastSeq', 'tail'}"
                )
            item_last_seq = item_boundary[CP_LAST_SEQ]
            if isinstance(item_last_seq, bool) or not isinstance(item_last_seq, int):
                raise type_invalid(
                    f"{where} boundary lastSeq must be an int"
                )
            if item_last_seq < 0:
                raise invalid(
                    f"{where} boundary lastSeq must be non-negative"
                )
            if not isinstance(item_boundary[CP_TAIL], str):
                raise type_invalid(f"{where} boundary tail must be a str")
            if not _is_digest(item_boundary[CP_TAIL]):
                raise invalid(
                    f"{where} boundary tail must be 64 lowercase hex chars"
                )
        conclusion = item[ADJ_CONCLUSION]
        if not isinstance(conclusion, str):
            raise type_invalid(f"{where} conclusion must be a str")
        if conclusion not in (
            ADJ_CONCLUSION_VALID,
            ADJ_CONCLUSION_INVALID,
            ADJ_CONCLUSION_DUPLICATE,
            ADJ_CONCLUSION_CONTRADICTION,
        ):
            raise invalid(f"{where} conclusion is not known")
        reason = item[ADJ_REASON]
        if conclusion == ADJ_CONCLUSION_VALID:
            if reason is not None:
                raise invalid(
                    f"{where} reason must be null for a valid packet"
                )
        else:
            if not isinstance(reason, str):
                raise type_invalid(f"{where} reason must be a str")
            if reason == "":
                raise invalid(
                    f"{where} reason must be a non-empty str"
                )

    if _checkpoint_compact(data) != raw:
        raise invalid("encoding is not the canonical compact form")
    return data


def _parse_verdict_proof(raw: object) -> tuple[dict, str]:
    """Validate proof bytes structurally into ``(payload, signature)``.

    A non-bytes argument or a field of the wrong JSON type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, range, signature-format or canonical-form fault
    raises :class:`InvalidRecoveryVerdictProofError`.  Semantic and
    digest bindings are checked by :func:`verify_recovery_verdict`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("proof must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _verdict_proof_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _verdict_proof_invalid("is not valid UTF-8") from exc

    def reject_duplicates(pairs: list[tuple]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise _verdict_proof_invalid(
                    f"duplicate key {key!r} in object"
                )
            result[key] = value
        return result

    try:
        data = json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise _verdict_proof_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise TypeError("proof must be a JSON object")
    if set(data.keys()) != _VERDICT_PROOF_KEYS:
        raise _verdict_proof_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("proof signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _verdict_proof_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("proof payload must be an object")
    if set(payload.keys()) != _VERDICT_PAYLOAD_KEYS:
        raise _verdict_proof_invalid(
            "payload must contain exactly the keys 'batch', 'issuer', "
            "'keyVersion', 'policyDigest', 'signedAt' and 'verdict'"
        )
    batch = payload[ADJ_BATCH]
    if not isinstance(batch, str):
        raise TypeError("payload batch must be a str")
    if batch == "":
        raise _verdict_proof_invalid("payload batch must be non-empty")
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _verdict_proof_invalid("payload issuer must be non-empty")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _verdict_proof_invalid("payload keyVersion must be positive")
    signed_at = payload[VD_SIGNED_AT]
    if isinstance(signed_at, bool) or not isinstance(signed_at, int):
        raise TypeError("payload signedAt must be an int")
    if signed_at < 0:
        raise _verdict_proof_invalid("payload signedAt must be non-negative")
    policy_digest = payload[VD_POLICY_DIGEST]
    if not isinstance(policy_digest, str):
        raise TypeError("payload policyDigest must be a str")
    if not _is_digest(policy_digest):
        raise _verdict_proof_invalid(
            "payload policyDigest must be 64 lowercase hex characters"
        )
    if not isinstance(payload[VD_VERDICT], dict):
        raise TypeError("payload verdict must be an object")

    if _checkpoint_compact(data) != raw:
        raise _verdict_proof_invalid(
            "encoding is not the canonical compact form"
        )
    return payload, signature


def export_recovery_verdict(
    verdict: bytes,
    policy: dict,
    keyring: dict,
    issuer: str,
    version: int,
    moment: int,
) -> bytes:
    """Sign an aggregate recovery verdict into an offline handover proof.

    ``verdict`` is the canonical compact JSON returned by
    :func:`adjudicate_recovery`; ``policy`` is the same
    ``{"batch", "sites", "threshold"}`` object the verdict was
    adjudicated under; ``keyring`` follows the
    :func:`apply_signed_remote` rules and ``moment`` is the signing
    time.  The proof is one canonical compact UTF-8 JSON object -- every
    object key recursively sorted, non-ASCII preserved, no trailing
    newline or any other trailing byte -- carrying exactly ``payload``
    and ``signature``.

    The payload binds exactly ``batch``, ``issuer``, ``keyVersion``,
    ``signedAt``, ``policyDigest`` and the complete ``verdict``.  The
    policy digest is the lowercase hex SHA-256 of one canonical compact
    encoding of the policy: sites in ascending order and each site's
    allowed versions as an ascending array, all keys recursively sorted.
    The signature is the lowercase hex HMAC-SHA256 of the canonical
    compact payload bytes under the key the keyring binds to the exact
    issuer and version, with no fallback; unknown credentials and a
    revoked, not-yet-valid or expired key raise
    :class:`AuthenticationError`.

    A non-bytes verdict or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    invalid issuer, version or moment raises :class:`ValueError`;
    keyring structure or format faults raise :class:`ValueError`;
    unknown credentials and a revoked, not-yet-valid or expired key
    raise :class:`AuthenticationError`; and a verdict that fails its
    canonical contract raises :class:`InvalidRecoveryVerdictError`.
    No file is read or written and no input is modified.
    """
    if not isinstance(verdict, bytes):
        raise TypeError("verdict must be bytes")
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")

    entry = _usable_checkpoint_key(validated_keyring, issuer, version, moment)
    parsed_verdict = _parse_verdict(verdict)

    policy_digest = hashlib.sha256(
        _verdict_policy_bytes(validated_policy)
    ).hexdigest()
    payload = {
        ADJ_BATCH: validated_policy[ADJ_BATCH],
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        VD_SIGNED_AT: moment,
        VD_POLICY_DIGEST: policy_digest,
        VD_VERDICT: parsed_verdict,
    }
    signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _verdict_payload_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


def verify_recovery_verdict(
    proof: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a signed recovery verdict proof entirely offline.

    Only the proof bytes, the expected ``policy``, the current
    ``keyring`` and the verification ``moment`` are consulted -- no file
    is read and no argument is modified.  Verification recomputes both
    digests from the proof and the policy: the policy digest over the
    canonical compact policy encoding, and the verdict digest as the
    SHA-256 of the canonical compact encoding of the verdict object
    bound into the payload.  It then checks that the payload batch and
    threshold match the policy, that the signing moment is a plausible
    past anchor, that the verdict structure and verdict digest agree
    with the bound object, and that the HMAC-SHA256 signature was made
    by the key the *current* keyring binds to the payload's exact issuer
    and version and which is usable at ``moment`` -- a later revocation
    or expiry rejects the proof just as it does a replay.

    The result is a fresh dict with the fixed keys ``batch``,
    ``issuer``, ``keyVersion``, ``signedAt``, ``policyDigest``,
    ``verdictDigest``, ``status``, ``digest``, ``boundary``, ``items``
    and ``version`` (the integer 1), where ``status``, ``digest``,
    ``boundary`` and ``items`` come from the authenticated verdict.

    A non-bytes proof or a public field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    invalid policy, identifier, version or moment raises
    :class:`ValueError`; keyring structure or format faults raise
    :class:`ValueError`; a bad proof structure, an illegal verdict
    structure, field type or canonical encoding bound into the payload,
    a recomputed digest mismatch or a payload that binds the wrong
    batch or threshold raises :class:`InvalidRecoveryVerdictProofError`
    (a :class:`ValueError` subclass; the standalone
    :class:`InvalidRecoveryVerdictError` guards only
    :func:`export_recovery_verdict`'s verdict argument); and unknown,
    revoked, not-yet-valid or expired credentials or a signature
    mismatch raise :class:`AuthenticationError`.
    """
    if not isinstance(proof, bytes):
        raise TypeError("proof must be bytes")
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return _verify_recovery_verdict(
        proof, validated_policy, validated_keyring, moment
    )


def _verify_recovery_verdict(
    proof: bytes,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one proof against already-validated policy/keyring/moment.

    This is the shared core of :func:`verify_recovery_verdict` and the
    batch :func:`verify_recovery_verdicts`; the caller owns the
    argument-type and batch-structure validation.  The returned dict is
    freshly built solely from authenticated proof material.
    """
    payload, signature = _parse_verdict_proof(proof)
    issuer = payload[VD_ISSUER]
    key_version = payload[KEY_VERSION]
    signed_at = payload[VD_SIGNED_AT]
    bound_batch = payload[ADJ_BATCH]
    verdict = payload[VD_VERDICT]

    # The verdict bound into the payload must be a structurally valid
    # canonical verdict on its own.  It is part of the proof payload, so
    # every structural, type or canonical-encoding fault is attributed to
    # the proof rather than to a standalone verdict.
    verdict_bytes = _checkpoint_compact(verdict)

    def bound_proof_invalid(message: str) -> InvalidRecoveryVerdictProofError:
        return _verdict_proof_invalid(f"bound verdict {message}")

    parsed_verdict = _parse_verdict(
        verdict_bytes,
        invalid=bound_proof_invalid,
        type_invalid=bound_proof_invalid,
    )

    recomputed_policy_digest = hashlib.sha256(
        _verdict_policy_bytes(validated_policy)
    ).hexdigest()
    if payload[VD_POLICY_DIGEST] != recomputed_policy_digest:
        raise _verdict_proof_invalid("policyDigest does not match the policy")
    if bound_batch != validated_policy[ADJ_BATCH]:
        raise _verdict_proof_invalid(
            "payload batch does not match the policy batch"
        )
    if parsed_verdict[ADJ_THRESHOLD] != validated_policy[ADJ_THRESHOLD]:
        raise _verdict_proof_invalid(
            "verdict threshold does not match the policy threshold"
        )
    if signed_at > moment:
        raise _verdict_proof_invalid(
            "signedAt must not be later than the verification moment"
        )

    entry = _usable_checkpoint_key(
        validated_keyring, issuer, key_version, moment
    )
    expected_signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _verdict_payload_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError("verdict proof signature does not match")

    verdict_digest = hashlib.sha256(verdict_bytes).hexdigest()
    result = {
        ADJ_BATCH: bound_batch,
        VD_ISSUER: issuer,
        KEY_VERSION: key_version,
        VD_SIGNED_AT: signed_at,
        VD_POLICY_DIGEST: recomputed_policy_digest,
        VD_VERDICT_DIGEST: verdict_digest,
        STATUS: parsed_verdict[STATUS],
        CP_DIGEST: parsed_verdict[CP_DIGEST],
        CHECKPOINT_ITEM_BOUNDARY: parsed_verdict[CHECKPOINT_ITEM_BOUNDARY],
        ITEMS: parsed_verdict[ITEMS],
        VERSION: RECOVERY_VERDICT_VERSION,
    }
    return {key: result[key] for key in _VERDICT_RESULT_KEYS}


VERDICTS_VERSION = 1
VERDICT_ITEM_PROOF = "proof"
VERDICT_ITEM_RESULT = "result"
VERIFY_INVALID_PROOF = "invalid-proof"

_VERDICT_BATCH_ITEM_KEYS = frozenset((ID, VERDICT_ITEM_PROOF))
_VERDICT_BATCH_REPORT_KEYS = (
    CHECKPOINT_ITEM_ERROR,
    ID,
    VERDICT_ITEM_RESULT,
    STATUS,
)


def _validated_verdict_items(items: object) -> list[dict]:
    """Validate the verdict-proof batch before any proof is verified.

    The argument must be a non-empty list of dicts each holding exactly
    ``id`` (a non-empty str, unique across the batch) and ``proof``
    (bytes).  Container, field and element type faults raise
    :class:`TypeError`; an empty list, an empty or duplicate id or a
    wrong key set raises :class:`ValueError`.  Only a fully validated
    batch comes back, as fresh item dicts that share neither the
    caller's containers nor its identity objects.
    """
    if not isinstance(items, list):
        raise TypeError("items must be a list")
    if not items:
        raise ValueError("items must be a non-empty list")
    validated: list[dict] = []
    seen_ids: set[str] = set()
    for position, item in enumerate(items):
        where = f"item {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{where} must be a dict")
        if set(item.keys()) != _VERDICT_BATCH_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'id' and 'proof'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        proof = item[VERDICT_ITEM_PROOF]
        if not isinstance(proof, bytes):
            raise TypeError(f"{where} proof must be bytes")
        validated.append({ID: item_id, VERDICT_ITEM_PROOF: proof})
    return validated


def _verdict_batch_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One batch verdict report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def _verify_verdict_item(
    item: dict,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one verdict proof in isolation and report its outcome.

    The proof runs through the exact :func:`verify_recovery_verdict`
    checks.  Current but revoked, not-yet-valid, expired or missing
    credentials and a wrong signature make the item ``unauthenticated``;
    every encoding, key-set, field, digest, batch, threshold, signing
    moment or embedded-verdict fault makes it ``invalid-proof``; a proof
    that passes is ``verified`` with the single-entry result.  The
    authenticated identity, digest and boundary reach a report only via
    the verified ``result`` -- a failed item never carries them.
    """
    item_id = item[ID]
    proof = item[VERDICT_ITEM_PROOF]
    try:
        result = _verify_recovery_verdict(
            proof, validated_policy, validated_keyring, moment
        )
    except AuthenticationError as exc:
        return _verdict_batch_report(
            item_id, VERIFY_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidRecoveryVerdictProofError, TypeError) as exc:
        # A TypeError here can only come from a wrong JSON field type
        # *inside* the proof payload; the public argument types were all
        # validated before the batch ran.
        return _verdict_batch_report(
            item_id, VERIFY_INVALID_PROOF, str(exc), None
        )
    return _verdict_batch_report(item_id, _VERIFY_VERIFIED, None, result)


def verify_recovery_verdicts(
    items: list, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a batch of signed recovery verdict proofs entirely offline.

    ``items`` is a non-empty list; each item is a dict with exactly the
    keys ``id`` (a non-empty str, unique across the batch) and ``proof``
    (the proof bytes :func:`export_recovery_verdict` produced).
    ``policy`` is the same ``{"batch", "sites", "threshold"}`` object,
    ``keyring`` follows the :func:`apply_signed_remote` rules and
    ``moment`` is the current time as a non-negative integer.  No file
    is read or written and no argument is modified.

    The whole batch structure, policy, keyring and moment are validated
    before any proof is verified: container, element or public field
    type faults raise :class:`TypeError` (a :class:`bool` never poses as
    an int) and an empty list, an empty or duplicate id or a wrong item
    key set raises :class:`ValueError` (policy, keyring and moment keep
    their single-entry classification).  Only these batch-level faults
    raise -- one proof's failure never stops the later proofs or alters
    an earlier report.

    Each proof is then verified in input order and in isolation through
    the exact :func:`verify_recovery_verdict` rules; the key is selected
    by that proof's own exact issuer and version with no fallback, so
    proofs bound to different issuers or key versions verify
    independently in one batch.  Current but revoked, not-yet-valid,
    expired or missing credentials and a wrong signature make the item
    ``unauthenticated``; an illegal encoding, key set, field, digest,
    batch, threshold, signing moment or embedded verdict makes it
    ``invalid-proof``; a passing proof is ``verified``.

    The result is a fresh dict with the fixed key order ``items`` and
    ``version`` (the integer 1).  Each item report strictly preserves
    input order and carries, in this key order, ``error`` (a definite,
    non-empty message for a failure, ``None`` when verified), ``id``,
    ``result`` (a fresh copy of the single-entry result when verified,
    otherwise ``None``) and ``status``.  Repeated calls return equal but
    independent results.
    """
    validated_items = _validated_verdict_items(items)
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return {
        ITEMS: [
            _verify_verdict_item(
                item, validated_policy, validated_keyring, moment
            )
            for item in validated_items
        ],
        VERSION: VERDICTS_VERSION,
    }


# --- Offline signed receipt of a batch verdict verification ------------------

BATCH_RECEIPT_VERSION = 1

RECEIPT_POLICY = "policy"
RECEIPT_ITEM_REPORT = "report"

_BATCH_RECEIPT_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_BATCH_RECEIPT_PAYLOAD_KEYS = frozenset((
    VD_ISSUER,
    KEY_VERSION,
    CP_MOMENT,
    RECEIPT_POLICY,
    ITEMS,
    VERSION,
))
_BATCH_RECEIPT_ITEM_KEYS = frozenset((ID, CP_DIGEST, RECEIPT_ITEM_REPORT))
_BATCH_RECEIPT_REPORT_KEYS = frozenset(_VERDICT_BATCH_REPORT_KEYS)
_BATCH_RECEIPT_REPORT_STATUSES = frozenset((
    _VERIFY_VERIFIED,
    VERIFY_UNAUTHENTICATED,
    VERIFY_INVALID_PROOF,
))


class InvalidBatchReceiptError(ValueError):
    """A signed batch receipt fails its canonical contract."""


def _receipt_invalid(message: str) -> InvalidBatchReceiptError:
    return InvalidBatchReceiptError(f"invalid batch receipt: {message}")


def _validated_receipt_boundary(boundary: object, where: str) -> None:
    """Require a receipt boundary to be null or a ``lastSeq``/``tail`` pair."""
    if boundary is None:
        return
    if not isinstance(boundary, dict):
        raise _receipt_invalid(f"{where} boundary must be an object or null")
    if set(boundary.keys()) != _ADJ_BOUNDARY_KEYS:
        raise _receipt_invalid(
            f"{where} boundary must be null or {{'lastSeq', 'tail'}}"
        )
    last_seq = boundary[CP_LAST_SEQ]
    if isinstance(last_seq, bool) or not isinstance(last_seq, int):
        raise _receipt_invalid(f"{where} boundary lastSeq must be an int")
    if last_seq < 0:
        raise _receipt_invalid(f"{where} boundary lastSeq must be >= 0")
    if not _is_digest(boundary[CP_TAIL]):
        raise _receipt_invalid(
            f"{where} boundary tail must be 64 lowercase hex characters"
        )


def _validated_receipt_verdict_item(item: object, where: str) -> None:
    """Validate one adjudication item report inside a verified result.

    Mirrors the per-item rules a verdict carries, so a receipt only ever
    binds a result :func:`verify_recovery_verdict` could have produced.
    """
    if not isinstance(item, dict):
        raise _receipt_invalid(f"{where} must be an object")
    if set(item.keys()) != _ADJ_ITEM_REPORT_KEYS:
        raise _receipt_invalid(
            f"{where} must contain exactly the keys 'boundary', "
            "'conclusion', 'digest', 'id', 'keyVersion', 'reason', "
            "'site' and 'status'"
        )
    item_id = item[ID]
    if not isinstance(item_id, str) or item_id == "":
        raise _receipt_invalid(f"{where} id must be a non-empty str")
    site = item[ADJ_SITE]
    if site is not None and (not isinstance(site, str) or site == ""):
        raise _receipt_invalid(f"{where} site must be a non-empty str or null")
    key_version = item[CP_KEY_VERSION]
    if key_version is not None:
        if isinstance(key_version, bool) or not isinstance(key_version, int):
            raise _receipt_invalid(f"{where} keyVersion must be an int or null")
        if key_version <= 0:
            raise _receipt_invalid(f"{where} keyVersion must be positive")
    digest = item[CP_DIGEST]
    if digest is not None and not _is_digest(digest):
        raise _receipt_invalid(
            f"{where} digest must be null or 64 lowercase hex characters"
        )
    status = item[STATUS]
    if status is not None and (
        not isinstance(status, str) or status not in _ADJ_RESULT_STATUSES
    ):
        raise _receipt_invalid(f"{where} status is not a known result status")
    _validated_receipt_boundary(item[CHECKPOINT_ITEM_BOUNDARY], where)
    conclusion = item[ADJ_CONCLUSION]
    if not isinstance(conclusion, str) or conclusion not in (
        ADJ_CONCLUSION_VALID,
        ADJ_CONCLUSION_INVALID,
        ADJ_CONCLUSION_DUPLICATE,
        ADJ_CONCLUSION_CONTRADICTION,
    ):
        raise _receipt_invalid(f"{where} conclusion is not known")
    reason = item[ADJ_REASON]
    if conclusion == ADJ_CONCLUSION_VALID:
        if reason is not None:
            raise _receipt_invalid(
                f"{where} reason must be null for a valid packet"
            )
    elif not isinstance(reason, str) or reason == "":
        raise _receipt_invalid(f"{where} reason must be a non-empty str")


def _validated_receipt_result(result: object, where: str) -> None:
    """Validate the verified single-entry result bound into a report.

    The shape is exactly the public :func:`verify_recovery_verdict`
    result: the fixed keys ``batch``, ``issuer``, ``keyVersion``,
    ``signedAt``, ``policyDigest``, ``verdictDigest``, ``status``,
    ``digest``, ``boundary``, ``items`` and ``version`` (the integer 1),
    with the accepted-only digest and boundary pairing the verdict
    itself enforces.
    """
    if not isinstance(result, dict):
        raise _receipt_invalid(f"{where} result must be an object")
    if set(result.keys()) != frozenset(_VERDICT_RESULT_KEYS):
        raise _receipt_invalid(
            f"{where} result must contain exactly the keys 'batch', "
            "'issuer', 'keyVersion', 'signedAt', 'policyDigest', "
            "'verdictDigest', 'status', 'digest', 'boundary', 'items' "
            "and 'version'"
        )
    if not isinstance(result[ADJ_BATCH], str) or result[ADJ_BATCH] == "":
        raise _receipt_invalid(f"{where} result batch must be a non-empty str")
    if not isinstance(result[VD_ISSUER], str) or result[VD_ISSUER] == "":
        raise _receipt_invalid(
            f"{where} result issuer must be a non-empty str"
        )
    key_version = result[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise _receipt_invalid(f"{where} result keyVersion must be an int")
    if key_version <= 0:
        raise _receipt_invalid(f"{where} result keyVersion must be positive")
    signed_at = result[VD_SIGNED_AT]
    if isinstance(signed_at, bool) or not isinstance(signed_at, int):
        raise _receipt_invalid(f"{where} result signedAt must be an int")
    if signed_at < 0:
        raise _receipt_invalid(f"{where} result signedAt must be non-negative")
    if not _is_digest(result[VD_POLICY_DIGEST]):
        raise _receipt_invalid(
            f"{where} result policyDigest must be 64 lowercase hex characters"
        )
    if not _is_digest(result[VD_VERDICT_DIGEST]):
        raise _receipt_invalid(
            f"{where} result verdictDigest must be 64 lowercase hex characters"
        )
    version = result[VERSION]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != RECOVERY_VERDICT_VERSION
    ):
        raise _receipt_invalid(f"{where} result version must be the integer 1")
    status = result[STATUS]
    if status not in (
        ADJ_STATUS_ACCEPTED,
        ADJ_STATUS_CONFLICTED,
        ADJ_STATUS_INSUFFICIENT,
    ):
        raise _receipt_invalid(
            f"{where} result status is not a known verdict status"
        )
    digest = result[CP_DIGEST]
    if digest is not None and not _is_digest(digest):
        raise _receipt_invalid(
            f"{where} result digest must be null or 64 lowercase hex "
            "characters"
        )
    if (status == ADJ_STATUS_ACCEPTED) != (digest is not None):
        raise _receipt_invalid(
            f"{where} result digest must be present exactly when accepted"
        )
    boundary = result[CHECKPOINT_ITEM_BOUNDARY]
    _validated_receipt_boundary(boundary, f"{where} result")
    if (status == ADJ_STATUS_ACCEPTED) != (boundary is not None):
        raise _receipt_invalid(
            f"{where} result boundary must be present exactly when accepted"
        )
    items = result[ITEMS]
    if not isinstance(items, list):
        raise _receipt_invalid(f"{where} result items must be a list")
    for position, item in enumerate(items):
        _validated_receipt_verdict_item(item, f"{where} result item {position}")


def _validated_receipt_report(report: object, item_id: str, where: str) -> None:
    """Validate one batch verification report bound into a receipt item.

    The report must follow the public :func:`verify_recovery_verdicts`
    item shape -- ``error``, ``id``, ``result`` and ``status`` -- with
    ``error`` null and ``result`` present exactly when ``verified``, and
    its ``id`` must equal the receipt item's ``id``, keeping the
    positional binding between the ordered items and their reports.
    """
    if not isinstance(report, dict):
        raise _receipt_invalid(f"{where} report must be an object")
    if set(report.keys()) != _BATCH_RECEIPT_REPORT_KEYS:
        raise _receipt_invalid(
            f"{where} report must contain exactly the keys 'error', 'id', "
            "'result' and 'status'"
        )
    report_id = report[ID]
    if not isinstance(report_id, str) or report_id == "":
        raise _receipt_invalid(f"{where} report id must be a non-empty str")
    if report_id != item_id:
        raise _receipt_invalid(
            f"{where} report id does not match the item id"
        )
    status = report[STATUS]
    if not isinstance(status, str) or status not in (
        _BATCH_RECEIPT_REPORT_STATUSES
    ):
        raise _receipt_invalid(f"{where} report status is not a known status")
    error = report[CHECKPOINT_ITEM_ERROR]
    result = report[VERDICT_ITEM_RESULT]
    if status == _VERIFY_VERIFIED:
        if error is not None:
            raise _receipt_invalid(
                f"{where} report error must be null when verified"
            )
        _validated_receipt_result(result, where)
    else:
        if not isinstance(error, str) or error == "":
            raise _receipt_invalid(
                f"{where} report error must be a non-empty str for a failure"
            )
        if result is not None:
            raise _receipt_invalid(
                f"{where} report result must be null for a failure"
            )


def _parse_batch_receipt(raw: object) -> tuple[dict, str]:
    """Validate receipt bytes structurally into ``(payload, signature)``.

    A non-bytes argument raises :class:`TypeError`; every encoding,
    key-set, version, digest, report-shape or canonical-form fault
    raises :class:`InvalidBatchReceiptError`.  The policy, moment,
    credential and signature bindings are checked by
    :func:`verify_batch_receipt`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("receipt must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _receipt_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _receipt_invalid("is not valid UTF-8") from exc

    def reject_duplicates(pairs: list[tuple]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise _receipt_invalid(f"duplicate key {key!r} in object")
            result[key] = value
        return result

    try:
        data = json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise _receipt_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _receipt_invalid("must be a JSON object")
    if set(data.keys()) != _BATCH_RECEIPT_TOP_KEYS:
        raise _receipt_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str) or _HEX64.fullmatch(signature) is None:
        raise _receipt_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise _receipt_invalid("payload must be an object")
    if set(payload.keys()) != _BATCH_RECEIPT_PAYLOAD_KEYS:
        raise _receipt_invalid(
            "payload must contain exactly the keys 'issuer', 'keyVersion', "
            "'moment', 'policy', 'items' and 'version'"
        )
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str) or issuer == "":
        raise _receipt_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise _receipt_invalid("payload keyVersion must be an int")
    if key_version <= 0:
        raise _receipt_invalid("payload keyVersion must be positive")
    moment = payload[CP_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise _receipt_invalid("payload moment must be an int")
    if moment < 0:
        raise _receipt_invalid("payload moment must be non-negative")
    if not _is_digest(payload[RECEIPT_POLICY]):
        raise _receipt_invalid(
            "payload policy must be 64 lowercase hex characters"
        )
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _receipt_invalid("payload version must be an int")
    if version != BATCH_RECEIPT_VERSION:
        raise _receipt_invalid("payload version must be the integer 1")
    items = payload[ITEMS]
    if not isinstance(items, list):
        raise _receipt_invalid("payload items must be a list")
    if not items:
        raise _receipt_invalid("payload items must be non-empty")
    for position, item in enumerate(items):
        where = f"item {position}"
        if not isinstance(item, dict):
            raise _receipt_invalid(f"{where} must be an object")
        if set(item.keys()) != _BATCH_RECEIPT_ITEM_KEYS:
            raise _receipt_invalid(
                f"{where} must contain exactly the keys 'id', 'digest' "
                "and 'report'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str) or item_id == "":
            raise _receipt_invalid(f"{where} id must be a non-empty str")
        if not _is_digest(item[CP_DIGEST]):
            raise _receipt_invalid(
                f"{where} digest must be 64 lowercase hex characters"
            )
        _validated_receipt_report(item[RECEIPT_ITEM_REPORT], item_id, where)

    item_ids = [item[ID] for item in items]
    if len(set(item_ids)) != len(item_ids):
        raise _receipt_invalid("item ids must be unique")

    if _checkpoint_compact(data) != raw:
        raise _receipt_invalid("encoding is not the canonical compact form")
    return payload, signature


def sign_batch_receipt(
    items: list,
    policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Sign a batch verdict verification into an offline receipt.

    ``items`` is the same non-empty list of ``{"id", "proof"}`` dicts
    :func:`verify_recovery_verdicts` takes; ``policy`` is the same
    ``{"batch", "sites", "threshold"}`` object, ``keyring`` follows the
    :func:`apply_signed_remote` rules, ``moment`` is the signing time
    and ``issuer``/``version`` name the signing credentials.  No file is
    read or written and no argument is modified.

    The batch runs through the exact :func:`verify_recovery_verdicts`
    rules: batch-level faults raise directly (container, element or
    public field type faults raise :class:`TypeError` -- a :class:`bool`
    never poses as an int -- and an empty list, an empty or duplicate
    id, a wrong item key set, an empty issuer or a non-positive version
    raises :class:`ValueError`), while one proof's failure never stops
    the batch and is recorded in that item's report with its original
    status, error and a null ``result``.

    The receipt is one canonical compact UTF-8 JSON object -- every
    object key recursively sorted, non-ASCII preserved, no trailing
    newline or any other trailing byte -- carrying exactly ``payload``
    and ``signature``.  The payload binds exactly ``issuer``,
    ``keyVersion``, ``moment``, ``policy``, ``items`` and ``version``
    (the integer 1).  ``policy`` is the lowercase hex SHA-256 of the
    canonical compact policy encoding (sites ascending, each site's
    versions an ascending array).  Each payload item, in the original
    input order with no sorting, deduplication or replacement, carries
    exactly ``id``, ``digest`` (the lowercase hex SHA-256 of that item's
    original proof bytes) and ``report`` (that item's batch verification
    report, bound verbatim).  ``signature`` is the lowercase hex
    HMAC-SHA256 of the canonical compact payload bytes under the key the
    keyring binds to the exact issuer and version, with no fallback;
    unknown credentials and a revoked, not-yet-valid or expired key
    raise :class:`AuthenticationError`.
    """
    validated_items = _validated_verdict_items(items)
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")

    entry = _usable_checkpoint_key(validated_keyring, issuer, version, moment)
    reports = [
        _verify_verdict_item(item, validated_policy, validated_keyring, moment)
        for item in validated_items
    ]
    receipt_items = [
        {
            ID: item[ID],
            CP_DIGEST: hashlib.sha256(item[VERDICT_ITEM_PROOF]).hexdigest(),
            RECEIPT_ITEM_REPORT: report,
        }
        for item, report in zip(validated_items, reports)
    ]
    payload = {
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        CP_MOMENT: moment,
        RECEIPT_POLICY: hashlib.sha256(
            _verdict_policy_bytes(validated_policy)
        ).hexdigest(),
        ITEMS: receipt_items,
        VERSION: BATCH_RECEIPT_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


def verify_batch_receipt(
    receipt: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a signed batch receipt entirely offline.

    Only the receipt bytes, the expected ``policy``, the current
    ``keyring`` and the verification ``moment`` are consulted -- no file
    is read or written and no argument is modified.  Verification
    recomputes the policy digest over the canonical compact policy
    encoding and the HMAC-SHA256 signature over the canonical compact
    payload bytes, and checks the payload structure, the item order
    (each report's ``id`` must match its item's ``id``), every report's
    shape and the moment binding: a receipt whose signing moment is
    later than the verification moment is rejected.  The key is the one
    the *current* keyring binds to the payload's exact issuer and
    version, usable at the verification moment, so a later revocation or
    expiry rejects the receipt just as it does a replay.

    A non-bytes receipt or a public field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    invalid policy, keyring or moment raises :class:`ValueError`; an
    illegal encoding, key set, version, digest, report shape or binding
    raises :class:`InvalidBatchReceiptError` (a :class:`ValueError`
    subclass); and unknown, revoked, not-yet-valid or expired
    credentials or a signature mismatch raise
    :class:`AuthenticationError`.

    The result is a fresh deep copy of the authenticated payload with
    the fixed keys ``issuer``, ``keyVersion``, ``moment``, ``policy``,
    ``items`` and ``version``; repeated calls return equal but mutually
    independent results that share no mutable object.
    """
    if not isinstance(receipt, bytes):
        raise TypeError("receipt must be bytes")
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")

    payload, signature = _parse_batch_receipt(receipt)
    recomputed_policy = hashlib.sha256(
        _verdict_policy_bytes(validated_policy)
    ).hexdigest()
    if payload[RECEIPT_POLICY] != recomputed_policy:
        raise _receipt_invalid("policy digest does not match the policy")
    if payload[CP_MOMENT] > moment:
        raise _receipt_invalid(
            "moment must not be later than the verification moment"
        )

    entry = _usable_checkpoint_key(
        validated_keyring, payload[VD_ISSUER], payload[KEY_VERSION], moment
    )
    expected_signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError("batch receipt signature does not match")
    return copy.deepcopy(payload)


RECEIPT_DELEGATION_VERSION = 1

DELEGATION_AUDIENCE = "audience"
DELEGATION_UPSTREAM = "upstream"
DELEGATION_HOPS = "hops"
DELEGATION_TARGET = "target"
DELEGATION_RECEIPT_DIGEST = "receiptDigest"

_DELEGATION_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_DELEGATION_PAYLOAD_KEYS = frozenset((
    VD_ISSUER,
    KEY_VERSION,
    CP_MOMENT,
    DELEGATION_AUDIENCE,
    DELEGATION_UPSTREAM,
    VERSION,
))


class InvalidReceiptDelegationError(ValueError):
    """A batch receipt delegation hop fails its canonical contract."""


def _delegation_invalid(message: str) -> InvalidReceiptDelegationError:
    return InvalidReceiptDelegationError(
        f"invalid receipt delegation: {message}"
    )


def _parse_receipt_delegation(raw: object, index: int) -> tuple[dict, str]:
    """Validate one hop's proof bytes into ``(payload, signature)``.

    A non-bytes hop raises :class:`TypeError`; every encoding, key-set,
    version, digest or canonical-form fault raises
    :class:`InvalidReceiptDelegationError` naming the hop.  The chain
    bindings, credentials and signature are checked by the chain walker.
    """
    where = f"hop {index}"
    if not isinstance(raw, bytes):
        raise TypeError(f"{where} must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _delegation_invalid(
            f"{where} must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _delegation_invalid(f"{where} is not valid UTF-8") from exc

    def reject_duplicates(pairs: list[tuple]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise _delegation_invalid(
                    f"{where} duplicate key {key!r} in object"
                )
            result[key] = value
        return result

    try:
        data = json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise _delegation_invalid(f"{where} is not valid JSON") from exc

    if not isinstance(data, dict):
        raise _delegation_invalid(f"{where} must be a JSON object")
    if set(data.keys()) != _DELEGATION_TOP_KEYS:
        raise _delegation_invalid(
            f"{where} must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str) or _HEX64.fullmatch(signature) is None:
        raise _delegation_invalid(
            f"{where} signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise _delegation_invalid(f"{where} payload must be an object")
    if set(payload.keys()) != _DELEGATION_PAYLOAD_KEYS:
        raise _delegation_invalid(
            f"{where} payload must contain exactly the keys 'issuer', "
            "'keyVersion', 'moment', 'audience', 'upstream' and 'version'"
        )
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str) or issuer == "":
        raise _delegation_invalid(
            f"{where} payload issuer must be a non-empty str"
        )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise _delegation_invalid(f"{where} payload keyVersion must be an int")
    if key_version <= 0:
        raise _delegation_invalid(
            f"{where} payload keyVersion must be positive"
        )
    hop_moment = payload[CP_MOMENT]
    if isinstance(hop_moment, bool) or not isinstance(hop_moment, int):
        raise _delegation_invalid(f"{where} payload moment must be an int")
    if hop_moment < 0:
        raise _delegation_invalid(
            f"{where} payload moment must be non-negative"
        )
    audience = payload[DELEGATION_AUDIENCE]
    if not isinstance(audience, str) or audience == "":
        raise _delegation_invalid(
            f"{where} payload audience must be a non-empty str"
        )
    if not _is_digest(payload[DELEGATION_UPSTREAM]):
        raise _delegation_invalid(
            f"{where} payload upstream must be 64 lowercase hex characters"
        )
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _delegation_invalid(f"{where} payload version must be an int")
    if version != RECEIPT_DELEGATION_VERSION:
        raise _delegation_invalid(
            f"{where} payload version must be the integer 1"
        )
    if _checkpoint_compact(data) != raw:
        raise _delegation_invalid(
            f"{where} encoding is not the canonical compact form"
        )
    return payload, signature


def _validated_delegation_args(
    receipt: object,
    hops: object,
    policy: object,
    keyring: object,
    moment: object,
) -> dict[str, list[dict]]:
    """Validate the shared delegation arguments ahead of any verification.

    Container, element or field type faults raise :class:`TypeError` (a
    :class:`bool` never poses as an int); policy, keyring or moment
    format faults raise :class:`ValueError`.  Returns the validated
    keyring; the policy is re-validated by :func:`verify_batch_receipt`.
    """
    if not isinstance(receipt, bytes):
        raise TypeError("receipt must be bytes")
    if not isinstance(hops, list):
        raise TypeError("hops must be a list")
    for index, hop in enumerate(hops):
        if not isinstance(hop, bytes):
            raise TypeError(f"hop {index} must be bytes")
    _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return validated_keyring


def _walk_delegation_chain(
    receipt: bytes,
    receipt_payload: dict,
    hops: list,
    keyring: dict[str, list[dict]],
    moment: int,
) -> tuple[list[dict], list[str]]:
    """Verify every hop over an already-verified base receipt.

    Returns the fresh hop payloads and the domain sequence -- the base
    receipt issuer followed by each hop's audience.  Hops are checked in
    order and the first failure is reported with its hop index: an
    encoding, key-set, version or chain-binding fault raises
    :class:`InvalidReceiptDelegationError`, while unknown, revoked,
    not-yet-valid or expired credentials -- at the hop's own moment or
    at the verification moment -- and a signature mismatch raise
    :class:`AuthenticationError`.
    """
    hop_payloads: list[dict] = []
    domains = [receipt_payload[VD_ISSUER]]
    upstream_bytes = receipt
    upstream_moment = receipt_payload[CP_MOMENT]
    for index, hop in enumerate(hops):
        where = f"hop {index}"
        payload, signature = _parse_receipt_delegation(hop, index)
        issuer = payload[VD_ISSUER]
        if issuer != domains[-1]:
            raise _delegation_invalid(
                f"{where} issuer must equal "
                + (
                    "the base receipt issuer"
                    if index == 0
                    else "the previous hop audience"
                )
            )
        audience = payload[DELEGATION_AUDIENCE]
        if audience == issuer:
            raise _delegation_invalid(f"{where} must not delegate to itself")
        if audience in domains:
            raise _delegation_invalid(
                f"{where} audience repeats an identity or target domain "
                "already in the chain"
            )
        upstream_digest = hashlib.sha256(upstream_bytes).hexdigest()
        if payload[DELEGATION_UPSTREAM] != upstream_digest:
            raise _delegation_invalid(
                f"{where} upstream digest does not match the "
                + ("base receipt" if index == 0 else "previous hop")
            )
        hop_moment = payload[CP_MOMENT]
        if hop_moment < upstream_moment:
            raise _delegation_invalid(
                f"{where} moment must not be earlier than its upstream"
            )
        if hop_moment > moment:
            raise _delegation_invalid(
                f"{where} moment must not be later than the verification "
                "moment"
            )
        entry = _usable_checkpoint_key(
            keyring, issuer, payload[KEY_VERSION], hop_moment
        )
        _usable_checkpoint_key(
            keyring, issuer, payload[KEY_VERSION], moment
        )
        expected_signature = hmac.new(
            bytes.fromhex(entry[SECRET]),
            _checkpoint_compact(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            raise AuthenticationError(
                f"receipt delegation {where} signature does not match"
            )
        domains.append(audience)
        hop_payloads.append(payload)
        upstream_bytes = hop
        upstream_moment = hop_moment
    return hop_payloads, domains


def delegate_batch_receipt(
    receipt: bytes,
    hops: list,
    policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
    audience: str,
) -> bytes:
    """Sign the next delegation hop over a verified batch receipt chain.

    ``receipt`` is the base receipt bytes :func:`sign_batch_receipt`
    produced and ``hops`` the existing delegation sequence (empty for
    the first hop); both are verified in full -- offline, reading and
    writing no file and modifying no argument -- before the new hop is
    signed.  ``policy``, ``keyring`` and ``moment`` keep their
    :func:`verify_batch_receipt` meaning, ``issuer``/``version`` name
    the signing credentials and ``audience`` is the next receiving
    domain.

    The new hop's issuer must equal the base receipt issuer (first hop)
    or the previous hop's audience, its audience must not be the issuer
    itself or any identity or target domain already in the chain, and
    its moment must not be earlier than its upstream's moment.  The hop
    is one canonical compact UTF-8 JSON object -- recursively sorted
    keys, non-ASCII preserved, no trailing byte -- carrying exactly
    ``payload`` and ``signature``.  The payload binds exactly
    ``issuer``, ``keyVersion``, ``moment``, ``audience``, ``upstream``
    (the lowercase hex SHA-256 of the base receipt or previous hop
    bytes) and ``version`` (the integer 1); ``signature`` is the
    lowercase hex HMAC-SHA256 of the canonical compact payload bytes
    under the key the keyring binds to the exact issuer and version,
    with no fallback.

    Parameter or public field type faults raise :class:`TypeError` (a
    :class:`bool` never poses as an int); an empty issuer or audience or
    a non-positive version raises :class:`ValueError`; an illegal base
    receipt raises :class:`InvalidBatchReceiptError`; an illegal
    delegation encoding, key set, version or chain binding raises
    :class:`InvalidReceiptDelegationError`; and unknown, revoked,
    not-yet-valid or expired credentials raise
    :class:`AuthenticationError`.
    """
    validated_keyring = _validated_delegation_args(
        receipt, hops, policy, keyring, moment
    )
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")
    if not isinstance(audience, str):
        raise TypeError("audience must be a str")
    if audience == "":
        raise ValueError("audience must be non-empty")

    receipt_payload = verify_batch_receipt(receipt, policy, keyring, moment)
    hop_payloads, domains = _walk_delegation_chain(
        receipt, receipt_payload, hops, validated_keyring, moment
    )
    where = f"hop {len(hops)}"
    if issuer != domains[-1]:
        raise _delegation_invalid(
            f"{where} issuer must equal "
            + (
                "the base receipt issuer"
                if not hops
                else "the previous hop audience"
            )
        )
    if audience == issuer:
        raise _delegation_invalid(f"{where} must not delegate to itself")
    if audience in domains:
        raise _delegation_invalid(
            f"{where} audience repeats an identity or target domain already "
            "in the chain"
        )
    upstream_bytes = receipt if not hops else hops[-1]
    upstream_moment = (
        receipt_payload[CP_MOMENT]
        if not hops
        else hop_payloads[-1][CP_MOMENT]
    )
    if moment < upstream_moment:
        raise _delegation_invalid(
            f"{where} moment must not be earlier than its upstream"
        )

    entry = _usable_checkpoint_key(validated_keyring, issuer, version, moment)
    payload = {
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        CP_MOMENT: moment,
        DELEGATION_AUDIENCE: audience,
        DELEGATION_UPSTREAM: hashlib.sha256(upstream_bytes).hexdigest(),
        VERSION: RECEIPT_DELEGATION_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


def verify_batch_receipt_chain(
    receipt: bytes,
    hops: list,
    policy: dict,
    keyring: dict,
    moment: int,
    target: str,
) -> dict:
    """Verify a batch receipt and its whole delegation chain offline.

    Only the base ``receipt`` bytes, the ordered ``hops`` proof bytes,
    the expected ``policy``, the current ``keyring``, the verification
    ``moment`` and the expected receiving domain ``target`` are
    consulted -- no file is read or written and no argument is modified.
    The base receipt is verified through the exact
    :func:`verify_batch_receipt` rules; every hop is then checked in
    order against the canonical delegation contract: exactly ``payload``
    and ``signature``, the payload binding exactly ``issuer``,
    ``keyVersion``, ``moment``, ``audience``, ``upstream`` and
    ``version`` (the integer 1), ``upstream`` chaining the lowercase hex
    SHA-256 of the base receipt or previous hop bytes, the first hop's
    issuer equal to the base receipt issuer, each later issuer equal to
    the previous hop's audience, no delegation to self, no repeated
    identity or target domain, and no hop moment earlier than its
    upstream or later than the verification moment.  Each hop's
    signature is the lowercase hex HMAC-SHA256 of its canonical compact
    payload bytes under the key the *current* keyring binds to the
    hop's exact issuer and version -- usable both at the hop's own
    moment and at the verification moment, with no fallback -- and the
    last hop's audience must equal ``target``.

    Parameter or public field type faults raise :class:`TypeError` (a
    :class:`bool` never poses as an int); an empty target, an empty hop
    sequence or a negative moment raises :class:`ValueError`; an illegal
    base receipt raises :class:`InvalidBatchReceiptError`; an illegal
    delegation encoding, key set, version or chain binding raises
    :class:`InvalidReceiptDelegationError` (a :class:`ValueError`
    subclass) with the first failing hop in the message; and unknown,
    revoked, not-yet-valid or expired credentials or a signature
    mismatch raise :class:`AuthenticationError`.

    The result is a fresh mapping with the fixed keys ``hops`` (the hop
    payloads in chain order), ``receipt`` (the base receipt payload),
    ``receiptDigest`` (the lowercase hex SHA-256 of the base receipt
    bytes), ``target`` and ``version`` (the integer 1); repeated calls
    return equal but mutually independent results.
    """
    validated_keyring = _validated_delegation_args(
        receipt, hops, policy, keyring, moment
    )
    if not isinstance(target, str):
        raise TypeError("target must be a str")
    if target == "":
        raise ValueError("target must be non-empty")
    if not hops:
        raise ValueError("hops must be non-empty")

    receipt_payload = verify_batch_receipt(receipt, policy, keyring, moment)
    hop_payloads, domains = _walk_delegation_chain(
        receipt, receipt_payload, hops, validated_keyring, moment
    )
    if domains[-1] != target:
        raise _delegation_invalid(
            f"hop {len(hops) - 1} audience must equal the expected target"
        )
    return {
        DELEGATION_HOPS: copy.deepcopy(hop_payloads),
        RECEIPT: receipt_payload,
        DELEGATION_RECEIPT_DIGEST: hashlib.sha256(receipt).hexdigest(),
        DELEGATION_TARGET: target,
        VERSION: RECEIPT_DELEGATION_VERSION,
    }
