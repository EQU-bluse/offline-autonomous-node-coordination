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

:func:`decide_forks` turns the signed receipt fork proofs
(:func:`sign_receipt_fork_proof`) into one multi-site
disposition decision, still entirely offline.  It takes a non-empty
``items`` list (each item exactly a non-empty, batch-unique ``id`` and
``proof`` bytes), a ``policy``, a ``keyring``, the current ``moment``
and the signing ``issuer`` and key ``version``.  The policy carries
exactly ``action`` (``"isolate"`` or ``"rollback"``), ``base`` (the
existing ``{"batch","sites","threshold"}`` proof policy), ``sites`` (a
non-empty map of each authorized non-empty site to its non-empty set of
allowed positive key versions) and ``threshold`` (a positive integer no
greater than the site count).  Each proof is first verified through the
exact :func:`verify_receipt_fork_proof` rules, then authorized by the
exact signing site and key version with no fallback and authenticated
against the current keyring; an invalid, unauthorized or unauthenticated
proof rejects only that item with one fixed reason
(``invalid-proof``, ``unauthorized-site``, ``unauthorized-version``,
``credential-unavailable``, ``revoked``, ``not-yet-valid``,
``expired`` or ``bad-signature``) without affecting the others.  An
identical proof digest counts once per site (extra copies are
``duplicate``); different valid proofs from one site are a
``contradiction``.  The valid proofs of distinct sites must agree on
every fork boundary made of the base receipt digest, the forking
upstream and the target domain.  A unique boundary set attested by at
least the threshold of distinct sites is ``accepted``; a contradiction
or boundary disagreement is ``conflicted``; every other case is
``insufficient``.  An accepted decision recommends isolating the
(deduplicated, ascending) target domains or rolling back to before the
fork, per the policy action; every other outcome recommends
``manual-review`` and claims no boundary or target.  The result is one
canonical compact UTF-8 JSON object (recursively sorted keys, non-ASCII
preserved, no trailing byte) carrying exactly ``payload`` and
``signature``; the payload binds exactly ``action``, ``boundaries``,
``decisions`` (sorted by site then id), ``issuer``, ``keyVersion``,
``policyDigest`` (the SHA-256 of the canonical policy), ``proofs`` (each
proof digest in the original input order), ``recommendation``,
``targets`` and ``version`` (the integer 1); the signature is the
lowercase hex HMAC-SHA256 of the canonical compact payload bytes under
the key bound to the exact issuer and version, with no fallback.

:func:`verify_fork_decision` re-checks such a decision entirely offline
from just the decision bytes, the expected policy, the current keyring
and the verification moment.  It validates the canonical encoding and
key sets, recomputes the policy digest and action binding, re-tallies
the bound per-proof decisions -- row ordering, the original-order proof
digest bindings, duplicates, contradictions, cross-site boundary
agreement, the threshold and the claimed boundaries, targets and
recommendation -- purely from the signed payload, and verifies the
HMAC against the key the *current* keyring binds to the payload's exact
issuer and version, usable at the verification moment, so a later
revocation or expiry rejects the decision.  It returns a fresh dict
keyed ``action``, ``boundaries``, ``decisions``, ``issuer``,
``keyVersion``, ``policyDigest``, ``proofDigest`` (the SHA-256 of the
decision bytes), ``proofs``, ``recommendation``, ``status``,
``targets`` and ``version`` (the integer 1).  A non-bytes argument or a
field of the wrong type raises :class:`TypeError` (a :class:`bool`
never poses as an int); an illegal policy, identifier, version or
moment raises :class:`ValueError`; an illegal encoding, key set,
digest, ordering, reference or binding raises
:class:`InvalidForkDecisionError` (a :class:`ValueError` subclass);
unknown, revoked, not-yet-valid or expired credentials or a signature
mismatch raise :class:`AuthenticationError`.

:func:`verify_fork_decisions` verifies a non-empty batch of those
decisions offline and independently, in strict input order.  Each item
contains exactly a non-empty, batch-unique ``id`` and the ``decision``
bytes; the batch and the shared policy, keyring and moment are
validated in full before any decision is verified, so only a
batch-level fault raises (container/field faults
:class:`TypeError`; an empty list, an empty or duplicate id or a wrong
item key set :class:`ValueError`).  Each decision is then reported in
input order as ``verified``, ``invalid`` or ``unauthenticated`` with
the fixed key order ``error``, ``id``, ``result`` and ``status``; a
failed item keeps a definite, non-empty copy of the original exception
text and a null result, and no identity of an unauthenticated payload
enters a result.  Repeated calls return equal but mutually independent
results.  None of the three entry points reads or writes a file or
modifies an input, and the existing proof interfaces and module
commands are unchanged.

:func:`plan_fork_execution` turns one sealed, accepted disposition into
a site execution plan entirely offline.  It re-verifies the decision
through the exact :func:`verify_fork_decision` rules against the current
keyring at the generation moment and only an ``accepted`` decision can
be planned (any other verdict raises :class:`ValueError`).  The plan is
one canonical compact UTF-8 JSON object (recursively sorted keys,
non-ASCII preserved, no trailing byte) binding exactly ``action``,
``boundaries``, ``decisionDigest``, ``expiresAt``, ``generatedAt``,
``operations``, ``policyDigest`` and ``version``; it carries every fork
boundary and the deduplicated, ascending target domains as exactly one
idempotent operation per target and no un-adopted proof material.  Each
operation's ``operationId`` is the SHA-256 over the decision digest,
action, target and the canonical bytes of its related boundaries; an
``isolate`` precondition requires ``{"state": "active"}`` while a
``rollback`` binds ``{"base", "upstream"}`` (the base receipt digest and
the forking upstream).

:func:`confirm_fork_execution` aggregates the per-site execution
receipts into one signed confirmation, reading and writing no file.  It
checks the plan packet, its decision and policy digests, the
still-accepted decision and the regenerated plan.  Each receipt binds
the plan digest, operation id, executing site and key version, site
version, execution moment, previous-state digest and one result
(``executed``/``rejected``/``failed``), an executed receipt also binding
the post-state digest.  The receipt site must equal the operation
target and its exact site/version key must be usable at both the
execution and aggregation moments.  A replaced verdict, unknown
operation, out-of-window execution, previous mismatch or same-site
out-of-order receipt rejects only that item with a fixed reason, as do
invalid or time-invalid credentials or a wrong signature; a
structurally illegal receipt only records ``invalid-receipt``.  The same
receipt digest counts once (``duplicate``); different valid results or
post-state digests for one operation are a ``contradiction``.
Contradictions, explicit rejections, missing/failed operations and full
success yield ``conflicted``, ``rejected``, ``partial`` and
``confirmed``.  The canonical ``{payload, signature}`` packet binds the
aggregator identity, the complete plan, the original-order receipt
digests, per-item reasons, per-operation conclusions and the overall
status; the signature is the HMAC-SHA256 of the canonical payload under
the exact aggregator key.

:func:`verify_fork_confirmation` and the batch
:func:`verify_fork_confirmations` re-check those packets entirely
offline.  Verification validates the encoding and key sets, regenerates
and compares the plan, re-derives the duplicate/contradiction markings,
per-operation conclusions and overall status purely from the bound
receipts and reasons, and checks the aggregator HMAC against the exact
issuer/version key usable at the verification moment, so later
revocation or expiry rejects it.  Batch items are validated up front
and handled in strict input order and isolation as ``verified``,
``invalid`` or ``unauthenticated``.  Across this layer a parameter,
container or public field type fault raises :class:`TypeError` (a
:class:`bool` never poses as an int); an empty value, duplicate
identifier or illegal moment raises :class:`ValueError`; an illegal
plan/packet encoding, digest, order or binding raises
:class:`InvalidForkExecutionError` (a :class:`ValueError` subclass, with
a structurally bad receipt only recorded as ``invalid-receipt``); and
unknown, revoked, not-yet-valid or expired credentials or a wrong
signature raise :class:`AuthenticationError`.  No file is read or
written and every existing public interface is unchanged.

:func:`seal_chain_checkpoint` seals a pruned *chain checkpoint* over
one verified, accepted and unforked target chain of a
:func:`verify_decision_chains` batch, so a verifier can keep checking
the chain after the prefix certificates and rounds are dropped.  The
checkpoint is one canonical compact UTF-8 JSON object carrying exactly
``payload`` and ``signature``; the payload binds the root digest, the
stable head digest, the height, the head status, the settlement
(``commonDigest``) and plan digests, the head policy digest and
version, the head effective moment, the ordered packet digests, the
per-stage policy digest history, the ordered evidence prefix digests
and the sealing moment, and the signature is the HMAC-SHA256 of the
canonical payload under the exact issuer/version key.  A target that
is not verified, accepted and fork-free raises :class:`ValueError`.

:func:`verify_chain_suffix` continues verification offline from just
the checkpoint, the successor packets past the checkpoint head, the
per-stage policies and the shared material.  An empty suffix returns
the sealed stable head; otherwise the first successor's predecessor
digest must equal the checkpoint head digest, its evidence prefix
count and digests must match the checkpoint and every hop follows the
exact :func:`verify_decision_chain` rules.  The stage policies start
at the checkpoint head policy and a version regression is always
rejected.  The result maps ``rootDigest``, ``headDigest``, ``height``,
``policyVersion``, ``status`` and ``checkpointDigest``.

:func:`verify_chain_suffixes` verifies a batch of such items (each
exactly ``id``, ``checkpoint``, ``successors`` and ``policies``) in
input order and isolation, reporting ``verified``,
``invalid-checkpoint``, ``invalid-suffix``, ``unauthenticated`` or
``conflicted``; the same predecessor digest pointing at two distinct
successors across the verified trajectories is a fork (a mere prefix
extension is not) and reclassifies every verified chain crossing it as
``conflicted`` with its result kept.  Checkpoint binding faults raise
:class:`InvalidCheckpointError`, suffix faults
:class:`InvalidChainError` and credential or signature faults
:class:`AuthenticationError`.  None of the three entry points reads or
writes a file or modifies an input, and the existing chain, anchor,
command and status behaviour is unchanged.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
from typing import BinaryIO, Callable

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
    """Require a receipt boundary to be null or a ``lastSeq``/``tail`` pair.

    A field of the wrong type raises :class:`TypeError` (a :class:`bool`
    never poses as an int); every key-set or value-format fault raises
    :class:`InvalidBatchReceiptError`.
    """
    if boundary is None:
        return
    if not isinstance(boundary, dict):
        raise TypeError(f"{where} boundary must be an object or null")
    if set(boundary.keys()) != _ADJ_BOUNDARY_KEYS:
        raise _receipt_invalid(
            f"{where} boundary must be null or {{'lastSeq', 'tail'}}"
        )
    last_seq = boundary[CP_LAST_SEQ]
    if isinstance(last_seq, bool) or not isinstance(last_seq, int):
        raise TypeError(f"{where} boundary lastSeq must be an int")
    if last_seq < 0:
        raise _receipt_invalid(f"{where} boundary lastSeq must be >= 0")
    tail = boundary[CP_TAIL]
    if not isinstance(tail, str):
        raise TypeError(f"{where} boundary tail must be a str")
    if not _is_digest(tail):
        raise _receipt_invalid(
            f"{where} boundary tail must be 64 lowercase hex characters"
        )


def _validated_receipt_verdict_item(item: object, where: str) -> None:
    """Validate one adjudication item report inside a verified result.

    Mirrors the per-item rules a verdict carries, so a receipt only ever
    binds a result :func:`verify_recovery_verdict` could have produced.
    A field of the wrong type raises :class:`TypeError` (a :class:`bool`
    never poses as an int); every key-set or value-format fault raises
    :class:`InvalidBatchReceiptError`.
    """
    if not isinstance(item, dict):
        raise TypeError(f"{where} must be an object")
    if set(item.keys()) != _ADJ_ITEM_REPORT_KEYS:
        raise _receipt_invalid(
            f"{where} must contain exactly the keys 'boundary', "
            "'conclusion', 'digest', 'id', 'keyVersion', 'reason', "
            "'site' and 'status'"
        )
    item_id = item[ID]
    if not isinstance(item_id, str):
        raise TypeError(f"{where} id must be a str")
    if item_id == "":
        raise _receipt_invalid(f"{where} id must be a non-empty str")
    site = item[ADJ_SITE]
    if site is not None and not isinstance(site, str):
        raise TypeError(f"{where} site must be a str or null")
    if site is not None and site == "":
        raise _receipt_invalid(f"{where} site must be a non-empty str or null")
    key_version = item[CP_KEY_VERSION]
    if key_version is not None:
        if isinstance(key_version, bool) or not isinstance(key_version, int):
            raise TypeError(f"{where} keyVersion must be an int or null")
        if key_version <= 0:
            raise _receipt_invalid(f"{where} keyVersion must be positive")
    digest = item[CP_DIGEST]
    if digest is not None and not isinstance(digest, str):
        raise TypeError(f"{where} digest must be a str or null")
    if digest is not None and not _is_digest(digest):
        raise _receipt_invalid(
            f"{where} digest must be null or 64 lowercase hex characters"
        )
    status = item[STATUS]
    if status is not None and not isinstance(status, str):
        raise TypeError(f"{where} status must be a str or null")
    if status is not None and status not in _ADJ_RESULT_STATUSES:
        raise _receipt_invalid(f"{where} status is not a known result status")
    _validated_receipt_boundary(item[CHECKPOINT_ITEM_BOUNDARY], where)
    conclusion = item[ADJ_CONCLUSION]
    if not isinstance(conclusion, str):
        raise TypeError(f"{where} conclusion must be a str")
    if conclusion not in (
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
    elif not isinstance(reason, str):
        raise TypeError(f"{where} reason must be a str")
    elif reason == "":
        raise _receipt_invalid(f"{where} reason must be a non-empty str")


def _validated_receipt_result(result: object, where: str) -> None:
    """Validate the verified single-entry result bound into a report.

    The shape is exactly the public :func:`verify_recovery_verdict`
    result: the fixed keys ``batch``, ``issuer``, ``keyVersion``,
    ``signedAt``, ``policyDigest``, ``verdictDigest``, ``status``,
    ``digest``, ``boundary``, ``items`` and ``version`` (the integer 1),
    with the accepted-only digest and boundary pairing the verdict
    itself enforces.

    A field of the wrong type raises :class:`TypeError` (a
    :class:`bool` never poses as an int); every key-set or
    value-format fault raises :class:`InvalidBatchReceiptError`.
    """
    if not isinstance(result, dict):
        raise TypeError(f"{where} result must be an object")
    if set(result.keys()) != frozenset(_VERDICT_RESULT_KEYS):
        raise _receipt_invalid(
            f"{where} result must contain exactly the keys 'batch', "
            "'issuer', 'keyVersion', 'signedAt', 'policyDigest', "
            "'verdictDigest', 'status', 'digest', 'boundary', 'items' "
            "and 'version'"
        )
    if not isinstance(result[ADJ_BATCH], str):
        raise TypeError(f"{where} result batch must be a str")
    if result[ADJ_BATCH] == "":
        raise _receipt_invalid(f"{where} result batch must be a non-empty str")
    if not isinstance(result[VD_ISSUER], str):
        raise TypeError(f"{where} result issuer must be a str")
    if result[VD_ISSUER] == "":
        raise _receipt_invalid(
            f"{where} result issuer must be a non-empty str"
        )
    key_version = result[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError(f"{where} result keyVersion must be an int")
    if key_version <= 0:
        raise _receipt_invalid(f"{where} result keyVersion must be positive")
    signed_at = result[VD_SIGNED_AT]
    if isinstance(signed_at, bool) or not isinstance(signed_at, int):
        raise TypeError(f"{where} result signedAt must be an int")
    if signed_at < 0:
        raise _receipt_invalid(f"{where} result signedAt must be non-negative")
    if not isinstance(result[VD_POLICY_DIGEST], str):
        raise TypeError(f"{where} result policyDigest must be a str")
    if not _is_digest(result[VD_POLICY_DIGEST]):
        raise _receipt_invalid(
            f"{where} result policyDigest must be 64 lowercase hex characters"
        )
    if not isinstance(result[VD_VERDICT_DIGEST], str):
        raise TypeError(f"{where} result verdictDigest must be a str")
    if not _is_digest(result[VD_VERDICT_DIGEST]):
        raise _receipt_invalid(
            f"{where} result verdictDigest must be 64 lowercase hex characters"
        )
    version = result[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError(f"{where} result version must be an int")
    if version != RECOVERY_VERDICT_VERSION:
        raise _receipt_invalid(f"{where} result version must be the integer 1")
    status = result[STATUS]
    if not isinstance(status, str):
        raise TypeError(f"{where} result status must be a str")
    if status not in (
        ADJ_STATUS_ACCEPTED,
        ADJ_STATUS_CONFLICTED,
        ADJ_STATUS_INSUFFICIENT,
    ):
        raise _receipt_invalid(
            f"{where} result status is not a known verdict status"
        )
    digest = result[CP_DIGEST]
    if digest is not None and not isinstance(digest, str):
        raise TypeError(f"{where} result digest must be a str or null")
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
        raise TypeError(f"{where} result items must be a list")
    for position, item in enumerate(items):
        _validated_receipt_verdict_item(item, f"{where} result item {position}")


def _validated_receipt_report(report: object, item_id: str, where: str) -> None:
    """Validate one batch verification report bound into a receipt item.

    The report must follow the public :func:`verify_recovery_verdicts`
    item shape -- ``error``, ``id``, ``result`` and ``status`` -- with
    ``error`` null and ``result`` present exactly when ``verified``, and
    its ``id`` must equal the receipt item's ``id``, keeping the
    positional binding between the ordered items and their reports.

    A field of the wrong type raises :class:`TypeError`; every key-set
    or value-format fault, including an id mismatch, raises
    :class:`InvalidBatchReceiptError`.
    """
    if not isinstance(report, dict):
        raise TypeError(f"{where} report must be an object")
    if set(report.keys()) != _BATCH_RECEIPT_REPORT_KEYS:
        raise _receipt_invalid(
            f"{where} report must contain exactly the keys 'error', 'id', "
            "'result' and 'status'"
        )
    report_id = report[ID]
    if not isinstance(report_id, str):
        raise TypeError(f"{where} report id must be a str")
    if report_id == "":
        raise _receipt_invalid(f"{where} report id must be a non-empty str")
    if report_id != item_id:
        raise _receipt_invalid(
            f"{where} report id does not match the item id"
        )
    status = report[STATUS]
    if not isinstance(status, str):
        raise TypeError(f"{where} report status must be a str")
    if status not in _BATCH_RECEIPT_REPORT_STATUSES:
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
        if not isinstance(error, str):
            raise TypeError(f"{where} report error must be a str for a failure")
        if error == "":
            raise _receipt_invalid(
                f"{where} report error must be a non-empty str for a failure"
            )
        if result is not None:
            raise _receipt_invalid(
                f"{where} report result must be null for a failure"
            )


def _parse_batch_receipt(raw: object) -> tuple[dict, str]:
    """Validate receipt bytes structurally into ``(payload, signature)``.

    A non-bytes argument or a public field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, value, digest, report-shape or
    canonical-form fault raises :class:`InvalidBatchReceiptError`.  The
    policy, moment, credential and signature bindings are checked by
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
        raise TypeError("receipt must be a JSON object")
    if set(data.keys()) != _BATCH_RECEIPT_TOP_KEYS:
        raise _receipt_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("receipt signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _receipt_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("receipt payload must be an object")
    if set(payload.keys()) != _BATCH_RECEIPT_PAYLOAD_KEYS:
        raise _receipt_invalid(
            "payload must contain exactly the keys 'issuer', 'keyVersion', "
            "'moment', 'policy', 'items' and 'version'"
        )
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("receipt payload issuer must be a str")
    if issuer == "":
        raise _receipt_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("receipt payload keyVersion must be an int")
    if key_version <= 0:
        raise _receipt_invalid("payload keyVersion must be positive")
    moment = payload[CP_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("receipt payload moment must be an int")
    if moment < 0:
        raise _receipt_invalid("payload moment must be non-negative")
    if not isinstance(payload[RECEIPT_POLICY], str):
        raise TypeError("receipt payload policy must be a str")
    if not _is_digest(payload[RECEIPT_POLICY]):
        raise _receipt_invalid(
            "payload policy must be 64 lowercase hex characters"
        )
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("receipt payload version must be an int")
    if version != BATCH_RECEIPT_VERSION:
        raise _receipt_invalid("payload version must be the integer 1")
    items = payload[ITEMS]
    if not isinstance(items, list):
        raise TypeError("receipt payload items must be a list")
    if not items:
        raise _receipt_invalid("payload items must be non-empty")
    for position, item in enumerate(items):
        where = f"item {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{where} must be an object")
        if set(item.keys()) != _BATCH_RECEIPT_ITEM_KEYS:
            raise _receipt_invalid(
                f"{where} must contain exactly the keys 'id', 'digest' "
                "and 'report'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise _receipt_invalid(f"{where} id must be a non-empty str")
        if not isinstance(item[CP_DIGEST], str):
            raise TypeError(f"{where} digest must be a str")
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

    A non-bytes hop or a public field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, value, digest or canonical-form fault
    raises :class:`InvalidReceiptDelegationError` naming the hop.  The
    chain bindings, credentials and signature are checked by the chain
    walker.
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
        raise TypeError(f"{where} must be a JSON object")
    if set(data.keys()) != _DELEGATION_TOP_KEYS:
        raise _delegation_invalid(
            f"{where} must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError(f"{where} signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _delegation_invalid(
            f"{where} signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError(f"{where} payload must be an object")
    if set(payload.keys()) != _DELEGATION_PAYLOAD_KEYS:
        raise _delegation_invalid(
            f"{where} payload must contain exactly the keys 'issuer', "
            "'keyVersion', 'moment', 'audience', 'upstream' and 'version'"
        )
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError(f"{where} payload issuer must be a str")
    if issuer == "":
        raise _delegation_invalid(
            f"{where} payload issuer must be a non-empty str"
        )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError(f"{where} payload keyVersion must be an int")
    if key_version <= 0:
        raise _delegation_invalid(
            f"{where} payload keyVersion must be positive"
        )
    hop_moment = payload[CP_MOMENT]
    if isinstance(hop_moment, bool) or not isinstance(hop_moment, int):
        raise TypeError(f"{where} payload moment must be an int")
    if hop_moment < 0:
        raise _delegation_invalid(
            f"{where} payload moment must be non-negative"
        )
    audience = payload[DELEGATION_AUDIENCE]
    if not isinstance(audience, str):
        raise TypeError(f"{where} payload audience must be a str")
    if audience == "":
        raise _delegation_invalid(
            f"{where} payload audience must be a non-empty str"
        )
    if not isinstance(payload[DELEGATION_UPSTREAM], str):
        raise TypeError(f"{where} payload upstream must be a str")
    if not _is_digest(payload[DELEGATION_UPSTREAM]):
        raise _delegation_invalid(
            f"{where} payload upstream must be 64 lowercase hex characters"
        )
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError(f"{where} payload version must be an int")
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


# --- Offline batch verification of receipt delegation chains -----------------

RECEIPT_CHAINS_VERSION = 1

CHAIN_ITEM_RECEIPT = "receipt"
CHAIN_ITEM_HOPS = "hops"
CHAINS_FORKS = "forks"

CHAINS_VERIFIED = "verified"
CHAINS_CONFLICTED = "conflicted"
CHAINS_INVALID_RECEIPT = "invalid-receipt"
CHAINS_INVALID_DELEGATION = "invalid-delegation"
CHAINS_UNAUTHENTICATED = "unauthenticated"

_CHAIN_ITEM_ERROR = "forked-delegation"

_CHAIN_ITEM_KEYS = frozenset((
    ID,
    CHAIN_ITEM_RECEIPT,
    CHAIN_ITEM_HOPS,
    DELEGATION_TARGET,
))
_FORK_AUDIENCES = "audiences"
_FORK_IDS = "ids"


def _validated_chain_items(items: object) -> list[dict]:
    """Validate the multi-chain batch before any chain is verified.

    The argument must be a non-empty list of dicts each holding exactly
    ``id`` (a non-empty str, unique across the batch), ``receipt``
    (bytes), ``hops`` (a non-empty list of bytes) and ``target`` (a
    non-empty str).  Container, element and field type faults raise
    :class:`TypeError`; an empty list, an empty or duplicate id, a wrong
    key set or an empty hops list raises :class:`ValueError`.  Only a
    fully validated batch comes back, as fresh item dicts with a copied
    hops list, so verification below never mutates the caller's objects.
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
        if set(item.keys()) != _CHAIN_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'hops', 'id', "
                "'receipt' and 'target'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        receipt = item[CHAIN_ITEM_RECEIPT]
        if not isinstance(receipt, bytes):
            raise TypeError(f"{where} receipt must be bytes")
        hops = item[CHAIN_ITEM_HOPS]
        if not isinstance(hops, list):
            raise TypeError(f"{where} hops must be a list")
        if not hops:
            raise ValueError(f"{where} hops must be a non-empty list")
        for hop_index, hop in enumerate(hops):
            if not isinstance(hop, bytes):
                raise TypeError(f"{where} hop {hop_index} must be bytes")
        target = item[DELEGATION_TARGET]
        if not isinstance(target, str):
            raise TypeError(f"{where} target must be a str")
        if target == "":
            raise ValueError(f"{where} target must be non-empty")
        validated.append(
            {
                ID: item_id,
                CHAIN_ITEM_RECEIPT: receipt,
                CHAIN_ITEM_HOPS: list(hops),
                DELEGATION_TARGET: target,
            }
        )
    return validated


def _chain_item_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One multi-chain item report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def _chain_fork_edges(
    validated_items: list[dict], results: list[dict | None]
) -> dict[tuple[str, str], set[str]]:
    """Map each forking ``(receiptDigest, upstream)`` edge to audiences.

    Only chains that verified successfully participate, grouped by the
    base receipt digest; delegation paths under different base receipts
    are never compared.  Chains are walked with the actual hop bytes:
    the edge leaving one node carries that hop's audience and the next
    node is the SHA-256 of the hop bytes -- exactly the digest the
    following hop's ``upstream`` binds.  A given upstream digest
    pointing at two or more distinct next-hop audiences within one
    base-receipt group is a fork; a mere prefix extension -- the same
    path growing longer -- adds no audience and is not a fork.
    """
    groups: dict[str, dict[str, set[str]]] = {}
    for item, result in zip(validated_items, results):
        if result is None:
            continue
        receipt_digest = result[DELEGATION_RECEIPT_DIGEST]
        edges = groups.setdefault(receipt_digest, {})
        node = receipt_digest
        for position, hop_bytes in enumerate(item[CHAIN_ITEM_HOPS]):
            audience = result[DELEGATION_HOPS][position][DELEGATION_AUDIENCE]
            edges.setdefault(node, set()).add(audience)
            node = hashlib.sha256(hop_bytes).hexdigest()
    fork_edges: dict[tuple[str, str], set[str]] = {}
    for receipt_digest, receipt_edges in groups.items():
        for upstream, audiences in receipt_edges.items():
            if len(audiences) > 1:
                fork_edges[(receipt_digest, upstream)] = audiences
    return fork_edges


def verify_batch_receipt_chains(
    items: list, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a batch of receipt delegation chains and spot delegation forks.

    ``items`` is a non-empty list; each item is a dict with exactly the
    keys ``id`` (a non-empty str, unique across the batch), ``receipt``
    (the base receipt bytes), ``hops`` (a non-empty list of delegation
    hop bytes) and ``target`` (the expected receiving domain).
    ``policy``, ``keyring`` and ``moment`` keep their
    :func:`verify_batch_receipt_chain` meaning.  No file is read or
    written and no argument is modified.

    The whole batch structure, policy, keyring and moment are validated
    before any chain is verified: container, element or field type
    faults raise :class:`TypeError` (a :class:`bool` never poses as an
    int) and an empty list, an empty or duplicate id, a wrong item key
    set or an empty hops list raises :class:`ValueError` (policy,
    keyring and moment keep their single-chain classification).  Only
    these batch-level faults raise.

    Each item is then verified independently, in strict input order,
    through the exact :func:`verify_batch_receipt_chain` rules: one
    chain's failure never stops a later chain or alters an earlier
    report.  A base-receipt fault is ``invalid-receipt``, a delegation
    encoding, key-set, version, value or chain-binding fault is
    ``invalid-delegation`` and an unknown, revoked, not-yet-valid or
    expired credential or a signature mismatch is ``unauthenticated``;
    a failed item keeps a definite, non-empty copy of the exception text
    and a null ``result``.

    Successful chains are grouped by ``receiptDigest`` -- delegation
    paths under different base receipts are never compared -- and the
    same ``upstream`` digest pointing at two or more distinct next-hop
    audiences is a fork (a plain prefix extension is not).  Every chain
    passing through a forking edge is reclassified ``conflicted``: its
    verified result is kept and its ``error`` is fixed to
    ``"forked-delegation"``.

    The top-level result is a fresh dict with the fixed key order
    ``forks``, ``items`` and ``version`` (the integer 1).  ``forks`` is
    sorted stably by ``receiptDigest`` then ``upstream``; each fork
    carries exactly ``receiptDigest``, ``upstream``, ``audiences``
    (ascending) and ``ids`` (the ascending ids of the chains passing
    through the edge).  Each item report strictly preserves input order
    and carries, in this key order, ``error``, ``id``, ``result`` (a
    fresh copy of the single-chain result when the chain verified,
    otherwise null) and ``status``.
    """
    validated_items = _validated_chain_items(items)
    _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")

    reports: list[dict] = []
    results: list[dict | None] = []
    for item in validated_items:
        item_id = item[ID]
        receipt = item[CHAIN_ITEM_RECEIPT]
        hops = item[CHAIN_ITEM_HOPS]
        target = item[DELEGATION_TARGET]
        try:
            receipt_payload = verify_batch_receipt(
                receipt, policy, keyring, moment
            )
        except AuthenticationError as exc:
            reports.append(
                _chain_item_report(
                    item_id, CHAINS_UNAUTHENTICATED, str(exc), None
                )
            )
            results.append(None)
            continue
        except (InvalidBatchReceiptError, TypeError) as exc:
            # A TypeError here can only come from a wrong JSON field
            # type *inside* the receipt bytes; the argument types were
            # all validated before the batch ran.
            reports.append(
                _chain_item_report(
                    item_id, CHAINS_INVALID_RECEIPT, str(exc), None
                )
            )
            results.append(None)
            continue

        result: dict | None = None
        try:
            hop_payloads, domains = _walk_delegation_chain(
                receipt, receipt_payload, hops, validated_keyring, moment
            )
            if domains[-1] != target:
                raise _delegation_invalid(
                    f"hop {len(hops) - 1} audience must equal the "
                    "expected target"
                )
        except AuthenticationError as exc:
            reports.append(
                _chain_item_report(
                    item_id, CHAINS_UNAUTHENTICATED, str(exc), None
                )
            )
            results.append(None)
            continue
        except (InvalidReceiptDelegationError, TypeError) as exc:
            # As above, an internal TypeError is a malformed hop field.
            reports.append(
                _chain_item_report(
                    item_id, CHAINS_INVALID_DELEGATION, str(exc), None
                )
            )
            results.append(None)
            continue
        else:
            result = {
                DELEGATION_HOPS: copy.deepcopy(hop_payloads),
                RECEIPT: receipt_payload,
                DELEGATION_RECEIPT_DIGEST: hashlib.sha256(receipt).hexdigest(),
                DELEGATION_TARGET: target,
                VERSION: RECEIPT_DELEGATION_VERSION,
            }
        reports.append(
            _chain_item_report(item_id, CHAINS_VERIFIED, None, result)
        )
        results.append(result)

    fork_edges = _chain_fork_edges(validated_items, results)
    edge_ids: dict[tuple[str, str], list[str]] = {
        edge: [] for edge in fork_edges
    }
    if fork_edges:
        # Record the chains crossing each forking edge and reclassify
        # those chains in one walk over the actual hop bytes.
        for item, report, result in zip(validated_items, reports, results):
            if result is None:
                continue
            receipt_digest = result[DELEGATION_RECEIPT_DIGEST]
            node = receipt_digest
            crosses_fork = False
            for hop_bytes in item[CHAIN_ITEM_HOPS]:
                edge = (receipt_digest, node)
                if edge in fork_edges:
                    edge_ids[edge].append(item[ID])
                    crosses_fork = True
                node = hashlib.sha256(hop_bytes).hexdigest()
            if crosses_fork:
                report[STATUS] = CHAINS_CONFLICTED
                report[CHECKPOINT_ITEM_ERROR] = _CHAIN_ITEM_ERROR

    forks = [
        {
            DELEGATION_RECEIPT_DIGEST: receipt_digest,
            DELEGATION_UPSTREAM: upstream,
            _FORK_AUDIENCES: sorted(fork_edges[(receipt_digest, upstream)]),
            _FORK_IDS: sorted(edge_ids[(receipt_digest, upstream)]),
        }
        for receipt_digest, upstream in sorted(fork_edges)
    ]
    return {
        CHAINS_FORKS: forks,
        ITEMS: reports,
        VERSION: RECEIPT_CHAINS_VERSION,
    }


# --- Offline signed fork evidence for receipt delegation chains ---------------

RECEIPT_FORK_PROOF_VERSION = 1

FORK_PROOF_REPORT = "report"
FORK_PROOF_CHAINS = "chains"
FORK_PROOF_DIGEST = "proofDigest"

FORK_PROOFS_VERSION = 1
FORK_PROOF_ITEM_PROOF = "proof"

_FORK_PROOF_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_FORK_PROOF_PAYLOAD_KEYS = frozenset((
    VD_ISSUER,
    KEY_VERSION,
    CP_MOMENT,
    RECEIPT_POLICY,
    FORK_PROOF_REPORT,
    FORK_PROOF_CHAINS,
    VERSION,
))
_FORK_CHAIN_KEYS = frozenset((
    ID,
    CP_DIGEST,
    DELEGATION_TARGET,
    DELEGATION_HOPS,
))
_FORK_PROOF_REPORT_KEYS = frozenset((CHAINS_FORKS, ITEMS, VERSION))
_FORK_PROOF_FORK_KEYS = frozenset((
    DELEGATION_RECEIPT_DIGEST,
    DELEGATION_UPSTREAM,
    _FORK_AUDIENCES,
    _FORK_IDS,
))
_FORK_PROOF_ITEM_REPORT_KEYS = frozenset((
    CHECKPOINT_ITEM_ERROR,
    ID,
    VERDICT_ITEM_RESULT,
    STATUS,
))
_FORK_PROOF_RESULT_KEYS = frozenset((
    DELEGATION_HOPS,
    RECEIPT,
    DELEGATION_RECEIPT_DIGEST,
    DELEGATION_TARGET,
    VERSION,
))
_FORK_PROOF_BATCH_ITEM_KEYS = frozenset((ID, FORK_PROOF_ITEM_PROOF))
_FORK_PROOF_REPORT_STATUSES = frozenset((
    CHAINS_VERIFIED,
    CHAINS_CONFLICTED,
    CHAINS_INVALID_RECEIPT,
    CHAINS_INVALID_DELEGATION,
    CHAINS_UNAUTHENTICATED,
))
_FORK_PROOF_VERIFY_VERIFIED = "verified"
_FORK_PROOF_VERIFY_INVALID = "invalid-proof"
_FORK_PROOF_VERIFY_UNAUTHENTICATED = "unauthenticated"


class InvalidReceiptForkProofError(ValueError):
    """A signed receipt fork proof fails its canonical contract."""


def _fork_proof_invalid(message: str) -> InvalidReceiptForkProofError:
    return InvalidReceiptForkProofError(f"invalid receipt fork proof: {message}")


def _fork_chain_materials(validated_items: list[dict]) -> list[dict]:
    """Summarize each input chain's material in strict input order.

    Every entry -- one per batch item, with no reordering and none
    omitted, including chains that failed single-chain verification --
    carries exactly ``id``, ``digest`` (the lowercase hex SHA-256 of
    that chain's base receipt bytes), ``target`` and ``hops`` (the
    lowercase hex SHA-256 of each hop's complete bytes, in chain
    order).
    """
    return [
        {
            ID: item[ID],
            CP_DIGEST: hashlib.sha256(
                item[CHAIN_ITEM_RECEIPT]
            ).hexdigest(),
            DELEGATION_TARGET: item[DELEGATION_TARGET],
            DELEGATION_HOPS: [
                hashlib.sha256(hop).hexdigest()
                for hop in item[CHAIN_ITEM_HOPS]
            ],
        }
        for item in validated_items
    ]


def _validated_fork_hop_payload(hop: object, where: str) -> dict:
    """Validate one delegation hop payload bound inside a chain result.

    Mirrors the payload half of :func:`_parse_receipt_delegation`: a
    field of the wrong type raises :class:`TypeError` (a :class:`bool`
    never poses as an int); every key-set or value-format fault raises
    :class:`InvalidReceiptForkProofError`.
    """
    if not isinstance(hop, dict):
        raise TypeError(f"{where} hop must be an object")
    if set(hop.keys()) != _DELEGATION_PAYLOAD_KEYS:
        raise _fork_proof_invalid(
            f"{where} hop must contain exactly the keys 'issuer', "
            "'keyVersion', 'moment', 'audience', 'upstream' and 'version'"
        )
    issuer = hop[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError(f"{where} hop issuer must be a str")
    if issuer == "":
        raise _fork_proof_invalid(f"{where} hop issuer must be non-empty")
    key_version = hop[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError(f"{where} hop keyVersion must be an int")
    if key_version <= 0:
        raise _fork_proof_invalid(f"{where} hop keyVersion must be positive")
    hop_moment = hop[CP_MOMENT]
    if isinstance(hop_moment, bool) or not isinstance(hop_moment, int):
        raise TypeError(f"{where} hop moment must be an int")
    if hop_moment < 0:
        raise _fork_proof_invalid(f"{where} hop moment must be non-negative")
    audience = hop[DELEGATION_AUDIENCE]
    if not isinstance(audience, str):
        raise TypeError(f"{where} hop audience must be a str")
    if audience == "":
        raise _fork_proof_invalid(f"{where} hop audience must be non-empty")
    upstream = hop[DELEGATION_UPSTREAM]
    if not isinstance(upstream, str):
        raise TypeError(f"{where} hop upstream must be a str")
    if not _is_digest(upstream):
        raise _fork_proof_invalid(
            f"{where} hop upstream must be 64 lowercase hex characters"
        )
    version = hop[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError(f"{where} hop version must be an int")
    if version != RECEIPT_DELEGATION_VERSION:
        raise _fork_proof_invalid(
            f"{where} hop version must be the integer 1"
        )
    return hop


def _validated_fork_receipt_payload(receipt: object, policy_digest: str,
                                    where: str) -> dict:
    """Validate the base receipt payload bound inside a chain result.

    Mirrors the payload half of :func:`_parse_batch_receipt` and reuses
    the bound report validators; its ``policy`` digest must equal the
    fork proof's policy digest.  A field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    key-set or value-format fault raises
    :class:`InvalidReceiptForkProofError`.
    """
    if not isinstance(receipt, dict):
        raise TypeError(f"{where} receipt must be an object")
    if set(receipt.keys()) != _BATCH_RECEIPT_PAYLOAD_KEYS:
        raise _fork_proof_invalid(
            f"{where} receipt must contain exactly the keys 'issuer', "
            "'keyVersion', 'moment', 'policy', 'items' and 'version'"
        )
    issuer = receipt[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError(f"{where} receipt issuer must be a str")
    if issuer == "":
        raise _fork_proof_invalid(f"{where} receipt issuer must be non-empty")
    key_version = receipt[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError(f"{where} receipt keyVersion must be an int")
    if key_version <= 0:
        raise _fork_proof_invalid(
            f"{where} receipt keyVersion must be positive"
        )
    moment = receipt[CP_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError(f"{where} receipt moment must be an int")
    if moment < 0:
        raise _fork_proof_invalid(f"{where} receipt moment must be non-negative")
    bound_policy = receipt[RECEIPT_POLICY]
    if not isinstance(bound_policy, str):
        raise TypeError(f"{where} receipt policy must be a str")
    if not _is_digest(bound_policy):
        raise _fork_proof_invalid(
            f"{where} receipt policy must be 64 lowercase hex characters"
        )
    if bound_policy != policy_digest:
        raise _fork_proof_invalid(
            f"{where} receipt policy digest does not match the proof policy"
        )
    version = receipt[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError(f"{where} receipt version must be an int")
    if version != BATCH_RECEIPT_VERSION:
        raise _fork_proof_invalid(
            f"{where} receipt version must be the integer 1"
        )
    items = receipt[ITEMS]
    if not isinstance(items, list):
        raise TypeError(f"{where} receipt items must be a list")
    if not items:
        raise _fork_proof_invalid(f"{where} receipt items must be non-empty")
    seen_ids: set[str] = set()
    for position, item in enumerate(items):
        item_where = f"{where} receipt item {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{item_where} must be an object")
        if set(item.keys()) != _BATCH_RECEIPT_ITEM_KEYS:
            raise _fork_proof_invalid(
                f"{item_where} must contain exactly the keys 'id', 'digest' "
                "and 'report'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{item_where} id must be a str")
        if item_id == "":
            raise _fork_proof_invalid(f"{item_where} id must be non-empty")
        if item_id in seen_ids:
            raise _fork_proof_invalid(f"{item_where} repeats an id")
        seen_ids.add(item_id)
        digest = item[CP_DIGEST]
        if not isinstance(digest, str):
            raise TypeError(f"{item_where} digest must be a str")
        if not _is_digest(digest):
            raise _fork_proof_invalid(
                f"{item_where} digest must be 64 lowercase hex characters"
            )
        try:
            _validated_receipt_report(
                item[RECEIPT_ITEM_REPORT], item_id, item_where
            )
        except InvalidBatchReceiptError as exc:
            raise _fork_proof_invalid(str(exc)) from exc
    return receipt


def _validated_fork_report(report: object, chains: list[dict],
                           policy_digest: str, payload_moment: int) -> dict:
    """Validate the complete chain-batch report bound into a fork proof.

    The report must follow the exact :func:`verify_batch_receipt_chains`
    shape -- ``forks``, ``items`` and ``version`` (the integer 1) -- with
    at least one fork.  Every binding to the chain material summary is
    checked: the item count and per-position ids, the base receipt
    digest/target/hop count and the hop upstream chaining of every
    successful result, the base receipt and each hop payload shape, and
    each fork's exact crossing chains and audiences recomputed from the
    bound results.  A field of the wrong type raises :class:`TypeError`
    (a :class:`bool` never poses as an int); every key-set, value,
    ordering, reference or binding fault raises
    :class:`InvalidReceiptForkProofError`.
    """
    if not isinstance(report, dict):
        raise TypeError("payload report must be an object")
    if set(report.keys()) != _FORK_PROOF_REPORT_KEYS:
        raise _fork_proof_invalid(
            "bound report must contain exactly the keys 'forks', 'items' "
            "and 'version'"
        )
    version = report[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("bound report version must be an int")
    if version != RECEIPT_CHAINS_VERSION:
        raise _fork_proof_invalid("bound report version must be the integer 1")

    items = report[ITEMS]
    if not isinstance(items, list):
        raise TypeError("bound report items must be a list")
    if not items:
        raise _fork_proof_invalid("bound report items must be non-empty")
    if len(items) != len(chains):
        raise _fork_proof_invalid(
            "bound report item count does not match the chain materials"
        )

    by_id: dict[str, dict] = {}
    for position, item_report in enumerate(items):
        where = f"bound report item {position}"
        if not isinstance(item_report, dict):
            raise TypeError(f"{where} must be an object")
        if set(item_report.keys()) != _FORK_PROOF_ITEM_REPORT_KEYS:
            raise _fork_proof_invalid(
                f"{where} must contain exactly the keys 'error', 'id', "
                "'result' and 'status'"
            )
        item_id = item_report[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise _fork_proof_invalid(f"{where} id must be a non-empty str")
        if item_id != chains[position][ID]:
            raise _fork_proof_invalid(
                f"{where} id does not match the chain material at its position"
            )
        if item_id in by_id:
            raise _fork_proof_invalid(f"{where} repeats an id")
        status = item_report[STATUS]
        if not isinstance(status, str):
            raise TypeError(f"{where} status must be a str")
        if status not in _FORK_PROOF_REPORT_STATUSES:
            raise _fork_proof_invalid(f"{where} status is not a known status")
        error = item_report[CHECKPOINT_ITEM_ERROR]
        result = item_report[VERDICT_ITEM_RESULT]
        if status == CHAINS_VERIFIED:
            if error is not None:
                raise _fork_proof_invalid(
                    f"{where} error must be null when verified"
                )
            if not isinstance(result, dict):
                raise TypeError(f"{where} result must be an object when verified")
        elif status == CHAINS_CONFLICTED:
            if not isinstance(error, str):
                raise TypeError(
                    f"{where} error must be a str when conflicted"
                )
            if error != _CHAIN_ITEM_ERROR:
                raise _fork_proof_invalid(
                    f"{where} error must be 'forked-delegation' when conflicted"
                )
            if not isinstance(result, dict):
                raise TypeError(
                    f"{where} result must be an object when conflicted"
                )
        else:
            if not isinstance(error, str):
                raise TypeError(f"{where} error must be a str for a failure")
            if error == "":
                raise _fork_proof_invalid(
                    f"{where} error must be a non-empty str for a failure"
                )
            if result is not None:
                raise _fork_proof_invalid(
                    f"{where} result must be null for a failure"
                )
        if isinstance(result, dict):
            if set(result.keys()) != _FORK_PROOF_RESULT_KEYS:
                raise _fork_proof_invalid(
                    f"{where} result must contain exactly the keys 'hops', "
                    "'receipt', 'receiptDigest', 'target' and 'version'"
                )
            result_version = result[VERSION]
            if isinstance(result_version, bool) or not isinstance(
                result_version, int
            ):
                raise TypeError(f"{where} result version must be an int")
            if result_version != RECEIPT_DELEGATION_VERSION:
                raise _fork_proof_invalid(
                    f"{where} result version must be the integer 1"
                )
            receipt_digest = result[DELEGATION_RECEIPT_DIGEST]
            if not isinstance(receipt_digest, str):
                raise TypeError(f"{where} result receiptDigest must be a str")
            if not _is_digest(receipt_digest):
                raise _fork_proof_invalid(
                    f"{where} result receiptDigest must be 64 lowercase hex "
                    "characters"
                )
            target = result[DELEGATION_TARGET]
            if not isinstance(target, str):
                raise TypeError(f"{where} result target must be a str")
            if target == "":
                raise _fork_proof_invalid(
                    f"{where} result target must be a non-empty str"
                )
            hops = result[DELEGATION_HOPS]
            if not isinstance(hops, list):
                raise TypeError(f"{where} result hops must be a list")
            if not hops:
                raise _fork_proof_invalid(
                    f"{where} result hops must be a non-empty list"
                )
            material = chains[position]
            if receipt_digest != material[CP_DIGEST]:
                raise _fork_proof_invalid(
                    f"{where} result receiptDigest does not match the chain "
                    "material"
                )
            if target != material[DELEGATION_TARGET]:
                raise _fork_proof_invalid(
                    f"{where} result target does not match the chain material"
                )
            if len(hops) != len(material[DELEGATION_HOPS]):
                raise _fork_proof_invalid(
                    f"{where} result hop count does not match the chain "
                    "material"
                )
            _validated_fork_receipt_payload(
                result[RECEIPT], policy_digest, where
            )
            if result[RECEIPT][CP_MOMENT] > payload_moment:
                raise _fork_proof_invalid(
                    f"{where} receipt moment must not be later than the "
                    "proof signing moment"
                )
            previous_audience = result[RECEIPT][VD_ISSUER]
            previous_moment = result[RECEIPT][CP_MOMENT]
            node = receipt_digest
            seen_domains = {previous_audience}
            for hop_index, hop in enumerate(hops):
                hop_where = f"{where} result hop {hop_index}"
                _validated_fork_hop_payload(hop, hop_where)
                if hop[VD_ISSUER] != previous_audience:
                    raise _fork_proof_invalid(
                        f"{hop_where} issuer does not chain to its upstream"
                    )
                if hop[DELEGATION_UPSTREAM] != node:
                    raise _fork_proof_invalid(
                        f"{hop_where} upstream does not chain to its upstream "
                        "bytes"
                    )
                if hop[CP_MOMENT] < previous_moment:
                    raise _fork_proof_invalid(
                        f"{hop_where} moment must not be earlier than its "
                        "upstream"
                    )
                if hop[CP_MOMENT] > payload_moment:
                    raise _fork_proof_invalid(
                        f"{hop_where} moment must not be later than the "
                        "proof signing moment"
                    )
                audience = hop[DELEGATION_AUDIENCE]
                if audience in seen_domains:
                    raise _fork_proof_invalid(
                        f"{hop_where} audience repeats a chain domain"
                    )
                seen_domains.add(audience)
                previous_audience = audience
                previous_moment = hop[CP_MOMENT]
                node = material[DELEGATION_HOPS][hop_index]
            if target != previous_audience:
                raise _fork_proof_invalid(
                    f"{where} result target must equal the last hop audience"
                )
        by_id[item_id] = item_report

    forks = report[CHAINS_FORKS]
    if not isinstance(forks, list):
        raise TypeError("bound report forks must be a list")
    if not forks:
        raise _fork_proof_invalid(
            "a fork proof must report at least one fork"
        )

    # Recompute every edge from the bound results and materials, then
    # demand the bound fork entries match exactly -- the same grouping
    # and fork rule verify_batch_receipt_chains uses.
    groups: dict[str, dict[str, set[str]]] = {}
    crossing: dict[tuple[str, str], set[str]] = {}
    for chain, item_report in zip(chains, items):
        result = item_report[VERDICT_ITEM_RESULT]
        if not isinstance(result, dict):
            continue
        receipt_digest = chain[CP_DIGEST]
        edges = groups.setdefault(receipt_digest, {})
        node = receipt_digest
        for hop_index, hop_material in enumerate(chain[DELEGATION_HOPS]):
            audience = result[DELEGATION_HOPS][hop_index][DELEGATION_AUDIENCE]
            edges.setdefault(node, set()).add(audience)
            node = hop_material
    expected_edges: dict[tuple[str, str], set[str]] = {}
    for receipt_digest, receipt_edges in groups.items():
        for upstream, audiences in receipt_edges.items():
            if len(audiences) > 1:
                expected_edges[(receipt_digest, upstream)] = audiences
    for edge in expected_edges:
        crossing[edge] = set()
    for chain, item_report in zip(chains, items):
        result = item_report[VERDICT_ITEM_RESULT]
        if not isinstance(result, dict):
            continue
        receipt_digest = chain[CP_DIGEST]
        node = receipt_digest
        for hop_index, hop_material in enumerate(chain[DELEGATION_HOPS]):
            edge = (receipt_digest, node)
            if edge in expected_edges:
                crossing[edge].add(chain[ID])
            node = hop_material

    seen_edges: set[tuple[str, str]] = set()
    previous_edge: tuple[str, str] | None = None
    for position, fork in enumerate(forks):
        where = f"bound report fork {position}"
        if not isinstance(fork, dict):
            raise TypeError(f"{where} must be an object")
        if set(fork.keys()) != _FORK_PROOF_FORK_KEYS:
            raise _fork_proof_invalid(
                f"{where} must contain exactly the keys 'receiptDigest', "
                "'upstream', 'audiences' and 'ids'"
            )
        receipt_digest = fork[DELEGATION_RECEIPT_DIGEST]
        upstream = fork[DELEGATION_UPSTREAM]
        if not isinstance(receipt_digest, str):
            raise TypeError(f"{where} receiptDigest must be a str")
        if not isinstance(upstream, str):
            raise TypeError(f"{where} upstream must be a str")
        if not _is_digest(receipt_digest):
            raise _fork_proof_invalid(
                f"{where} receiptDigest must be 64 lowercase hex characters"
            )
        if not _is_digest(upstream):
            raise _fork_proof_invalid(
                f"{where} upstream must be 64 lowercase hex characters"
            )
        edge = (receipt_digest, upstream)
        if edge in seen_edges:
            raise _fork_proof_invalid(f"{where} repeats a fork edge")
        seen_edges.add(edge)
        if previous_edge is not None and edge < previous_edge:
            raise _fork_proof_invalid(
                f"{where} forks must be sorted by receiptDigest then upstream"
            )
        previous_edge = edge
        if edge not in expected_edges:
            raise _fork_proof_invalid(
                f"{where} is not a fork in the bound chain results"
            )
        audiences = fork[_FORK_AUDIENCES]
        if not isinstance(audiences, list):
            raise TypeError(f"{where} audiences must be a list")
        if any(not isinstance(audience, str) for audience in audiences):
            raise TypeError(f"{where} audiences must be strs")
        if any(audience == "" for audience in audiences):
            raise _fork_proof_invalid(f"{where} audiences must be non-empty")
        if audiences != sorted(audiences) or len(set(audiences)) != len(
            audiences
        ):
            raise _fork_proof_invalid(
                f"{where} audiences must be unique and sorted ascending"
            )
        if set(audiences) != expected_edges[edge]:
            raise _fork_proof_invalid(
                f"{where} audiences do not match the forking edge"
            )
        ids = fork[_FORK_IDS]
        if not isinstance(ids, list):
            raise TypeError(f"{where} ids must be a list")
        if any(not isinstance(fork_id, str) for fork_id in ids):
            raise TypeError(f"{where} ids must be strs")
        if any(fork_id == "" for fork_id in ids):
            raise _fork_proof_invalid(f"{where} ids must be non-empty")
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise _fork_proof_invalid(
                f"{where} ids must be unique and sorted ascending"
            )
        if set(ids) != crossing[edge]:
            raise _fork_proof_invalid(
                f"{where} ids do not match the chains crossing the edge"
            )

    if seen_edges != set(expected_edges):
        raise _fork_proof_invalid(
            "the bound forks do not match the forking edges in the results"
        )
    conflicted = {
        item_report[ID]
        for item_report in items
        if item_report[STATUS] == CHAINS_CONFLICTED
    }
    all_fork_ids: set[str] = set()
    for edge_ids in crossing.values():
        all_fork_ids |= edge_ids
    if conflicted != all_fork_ids:
        raise _fork_proof_invalid(
            "the fork id sets must equal the conflicted report items"
        )
    return report


def _validated_fork_chains(chains: object) -> list[dict]:
    """Validate the bound chain material summary into fresh ordered dicts.

    Each entry must carry exactly ``id`` (a non-empty str), ``digest``
    (64 lowercase hex characters), ``target`` (a non-empty str) and
    ``hops`` (a non-empty list of 64-char lowercase hex digests).  A
    field of the wrong type raises :class:`TypeError` (a :class:`bool`
    never poses as an int); every key-set, value-format or ordering
    fault raises :class:`InvalidReceiptForkProofError`.
    """
    if not isinstance(chains, list):
        raise TypeError("payload chains must be a list")
    if not chains:
        raise _fork_proof_invalid("payload chains must be non-empty")
    validated: list[dict] = []
    seen_ids: set[str] = set()
    for position, chain in enumerate(chains):
        where = f"chain {position}"
        if not isinstance(chain, dict):
            raise TypeError(f"{where} must be an object")
        if set(chain.keys()) != _FORK_CHAIN_KEYS:
            raise _fork_proof_invalid(
                f"{where} must contain exactly the keys 'id', 'digest', "
                "'target' and 'hops'"
            )
        chain_id = chain[ID]
        if not isinstance(chain_id, str):
            raise TypeError(f"{where} id must be a str")
        if chain_id == "":
            raise _fork_proof_invalid(f"{where} id must be a non-empty str")
        if chain_id in seen_ids:
            raise _fork_proof_invalid(f"{where} repeats an id")
        seen_ids.add(chain_id)
        digest = chain[CP_DIGEST]
        if not isinstance(digest, str):
            raise TypeError(f"{where} digest must be a str")
        if not _is_digest(digest):
            raise _fork_proof_invalid(
                f"{where} digest must be 64 lowercase hex characters"
            )
        target = chain[DELEGATION_TARGET]
        if not isinstance(target, str):
            raise TypeError(f"{where} target must be a str")
        if target == "":
            raise _fork_proof_invalid(f"{where} target must be a non-empty str")
        hops = chain[DELEGATION_HOPS]
        if not isinstance(hops, list):
            raise TypeError(f"{where} hops must be a list")
        if not hops:
            raise _fork_proof_invalid(
                f"{where} hops must be a non-empty list"
            )
        for hop_index, hop in enumerate(hops):
            if not isinstance(hop, str):
                raise TypeError(f"{where} hop {hop_index} must be a str")
            if not _is_digest(hop):
                raise _fork_proof_invalid(
                    f"{where} hop {hop_index} must be 64 lowercase hex "
                    "characters"
                )
        validated.append(
            {
                ID: chain_id,
                CP_DIGEST: digest,
                DELEGATION_TARGET: target,
                DELEGATION_HOPS: list(hops),
            }
        )
    return validated


def _parse_fork_proof(raw: object) -> tuple[dict, str, list[dict]]:
    """Validate fork proof bytes into ``(payload, signature, chains)``.

    A non-bytes argument or a public field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, digest, ordering, reference or
    report-binding fault raises
    :class:`InvalidReceiptForkProofError`.  The policy, moment,
    credential and signature bindings are checked by
    :func:`verify_receipt_fork_proof`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("proof must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _fork_proof_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fork_proof_invalid("is not valid UTF-8") from exc

    def reject_duplicates(pairs: list[tuple]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise _fork_proof_invalid(f"duplicate key {key!r} in object")
            result[key] = value
        return result

    try:
        data = json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise _fork_proof_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise TypeError("proof must be a JSON object")
    if set(data.keys()) != _FORK_PROOF_TOP_KEYS:
        raise _fork_proof_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("proof signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _fork_proof_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("proof payload must be an object")
    if set(payload.keys()) != _FORK_PROOF_PAYLOAD_KEYS:
        raise _fork_proof_invalid(
            "payload must contain exactly the keys 'issuer', 'keyVersion', "
            "'moment', 'policy', 'report', 'chains' and 'version'"
        )
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _fork_proof_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _fork_proof_invalid("payload keyVersion must be positive")
    moment = payload[CP_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("payload moment must be an int")
    if moment < 0:
        raise _fork_proof_invalid("payload moment must be non-negative")
    policy_digest = payload[RECEIPT_POLICY]
    if not isinstance(policy_digest, str):
        raise TypeError("payload policy must be a str")
    if not _is_digest(policy_digest):
        raise _fork_proof_invalid(
            "payload policy must be 64 lowercase hex characters"
        )
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("payload version must be an int")
    if version != RECEIPT_FORK_PROOF_VERSION:
        raise _fork_proof_invalid("payload version must be the integer 1")
    if not isinstance(payload[FORK_PROOF_REPORT], dict):
        raise TypeError("payload report must be an object")
    chains = _validated_fork_chains(payload[FORK_PROOF_CHAINS])
    _validated_fork_report(
        payload[FORK_PROOF_REPORT], chains, policy_digest,
        payload[CP_MOMENT],
    )

    if _checkpoint_compact(data) != raw:
        raise _fork_proof_invalid(
            "encoding is not the canonical compact form"
        )
    return payload, signature, chains


def sign_receipt_fork_proof(
    items: list,
    policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Sign the fork summary of a delegation-chain batch for offline handover.

    ``items`` is the same non-empty list of ``{"id", "receipt", "hops",
    "target"}`` dicts :func:`verify_batch_receipt_chains` takes;
    ``policy`` is the same ``{"batch", "sites", "threshold"}`` object,
    ``keyring`` follows the :func:`apply_signed_remote` rules,
    ``moment`` is the signing time and ``issuer``/``version`` name the
    signing credentials.  The batch first runs through the exact
    :func:`verify_batch_receipt_chains` rules and the proof is issued
    only when the resulting summary reports at least one fork.  No file
    is read or written and no argument is modified.

    The proof is one canonical compact UTF-8 JSON object -- every
    object key recursively sorted, non-ASCII preserved, no trailing
    newline or any other trailing byte -- carrying exactly ``payload``
    and ``signature``.  The payload binds exactly ``issuer``,
    ``keyVersion``, ``moment``, ``policy`` (the lowercase hex SHA-256
    of the canonical compact policy encoding), the complete ``report``
    and ``chains``, and ``version`` (the integer 1).  ``chains``
    summarizes every input chain, strictly in input order with no
    reordering and none omitted: each entry carries exactly ``id``,
    ``digest`` (the SHA-256 of that chain's base receipt bytes),
    ``target`` and ``hops`` (the SHA-256 of each hop's complete bytes
    in chain order).  ``signature`` is the lowercase hex HMAC-SHA256
    of the canonical compact payload bytes under the key the keyring
    binds to the exact issuer and version, with no fallback.

    A parameter or public field type fault raises :class:`TypeError`
    (a :class:`bool` never poses as an int); an empty issuer, a
    non-positive version, a negative moment, an illegal shared policy
    value or a report without a fork raises :class:`ValueError`; and
    unknown, revoked, not-yet-valid or expired credentials raise
    :class:`AuthenticationError`.
    """
    validated_items = _validated_chain_items(items)
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

    report = verify_batch_receipt_chains(
        validated_items, policy, keyring, moment
    )
    if not report[CHAINS_FORKS]:
        raise ValueError(
            "a receipt fork proof requires at least one fork in the "
            "chain report"
        )
    entry = _usable_checkpoint_key(validated_keyring, issuer, version, moment)
    payload = {
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        CP_MOMENT: moment,
        RECEIPT_POLICY: hashlib.sha256(
            _verdict_policy_bytes(validated_policy)
        ).hexdigest(),
        FORK_PROOF_REPORT: copy.deepcopy(report),
        FORK_PROOF_CHAINS: _fork_chain_materials(validated_items),
        VERSION: RECEIPT_FORK_PROOF_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact({TICKET_PAYLOAD: payload, SIGNATURE: signature})


def _verify_receipt_fork_proof(
    proof: bytes,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one fork proof against already-validated shared materials.

    This is the shared core of :func:`verify_receipt_fork_proof` and the
    batch :func:`verify_receipt_fork_proofs`; the caller owns the
    argument-type and shared-material validation.  The returned dict is
    freshly built solely from authenticated proof material.
    """
    payload, signature, chains = _parse_fork_proof(proof)
    recomputed_policy = hashlib.sha256(
        _verdict_policy_bytes(validated_policy)
    ).hexdigest()
    if payload[RECEIPT_POLICY] != recomputed_policy:
        raise _fork_proof_invalid("policy digest does not match the policy")
    if payload[CP_MOMENT] > moment:
        raise _fork_proof_invalid(
            "moment must not be later than the verification moment"
        )

    key_entry = _usable_checkpoint_key(
        validated_keyring, payload[VD_ISSUER], payload[KEY_VERSION], moment
    )
    expected_signature = hmac.new(
        bytes.fromhex(key_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError("receipt fork proof signature does not match")

    return {
        FORK_PROOF_CHAINS: copy.deepcopy(chains),
        VD_ISSUER: payload[VD_ISSUER],
        KEY_VERSION: payload[KEY_VERSION],
        CP_MOMENT: payload[CP_MOMENT],
        VD_POLICY_DIGEST: recomputed_policy,
        FORK_PROOF_DIGEST: hashlib.sha256(proof).hexdigest(),
        FORK_PROOF_REPORT: copy.deepcopy(payload[FORK_PROOF_REPORT]),
        VERSION: RECEIPT_FORK_PROOF_VERSION,
    }


def verify_receipt_fork_proof(
    proof: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a signed receipt fork proof entirely offline.

    Only the proof bytes, the expected ``policy``, the current
    ``keyring`` and the verification ``moment`` are consulted -- no
    file is read or written and no argument is modified.  Verification
    recomputes the policy digest over the canonical compact policy
    encoding, validates the proof encoding, key sets, version,
    digests, ordering, chain/report references and the complete bound
    chain-batch report, requires the signing moment not to be later
    than the verification moment, and verifies the HMAC-SHA256
    signature against the key the *current* keyring binds to the
    payload's exact issuer and version, usable at the verification
    moment, so a later revocation or expiry rejects the proof.

    On success a fresh mapping is returned with the fixed keys
    ``chains``, ``issuer``, ``keyVersion``, ``moment``,
    ``policyDigest``, ``proofDigest`` (the lowercase hex SHA-256 of
    the proof bytes), ``report`` and ``version`` (the integer 1).
    A non-bytes proof or a public field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    illegal policy, keyring or moment raises :class:`ValueError`; an
    illegal encoding, key set, version, digest, ordering, reference or
    report binding raises :class:`InvalidReceiptForkProofError` (a
    :class:`ValueError` subclass); and unknown, revoked, not-yet-valid
    or expired credentials or a signature mismatch raise
    :class:`AuthenticationError`.
    """
    if not isinstance(proof, bytes):
        raise TypeError("proof must be bytes")
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return _verify_receipt_fork_proof(
        proof, validated_policy, validated_keyring, moment
    )


def _validated_fork_proof_items(items: object) -> list[dict]:
    """Validate the fork-proof batch before any proof is verified.

    The argument must be a non-empty list of dicts each holding exactly
    ``id`` (a non-empty str, unique across the batch) and ``proof``
    (bytes).  Container, element and field type faults raise
    :class:`TypeError`; an empty list, an empty or duplicate id or a
    wrong key set raises :class:`ValueError`.
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
        if set(item.keys()) != _FORK_PROOF_BATCH_ITEM_KEYS:
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
        proof = item[FORK_PROOF_ITEM_PROOF]
        if not isinstance(proof, bytes):
            raise TypeError(f"{where} proof must be bytes")
        validated.append({ID: item_id, FORK_PROOF_ITEM_PROOF: proof})
    return validated


def _fork_proof_item_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One fork-proof batch report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def _verify_fork_proof_item(
    item: dict,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one fork proof in isolation and report its outcome.

    Current but revoked, not-yet-valid, expired or missing credentials
    and a wrong signature make the item ``unauthenticated``; every
    encoding, key-set, version, digest, ordering, reference or
    report-binding fault makes it ``invalid-proof``; a passing proof is
    ``verified`` with the single-entry result.
    """
    item_id = item[ID]
    proof = item[FORK_PROOF_ITEM_PROOF]
    try:
        result = _verify_receipt_fork_proof(
            proof, validated_policy, validated_keyring, moment
        )
    except AuthenticationError as exc:
        return _fork_proof_item_report(
            item_id, _FORK_PROOF_VERIFY_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidReceiptForkProofError, TypeError) as exc:
        # A TypeError here can only come from a wrong JSON field type
        # *inside* the proof bytes; the public argument types were all
        # validated before the batch ran.
        return _fork_proof_item_report(
            item_id, _FORK_PROOF_VERIFY_INVALID, str(exc), None
        )
    return _fork_proof_item_report(
        item_id, _FORK_PROOF_VERIFY_VERIFIED, None, result
    )


def verify_receipt_fork_proofs(
    items: list, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a whole batch of receipt fork proofs entirely offline.

    ``items`` is a non-empty list; each item is a dict with exactly the
    keys ``id`` (a non-empty str, unique across the batch) and ``proof``
    (the proof bytes :func:`sign_receipt_fork_proof` produced).
    ``policy``, ``keyring`` and ``moment`` keep their single-proof
    meaning.  The whole batch structure and the shared materials are
    validated in full before any proof is verified: container, element
    or field type faults raise :class:`TypeError` (a :class:`bool`
    never poses as an int) and an empty list, an empty or duplicate id
    or a wrong item key set raises :class:`ValueError` (policy, keyring
    and moment keep their single-entry classification).  Only these
    batch-level faults raise.

    Each proof is then verified independently, in strict input order,
    through the exact :func:`verify_receipt_fork_proof` rules: one
    proof's failure never stops a later proof or alters an earlier
    report.  Currently revoked, not-yet-valid, expired or missing
    credentials or a wrong signature make the item ``unauthenticated``;
    an illegal encoding, key set, version, digest, ordering, reference
    or report binding makes it ``invalid-proof``; a passing proof is
    ``verified``.

    The top-level result is a fresh dict with the fixed keys ``items``
    and ``version`` (the integer 1); each item report carries, in this
    key order, ``error`` (null exactly when verified), ``id``,
    ``result`` (a fresh independent copy of the single-entry result
    when verified, otherwise null) and ``status``.  Repeated calls
    return equal but mutually independent results.  No file is read or
    written and no input is modified.
    """
    validated_items = _validated_fork_proof_items(items)
    validated_policy = _validated_adjudication_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return {
        ITEMS: [
            _verify_fork_proof_item(
                item, validated_policy, validated_keyring, moment
            )
            for item in validated_items
        ],
        VERSION: FORK_PROOFS_VERSION,
    }


# --- Offline multi-site disposition decisions over receipt fork proofs --------

FORK_DECISION_VERSION = 1

FD_ACTION = "action"
FD_BASE = "base"
FD_BOUNDARIES = "boundaries"
FD_DECISIONS = "decisions"
FD_POLICY_DIGEST = "policyDigest"
FD_PROOFS = "proofs"
FD_RECOMMENDATION = "recommendation"
FD_TARGETS = "targets"
FD_PROOF = "proof"
FD_SITE = ADJ_SITE
FD_SITES = ADJ_SITES
FD_CONCLUSION = ADJ_CONCLUSION
FD_REASON = ADJ_REASON

FD_ACTION_ISOLATE = "isolate"
FD_ACTION_ROLLBACK = "rollback"
_FD_ACTIONS = frozenset((FD_ACTION_ISOLATE, FD_ACTION_ROLLBACK))

FD_RECOMMENDATION_ISOLATE = FD_ACTION_ISOLATE
FD_RECOMMENDATION_ROLLBACK = FD_ACTION_ROLLBACK
FD_RECOMMENDATION_MANUAL = "manual-review"
_FD_RECOMMENDATIONS = frozenset((
    FD_RECOMMENDATION_ISOLATE,
    FD_RECOMMENDATION_ROLLBACK,
    FD_RECOMMENDATION_MANUAL,
))

FD_STATUS_ACCEPTED = ADJ_STATUS_ACCEPTED
FD_STATUS_CONFLICTED = ADJ_STATUS_CONFLICTED
FD_STATUS_INSUFFICIENT = ADJ_STATUS_INSUFFICIENT

FD_CONCLUSION_VALID = ADJ_CONCLUSION_VALID
FD_CONCLUSION_INVALID = ADJ_CONCLUSION_INVALID
FD_CONCLUSION_DUPLICATE = ADJ_CONCLUSION_DUPLICATE
FD_CONCLUSION_CONTRADICTION = ADJ_CONCLUSION_CONTRADICTION
_FD_CONCLUSIONS = frozenset((
    FD_CONCLUSION_VALID,
    FD_CONCLUSION_INVALID,
    FD_CONCLUSION_DUPLICATE,
    FD_CONCLUSION_CONTRADICTION,
))

FD_REASON_INVALID_PROOF = "invalid-proof"
_FD_INVALID_REASONS = frozenset((
    FD_REASON_INVALID_PROOF,
    REASON_UNAUTHORIZED_SITE,
    REASON_UNAUTHORIZED_VERSION,
    REASON_CREDENTIAL_UNAVAILABLE,
    REASON_REVOKED,
    REASON_NOT_YET_VALID,
    REASON_EXPIRED,
    REASON_BAD_SIGNATURE,
))
_FD_REASONS = _FD_INVALID_REASONS | frozenset((
    REASON_DUPLICATE,
    REASON_CONTRADICTION,
))

_FD_POLICY_KEYS = frozenset((
    FD_ACTION,
    FD_BASE,
    FD_SITES,
    ADJ_THRESHOLD,
))
_FD_ITEM_KEYS = frozenset((ID, FD_PROOF))
_FD_DECISION_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_FD_PAYLOAD_KEYS = frozenset((
    FD_ACTION,
    FD_BOUNDARIES,
    FD_DECISIONS,
    VD_ISSUER,
    KEY_VERSION,
    FD_POLICY_DIGEST,
    FD_PROOFS,
    FD_RECOMMENDATION,
    FD_TARGETS,
    VERSION,
))
_FD_BOUNDARY_KEYS = frozenset((
    DELEGATION_RECEIPT_DIGEST,
    DELEGATION_TARGET,
    DELEGATION_UPSTREAM,
))
_FD_ROW_KEYS = frozenset((
    FD_BOUNDARIES,
    FD_CONCLUSION,
    ID,
    KEY_VERSION,
    CP_DIGEST,
    FD_REASON,
    FD_SITE,
))
_FD_BATCH_ITEM_KEYS = frozenset((ID, "decision"))
_FD_VERIFY_VERIFIED = "verified"
_FD_VERIFY_INVALID = "invalid"
_FD_VERIFY_UNAUTHENTICATED = "unauthenticated"
_FD_RESULT_KEYS = (
    FD_ACTION,
    FD_BOUNDARIES,
    FD_DECISIONS,
    VD_ISSUER,
    KEY_VERSION,
    FD_POLICY_DIGEST,
    FORK_PROOF_DIGEST,
    FD_PROOFS,
    FD_RECOMMENDATION,
    STATUS,
    FD_TARGETS,
    VERSION,
)


class InvalidForkDecisionError(ValueError):
    """A signed fork decision fails its canonical or binding contract."""


def _fork_decision_invalid(message: str) -> InvalidForkDecisionError:
    return InvalidForkDecisionError(f"invalid fork decision: {message}")


def _reject_duplicate_fork_decision_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate decision keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _fork_decision_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _validated_boundary_object(value: object, where: str) -> dict:
    """Validate one ``{'receiptDigest','target','upstream'}`` boundary."""
    if not isinstance(value, dict):
        raise TypeError(f"{where} boundary must be an object")
    if set(value.keys()) != _FD_BOUNDARY_KEYS:
        raise _fork_decision_invalid(
            f"{where} boundary must contain exactly the keys 'receiptDigest', "
            "'target' and 'upstream'"
        )
    receipt_digest = value[DELEGATION_RECEIPT_DIGEST]
    upstream = value[DELEGATION_UPSTREAM]
    target = value[DELEGATION_TARGET]
    if not isinstance(receipt_digest, str):
        raise TypeError(f"{where} receiptDigest must be a str")
    if not isinstance(upstream, str):
        raise TypeError(f"{where} upstream must be a str")
    if not isinstance(target, str):
        raise TypeError(f"{where} target must be a str")
    if not _is_digest(receipt_digest):
        raise _fork_decision_invalid(
            f"{where} receiptDigest must be 64 lowercase hex characters"
        )
    if not _is_digest(upstream):
        raise _fork_decision_invalid(
            f"{where} upstream must be 64 lowercase hex characters"
        )
    if target == "":
        raise _fork_decision_invalid(f"{where} target must be non-empty")
    return {
        DELEGATION_RECEIPT_DIGEST: receipt_digest,
        DELEGATION_TARGET: target,
        DELEGATION_UPSTREAM: upstream,
    }


def _boundary_triples(boundaries: list[dict]) -> tuple[tuple[str, str, str], ...]:
    """Order-preserving boundary objects to comparable triples."""
    return tuple(
        (
            boundary[DELEGATION_RECEIPT_DIGEST],
            boundary[DELEGATION_UPSTREAM],
            boundary[DELEGATION_TARGET],
        )
        for boundary in boundaries
    )


def _sorted_boundary_objects(
    triples: set[tuple[str, str, str]] | frozenset[tuple[str, str, str]]
) -> list[dict]:
    """Unique boundary triples sorted as (receiptDigest, upstream, target)."""
    return [
        {
            DELEGATION_RECEIPT_DIGEST: receipt_digest,
            DELEGATION_TARGET: target,
            DELEGATION_UPSTREAM: upstream,
        }
        for receipt_digest, upstream, target in sorted(triples)
    ]


def _validated_fork_policy(policy: object) -> dict:
    """Validate the fork decision policy into a fresh normalized dict.

    The policy carries exactly ``action``, ``base``, ``sites`` and
    ``threshold``; ``base`` follows the exact adjudication policy
    contract and ``sites``/``threshold`` its per-site version-set and
    threshold rules.  Type faults raise :class:`TypeError` (a
    :class:`bool` never poses as an int); every key-set or value fault
    raises :class:`ValueError`.
    """
    if not isinstance(policy, dict):
        raise TypeError("policy must be a dict")
    if set(policy.keys()) != _FD_POLICY_KEYS:
        raise ValueError(
            "policy must contain exactly the keys 'action', 'base', "
            "'sites' and 'threshold'"
        )
    base = policy[FD_BASE]
    if not isinstance(base, dict):
        raise TypeError("policy base must be a dict")
    validated_base = _validated_adjudication_policy(base)
    action = policy[FD_ACTION]
    if not isinstance(action, str):
        raise TypeError("policy action must be a str")
    if action not in _FD_ACTIONS:
        raise ValueError("policy action must be one of 'isolate' or 'rollback'")
    threshold = policy[ADJ_THRESHOLD]
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise TypeError("policy threshold must be an int")
    if threshold <= 0:
        raise ValueError("policy threshold must be a positive integer")
    sites = policy[FD_SITES]
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
            raise TypeError(f"allowed versions for site {site!r} must be a set")
        site_versions: set[int] = set()
        for key_version in versions:
            if isinstance(key_version, bool) or not isinstance(key_version, int):
                raise TypeError(
                    f"allowed versions for site {site!r} must be ints"
                )
            if key_version <= 0:
                raise ValueError(
                    f"allowed versions for site {site!r} must be positive"
                )
            site_versions.add(key_version)
        if not site_versions:
            raise ValueError(f"site {site!r} must allow at least one key version")
        allowed[site] = frozenset(site_versions)
    if threshold > len(allowed):
        raise ValueError(
            "policy threshold must not exceed the number of policy sites"
        )
    return {
        FD_ACTION: action,
        FD_BASE: validated_base,
        FD_SITES: allowed,
        ADJ_THRESHOLD: threshold,
    }


def _fork_policy_bytes(policy: dict) -> bytes:
    """Canonical compact bytes of the normalized fork decision policy.

    The nested ``base`` policy is canonicalized exactly as
    :func:`_verdict_policy_bytes` canonicalizes it; sites are listed
    ascending with ascending version arrays and every key is sorted.
    """
    base = policy[FD_BASE]
    canonical_base = {
        ADJ_BATCH: base[ADJ_BATCH],
        ADJ_SITES: {
            site: sorted(base[ADJ_SITES][site]) for site in sorted(base[ADJ_SITES])
        },
        ADJ_THRESHOLD: base[ADJ_THRESHOLD],
    }
    canonical = {
        FD_ACTION: policy[FD_ACTION],
        FD_BASE: canonical_base,
        FD_SITES: {
            site: sorted(policy[FD_SITES][site])
            for site in sorted(policy[FD_SITES])
        },
        ADJ_THRESHOLD: policy[ADJ_THRESHOLD],
    }
    return _checkpoint_compact(canonical)


def _validated_fork_items(items: object) -> list[dict]:
    """Validate the proof-item container before any proof is examined.

    A non-list container or a non-dict element, non-str id or non-bytes
    proof raises :class:`TypeError`; an empty list, an empty or duplicate
    id or a wrong item key set raises :class:`ValueError`.  Empty proof
    bytes are accepted here and rejected per item later.
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
        if set(item.keys()) != _FD_ITEM_KEYS:
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
        proof = item[FD_PROOF]
        if not isinstance(proof, bytes):
            raise TypeError(f"{where} proof must be bytes")
        validated.append({ID: item_id, FD_PROOF: proof})
    return validated


def _fork_proof_boundaries(
    payload: dict, chains: list[dict]
) -> frozenset[tuple[str, str, str]]:
    """The fork boundaries a verified proof claims.

    Each forking edge crossed by a chain contributes one
    ``(receiptDigest, upstream, target)`` triple -- the base receipt, the
    forking upstream and that crossing chain's final target domain.  The
    fork proof's own validation already proved the fork entries and
    crossing chains, so every named id names a chain material.
    """
    targets_by_id = {chain[ID]: chain[DELEGATION_TARGET] for chain in chains}
    boundaries: set[tuple[str, str, str]] = set()
    for fork in payload[FORK_PROOF_REPORT][CHAINS_FORKS]:
        receipt_digest = fork[DELEGATION_RECEIPT_DIGEST]
        upstream = fork[DELEGATION_UPSTREAM]
        for chain_id in fork[_FORK_IDS]:
            boundaries.add(
                (receipt_digest, upstream, targets_by_id[chain_id])
            )
    return frozenset(boundaries)


def _fork_decision_row(
    item_id: str,
    proof_digest: str,
    site: str | None,
    key_version: int | None,
    boundaries: list[dict] | None,
    conclusion: str,
    reason: str | None,
) -> dict:
    """One per-proof decision row with the fixed bound key set."""
    return {
        FD_BOUNDARIES: boundaries,
        FD_CONCLUSION: conclusion,
        ID: item_id,
        KEY_VERSION: key_version,
        CP_DIGEST: proof_digest,
        FD_REASON: reason,
        FD_SITE: site,
    }


def _decide_fork_one(
    item: dict,
    policy: dict,
    keyring: dict[str, list[dict]],
    moment: int,
    base_policy_digest: str,
) -> dict:
    """Verify, authorize and authenticate one fork proof in isolation.

    Returns a fresh decision row.  The proof is first checked through the
    exact :func:`verify_receipt_fork_proof` structural rules, then the
    signing site and key version are authorized exactly against the
    policy with no fallback, and finally the HMAC is checked against the
    current keyring.  Any failure rejects just this row with one fixed
    reason and never affects the other items.
    """
    item_id = item[ID]
    raw_proof = item[FD_PROOF]
    proof_digest = hashlib.sha256(raw_proof).hexdigest()

    def structural_invalid() -> dict:
        return _fork_decision_row(
            item_id, proof_digest, None, None, None,
            FD_CONCLUSION_INVALID, FD_REASON_INVALID_PROOF,
        )

    try:
        payload, signature, chains = _parse_fork_proof(raw_proof)
    except (TypeError, ValueError):
        return structural_invalid()

    site = payload[VD_ISSUER]
    key_version = payload[KEY_VERSION]
    try:
        boundary_triples = _fork_proof_boundaries(payload, chains)
        boundaries = _sorted_boundary_objects(boundary_triples)
    except (TypeError, ValueError):
        return structural_invalid()

    def reject(reason: str) -> dict:
        return _fork_decision_row(
            item_id, proof_digest, site, key_version, boundaries,
            FD_CONCLUSION_INVALID, reason,
        )

    if payload[RECEIPT_POLICY] != base_policy_digest:
        # A proof for a different base policy cannot be trusted to name
        # anything: reject it as a structural mismatch with no identity.
        return structural_invalid()
    if payload[CP_MOMENT] > moment:
        return structural_invalid()

    allowed_versions = policy[FD_SITES].get(site)
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

    return _fork_decision_row(
        item_id, proof_digest, site, key_version, boundaries,
        FD_CONCLUSION_VALID, None,
    )


def _tally_fork_rows(
    rows: list[dict],
) -> tuple[
    bool,
    dict[str, frozenset[tuple[str, str, str]]],
    dict[str, list[dict]],
]:
    """Group authenticated rows per site and detect same-site forks.

    Returns ``(contradicted, votes, representatives)`` where ``votes``
    maps each non-contradicting site to its one boundary set and
    ``representatives`` maps each site to the digest-group rows that
    represent it (the rows marked ``valid``/``contradiction``).
    """
    by_site: dict[str, list[dict]] = {}
    for row in rows:
        if row[FD_CONCLUSION] in (
            FD_CONCLUSION_VALID,
            FD_CONCLUSION_DUPLICATE,
            FD_CONCLUSION_CONTRADICTION,
        ):
            by_site.setdefault(row[FD_SITE], []).append(row)

    contradicted = False
    votes: dict[str, frozenset[tuple[str, str, str]]] = {}
    representatives: dict[str, list[dict]] = {}
    for site, site_rows in by_site.items():
        groups: dict[str, list[dict]] = {}
        for row in site_rows:
            groups.setdefault(row[CP_DIGEST], []).append(row)
        if len(groups) > 1:
            contradicted = True
            reps: list[dict] = []
            for digest, members in groups.items():
                members.sort(key=lambda row: row[ID])
                members[0][FD_CONCLUSION] = FD_CONCLUSION_CONTRADICTION
                members[0][FD_REASON] = REASON_CONTRADICTION
                for extra in members[1:]:
                    extra[FD_CONCLUSION] = FD_CONCLUSION_DUPLICATE
                    extra[FD_REASON] = REASON_DUPLICATE
                reps.append(members[0])
            representatives[site] = reps
        else:
            members = sorted(
                next(iter(groups.values())), key=lambda row: row[ID]
            )
            members[0][FD_CONCLUSION] = FD_CONCLUSION_VALID
            members[0][FD_REASON] = None
            for extra in members[1:]:
                extra[FD_CONCLUSION] = FD_CONCLUSION_DUPLICATE
                extra[FD_REASON] = REASON_DUPLICATE
            representatives[site] = [members[0]]
            votes[site] = frozenset(
                _boundary_triples(members[0][FD_BOUNDARIES])
            )
    return contradicted, votes, representatives


def decide_forks(
    items: list,
    policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Decide a multi-site fork disposition offline and sign the outcome.

    ``items`` is a non-empty list; each item contains exactly a unique,
    non-empty str ``id`` and ``proof`` bytes produced by
    :func:`sign_receipt_fork_proof`.  ``policy`` carries exactly
    ``action`` (``"isolate"`` or ``"rollback"``), ``base`` (the existing
    ``{"batch","sites","threshold"}`` proof policy), ``sites`` (a
    non-empty mapping of each authorized non-empty site to its non-empty
    set of allowed positive key versions) and ``threshold`` (a positive
    integer no greater than the site count).  ``keyring`` follows the
    :func:`apply_signed_remote` rules, ``moment`` is the current time as
    a non-negative integer and ``issuer``/``version`` name the signing
    credentials.  No file is read or written and no input is modified.

    Every proof is first verified through the existing receipt fork
    proof rules, then authorized by the exact signing site and key
    version with no fallback, then authenticated against the current
    keyring.  An invalid, unauthorized or unauthenticated proof rejects
    just that item with one fixed reason (``invalid-proof``,
    ``unauthorized-site``, ``unauthorized-version``,
    ``credential-unavailable``, ``revoked``, ``not-yet-valid``,
    ``expired`` or ``bad-signature``) without affecting the others.  An
    identical proof digest counts once per site -- extras are
    ``duplicate`` -- while different valid proofs from the same site are
    a ``contradiction``.  The valid proofs of distinct sites must agree
    on every fork boundary made of the base receipt digest, the forking
    upstream and the target domain.

    A unique boundary set attested by at least the threshold of distinct
    sites is ``accepted``; any contradiction or boundary disagreement is
    ``conflicted``; everything else is ``insufficient``.  An accepted
    decision recommends the policy action -- isolate the (deduplicated,
    ascending) target domains or roll back to before the fork -- while
    every other outcome recommends ``manual-review`` with no boundary or
    target claimed.

    The result is one canonical compact UTF-8 JSON object with
    recursively sorted keys, non-ASCII preserved and no trailing byte,
    carrying exactly ``payload`` and ``signature``.  The payload binds
    exactly ``action``, ``boundaries``, ``decisions``, ``issuer``,
    ``keyVersion``, ``policyDigest`` (the SHA-256 of the canonical
    policy), ``proofs`` (each proof digest in the original input order),
    ``recommendation``, ``targets`` and ``version`` (the integer 1);
    ``signature`` is the lowercase hex HMAC-SHA256 of the canonical
    compact payload bytes under the key bound to the exact issuer and
    version, with no fallback.

    A parameter, container or field type fault raises :class:`TypeError`
    (a :class:`bool` never poses as an int); an empty list, an empty or
    duplicate id or an illegal policy value raises :class:`ValueError`;
    unknown, revoked, not-yet-valid or expired signing credentials raise
    :class:`AuthenticationError`.
    """
    validated_items = _validated_fork_items(items)
    validated_policy = _validated_fork_policy(policy)
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

    base_policy_digest = hashlib.sha256(
        _verdict_policy_bytes(validated_policy[FD_BASE])
    ).hexdigest()

    proof_digests = [
        hashlib.sha256(item[FD_PROOF]).hexdigest() for item in validated_items
    ]
    rows = [
        _decide_fork_one(
            item, validated_policy, validated_keyring, moment,
            base_policy_digest,
        )
        for item in validated_items
    ]

    contradicted, votes, _representatives = _tally_fork_rows(rows)

    boundary_sets = set(votes.values())
    if contradicted or len(boundary_sets) > 1:
        status = FD_STATUS_CONFLICTED
    elif len(boundary_sets) == 1:
        if len(votes) >= validated_policy[ADJ_THRESHOLD]:
            status = FD_STATUS_ACCEPTED
        else:
            status = FD_STATUS_INSUFFICIENT
    else:
        status = FD_STATUS_INSUFFICIENT

    if status == FD_STATUS_ACCEPTED:
        agreed = next(iter(boundary_sets))
        boundaries = _sorted_boundary_objects(agreed)
        targets = sorted({triple[2] for triple in agreed})
        recommendation = validated_policy[FD_ACTION]
    else:
        boundaries = []
        targets = []
        recommendation = FD_RECOMMENDATION_MANUAL

    rows.sort(
        key=lambda row: (
            row[FD_SITE] is not None,
            row[FD_SITE] or "",
            row[ID],
        )
    )

    signing_entry = _usable_checkpoint_key(
        validated_keyring, issuer, version, moment
    )
    payload = {
        FD_ACTION: validated_policy[FD_ACTION],
        FD_BOUNDARIES: boundaries,
        FD_DECISIONS: [copy.deepcopy(row) for row in rows],
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        FD_POLICY_DIGEST: hashlib.sha256(
            _fork_policy_bytes(validated_policy)
        ).hexdigest(),
        FD_PROOFS: proof_digests,
        FD_RECOMMENDATION: recommendation,
        FD_TARGETS: targets,
        VERSION: FORK_DECISION_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact(
        {TICKET_PAYLOAD: payload, SIGNATURE: signature}
    )


def _parse_fork_decision(raw: object) -> tuple[dict, str]:
    """Validate decision bytes structurally into ``(payload, signature)``.

    A non-bytes argument or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, digest or value-format fault raises
    :class:`InvalidForkDecisionError`.  The policy, tally and credential
    bindings are checked by :func:`verify_fork_decision`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("decision must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _fork_decision_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fork_decision_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_fork_decision_keys
        )
    except json.JSONDecodeError as exc:
        raise _fork_decision_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise TypeError("decision must be a JSON object")
    if set(data.keys()) != _FD_DECISION_TOP_KEYS:
        raise _fork_decision_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("decision signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _fork_decision_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("decision payload must be an object")
    if set(payload.keys()) != _FD_PAYLOAD_KEYS:
        raise _fork_decision_invalid(
            "payload must contain exactly the keys 'action', 'boundaries', "
            "'decisions', 'issuer', 'keyVersion', 'policyDigest', 'proofs', "
            "'recommendation', 'targets' and 'version'"
        )

    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _fork_decision_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _fork_decision_invalid("payload keyVersion must be positive")
    action = payload[FD_ACTION]
    if not isinstance(action, str):
        raise TypeError("payload action must be a str")
    if action not in _FD_ACTIONS:
        raise _fork_decision_invalid(
            "payload action must be one of 'isolate' or 'rollback'"
        )
    recommendation = payload[FD_RECOMMENDATION]
    if not isinstance(recommendation, str):
        raise TypeError("payload recommendation must be a str")
    if recommendation not in _FD_RECOMMENDATIONS:
        raise _fork_decision_invalid(
            "payload recommendation must be one of 'isolate', 'rollback' or "
            "'manual-review'"
        )
    policy_digest = payload[FD_POLICY_DIGEST]
    if not isinstance(policy_digest, str):
        raise TypeError("payload policyDigest must be a str")
    if not _is_digest(policy_digest):
        raise _fork_decision_invalid(
            "payload policyDigest must be 64 lowercase hex characters"
        )
    proofs = payload[FD_PROOFS]
    if not isinstance(proofs, list):
        raise TypeError("payload proofs must be a list")
    if not proofs:
        raise _fork_decision_invalid("payload proofs must be non-empty")
    for position, digest in enumerate(proofs):
        if not isinstance(digest, str):
            raise TypeError(f"payload proof {position} digest must be a str")
        if not _is_digest(digest):
            raise _fork_decision_invalid(
                f"payload proof {position} digest must be 64 lowercase hex "
                "characters"
            )

    decisions = payload[FD_DECISIONS]
    if not isinstance(decisions, list):
        raise TypeError("payload decisions must be a list")
    if not decisions:
        raise _fork_decision_invalid("payload decisions must be non-empty")
    parsed_rows: list[dict] = []
    seen_ids: set[str] = set()
    for position, row in enumerate(decisions):
        where = f"payload decision {position}"
        if not isinstance(row, dict):
            raise TypeError(f"{where} must be an object")
        if set(row.keys()) != _FD_ROW_KEYS:
            raise _fork_decision_invalid(
                f"{where} must contain exactly the keys 'boundary', "
                "'conclusion', 'id', 'keyVersion', 'digest', 'reason' and "
                "'site'"
            )
        row_id = row[ID]
        if not isinstance(row_id, str):
            raise TypeError(f"{where} id must be a str")
        if row_id == "":
            raise _fork_decision_invalid(f"{where} id must be non-empty")
        if row_id in seen_ids:
            raise _fork_decision_invalid(f"{where} repeats an id")
        seen_ids.add(row_id)
        digest = row[CP_DIGEST]
        if not isinstance(digest, str):
            raise TypeError(f"{where} digest must be a str")
        if not _is_digest(digest):
            raise _fork_decision_invalid(
                f"{where} digest must be 64 lowercase hex characters"
            )
        site = row[FD_SITE]
        if site is not None:
            if not isinstance(site, str):
                raise TypeError(f"{where} site must be a str or null")
            if site == "":
                raise _fork_decision_invalid(f"{where} site must be non-empty")
        row_key_version = row[KEY_VERSION]
        if isinstance(row_key_version, bool) or not isinstance(
            row_key_version, int
        ):
            if row_key_version is not None:
                raise TypeError(f"{where} keyVersion must be an int or null")
        elif row_key_version <= 0:
            raise _fork_decision_invalid(f"{where} keyVersion must be positive")
        if (site is None) != (row_key_version is None):
            raise _fork_decision_invalid(
                f"{where} site and keyVersion must be null together"
            )
        conclusion = row[FD_CONCLUSION]
        if not isinstance(conclusion, str):
            raise TypeError(f"{where} conclusion must be a str")
        if conclusion not in _FD_CONCLUSIONS:
            raise _fork_decision_invalid(f"{where} conclusion is not known")
        reason = row[FD_REASON]
        if conclusion == FD_CONCLUSION_VALID:
            if reason is not None:
                raise _fork_decision_invalid(
                    f"{where} reason must be null for a valid decision"
                )
        else:
            if not isinstance(reason, str):
                raise TypeError(f"{where} reason must be a str")
            if reason not in _FD_REASONS:
                raise _fork_decision_invalid(f"{where} reason is not known")
        if conclusion == FD_CONCLUSION_INVALID:
            if reason not in _FD_INVALID_REASONS:
                raise _fork_decision_invalid(
                    f"{where} reason does not match an invalid decision"
                )
        elif conclusion != FD_CONCLUSION_VALID:
            if reason != conclusion:
                raise _fork_decision_invalid(
                    f"{where} reason must match its conclusion"
                )
        raw_boundaries = row[FD_BOUNDARIES]
        if raw_boundaries is not None:
            if not isinstance(raw_boundaries, list):
                raise TypeError(f"{where} boundaries must be a list or null")
            if not raw_boundaries:
                raise _fork_decision_invalid(
                    f"{where} boundaries must be non-empty for an "
                    "authenticated proof"
                )
            row_boundaries = [
                _validated_boundary_object(value, where)
                for value in raw_boundaries
            ]
            triples = _boundary_triples(row_boundaries)
            if len(set(triples)) != len(triples):
                raise _fork_decision_invalid(
                    f"{where} boundaries must be unique"
                )
            if list(triples) != sorted(triples):
                raise _fork_decision_invalid(
                    f"{where} boundaries must be sorted ascending"
                )
        parsed_boundaries = raw_boundaries
        identity_expected = reason != FD_REASON_INVALID_PROOF
        if identity_expected:
            if site is None or parsed_boundaries is None:
                raise _fork_decision_invalid(
                    f"{where} an authenticated proof must carry its site and "
                    "boundaries"
                )
        else:
            if site is not None or parsed_boundaries is not None:
                raise _fork_decision_invalid(
                    f"{where} an invalid-proof decision must carry no site or "
                    "boundaries"
                )
        parsed_rows.append(
            {
                FD_BOUNDARIES: (
                    None
                    if parsed_boundaries is None
                    else [dict(value) for value in parsed_boundaries]
                ),
                FD_CONCLUSION: conclusion,
                ID: row_id,
                KEY_VERSION: row_key_version,
                CP_DIGEST: digest,
                FD_REASON: reason,
                FD_SITE: site,
            }
        )

    bound_boundaries = payload[FD_BOUNDARIES]
    if not isinstance(bound_boundaries, list):
        raise TypeError("payload boundaries must be a list")
    parsed_top_boundaries = [
        _validated_boundary_object(value, "payload boundaries")
        for value in bound_boundaries
    ]
    top_triples = _boundary_triples(parsed_top_boundaries)
    if len(set(top_triples)) != len(top_triples) or list(top_triples) != sorted(
        top_triples
    ):
        raise _fork_decision_invalid(
            "payload boundaries must be unique and sorted ascending"
        )
    targets = payload[FD_TARGETS]
    if not isinstance(targets, list):
        raise TypeError("payload targets must be a list")
    for position, target in enumerate(targets):
        if not isinstance(target, str):
            raise TypeError(f"payload target {position} must be a str")
        if target == "":
            raise _fork_decision_invalid(
                f"payload target {position} must be non-empty"
            )
    if len(set(targets)) != len(targets) or targets != sorted(targets):
        raise _fork_decision_invalid(
            "payload targets must be unique and sorted ascending"
        )
    decision_version = payload[VERSION]
    if isinstance(decision_version, bool) or not isinstance(
        decision_version, int
    ):
        raise TypeError("payload version must be an int")
    if decision_version != FORK_DECISION_VERSION:
        raise _fork_decision_invalid("payload version must be the integer 1")

    if _checkpoint_compact(data) != raw:
        raise _fork_decision_invalid(
            "encoding is not the canonical compact form"
        )
    return payload, signature


def _reconcile_fork_payload(
    payload: dict, threshold: int, action: str
) -> str:
    """Re-derive every aggregate binding of a parsed decision payload.

    Re-tallies the per-proof rows the signature covers -- row ordering,
    proof digests, duplicate/contradiction conclusions, the cross-site
    boundary agreement, the threshold acceptance and the claimed
    boundaries, targets and recommendation -- without seeing any fork
    proof.  Any mismatch raises :class:`InvalidForkDecisionError`;
    otherwise the derived status is returned.
    """
    decisions = payload[FD_DECISIONS]
    proofs = payload[FD_PROOFS]
    if len(decisions) != len(proofs):
        raise _fork_decision_invalid(
            "the decisions must cover every proof and vice versa"
        )
    expected_order = sorted(
        decisions,
        key=lambda row: (
            row[FD_SITE] is not None,
            row[FD_SITE] or "",
            row[ID],
        ),
    )
    if [row[ID] for row in expected_order] != [
        row[ID] for row in decisions
    ]:
        raise _fork_decision_invalid(
            "decisions must be sorted by site then id"
        )
    decision_digests = [row[CP_DIGEST] for row in decisions]
    if sorted(decision_digests) != sorted(proofs):
        raise _fork_decision_invalid(
            "the bound proof digests must equal the per-decision digests"
        )

    # Re-derive per-site duplicate/contradiction conclusions and compare
    # them against the signed rows; no proof bytes are needed because a
    # digest uniquely names a proof.
    by_site: dict[str, dict[str, list[dict]]] = {}
    for row in decisions:
        if row[FD_CONCLUSION] == FD_CONCLUSION_INVALID:
            continue
        by_site.setdefault(row[FD_SITE], {}).setdefault(
            row[CP_DIGEST], []
        ).append(row)

    contradicted = False
    votes: dict[str, frozenset[tuple[str, str, str]]] = {}
    for site, groups in by_site.items():
        if len(groups) > 1:
            contradicted = True
            expected_conclusion = FD_CONCLUSION_CONTRADICTION
            expected_reason = REASON_CONTRADICTION
        else:
            expected_conclusion = FD_CONCLUSION_VALID
            expected_reason = None
            sole_members = sorted(
                next(iter(groups.values())), key=lambda row: row[ID]
            )
            votes[site] = frozenset(
                _boundary_triples(sole_members[0][FD_BOUNDARIES])
            )
        for digest, members_raw in groups.items():
            members = sorted(members_raw, key=lambda row: row[ID])
            for index, row in enumerate(members):
                if index == 0:
                    if row[FD_CONCLUSION] != expected_conclusion:
                        raise _fork_decision_invalid(
                            f"decision {row[ID]!r} has the wrong conclusion"
                        )
                    if row[FD_REASON] != expected_reason:
                        raise _fork_decision_invalid(
                            f"decision {row[ID]!r} has the wrong reason"
                        )
                else:
                    if row[FD_CONCLUSION] != FD_CONCLUSION_DUPLICATE:
                        raise _fork_decision_invalid(
                            f"decision {row[ID]!r} must be a duplicate"
                        )
                    if row[FD_REASON] != REASON_DUPLICATE:
                        raise _fork_decision_invalid(
                            f"decision {row[ID]!r} must carry the duplicate "
                            "reason"
                        )
            representative = members[0]
            for row in members[1:]:
                if _boundary_triples(
                    row[FD_BOUNDARIES]
                ) != _boundary_triples(representative[FD_BOUNDARIES]):
                    raise _fork_decision_invalid(
                        f"decision {row[ID]!r} duplicates a proof with "
                        "different boundaries"
                    )

    boundary_sets = set(votes.values())
    if contradicted or len(boundary_sets) > 1:
        status = FD_STATUS_CONFLICTED
    elif len(boundary_sets) == 1 and len(votes) >= threshold:
        status = FD_STATUS_ACCEPTED
    else:
        status = FD_STATUS_INSUFFICIENT

    if status == FD_STATUS_ACCEPTED:
        agreed = next(iter(boundary_sets))
        expected_boundaries = _sorted_boundary_objects(agreed)
        expected_targets = sorted({triple[2] for triple in agreed})
        expected_recommendation = action
    else:
        expected_boundaries = []
        expected_targets = []
        expected_recommendation = FD_RECOMMENDATION_MANUAL

    if payload[FD_BOUNDARIES] != expected_boundaries:
        raise _fork_decision_invalid(
            "the bound boundaries do not match the tallied decisions"
        )
    if payload[FD_TARGETS] != expected_targets:
        raise _fork_decision_invalid(
            "the bound targets do not match the tallied decisions"
        )
    if payload[FD_RECOMMENDATION] != expected_recommendation:
        raise _fork_decision_invalid(
            "the recommendation does not match the action and tallied status"
        )
    return status


def _verify_fork_decision(
    decision: bytes,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one fork decision against already-validated shared materials.

    This is the shared core of :func:`verify_fork_decision` and the batch
    :func:`verify_fork_decisions`; the caller owns the argument-type and
    shared-material validation.  The returned dict is freshly built
    solely from authenticated decision material.
    """
    payload, signature = _parse_fork_decision(decision)
    expected_policy_digest = hashlib.sha256(
        _fork_policy_bytes(validated_policy)
    ).hexdigest()
    if payload[FD_POLICY_DIGEST] != expected_policy_digest:
        raise _fork_decision_invalid("policy digest does not match the policy")
    if payload[FD_ACTION] != validated_policy[FD_ACTION]:
        raise _fork_decision_invalid("action does not match the policy")

    status = _reconcile_fork_payload(
        payload,
        validated_policy[ADJ_THRESHOLD],
        validated_policy[FD_ACTION],
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
        raise AuthenticationError("fork decision signature does not match")

    return {
        key: copy.deepcopy(value)
        for key, value in (
            (FD_ACTION, payload[FD_ACTION]),
            (FD_BOUNDARIES, payload[FD_BOUNDARIES]),
            (FD_DECISIONS, payload[FD_DECISIONS]),
            (VD_ISSUER, payload[VD_ISSUER]),
            (KEY_VERSION, payload[KEY_VERSION]),
            (FD_POLICY_DIGEST, expected_policy_digest),
            (FORK_PROOF_DIGEST, hashlib.sha256(decision).hexdigest()),
            (FD_PROOFS, payload[FD_PROOFS]),
            (FD_RECOMMENDATION, payload[FD_RECOMMENDATION]),
            (STATUS, status),
            (FD_TARGETS, payload[FD_TARGETS]),
            (VERSION, FORK_DECISION_VERSION),
        )
    }


def verify_fork_decision(
    decision: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify one signed multi-site fork decision entirely offline.

    Only the decision bytes, the expected ``policy``, the current
    ``keyring`` and the verification ``moment`` are consulted -- no file
    is read or written and no argument is modified.  Verification
    validates the canonical encoding and key sets, recomputes the policy
    digest, re-tallies the bound per-proof decisions (ordering, digest
    bindings, duplicates, contradictions, cross-site boundary
    agreement, threshold, boundaries, targets and recommendation) purely
    from the signed payload, and checks the HMAC-SHA256 against the key
    the *current* keyring binds to the payload's exact issuer and
    version, usable at the verification moment, so a later revocation or
    expiry rejects the decision with no fallback.

    On success a fresh mapping is returned with the fixed keys
    ``action``, ``boundaries``, ``decisions``, ``issuer``,
    ``keyVersion``, ``policyDigest``, ``proofDigest`` (the SHA-256 of the
    decision bytes), ``proofs``, ``recommendation``, ``status``,
    ``targets`` and ``version`` (the integer 1).  A non-bytes decision
    or a field of the wrong type raises :class:`TypeError` (a
    :class:`bool` never poses as an int); an illegal policy, keyring or
    moment raises :class:`ValueError`; an illegal encoding, key set,
    digest, ordering, reference or binding raises
    :class:`InvalidForkDecisionError` (a :class:`ValueError` subclass);
    unknown, revoked, not-yet-valid or expired credentials or a
    signature mismatch raise :class:`AuthenticationError`.
    """
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return _verify_fork_decision(
        decision, validated_policy, validated_keyring, moment
    )


def _validated_fork_decision_items(items: object) -> list[dict]:
    """Validate the decision batch before any decision is verified.

    The argument must be a non-empty list of dicts each holding exactly
    ``id`` (a non-empty str, unique across the batch) and ``decision``
    (bytes).  Container, element and field type faults raise
    :class:`TypeError`; an empty list, an empty or duplicate id or a
    wrong key set raises :class:`ValueError`.
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
        if set(item.keys()) != _FD_BATCH_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'decision' and 'id'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        decision = item["decision"]
        if not isinstance(decision, bytes):
            raise TypeError(f"{where} decision must be bytes")
        validated.append({ID: item_id, "decision": decision})
    return validated


def _fork_decision_item_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One fork-decision batch report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def _verify_fork_decision_item(
    item: dict,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one decision in isolation and report its outcome.

    Unknown, revoked, not-yet-valid or expired credentials or a wrong
    signature make the item ``unauthenticated``; every encoding,
    key-set, digest, ordering, reference or binding fault makes it
    ``invalid``; a passing decision is ``verified``.
    """
    item_id = item[ID]
    decision = item["decision"]
    try:
        result = _verify_fork_decision(
            decision, validated_policy, validated_keyring, moment
        )
    except AuthenticationError as exc:
        return _fork_decision_item_report(
            item_id, _FD_VERIFY_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidForkDecisionError, TypeError) as exc:
        # A TypeError here can only come from a wrong JSON field type
        # *inside* the decision bytes; the public argument types were all
        # validated before the batch ran.
        return _fork_decision_item_report(
            item_id, _FD_VERIFY_INVALID, str(exc), None
        )
    return _fork_decision_item_report(
        item_id, _FD_VERIFY_VERIFIED, None, result
    )


def verify_fork_decisions(
    items: list, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a whole batch of multi-site fork decisions entirely offline.

    ``items`` is a non-empty list; each item is a dict with exactly the
    keys ``id`` (a non-empty str, unique across the batch) and
    ``decision`` (the bytes :func:`decide_forks` produced).  The batch
    and the shared ``policy``, ``keyring`` and ``moment`` are validated
    in full before any decision is verified: container, element or field
    type faults raise :class:`TypeError` (a :class:`bool` never poses as
    an int) and an empty list, an empty or duplicate id or a wrong item
    key set raises :class:`ValueError`; only these batch-level faults
    raise.

    Each decision is then verified independently, in strict input order,
    through the exact :func:`verify_fork_decision` rules: one decision's
    failure never stops a later one or alters an earlier report.
    Currently unknown, revoked, not-yet-valid or expired credentials or a
    wrong signature make the item ``unauthenticated``; an illegal
    encoding, key set, digest, ordering, reference or binding makes it
    ``invalid``; a passing decision is ``verified``.

    The top-level result is a fresh dict with the fixed keys ``items``
    and ``version`` (the integer 1); each item report carries, in this
    key order, ``error`` (null exactly when verified), ``id``,
    ``result`` (a fresh independent copy of the single-decision result
    when verified, otherwise null) and ``status``; a failed item keeps a
    definite, non-empty copy of the original exception text.  Repeated
    calls return equal but mutually independent results.
    """
    validated_items = _validated_fork_decision_items(items)
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("moment must be an int")
    if moment < 0:
        raise ValueError("moment must be non-negative")
    return {
        ITEMS: [
            _verify_fork_decision_item(
                item, validated_policy, validated_keyring, moment
            )
            for item in validated_items
        ],
        VERSION: FORK_DECISION_VERSION,
    }



# --- Offline site execution plans and multi-site confirmations ----------------

FORK_EXECUTION_VERSION = 1

FE_ACTION = FD_ACTION
FE_BOUNDARIES = FD_BOUNDARIES
FE_DECISION_DIGEST = "decisionDigest"
FE_EXPIRES_AT = "expiresAt"
FE_GENERATED_AT = "generatedAt"
FE_OPERATIONS = "operations"
FE_OPERATION_ID = "operationId"
FE_POLICY_DIGEST = FD_POLICY_DIGEST
FE_TARGET = DELEGATION_TARGET
FE_REQUIRES = "requires"
FE_STATE = "state"
FE_BASE = "base"
FE_UPSTREAM = DELEGATION_UPSTREAM

FE_AGGREGATED_AT = "aggregatedAt"
FE_ISSUER = TICKET_ISSUER
FE_PLAN = "plan"
FE_PLAN_DIGEST = "planDigest"
FE_SITE = ADJ_SITE
FE_SITE_VERSION = "siteVersion"
FE_EXECUTION_MOMENT = "executionMoment"
FE_PREVIOUS = "previous"
FE_RESULT = "result"
FE_POST_DIGEST = "postDigest"
FE_RECEIPTS = "receipts"
FE_REASONS = "reasons"
FE_RESULTS = "results"
FE_CONFIRMATION_DIGEST = "confirmationDigest"

FE_RESULT_EXECUTED = "executed"
FE_RESULT_REJECTED = "rejected"
FE_RESULT_FAILED = "failed"
_FE_RESULTS = frozenset(
    (FE_RESULT_EXECUTED, FE_RESULT_REJECTED, FE_RESULT_FAILED)
)

FE_STATE_ACTIVE = "active"

FE_STATUS_CONFIRMED = "confirmed"
FE_STATUS_PARTIAL = "partial"
FE_STATUS_REJECTED = "rejected"
FE_STATUS_CONFLICTED = ADJ_STATUS_CONFLICTED
_FE_STATUSES = frozenset((
    FE_STATUS_CONFIRMED,
    FE_STATUS_PARTIAL,
    FE_STATUS_REJECTED,
    FE_STATUS_CONFLICTED,
))

FE_REASON_DECISION_REPLACED = "decision-replaced"
FE_REASON_UNKNOWN_OPERATION = "unknown-operation"
FE_REASON_OUTSIDE_VALIDITY = "outside-validity"
FE_REASON_PREVIOUS_MISMATCH = "previous-mismatch"
FE_REASON_OUT_OF_ORDER = "out-of-order"
FE_REASON_INVALID_RECEIPT = "invalid-receipt"
FE_REASON_BAD_CREDENTIAL = REASON_BAD_SIGNATURE
FE_REASON_DUPLICATE = REASON_DUPLICATE
FE_REASON_CONTRADICTION = REASON_CONTRADICTION
_FE_FIXED_REASONS = frozenset((
    FE_REASON_DECISION_REPLACED,
    FE_REASON_UNKNOWN_OPERATION,
    FE_REASON_OUTSIDE_VALIDITY,
    FE_REASON_PREVIOUS_MISMATCH,
    FE_REASON_OUT_OF_ORDER,
    FE_REASON_INVALID_RECEIPT,
    FE_REASON_BAD_CREDENTIAL,
))
_FE_BOUND_REASONS = _FE_FIXED_REASONS | frozenset((
    FE_REASON_DUPLICATE,
    FE_REASON_CONTRADICTION,
))

_FE_PLAN_KEYS = frozenset((
    FE_ACTION,
    FE_BOUNDARIES,
    FE_DECISION_DIGEST,
    FE_EXPIRES_AT,
    FE_GENERATED_AT,
    FE_OPERATIONS,
    FE_POLICY_DIGEST,
    VERSION,
))
_FE_OPERATION_KEYS = frozenset((
    FE_ACTION,
    FE_BOUNDARIES,
    FE_OPERATION_ID,
    FE_REQUIRES,
    FE_TARGET,
))
_FE_RECEIPT_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_FE_RECEIPT_PAYLOAD_KEYS = frozenset((
    FE_EXECUTION_MOMENT,
    FE_SITE_VERSION,
    KEY_VERSION,
    FE_OPERATION_ID,
    FE_PLAN_DIGEST,
    FE_POST_DIGEST,
    FE_PREVIOUS,
    FE_RESULT,
    FE_SITE,
))
_FE_REASON_ROW_KEYS = frozenset((
    CP_DIGEST,
    FE_OPERATION_ID,
    FE_POST_DIGEST,
    FE_RESULT,
    ADJ_REASON,
    FE_SITE,
))
_FE_OP_RESULT_KEYS = frozenset((FE_OPERATION_ID, FE_RESULT, FE_TARGET))
_FE_CONFIRMATION_PAYLOAD_KEYS = frozenset((
    FE_AGGREGATED_AT,
    KEY_VERSION,
    FE_ISSUER,
    FE_PLAN,
    FE_RECEIPTS,
    FE_REASONS,
    FE_RESULTS,
    STATUS,
    VERSION,
))
_FE_BATCH_ITEM_KEYS = frozenset((ID, "confirmation"))
_FE_VERIFY_VERIFIED = "verified"
_FE_VERIFY_INVALID = "invalid"
_FE_VERIFY_UNAUTHENTICATED = "unauthenticated"
_FE_VERIFY_RESULT_KEYS = (
    FE_AGGREGATED_AT,
    FE_CONFIRMATION_DIGEST,
    FE_DECISION_DIGEST,
    FE_EXPIRES_AT,
    FE_GENERATED_AT,
    FE_ISSUER,
    KEY_VERSION,
    FE_OPERATIONS,
    FE_PLAN_DIGEST,
    FE_POLICY_DIGEST,
    FE_RECEIPTS,
    FE_REASONS,
    FE_RESULTS,
    STATUS,
    VERSION,
)


class InvalidForkExecutionError(ValueError):
    """A fork execution plan or confirmation packet breaks its contract."""


def _fork_execution_invalid(message: str) -> InvalidForkExecutionError:
    return InvalidForkExecutionError(f"invalid fork execution: {message}")


def _reject_duplicate_fork_execution_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate execution keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _fork_execution_invalid(
                f"duplicate key {key!r} in object"
            )
        result[key] = value
    return result


def _fe_moment(value: object, name: str) -> int:
    """Validate a public non-negative, non-bool moment argument."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _validated_fe_boundary(value: object, where: str) -> dict:
    """Validate one fork boundary inside an execution plan.

    Same shape as :func:`_validated_boundary_object`, but every
    non-type fault raises :class:`InvalidForkExecutionError` rather than
    the fork-decision error, since the boundary is bound inside a plan.
    """
    if not isinstance(value, dict):
        raise TypeError(f"{where} boundary must be an object")
    if set(value.keys()) != _FD_BOUNDARY_KEYS:
        raise _fork_execution_invalid(
            f"{where} boundary must contain exactly the keys 'receiptDigest', "
            "'target' and 'upstream'"
        )
    receipt_digest = value[DELEGATION_RECEIPT_DIGEST]
    upstream = value[DELEGATION_UPSTREAM]
    target = value[DELEGATION_TARGET]
    if not isinstance(receipt_digest, str):
        raise TypeError(f"{where} receiptDigest must be a str")
    if not isinstance(upstream, str):
        raise TypeError(f"{where} upstream must be a str")
    if not isinstance(target, str):
        raise TypeError(f"{where} target must be a str")
    if not _is_digest(receipt_digest):
        raise _fork_execution_invalid(
            f"{where} receiptDigest must be 64 lowercase hex characters"
        )
    if not _is_digest(upstream):
        raise _fork_execution_invalid(
            f"{where} upstream must be 64 lowercase hex characters"
        )
    if target == "":
        raise _fork_execution_invalid(f"{where} target must be non-empty")
    return {
        DELEGATION_RECEIPT_DIGEST: receipt_digest,
        DELEGATION_TARGET: target,
        DELEGATION_UPSTREAM: upstream,
    }


def _fe_boundary_bytes(boundary: dict) -> bytes:
    """Canonical bytes of one fork boundary, the idempotency material."""
    return _checkpoint_compact({
        DELEGATION_RECEIPT_DIGEST: boundary[DELEGATION_RECEIPT_DIGEST],
        DELEGATION_TARGET: boundary[DELEGATION_TARGET],
        DELEGATION_UPSTREAM: boundary[DELEGATION_UPSTREAM],
    })


def _fe_operation_id(
    decision_digest: str, action: str, target: str, boundaries: list[dict]
) -> str:
    """Idempotent identity over verdict, action, target and boundaries.

    The SHA-256 feeds the decision digest, the action, the target domain
    and every related boundary's canonical bytes (boundaries ascending),
    so a different verdict, action, target or boundary set names a
    different operation.
    """
    hasher = hashlib.sha256()
    hasher.update(decision_digest.encode("ascii"))
    hasher.update(action.encode("utf-8"))
    hasher.update(target.encode("utf-8"))
    for boundary in boundaries:
        hasher.update(_fe_boundary_bytes(boundary))
    return hasher.hexdigest()


def _fe_requires(action: str, boundaries: list[dict]) -> dict:
    """The execution precondition bound to one target's operation.

    An isolation requires its target domain to still be active; a
    rollback binds the base receipt digest and the forking upstream of
    the first (ascending) boundary addressed to that target.
    """
    if action == FD_ACTION_ISOLATE:
        return {FE_STATE: FE_STATE_ACTIVE}
    first = boundaries[0]
    return {
        FE_BASE: first[DELEGATION_RECEIPT_DIGEST],
        FE_UPSTREAM: first[DELEGATION_UPSTREAM],
    }


def _fe_previous_digest(operation: dict) -> str:
    """The previous-state digest an execution receipt must bind."""
    return hashlib.sha256(
        _checkpoint_compact(operation[FE_REQUIRES])
    ).hexdigest()


def _fe_build_plan(
    action: str,
    boundaries: list[dict],
    targets: list[str],
    decision_digest: str,
    policy_digest: str,
    generated_at: int,
    expires_at: int,
) -> dict:
    """Build the normalized, ascending-target plan object."""
    by_target: dict[str, list[dict]] = {target: [] for target in targets}
    for boundary in boundaries:
        by_target[boundary[DELEGATION_TARGET]].append(boundary)
    operations = []
    for target in targets:
        target_boundaries = sorted(
            by_target[target],
            key=lambda boundary: (
                boundary[DELEGATION_RECEIPT_DIGEST],
                boundary[DELEGATION_UPSTREAM],
                boundary[DELEGATION_TARGET],
            ),
        )
        operations.append({
            FE_ACTION: action,
            FE_BOUNDARIES: [dict(boundary) for boundary in target_boundaries],
            FE_OPERATION_ID: _fe_operation_id(
                decision_digest, action, target, target_boundaries
            ),
            FE_REQUIRES: _fe_requires(action, target_boundaries),
            FE_TARGET: target,
        })
    return {
        FE_ACTION: action,
        FE_BOUNDARIES: [dict(boundary) for boundary in boundaries],
        FE_DECISION_DIGEST: decision_digest,
        FE_EXPIRES_AT: expires_at,
        FE_GENERATED_AT: generated_at,
        FE_OPERATIONS: operations,
        FE_POLICY_DIGEST: policy_digest,
        VERSION: FORK_EXECUTION_VERSION,
    }


def plan_fork_execution(
    decision: bytes,
    policy: dict,
    keyring: dict,
    generated_at: int,
    expires_at: int,
) -> bytes:
    """Plan the site execution of one accepted multi-site fork decision.

    ``decision`` is the canonical packet :func:`decide_forks` returned;
    ``policy`` and ``keyring`` are the same fork policy and current
    keyring, and ``generated_at``/``expires_at`` bind the plan's
    validity window (both bounds inclusive).  The decision is verified
    through the exact :func:`verify_fork_decision` rules at the
    generation moment, so its signature and credentials are checked
    against the current keyring; only an ``accepted`` decision can be
    planned and any other verdict raises :class:`ValueError`.

    The plan is one canonical compact UTF-8 JSON object with recursively
    sorted keys, non-ASCII preserved and no trailing byte.  It binds the
    decision and policy digests, the action, the validity window, every
    fork boundary and the ascending target domains -- one idempotent
    operation per target and no un-adopted proof material.  Each
    operation carries its ``operationId`` (the SHA-256 over the decision
    digest, action, target domain and related boundary canonical bytes),
    its boundaries and its precondition: an isolation requires the
    target domain to stay active; a rollback binds the base receipt
    digest and the forking upstream.

    A parameter, container or public field type fault raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    illegal moment window, a non-accepted decision or any other value
    fault raises :class:`ValueError`; an illegal decision packet raises
    :class:`InvalidForkDecisionError`; unknown, revoked, not-yet-valid
    or expired credentials or a wrong decision signature raise
    :class:`AuthenticationError`.  No file is read or written and no
    argument is modified.
    """
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    generated = _fe_moment(generated_at, "generated_at")
    expires = _fe_moment(expires_at, "expires_at")
    if generated > expires:
        raise ValueError("generated_at must not exceed expires_at")

    verified = _verify_fork_decision(
        decision, validated_policy, validated_keyring, generated
    )
    if verified[STATUS] != FD_STATUS_ACCEPTED:
        raise ValueError(
            "only an accepted fork decision can be planned, got "
            f"{verified[STATUS]!r}"
        )

    plan = _fe_build_plan(
        verified[FD_ACTION],
        verified[FD_BOUNDARIES],
        verified[FD_TARGETS],
        verified[FORK_PROOF_DIGEST],
        verified[FD_POLICY_DIGEST],
        generated,
        expires,
    )
    return _checkpoint_compact(plan)


def _parse_fork_execution_plan(raw: object) -> dict:
    """Validate plan bytes structurally into the normalized plan object.

    A non-bytes argument or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, digest, window, ordering or binding fault raises
    :class:`InvalidForkExecutionError`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("plan must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _fork_execution_invalid(
            "plan must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fork_execution_invalid("plan is not valid UTF-8") from exc
    try:
        plan = json.loads(
            text, object_pairs_hook=_reject_duplicate_fork_execution_keys
        )
    except json.JSONDecodeError as exc:
        raise _fork_execution_invalid("plan is not valid JSON") from exc

    if not isinstance(plan, dict):
        raise TypeError("plan must be a JSON object")
    if set(plan.keys()) != _FE_PLAN_KEYS:
        raise _fork_execution_invalid(
            "plan must contain exactly the keys 'action', 'boundaries', "
            "'decisionDigest', 'expiresAt', 'generatedAt', 'operations', "
            "'policyDigest' and 'version'"
        )
    action = plan[FE_ACTION]
    if not isinstance(action, str):
        raise TypeError("plan action must be a str")
    if action not in _FD_ACTIONS:
        raise _fork_execution_invalid(
            "plan action must be one of 'isolate' or 'rollback'"
        )
    for name in (FE_DECISION_DIGEST, FE_POLICY_DIGEST):
        value = plan[name]
        if not isinstance(value, str):
            raise TypeError(f"plan {name} must be a str")
        if not _is_digest(value):
            raise _fork_execution_invalid(
                f"plan {name} must be 64 lowercase hex characters"
            )
    for name in (FE_GENERATED_AT, FE_EXPIRES_AT):
        value = plan[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"plan {name} must be an int")
        if value < 0:
            raise _fork_execution_invalid(f"plan {name} must be >= 0")
    if plan[FE_GENERATED_AT] > plan[FE_EXPIRES_AT]:
        raise _fork_execution_invalid(
            "plan generatedAt must not exceed expiresAt"
        )
    version = plan[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("plan version must be an int")
    if version != FORK_EXECUTION_VERSION:
        raise _fork_execution_invalid("plan version must be the integer 1")

    raw_boundaries = plan[FE_BOUNDARIES]
    if not isinstance(raw_boundaries, list):
        raise TypeError("plan boundaries must be a list")
    if not raw_boundaries:
        raise _fork_execution_invalid("plan boundaries must be non-empty")
    boundaries = [
        _validated_fe_boundary(value, "plan boundaries")
        for value in raw_boundaries
    ]
    boundary_triples = _boundary_triples(boundaries)
    if len(set(boundary_triples)) != len(boundary_triples):
        raise _fork_execution_invalid("plan boundaries must be unique")
    if list(boundary_triples) != sorted(boundary_triples):
        raise _fork_execution_invalid(
            "plan boundaries must be sorted ascending"
        )

    raw_operations = plan[FE_OPERATIONS]
    if not isinstance(raw_operations, list):
        raise TypeError("plan operations must be a list")
    if not raw_operations:
        raise _fork_execution_invalid("plan operations must be non-empty")
    operations: list[dict] = []
    seen_operation_ids: set[str] = set()
    for position, operation in enumerate(raw_operations):
        where = f"plan operation {position}"
        if not isinstance(operation, dict):
            raise TypeError(f"{where} must be an object")
        if set(operation.keys()) != _FE_OPERATION_KEYS:
            raise _fork_execution_invalid(
                f"{where} must contain exactly the keys 'action', "
                "'boundaries', 'operationId', 'requires' and 'target'"
            )
        if operation[FE_ACTION] != action:
            raise _fork_execution_invalid(
                f"{where} action must match the plan action"
            )
        target = operation[FE_TARGET]
        if not isinstance(target, str):
            raise TypeError(f"{where} target must be a str")
        if target == "":
            raise _fork_execution_invalid(f"{where} target must be non-empty")
        operation_id = operation[FE_OPERATION_ID]
        if not isinstance(operation_id, str):
            raise TypeError(f"{where} operationId must be a str")
        if not _is_digest(operation_id):
            raise _fork_execution_invalid(
                f"{where} operationId must be 64 lowercase hex characters"
            )
        if operation_id in seen_operation_ids:
            raise _fork_execution_invalid(f"{where} repeats an operationId")
        seen_operation_ids.add(operation_id)
        requires = operation[FE_REQUIRES]
        if not isinstance(requires, dict):
            raise TypeError(f"{where} requires must be an object")
        if action == FD_ACTION_ISOLATE:
            if set(requires.keys()) != {FE_STATE}:
                raise _fork_execution_invalid(
                    f"{where} requires must contain exactly 'state'"
                )
            if requires[FE_STATE] != FE_STATE_ACTIVE:
                raise _fork_execution_invalid(
                    f"{where} requires the active state"
                )
        else:
            if set(requires.keys()) != {FE_BASE, FE_UPSTREAM}:
                raise _fork_execution_invalid(
                    f"{where} requires must contain exactly 'base' and "
                    "'upstream'"
                )
            for name in (FE_BASE, FE_UPSTREAM):
                if not isinstance(requires[name], str):
                    raise TypeError(f"{where} requires {name} must be a str")
                if not _is_digest(requires[name]):
                    raise _fork_execution_invalid(
                        f"{where} requires {name} must be 64 lowercase hex "
                        "characters"
                    )
        op_boundaries = [
            _validated_fe_boundary(value, where)
            for value in operation[FE_BOUNDARIES]
        ]
        if not op_boundaries:
            raise _fork_execution_invalid(
                f"{where} boundaries must be non-empty"
            )
        triples = _boundary_triples(op_boundaries)
        if any(triple[2] != target for triple in triples):
            raise _fork_execution_invalid(
                f"{where} every boundary target must equal the operation target"
            )
        if len(set(triples)) != len(triples) or list(triples) != sorted(triples):
            raise _fork_execution_invalid(
                f"{where} boundaries must be unique and sorted ascending"
            )
        operations.append({
            FE_ACTION: action,
            FE_BOUNDARIES: op_boundaries,
            FE_OPERATION_ID: operation_id,
            FE_REQUIRES: dict(requires),
            FE_TARGET: target,
        })

    targets = [operation[FE_TARGET] for operation in operations]
    if len(set(targets)) != len(targets):
        raise _fork_execution_invalid(
            "plan operations must name each target domain exactly once"
        )
    if targets != sorted(targets):
        raise _fork_execution_invalid(
            "plan operations must be sorted by ascending target domain"
        )
    if {triple[2] for triple in boundary_triples} != set(targets):
        raise _fork_execution_invalid(
            "plan boundaries and operations must name the same target domains"
        )
    op_triples = sorted(
        triple
        for operation in operations
        for triple in _boundary_triples(operation[FE_BOUNDARIES])
    )
    if op_triples != sorted(boundary_triples):
        raise _fork_execution_invalid(
            "the operations must partition the plan boundaries exactly"
        )
    for operation in operations:
        expected_id = _fe_operation_id(
            plan[FE_DECISION_DIGEST], action,
            operation[FE_TARGET], operation[FE_BOUNDARIES],
        )
        if operation[FE_OPERATION_ID] != expected_id:
            raise _fork_execution_invalid(
                f"operation for {operation[FE_TARGET]!r} has a wrong "
                "operationId"
            )
        if operation[FE_REQUIRES] != _fe_requires(
            action, operation[FE_BOUNDARIES]
        ):
            raise _fork_execution_invalid(
                f"operation for {operation[FE_TARGET]!r} has a wrong "
                "precondition"
            )

    if _checkpoint_compact(plan) != raw:
        raise _fork_execution_invalid(
            "plan encoding is not the canonical compact form"
        )
    return {
        FE_ACTION: action,
        FE_BOUNDARIES: boundaries,
        FE_DECISION_DIGEST: plan[FE_DECISION_DIGEST],
        FE_EXPIRES_AT: plan[FE_EXPIRES_AT],
        FE_GENERATED_AT: plan[FE_GENERATED_AT],
        FE_OPERATIONS: operations,
        FE_POLICY_DIGEST: plan[FE_POLICY_DIGEST],
        VERSION: FORK_EXECUTION_VERSION,
    }


def _parse_fork_execution_receipt(raw: object) -> tuple[dict, str]:
    """Validate one execution receipt envelope into ``(payload, signature)``.

    A non-bytes argument or a wrong field type raises :class:`TypeError`;
    every encoding, key-set, version, digest or value-format fault
    raises :class:`ValueError`.  Confirmation turns either class into an
    ``invalid-receipt`` reason record.
    """
    if not isinstance(raw, bytes):
        raise TypeError("receipt must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise ValueError(
            "invalid fork execution receipt: must end with the closing "
            "brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid fork execution receipt: not UTF-8") from exc
    try:
        envelope = json.loads(
            text, object_pairs_hook=_reject_duplicate_fork_execution_keys
        )
    except json.JSONDecodeError as exc:
        raise ValueError("invalid fork execution receipt: not JSON") from exc
    if not isinstance(envelope, dict):
        raise TypeError("receipt must be a JSON object")
    if set(envelope.keys()) != _FE_RECEIPT_TOP_KEYS:
        raise ValueError(
            "invalid fork execution receipt: must contain exactly 'payload' "
            "and 'signature'"
        )
    signature = envelope[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("receipt signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise ValueError(
            "invalid fork execution receipt: signature must be 64 lowercase "
            "hex characters"
        )
    payload = envelope[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("receipt payload must be an object")
    if set(payload.keys()) != _FE_RECEIPT_PAYLOAD_KEYS:
        raise ValueError(
            "invalid fork execution receipt: payload must contain exactly "
            "'executionMoment', 'siteVersion', 'keyVersion', 'operationId', "
            "'planDigest', 'postDigest', 'previous', 'result' and 'site'"
        )
    result = payload[FE_RESULT]
    if not isinstance(result, str):
        raise TypeError("receipt result must be a str")
    if result not in _FE_RESULTS:
        raise ValueError(
            "invalid fork execution receipt: result must be one of "
            "'executed', 'rejected' or 'failed'"
        )
    post_digest = payload[FE_POST_DIGEST]
    if result == FE_RESULT_EXECUTED:
        if not isinstance(post_digest, str):
            raise TypeError("receipt postDigest must be a str")
        if not _is_digest(post_digest):
            raise ValueError(
                "invalid fork execution receipt: postDigest must be 64 "
                "lowercase hex characters"
            )
    elif post_digest is not None:
        raise ValueError(
            "invalid fork execution receipt: only an executed receipt may "
            "bind a postDigest"
        )
    for name in (FE_PLAN_DIGEST, FE_OPERATION_ID, FE_PREVIOUS):
        value = payload[name]
        if not isinstance(value, str):
            raise TypeError(f"receipt {name} must be a str")
        if not _is_digest(value):
            raise ValueError(
                f"invalid fork execution receipt: {name} must be 64 lowercase "
                "hex characters"
            )
    for name in (FE_SITE, FE_SITE_VERSION):
        value = payload[name]
        if not isinstance(value, str):
            raise TypeError(f"receipt {name} must be a str")
        if value == "":
            raise ValueError(
                f"invalid fork execution receipt: {name} must be non-empty"
            )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("receipt keyVersion must be an int")
    if key_version <= 0:
        raise ValueError(
            "invalid fork execution receipt: keyVersion must be positive"
        )
    moment = payload[FE_EXECUTION_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("receipt executionMoment must be an int")
    if moment < 0:
        raise ValueError(
            "invalid fork execution receipt: executionMoment must be >= 0"
        )
    if _checkpoint_compact(envelope) != raw:
        raise ValueError(
            "invalid fork execution receipt: encoding is not the canonical "
            "compact form"
        )
    return payload, signature


def _fe_reason_row(
    digest: str,
    site: str | None,
    operation_id: str | None,
    result: str,
    post_digest: str | None,
    reason: str | None,
) -> dict:
    """One per-receipt reason record with the fixed bound key set."""
    return {
        CP_DIGEST: digest,
        FE_OPERATION_ID: operation_id,
        FE_POST_DIGEST: post_digest,
        FE_RESULT: result,
        ADJ_REASON: reason,
        FE_SITE: site,
    }


def _fe_key_usable_at(entry: dict, moment: int) -> bool:
    """Whether a validated keyring entry is usable at one moment."""
    return (
        not entry[REVOKED]
        and entry[NOT_BEFORE] <= moment <= entry[NOT_AFTER]
    )


def _fe_select_entry(
    keyring: dict[str, list[dict]], site: str, key_version: int
) -> dict | None:
    """Pick the exact site/version entry with no fallback."""
    for candidate in keyring.get(site, ()):
        if candidate[VERSION] == key_version:
            return candidate
    return None


def _tally_fork_execution_receipts(
    plan: dict,
    receipt_bytes: list[bytes],
    keyring: dict[str, list[dict]],
    aggregate_moment: int,
) -> tuple[list[str], list[dict], list[dict], str]:
    """Authenticate and tally execution receipts against one plan.

    Returns ``(receipt_digests, reason_rows, operation_results, status)``
    with both lists in strict input order.  Each receipt is handled in
    isolation: a structurally illegal receipt only records
    ``invalid-receipt`` and a credential or signature failure at the
    execution or aggregation moment only rejects that receipt with
    ``bad-signature`` -- confirmation never raises for one bad receipt.

    The same receipt digest counts once and extra copies are
    ``duplicate``; different valid results or different post-state
    digests for one operation are a ``contradiction``.  Contradictions,
    explicit site rejections, missing/failed operations and full success
    yield ``conflicted``, ``rejected``, ``partial`` and ``confirmed``.
    """
    operations_by_id = {
        operation[FE_OPERATION_ID]: operation
        for operation in plan[FE_OPERATIONS]
    }
    plan_digest = hashlib.sha256(_checkpoint_compact(plan)).hexdigest()

    receipt_digests: list[str] = []
    rows: list[dict] = []
    seen_digests: set[str] = set()
    last_site_moment: dict[str, int] = {}
    counted_by_op: dict[str, list[dict]] = {}

    for raw in receipt_bytes:
        digest = hashlib.sha256(raw).hexdigest()
        receipt_digests.append(digest)
        try:
            payload, signature = _parse_fork_execution_receipt(raw)
        except (TypeError, ValueError):
            rows.append(_fe_reason_row(
                digest, None, None, FE_RESULT_FAILED, None,
                FE_REASON_INVALID_RECEIPT,
            ))
            continue

        def reject(reason: str) -> None:
            rows.append(_fe_reason_row(
                digest,
                payload[FE_SITE],
                payload[FE_OPERATION_ID],
                payload[FE_RESULT],
                payload.get(FE_POST_DIGEST),
                reason,
            ))

        if payload[FE_PLAN_DIGEST] != plan_digest:
            reject(FE_REASON_DECISION_REPLACED)
            continue
        operation = operations_by_id.get(payload[FE_OPERATION_ID])
        if operation is None or payload[FE_SITE] != operation[FE_TARGET]:
            reject(FE_REASON_UNKNOWN_OPERATION)
            continue
        execution_moment = payload[FE_EXECUTION_MOMENT]
        if not (
            plan[FE_GENERATED_AT] <= execution_moment <= plan[FE_EXPIRES_AT]
        ):
            reject(FE_REASON_OUTSIDE_VALIDITY)
            continue

        entry = _fe_select_entry(
            keyring, payload[FE_SITE], payload[KEY_VERSION]
        )
        signature_ok = False
        if entry is not None:
            expected_signature = hmac.new(
                bytes.fromhex(entry[SECRET]),
                _checkpoint_compact(payload),
                hashlib.sha256,
            ).hexdigest()
            signature_ok = hmac.compare_digest(expected_signature, signature)
        if (
            entry is None
            or not _fe_key_usable_at(entry, execution_moment)
            or not _fe_key_usable_at(entry, aggregate_moment)
            or not signature_ok
        ):
            reject(FE_REASON_BAD_CREDENTIAL)
            continue

        if payload[FE_PREVIOUS] != _fe_previous_digest(operation):
            reject(FE_REASON_PREVIOUS_MISMATCH)
            continue
        # The same bytes are one receipt: duplicates are recognized
        # before same-site sequencing is enforced.
        if digest in seen_digests:
            rows.append(_fe_reason_row(
                digest,
                payload[FE_SITE],
                payload[FE_OPERATION_ID],
                payload[FE_RESULT],
                payload.get(FE_POST_DIGEST),
                FE_REASON_DUPLICATE,
            ))
            continue
        previous_moment = last_site_moment.get(payload[FE_SITE])
        if (
            previous_moment is not None
            and execution_moment <= previous_moment
        ):
            reject(FE_REASON_OUT_OF_ORDER)
            continue

        seen_digests.add(digest)
        last_site_moment[payload[FE_SITE]] = execution_moment
        rows.append(_fe_reason_row(
            digest,
            payload[FE_SITE],
            payload[FE_OPERATION_ID],
            payload[FE_RESULT],
            payload.get(FE_POST_DIGEST),
            None,
        ))
        counted_by_op.setdefault(payload[FE_OPERATION_ID], []).append(
            rows[-1]
        )

    # Mark contradictions: one operation with distinct valid results, or
    # distinct post-state digests among its executed receipts.
    contradicted_ops: set[str] = set()
    for operation_id, op_rows in counted_by_op.items():
        outcomes = {row[FE_RESULT] for row in op_rows}
        posts = {
            row[FE_POST_DIGEST]
            for row in op_rows
            if row[FE_RESULT] == FE_RESULT_EXECUTED
        }
        if len(outcomes) > 1 or len(posts) > 1:
            contradicted_ops.add(operation_id)
            for row in op_rows:
                row[ADJ_REASON] = FE_REASON_CONTRADICTION

    operation_results: list[dict] = []
    any_rejected = False
    any_failed = False
    for operation in plan[FE_OPERATIONS]:
        op_rows = counted_by_op.get(operation[FE_OPERATION_ID], [])
        if operation[FE_OPERATION_ID] in contradicted_ops:
            final_result = FE_RESULT_FAILED
            any_failed = True
        else:
            outcomes = {row[FE_RESULT] for row in op_rows}
            if FE_RESULT_EXECUTED in outcomes:
                final_result = FE_RESULT_EXECUTED
            elif FE_RESULT_REJECTED in outcomes:
                final_result = FE_RESULT_REJECTED
                any_rejected = True
            else:
                final_result = FE_RESULT_FAILED
                any_failed = True
        operation_results.append({
            FE_OPERATION_ID: operation[FE_OPERATION_ID],
            FE_RESULT: final_result,
            FE_TARGET: operation[FE_TARGET],
        })

    if contradicted_ops:
        status = FE_STATUS_CONFLICTED
    elif any_rejected:
        status = FE_STATUS_REJECTED
    elif any_failed:
        status = FE_STATUS_PARTIAL
    else:
        status = FE_STATUS_CONFIRMED
    return receipt_digests, rows, operation_results, status


def _reconcile_fork_execution_rows(
    plan: dict, receipt_digests: list[str], rows: list[dict]
) -> tuple[list[dict], str]:
    """Re-derive operation conclusions and status from bound reason rows.

    This is the verification-side tally: the receipt signatures were
    checked at confirmation time, so the packet only binds their
    digests, original order and per-receipt reason records.  The
    duplicate/contradiction markings, the per-operation conclusions and
    the overall status must all regenerate exactly from those records.
    """
    if len(rows) != len(receipt_digests):
        raise _fork_execution_invalid(
            "one reason record must be bound per receipt"
        )
    for position, (row, digest) in enumerate(zip(rows, receipt_digests)):
        if row[CP_DIGEST] != digest:
            raise _fork_execution_invalid(
                f"reason record {position} must follow the receipts in order"
            )

    operations_by_id = {
        operation[FE_OPERATION_ID]: operation
        for operation in plan[FE_OPERATIONS]
    }
    seen_digests: set[str] = set()
    counted_digest_identity: dict[str, tuple[str, str]] = {}
    counted_by_op: dict[str, list[dict]] = {}

    def require_known(row: dict, position: int) -> dict:
        operation = operations_by_id.get(row[FE_OPERATION_ID])
        if operation is None or row[FE_SITE] != operation[FE_TARGET]:
            raise _fork_execution_invalid(
                f"reason record {position}: the bound site/operation pair is "
                "not part of the plan"
            )
        return operation

    for position, row in enumerate(rows):
        reason = row[ADJ_REASON]
        op_id = row[FE_OPERATION_ID]
        if reason == FE_REASON_INVALID_RECEIPT:
            if row[FE_SITE] is not None or op_id is not None:
                raise _fork_execution_invalid(
                    f"reason record {position}: an invalid receipt binds no "
                    "site or operation"
                )
            if row[FE_RESULT] != FE_RESULT_FAILED or row[FE_POST_DIGEST] is not None:
                raise _fork_execution_invalid(
                    f"reason record {position}: an invalid receipt is a "
                    "failure with no post-state digest"
                )
            continue
        if row[FE_SITE] is None or not isinstance(row[FE_SITE], str):
            raise _fork_execution_invalid(
                f"reason record {position} must bind its site"
            )
        if not isinstance(op_id, str) or not _is_digest(op_id):
            raise _fork_execution_invalid(
                f"reason record {position} must bind its operationId"
            )
        if row[FE_RESULT] not in _FE_RESULTS:
            raise _fork_execution_invalid(
                f"reason record {position} has an unknown result"
            )
        if row[FE_RESULT] == FE_RESULT_EXECUTED:
            if not _is_digest(row[FE_POST_DIGEST]):
                raise _fork_execution_invalid(
                    f"reason record {position}: an executed receipt must bind "
                    "a post-state digest"
                )
        elif row[FE_POST_DIGEST] is not None:
            raise _fork_execution_invalid(
                f"reason record {position}: only an executed receipt binds a "
                "post-state digest"
            )
        digest = row[CP_DIGEST]
        # A decision-replaced receipt names another plan, so neither its
        # site nor its operation can be checked against this plan.
        if reason == FE_REASON_DECISION_REPLACED:
            continue
        if reason == FE_REASON_UNKNOWN_OPERATION:
            operation = operations_by_id.get(op_id)
            if operation is not None and row[FE_SITE] == operation[FE_TARGET]:
                raise _fork_execution_invalid(
                    f"reason record {position}: the site/operation pair is a "
                    "planned operation and cannot be marked unknown-operation"
                )
            continue
        # Every remaining fixed rejection only happens for a receipt that
        # already named a planned operation at its own target site.
        if reason in (
            FE_REASON_OUTSIDE_VALIDITY,
            FE_REASON_PREVIOUS_MISMATCH,
            FE_REASON_OUT_OF_ORDER,
            FE_REASON_BAD_CREDENTIAL,
        ):
            require_known(row, position)
            continue
        if reason == FE_REASON_DUPLICATE:
            identity = counted_digest_identity.get(digest)
            if identity is None:
                raise _fork_execution_invalid(
                    f"reason record {position} is marked duplicate without a "
                    "first counted copy"
                )
            if identity != (op_id, row[FE_SITE]):
                raise _fork_execution_invalid(
                    f"reason record {position}: a duplicate must repeat the "
                    "same operation and site as its first copy"
                )
            continue
        if reason is not None and reason != FE_REASON_CONTRADICTION:
            raise _fork_execution_invalid(
                f"reason record {position} carries an unknown reason"
            )
        if digest in seen_digests:
            raise _fork_execution_invalid(
                f"reason record {position}: a repeated receipt must be marked "
                "duplicate"
            )
        require_known(row, position)
        seen_digests.add(digest)
        counted_digest_identity[digest] = (op_id, row[FE_SITE])
        counted_by_op.setdefault(op_id, []).append(row)

    contradicted_ops: set[str] = set()
    for operation_id, op_rows in counted_by_op.items():
        outcomes = {row[FE_RESULT] for row in op_rows}
        posts = {
            row[FE_POST_DIGEST]
            for row in op_rows
            if row[FE_RESULT] == FE_RESULT_EXECUTED
        }
        is_contradiction = len(outcomes) > 1 or len(posts) > 1
        if is_contradiction:
            contradicted_ops.add(operation_id)
            for row in op_rows:
                if row[ADJ_REASON] != FE_REASON_CONTRADICTION:
                    raise _fork_execution_invalid(
                        "a contradicting receipt must be marked contradiction"
                    )
        else:
            for row in op_rows:
                if row[ADJ_REASON] is not None:
                    raise _fork_execution_invalid(
                        "a counted receipt without a contradiction must carry "
                        "no rejection reason"
                    )

    operation_results: list[dict] = []
    any_rejected = False
    any_failed = False
    for operation in plan[FE_OPERATIONS]:
        op_rows = counted_by_op.get(operation[FE_OPERATION_ID], [])
        if operation[FE_OPERATION_ID] in contradicted_ops:
            final_result = FE_RESULT_FAILED
            any_failed = True
        else:
            outcomes = {row[FE_RESULT] for row in op_rows}
            if FE_RESULT_EXECUTED in outcomes:
                final_result = FE_RESULT_EXECUTED
            elif FE_RESULT_REJECTED in outcomes:
                final_result = FE_RESULT_REJECTED
                any_rejected = True
            else:
                final_result = FE_RESULT_FAILED
                any_failed = True
        operation_results.append({
            FE_OPERATION_ID: operation[FE_OPERATION_ID],
            FE_RESULT: final_result,
            FE_TARGET: operation[FE_TARGET],
        })

    if contradicted_ops:
        status = FE_STATUS_CONFLICTED
    elif any_rejected:
        status = FE_STATUS_REJECTED
    elif any_failed:
        status = FE_STATUS_PARTIAL
    else:
        status = FE_STATUS_CONFIRMED
    return operation_results, status


def _validated_fork_receipts(receipts: object) -> list[bytes]:
    """Validate the public receipt container before any tally runs."""
    if not isinstance(receipts, list):
        raise TypeError("receipts must be a list")
    if not receipts:
        raise ValueError("receipts must be a non-empty list")
    validated: list[bytes] = []
    for position, receipt in enumerate(receipts):
        if not isinstance(receipt, bytes):
            raise TypeError(f"receipt {position} must be bytes")
        if not receipt:
            raise ValueError(f"receipt {position} must be non-empty")
        validated.append(receipt)
    return validated


def confirm_fork_execution(
    plan: bytes,
    decision: bytes,
    policy: dict,
    receipts: list,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Aggregate per-site execution receipts into one signed confirmation.

    ``plan`` is the canonical packet :func:`plan_fork_execution` produced
    and ``decision`` the original accepted fork decision bytes; both
    bindings must still match -- a plan bound to another decision, a
    plan/policy mismatch or a plan that does not regenerate from the
    decision and policy raises :class:`InvalidForkExecutionError`.
    ``receipts`` is a non-empty list of canonical receipt envelopes in
    their collection order; ``keyring`` follows the
    :func:`apply_signed_remote` rules; ``moment`` is the aggregation
    moment and ``issuer``/``version`` name the aggregator signing key.

    Each receipt binds the plan digest, its operation id, the executing
    site and key version, the site version, the execution moment, the
    previous-state digest and one result -- ``executed``, ``rejected``
    or ``failed`` -- with an executed receipt additionally binding the
    post-state digest.  The receipt site must equal the operation target
    and its key is selected by exact site and version.  A receipt for a
    replaced verdict, an unknown operation, a moment outside the plan's
    validity, a previous-digest mismatch or an out-of-order same-site
    receipt rejects only that receipt with one fixed reason
    (``decision-replaced``, ``unknown-operation``, ``outside-validity``,
    ``previous-mismatch`` or ``out-of-order``); credentials unknown,
    revoked or time-invalid at the execution or aggregation moment, or
    a wrong signature, reject only that receipt as ``bad-signature`` and
    a structurally illegal receipt only records ``invalid-receipt``.
    The same receipt digest counts once and extra copies are
    ``duplicate``; different valid results or post-state digests for one
    operation are a ``contradiction``.

    Contradictions, explicit site rejections, missing or failed
    operations and full success yield the overall statuses
    ``conflicted``, ``rejected``, ``partial`` and ``confirmed`` in that
    precedence.  The result is one canonical compact UTF-8 JSON object
    with recursively sorted keys, non-ASCII preserved and no trailing
    byte, carrying exactly ``payload`` and ``signature``; the payload
    binds exactly ``aggregatedAt``, ``issuer``, ``keyVersion``, the
    complete ``plan``, the receipt digests in their original order, the
    per-item reason records, the per-operation conclusions, the overall
    ``status`` and ``version``.  The signature is the lowercase hex
    HMAC-SHA256 of the canonical compact payload bytes under the key
    bound to the exact issuer and version with no fallback; unknown,
    revoked, not-yet-valid or expired aggregator credentials raise
    :class:`AuthenticationError`.

    A parameter, container or public field type fault raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    empty/null value or an illegal moment raises :class:`ValueError`; an
    illegal plan, packet encoding, digest, ordering or binding raises
    :class:`InvalidForkExecutionError` (a :class:`ValueError` subclass).
    No file is read or written and no input is modified.
    """
    if not isinstance(plan, bytes):
        raise TypeError("plan must be bytes")
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_receipts = _validated_fork_receipts(receipts)
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    aggregate_moment = _fe_moment(moment, "moment")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")

    parsed_plan = _parse_fork_execution_plan(plan)
    if parsed_plan[FE_DECISION_DIGEST] != hashlib.sha256(decision).hexdigest():
        raise _fork_execution_invalid(
            "plan is bound to a different fork decision"
        )
    policy_digest = hashlib.sha256(
        _fork_policy_bytes(validated_policy)
    ).hexdigest()
    if parsed_plan[FE_POLICY_DIGEST] != policy_digest:
        raise _fork_execution_invalid(
            "plan policy digest does not match the policy"
        )
    verified_decision = _verify_fork_decision(
        decision, validated_policy, validated_keyring, aggregate_moment
    )
    if verified_decision[STATUS] != FD_STATUS_ACCEPTED:
        raise _fork_execution_invalid(
            "the bound fork decision is not accepted"
        )
    regenerated = _fe_build_plan(
        verified_decision[FD_ACTION],
        verified_decision[FD_BOUNDARIES],
        verified_decision[FD_TARGETS],
        verified_decision[FORK_PROOF_DIGEST],
        policy_digest,
        parsed_plan[FE_GENERATED_AT],
        parsed_plan[FE_EXPIRES_AT],
    )
    if parsed_plan != regenerated:
        raise _fork_execution_invalid(
            "the plan does not regenerate from the decision and policy"
        )
    if aggregate_moment < parsed_plan[FE_GENERATED_AT]:
        raise ValueError(
            "aggregation moment must not precede the plan generation moment"
        )

    receipt_digests, rows, operation_results, status = (
        _tally_fork_execution_receipts(
            parsed_plan, validated_receipts, validated_keyring,
            aggregate_moment,
        )
    )

    signing_entry = _usable_checkpoint_key(
        validated_keyring, issuer, version, aggregate_moment
    )
    payload = {
        FE_AGGREGATED_AT: aggregate_moment,
        KEY_VERSION: version,
        FE_ISSUER: issuer,
        FE_PLAN: parsed_plan,
        FE_RECEIPTS: receipt_digests,
        FE_REASONS: rows,
        FE_RESULTS: operation_results,
        STATUS: status,
        VERSION: FORK_EXECUTION_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact(
        {TICKET_PAYLOAD: payload, SIGNATURE: signature}
    )


def _parse_fork_confirmation(raw: object) -> tuple[dict, str]:
    """Validate a confirmation packet structurally into payload/signature.

    A non-bytes argument or a wrong public field type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, digest, ordering or binding fault raises
    :class:`InvalidForkExecutionError`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("confirmation must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _fork_execution_invalid(
            "confirmation must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fork_execution_invalid(
            "confirmation is not valid UTF-8"
        ) from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_fork_execution_keys
        )
    except json.JSONDecodeError as exc:
        raise _fork_execution_invalid(
            "confirmation is not valid JSON"
        ) from exc
    if not isinstance(data, dict):
        raise TypeError("confirmation must be a JSON object")
    if set(data.keys()) != _FE_RECEIPT_TOP_KEYS:
        raise _fork_execution_invalid(
            "confirmation must contain exactly 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("confirmation signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _fork_execution_invalid(
            "confirmation signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("confirmation payload must be an object")
    if set(payload.keys()) != _FE_CONFIRMATION_PAYLOAD_KEYS:
        raise _fork_execution_invalid(
            "confirmation payload must contain exactly the keys "
            "'aggregatedAt', 'issuer', 'keyVersion', 'plan', 'receipts', "
            "'reasons', 'results', 'status' and 'version'"
        )
    if not isinstance(payload[FE_ISSUER], str):
        raise TypeError("confirmation issuer must be a str")
    if payload[FE_ISSUER] == "":
        raise _fork_execution_invalid(
            "confirmation issuer must be non-empty"
        )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("confirmation keyVersion must be an int")
    if key_version <= 0:
        raise _fork_execution_invalid(
            "confirmation keyVersion must be positive"
        )
    aggregated_at = payload[FE_AGGREGATED_AT]
    if isinstance(aggregated_at, bool) or not isinstance(aggregated_at, int):
        raise TypeError("confirmation aggregatedAt must be an int")
    if aggregated_at < 0:
        raise _fork_execution_invalid("confirmation aggregatedAt must be >= 0")
    status = payload[STATUS]
    if not isinstance(status, str):
        raise TypeError("confirmation status must be a str")
    if status not in _FE_STATUSES:
        raise _fork_execution_invalid("confirmation status is not known")
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("confirmation version must be an int")
    if version != FORK_EXECUTION_VERSION:
        raise _fork_execution_invalid(
            "confirmation version must be the integer 1"
        )

    bound_plan = payload[FE_PLAN]
    if not isinstance(bound_plan, dict):
        raise TypeError("confirmation plan must be an object")
    plan_bytes = _checkpoint_compact(bound_plan)
    parsed_plan = _parse_fork_execution_plan(plan_bytes)

    receipts = payload[FE_RECEIPTS]
    if not isinstance(receipts, list):
        raise TypeError("confirmation receipts must be a list")
    if not receipts:
        raise _fork_execution_invalid(
            "confirmation receipts must be non-empty"
        )
    for position, digest in enumerate(receipts):
        if not isinstance(digest, str):
            raise TypeError(f"confirmation receipt {position} digest must str")
        if not _is_digest(digest):
            raise _fork_execution_invalid(
                f"confirmation receipt {position} digest must be 64 lowercase "
                "hex characters"
            )

    reasons = payload[FE_REASONS]
    if not isinstance(reasons, list):
        raise TypeError("confirmation reasons must be a list")
    for position, row in enumerate(reasons):
        if not isinstance(row, dict):
            raise TypeError(f"confirmation reason {position} must be an object")
        if set(row.keys()) != _FE_REASON_ROW_KEYS:
            raise _fork_execution_invalid(
                f"confirmation reason {position} must contain exactly "
                "'digest', 'operationId', 'postDigest', 'result', 'reason' "
                "and 'site'"
            )
        if not isinstance(row[CP_DIGEST], str) or not _is_digest(row[CP_DIGEST]):
            if not isinstance(row[CP_DIGEST], str):
                raise TypeError(
                    f"confirmation reason {position} digest must be a str"
                )
            raise _fork_execution_invalid(
                f"confirmation reason {position} digest must be 64 lowercase "
                "hex characters"
            )
        site = row[FE_SITE]
        if site is not None and not isinstance(site, str):
            raise TypeError(f"confirmation reason {position} site must str/null")
        operation_id = row[FE_OPERATION_ID]
        if operation_id is not None:
            if not isinstance(operation_id, str):
                raise TypeError(
                    f"confirmation reason {position} operationId must str/null"
                )
            if not _is_digest(operation_id):
                raise _fork_execution_invalid(
                    f"confirmation reason {position} operationId must be 64 "
                    "lowercase hex characters"
                )
        post_digest = row[FE_POST_DIGEST]
        if post_digest is not None:
            if not isinstance(post_digest, str):
                raise TypeError(
                    f"confirmation reason {position} postDigest must str/null"
                )
            if not _is_digest(post_digest):
                raise _fork_execution_invalid(
                    f"confirmation reason {position} postDigest must be 64 "
                    "lowercase hex characters"
                )
        if not isinstance(row[FE_RESULT], str):
            raise TypeError(f"confirmation reason {position} result must str")
        if row[FE_RESULT] not in _FE_RESULTS:
            raise _fork_execution_invalid(
                f"confirmation reason {position} result is not known"
            )
        reason = row[ADJ_REASON]
        if reason is not None:
            if not isinstance(reason, str):
                raise TypeError(
                    f"confirmation reason {position} reason must be str/null"
                )
            if reason not in _FE_BOUND_REASONS:
                raise _fork_execution_invalid(
                    f"confirmation reason {position} reason is not known"
                )

    results = payload[FE_RESULTS]
    if not isinstance(results, list):
        raise TypeError("confirmation results must be a list")
    expected_ids = [
        operation[FE_OPERATION_ID]
        for operation in parsed_plan[FE_OPERATIONS]
    ]
    if [row[FE_OPERATION_ID] for row in results] != expected_ids:
        raise _fork_execution_invalid(
            "confirmation results must follow the plan operations in order"
        )
    for position, row in enumerate(results):
        if not isinstance(row, dict):
            raise TypeError(f"confirmation result {position} must be an object")
        if set(row.keys()) != _FE_OP_RESULT_KEYS:
            raise _fork_execution_invalid(
                f"confirmation result {position} must contain exactly "
                "'operationId', 'result' and 'target'"
            )
        if not isinstance(row[FE_OPERATION_ID], str) or not _is_digest(
            row[FE_OPERATION_ID]
        ):
            if not isinstance(row[FE_OPERATION_ID], str):
                raise TypeError(
                    f"confirmation result {position} operationId must str"
                )
            raise _fork_execution_invalid(
                f"confirmation result {position} operationId must be 64 "
                "lowercase hex characters"
            )
        if not isinstance(row[FE_TARGET], str) or row[FE_TARGET] == "":
            if not isinstance(row[FE_TARGET], str):
                raise TypeError(
                    f"confirmation result {position} target must be a str"
                )
            raise _fork_execution_invalid(
                f"confirmation result {position} target must be non-empty"
            )
        if not isinstance(row[FE_RESULT], str):
            raise TypeError(
                f"confirmation result {position} result must be a str"
            )
        if row[FE_RESULT] not in _FE_RESULTS:
            raise _fork_execution_invalid(
                f"confirmation result {position} result is not known"
            )

    if _checkpoint_compact(data) != raw:
        raise _fork_execution_invalid(
            "confirmation encoding is not the canonical compact form"
        )
    return payload, signature


def _verify_fork_confirmation(
    confirmation: bytes,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    decision: bytes,
    moment: int,
) -> dict:
    """Verify one confirmation against already-validated shared materials."""
    payload, signature = _parse_fork_confirmation(confirmation)
    parsed_plan = _parse_fork_execution_plan(
        _checkpoint_compact(payload[FE_PLAN])
    )

    if parsed_plan[FE_DECISION_DIGEST] != hashlib.sha256(decision).hexdigest():
        raise _fork_execution_invalid(
            "the bound plan names a different fork decision"
        )
    policy_digest = hashlib.sha256(
        _fork_policy_bytes(validated_policy)
    ).hexdigest()
    if parsed_plan[FE_POLICY_DIGEST] != policy_digest:
        raise _fork_execution_invalid(
            "plan policy digest does not match the policy"
        )

    verified_decision = _verify_fork_decision(
        decision, validated_policy, validated_keyring, moment
    )
    if verified_decision[STATUS] != FD_STATUS_ACCEPTED:
        raise _fork_execution_invalid(
            "the bound fork decision is no longer accepted"
        )
    regenerated = _fe_build_plan(
        verified_decision[FD_ACTION],
        verified_decision[FD_BOUNDARIES],
        verified_decision[FD_TARGETS],
        verified_decision[FORK_PROOF_DIGEST],
        policy_digest,
        parsed_plan[FE_GENERATED_AT],
        parsed_plan[FE_EXPIRES_AT],
    )
    if parsed_plan != regenerated:
        raise _fork_execution_invalid(
            "the bound plan does not regenerate from the decision and policy"
        )

    aggregate_moment = payload[FE_AGGREGATED_AT]
    if aggregate_moment > moment:
        raise _fork_execution_invalid(
            "aggregation moment must not be later than the verification moment"
        )
    if aggregate_moment < parsed_plan[FE_GENERATED_AT]:
        raise _fork_execution_invalid(
            "aggregation moment must not precede the plan generation moment"
        )

    derived_results, derived_status = _reconcile_fork_execution_rows(
        parsed_plan, payload[FE_RECEIPTS], payload[FE_REASONS]
    )
    if payload[FE_RESULTS] != derived_results:
        raise _fork_execution_invalid(
            "the bound operation results do not match the re-tallied receipts"
        )
    if payload[STATUS] != derived_status:
        raise _fork_execution_invalid(
            "the bound overall status does not match the re-tallied receipts"
        )

    signing_entry = _usable_checkpoint_key(
        validated_keyring,
        payload[FE_ISSUER],
        payload[KEY_VERSION],
        moment,
    )
    expected_signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError(
            "fork execution confirmation signature does not match"
        )

    plan_bytes = _checkpoint_compact(parsed_plan)
    return {
        key: value
        for key, value in (
            (FE_AGGREGATED_AT, aggregate_moment),
            (FE_CONFIRMATION_DIGEST,
             hashlib.sha256(confirmation).hexdigest()),
            (FE_DECISION_DIGEST, parsed_plan[FE_DECISION_DIGEST]),
            (FE_EXPIRES_AT, parsed_plan[FE_EXPIRES_AT]),
            (FE_GENERATED_AT, parsed_plan[FE_GENERATED_AT]),
            (FE_ISSUER, payload[FE_ISSUER]),
            (KEY_VERSION, payload[KEY_VERSION]),
            (FE_OPERATIONS, copy.deepcopy(parsed_plan[FE_OPERATIONS])),
            (FE_PLAN_DIGEST, hashlib.sha256(plan_bytes).hexdigest()),
            (FE_POLICY_DIGEST, policy_digest),
            (FE_RECEIPTS, list(payload[FE_RECEIPTS])),
            (FE_REASONS, copy.deepcopy(payload[FE_REASONS])),
            (FE_RESULTS, copy.deepcopy(derived_results)),
            (STATUS, derived_status),
            (VERSION, FORK_EXECUTION_VERSION),
        )
    }


def verify_fork_confirmation(
    confirmation: bytes,
    decision: bytes,
    policy: dict,
    keyring: dict,
    moment: int,
) -> dict:
    """Verify one signed fork execution confirmation entirely offline.

    Only the confirmation packet, the original ``decision`` bytes, the
    expected ``policy``, the current ``keyring`` and the verification
    ``moment`` are consulted -- no file is read or written and no
    argument is modified.  Verification re-checks every binding: the
    canonical packet encoding and key sets, the plan's regeneration from
    the decision and policy (digests, action, boundaries, operations,
    preconditions, window), the original-order receipt digests, the
    per-item reason records, the per-operation conclusions and the
    overall status, the last two re-derived purely from the bound
    receipts and reasons.  The HMAC-SHA256 is checked against the key
    the current keyring binds to the payload's exact aggregator issuer
    and version, usable at the verification moment, so a later
    revocation or expiry rejects the packet with no fallback.

    On success a fresh mapping is returned with the fixed keys
    ``aggregatedAt``, ``confirmationDigest``, ``decisionDigest``,
    ``expiresAt``, ``generatedAt``, ``issuer``, ``keyVersion``,
    ``operations``, ``planDigest``, ``policyDigest``, ``receipts``,
    ``reasons``, ``results``, ``status`` and ``version`` (the integer
    1).  A non-bytes argument or a wrong public field type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    illegal policy, keyring or moment raises :class:`ValueError`; an
    illegal encoding, digest, order or binding raises
    :class:`InvalidForkExecutionError` (a :class:`ValueError` subclass);
    unknown, revoked, not-yet-valid or expired credentials or a wrong
    signature raise :class:`AuthenticationError`.
    """
    if not isinstance(confirmation, bytes):
        raise TypeError("confirmation must be bytes")
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    return _verify_fork_confirmation(
        confirmation, validated_policy, validated_keyring, decision,
        verify_moment,
    )


def _validated_fork_confirmation_items(items: object) -> list[dict]:
    """Validate the confirmation batch before any packet is verified."""
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
        if set(item.keys()) != _FE_BATCH_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'confirmation' and 'id'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        confirmation = item["confirmation"]
        if not isinstance(confirmation, bytes):
            raise TypeError(f"{where} confirmation must be bytes")
        validated.append({ID: item_id, "confirmation": confirmation})
    return validated


def _fork_confirmation_item_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One confirmation batch report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def _verify_fork_confirmation_item(
    item: dict,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    decision: bytes,
    moment: int,
) -> dict:
    """Verify one confirmation in isolation and report its outcome."""
    item_id = item[ID]
    try:
        result = _verify_fork_confirmation(
            item["confirmation"], validated_policy, validated_keyring,
            decision, moment,
        )
    except AuthenticationError as exc:
        return _fork_confirmation_item_report(
            item_id, _FE_VERIFY_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidForkExecutionError, TypeError) as exc:
        # A TypeError here can only come from a wrong JSON field type
        # inside the packet bytes; the public argument types were all
        # validated before the batch ran.
        return _fork_confirmation_item_report(
            item_id, _FE_VERIFY_INVALID, str(exc), None
        )
    return _fork_confirmation_item_report(
        item_id, _FE_VERIFY_VERIFIED, None, result
    )


def verify_fork_confirmations(
    items: list, decision: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a whole batch of fork execution confirmations entirely offline.

    ``items`` is a non-empty list; each item contains exactly a
    non-empty, batch-unique ``id`` and ``confirmation`` bytes.  The
    batch and the shared ``decision``, ``policy``, ``keyring`` and
    ``moment`` are validated in full before any confirmation is
    verified, so only batch-level faults raise (container, element or
    field type faults :class:`TypeError`; an empty list, an empty or
    duplicate id or a wrong item key set :class:`ValueError`).  Each
    confirmation is then handled independently, in strict input order,
    through the exact :func:`verify_fork_confirmation` rules: unknown,
    revoked, not-yet-valid or expired credentials or a wrong signature
    make it ``unauthenticated``; every encoding, digest, ordering or
    binding fault makes it ``invalid``; a passing packet is
    ``verified``.  One packet's failure never stops a later one.

    The top-level result is a fresh dict with the fixed keys ``items``
    and ``version`` (the integer 1); each report carries, in this key
    order, ``error`` (null exactly when verified), ``id``, ``result`` (a
    fresh independent copy of the single-packet result when verified,
    null otherwise) and ``status``.  Repeated calls return equal but
    mutually independent results.
    """
    validated_items = _validated_fork_confirmation_items(items)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    return {
        ITEMS: [
            _verify_fork_confirmation_item(
                item, validated_policy, validated_keyring, decision,
                verify_moment,
            )
            for item in validated_items
        ],
        VERSION: FORK_EXECUTION_VERSION,
    }


# --- Multi-round fork convergence certificates --------------------------------

FORK_CONVERGENCE_VERSION = 1

FC_CERTIFIED_AT = "certifiedAt"
FC_CERTIFICATE_DIGEST = "certificateDigest"
FC_CERTIFICATE = "certificate"
FC_ROUNDS = "rounds"
FC_SEQ = "seq"
FC_CONFIRMATION = "confirmation"
FC_SETTLED_ROUND = "settledRound"
FC_RESULT_CONFLICTED = ADJ_STATUS_CONFLICTED

_FC_ROUND_KEYS = frozenset((FC_CONFIRMATION, FE_PREVIOUS, FC_SEQ))
_FC_RESULT_ROW_KEYS = frozenset((
    FE_OPERATION_ID,
    FE_POST_DIGEST,
    FE_RESULT,
    FC_SETTLED_ROUND,
    FE_TARGET,
))
_FC_RESULT_VALUES = _FE_RESULTS | frozenset((FC_RESULT_CONFLICTED,))
_FC_PAYLOAD_KEYS = frozenset((
    FC_CERTIFIED_AT,
    FE_DECISION_DIGEST,
    FE_ISSUER,
    KEY_VERSION,
    FE_PLAN_DIGEST,
    FE_RESULTS,
    FC_ROUNDS,
    STATUS,
    VERSION,
))
_FC_BATCH_ITEM_KEYS = frozenset((FC_CERTIFICATE, ID, FC_ROUNDS))
_FC_VERIFY_VERIFIED = "verified"
_FC_VERIFY_INVALID = "invalid"
_FC_VERIFY_UNAUTHENTICATED = "unauthenticated"
_FC_VERIFY_RESULT_KEYS = (
    FC_CERTIFIED_AT,
    FC_CERTIFICATE_DIGEST,
    FE_DECISION_DIGEST,
    FE_ISSUER,
    KEY_VERSION,
    FE_PLAN_DIGEST,
    FE_RESULTS,
    FC_ROUNDS,
    STATUS,
    VERSION,
)


class InvalidForkConvergenceError(ValueError):
    """A fork convergence certificate or round chain breaks its contract."""


def _fork_convergence_invalid(message: str) -> InvalidForkConvergenceError:
    return InvalidForkConvergenceError(f"invalid fork convergence: {message}")


def _reject_duplicate_fork_convergence_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate certificate keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _fork_convergence_invalid(
                f"duplicate key {key!r} in object"
            )
        result[key] = value
    return result


def _validated_convergence_round_shapes(rounds: object) -> list[dict]:
    """Validate the public round-chain shape before any chain or proof work.

    Each round carries exactly ``seq``, ``previous`` and
    ``confirmation``; only the container and public field contract is
    checked here (the sequence numbering and previous-confirmation
    links are the chain contract of
    :func:`_validated_convergence_rounds`).  Container and field type
    faults raise :class:`TypeError` (a :class:`bool` never poses as an
    int) and an empty list, a wrong key set or an empty confirmation
    raises :class:`ValueError`.
    """
    if not isinstance(rounds, list):
        raise TypeError("rounds must be a list")
    if not rounds:
        raise ValueError("rounds must be a non-empty list")
    validated: list[dict] = []
    for position, entry in enumerate(rounds):
        where = f"round {position}"
        if not isinstance(entry, dict):
            raise TypeError(f"{where} must be a dict")
        if set(entry.keys()) != _FC_ROUND_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'confirmation', "
                "'previous' and 'seq'"
            )
        seq = entry[FC_SEQ]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise TypeError(f"{where} seq must be an int")
        previous = entry[FE_PREVIOUS]
        if previous is not None and not isinstance(previous, str):
            raise TypeError(f"{where} previous must be a str or null")
        confirmation = entry[FC_CONFIRMATION]
        if not isinstance(confirmation, bytes):
            raise TypeError(f"{where} confirmation must be bytes")
        if not confirmation:
            raise ValueError(f"{where} confirmation must be non-empty")
        validated.append({
            FC_CONFIRMATION: confirmation,
            FE_PREVIOUS: previous,
            FC_SEQ: seq,
        })
    return validated


def _validated_convergence_rounds(rounds: object) -> list[dict]:
    """Validate the public round chain before any confirmation is checked.

    The shape contract is validated first through
    :func:`_validated_convergence_round_shapes`, then the chain
    contract: rounds are numbered consecutively from one, the first
    round binds no previous confirmation and every later round binds
    the SHA-256 of the previous round's confirmation bytes.  A sequence
    gap, reordering, duplicate or broken chain link raises
    :class:`InvalidForkConvergenceError`.
    """
    validated = _validated_convergence_round_shapes(rounds)
    previous_digest: str | None = None
    for position, entry in enumerate(validated):
        where = f"round {position}"
        seq = entry[FC_SEQ]
        if seq != position + 1:
            raise _fork_convergence_invalid(
                f"{where} seq must be {position + 1}: rounds are numbered "
                "consecutively from one with no gap, reordering or duplicate"
            )
        previous = entry[FE_PREVIOUS]
        if position == 0:
            if previous is not None:
                raise _fork_convergence_invalid(
                    "the first round binds no previous confirmation"
                )
        elif previous != previous_digest:
            raise _fork_convergence_invalid(
                f"{where} does not chain to the previous confirmation digest"
            )
        previous_digest = hashlib.sha256(entry[FC_CONFIRMATION]).hexdigest()
    return validated


def _fc_round_outcomes(verified: dict) -> dict[str, tuple[str, str | None]]:
    """Map one verified confirmation's operations to result/post-digest.

    The post-state digest of an executed operation comes from its counted
    (reason-free) executed receipt; verification already guarantees every
    counted executed receipt of one operation binds the same digest.
    """
    outcomes: dict[str, list] = {
        row[FE_OPERATION_ID]: [row[FE_RESULT], None]
        for row in verified[FE_RESULTS]
    }
    for row in verified[FE_REASONS]:
        if row[ADJ_REASON] is None and row[FE_RESULT] == FE_RESULT_EXECUTED:
            outcomes[row[FE_OPERATION_ID]][1] = row[FE_POST_DIGEST]
    return {
        operation_id: (outcome[0], outcome[1])
        for operation_id, outcome in outcomes.items()
    }


def _converge_fork_execution(
    rounds: list[dict],
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    decision: bytes,
    moment: int,
) -> tuple[str, list[dict], str]:
    """Verify every round's confirmation and converge the plan operations.

    Each confirmation is re-checked through the exact
    :func:`verify_fork_confirmation` rules at ``moment`` against the same
    decision, policy and keyring, so a bad confirmation raises
    :class:`InvalidForkExecutionError` and bad credentials raise
    :class:`AuthenticationError`.  Every round must bind the same plan
    and the aggregation moments must be strictly increasing; a violation
    raises :class:`InvalidForkConvergenceError`.

    Returns ``(plan_digest, results, status)`` with one result row per
    plan operation in plan order.  A ``failed`` round may advance to
    ``executed`` or ``rejected`` in a later round; a settled execution or
    rejection that is rolled back, swapped, or re-executed with a
    different post-state digest marks the operation ``conflicted`` and
    the original evidence is kept, never overwritten.
    """
    verified_rounds = [
        _verify_fork_confirmation(
            entry[FC_CONFIRMATION], validated_policy, validated_keyring,
            decision, moment,
        )
        for entry in rounds
    ]
    plan_digest = verified_rounds[0][FE_PLAN_DIGEST]
    for entry, verified in zip(rounds[1:], verified_rounds[1:]):
        if verified[FE_PLAN_DIGEST] != plan_digest:
            raise _fork_convergence_invalid(
                f"round {entry[FC_SEQ]} binds a different plan than the "
                "first round"
            )
    for earlier, later, entry in zip(
        verified_rounds, verified_rounds[1:], rounds[1:]
    ):
        if later[FE_AGGREGATED_AT] <= earlier[FE_AGGREGATED_AT]:
            raise _fork_convergence_invalid(
                f"round {entry[FC_SEQ]} aggregation moment must be later "
                "than the previous round's"
            )

    outcomes = [_fc_round_outcomes(verified) for verified in verified_rounds]
    results: list[dict] = []
    for plan_row in verified_rounds[0][FE_RESULTS]:
        operation_id = plan_row[FE_OPERATION_ID]
        settled: str | None = None
        settled_round: int | None = None
        post_digest: str | None = None
        conflicted = False
        for index, round_outcomes in enumerate(outcomes):
            round_result, round_post = round_outcomes[operation_id]
            if settled is None:
                if round_result == FE_RESULT_FAILED:
                    continue
                settled = round_result
                settled_round = rounds[index][FC_SEQ]
                post_digest = round_post
            elif settled == FE_RESULT_EXECUTED:
                if (
                    round_result != FE_RESULT_EXECUTED
                    or round_post != post_digest
                ):
                    conflicted = True
                    break
            elif round_result != FE_RESULT_REJECTED:
                conflicted = True
                break
        if conflicted:
            conclusion = FC_RESULT_CONFLICTED
        elif settled is None:
            conclusion = FE_RESULT_FAILED
        else:
            conclusion = settled
        results.append({
            FE_OPERATION_ID: operation_id,
            FE_POST_DIGEST: post_digest,
            FE_RESULT: conclusion,
            FC_SETTLED_ROUND: settled_round,
            FE_TARGET: plan_row[FE_TARGET],
        })

    conclusions = {row[FE_RESULT] for row in results}
    if FC_RESULT_CONFLICTED in conclusions:
        status = FE_STATUS_CONFLICTED
    elif FE_RESULT_REJECTED in conclusions:
        status = FE_STATUS_REJECTED
    elif FE_RESULT_FAILED in conclusions:
        status = FE_STATUS_PARTIAL
    else:
        status = FE_STATUS_CONFIRMED
    return plan_digest, results, status


def _fc_certificate_payload_bytes(payload: dict) -> bytes:
    """The signed canonical bytes: the payload alone, compact and sorted."""
    return _checkpoint_compact(payload)


def certify_fork_convergence(
    rounds: list,
    decision: bytes,
    policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Certify the multi-round convergence of one fork execution plan.

    ``rounds`` is a non-empty list of round entries in chain order; each
    entry carries exactly ``seq`` (consecutive from one), ``previous``
    (the SHA-256 of the previous round's confirmation bytes, null for the
    first round) and the ``confirmation`` packet bytes.
    ``decision`` is the original accepted fork decision bytes and
    ``policy``/``keyring`` the shared materials; ``moment`` is the
    certification moment and ``issuer``/``version`` name the signing key.

    Every confirmation is verified through the exact
    :func:`verify_fork_confirmation` rules at the certification moment
    and must bind the same plan, decision and policy; the aggregation
    moments must be strictly increasing across rounds.  Each plan
    operation then converges in plan order: a ``failed`` round may
    advance to ``executed`` or ``rejected`` later, but a settled
    execution or rejection must never be rolled back or swapped, and a
    re-execution binding a different post-state digest, marks the
    operation ``conflicted`` -- new evidence never overwrites the
    settled evidence.  One conflicted operation makes the overall status
    ``conflicted``; otherwise a rejection yields ``rejected``, an
    unconverged operation ``partial`` and full convergence ``confirmed``.

    The certificate is one canonical compact UTF-8 JSON object with
    recursively sorted keys, non-ASCII preserved and no trailing byte,
    carrying exactly ``payload`` and ``signature``; the payload binds
    exactly ``certifiedAt``, ``decisionDigest``, ``issuer``,
    ``keyVersion``, ``planDigest``, the per-operation ``results`` (each
    with ``operationId``, ``postDigest``, ``result``, ``settledRound``
    and ``target``, in plan order), the per-round confirmation digests
    (``rounds``), the overall ``status`` and ``version`` (the integer 1).
    The signature is the lowercase hex HMAC-SHA256 of the canonical
    compact payload bytes under the key bound to the exact issuer and
    version with no fallback.

    A parameter, container or public field type fault raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an empty
    round list, a wrong round key set, an empty confirmation or an
    illegal moment, issuer or version raises :class:`ValueError`; a
    broken round chain or convergence relation raises
    :class:`InvalidForkConvergenceError` (a :class:`ValueError`
    subclass); a bad confirmation raises
    :class:`InvalidForkExecutionError`; unknown, revoked, not-yet-valid
    or expired credentials raise :class:`AuthenticationError`.  No file
    is read or written and no input is modified.
    """
    validated_rounds = _validated_convergence_rounds(rounds)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    certify_moment = _fe_moment(moment, "moment")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")

    plan_digest, results, status = _converge_fork_execution(
        validated_rounds, validated_policy, validated_keyring, decision,
        certify_moment,
    )

    signing_entry = _usable_checkpoint_key(
        validated_keyring, issuer, version, certify_moment
    )
    payload = {
        FC_CERTIFIED_AT: certify_moment,
        FE_DECISION_DIGEST: hashlib.sha256(decision).hexdigest(),
        FE_ISSUER: issuer,
        KEY_VERSION: version,
        FE_PLAN_DIGEST: plan_digest,
        FE_RESULTS: results,
        FC_ROUNDS: [
            hashlib.sha256(entry[FC_CONFIRMATION]).hexdigest()
            for entry in validated_rounds
        ],
        STATUS: status,
        VERSION: FORK_CONVERGENCE_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _fc_certificate_payload_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact(
        {TICKET_PAYLOAD: payload, SIGNATURE: signature}
    )


def _parse_fork_convergence_certificate(raw: object) -> tuple[dict, str]:
    """Validate certificate bytes structurally into ``(payload, signature)``.

    A non-bytes argument or a wrong public field type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, digest, ordering or shape fault raises
    :class:`InvalidForkConvergenceError`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("certificate must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _fork_convergence_invalid(
            "certificate must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fork_convergence_invalid(
            "certificate is not valid UTF-8"
        ) from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_fork_convergence_keys
        )
    except json.JSONDecodeError as exc:
        raise _fork_convergence_invalid(
            "certificate is not valid JSON"
        ) from exc
    if not isinstance(data, dict):
        raise TypeError("certificate must be a JSON object")
    if set(data.keys()) != _FE_RECEIPT_TOP_KEYS:
        raise _fork_convergence_invalid(
            "certificate must contain exactly 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("certificate signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _fork_convergence_invalid(
            "certificate signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("certificate payload must be an object")
    if set(payload.keys()) != _FC_PAYLOAD_KEYS:
        raise _fork_convergence_invalid(
            "certificate payload must contain exactly the keys "
            "'certifiedAt', 'decisionDigest', 'issuer', 'keyVersion', "
            "'planDigest', 'results', 'rounds', 'status' and 'version'"
        )
    if not isinstance(payload[FE_ISSUER], str):
        raise TypeError("certificate issuer must be a str")
    if payload[FE_ISSUER] == "":
        raise _fork_convergence_invalid(
            "certificate issuer must be non-empty"
        )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("certificate keyVersion must be an int")
    if key_version <= 0:
        raise _fork_convergence_invalid(
            "certificate keyVersion must be positive"
        )
    certified_at = payload[FC_CERTIFIED_AT]
    if isinstance(certified_at, bool) or not isinstance(certified_at, int):
        raise TypeError("certificate certifiedAt must be an int")
    if certified_at < 0:
        raise _fork_convergence_invalid(
            "certificate certifiedAt must be >= 0"
        )
    for name in (FE_DECISION_DIGEST, FE_PLAN_DIGEST):
        value = payload[name]
        if not isinstance(value, str):
            raise TypeError(f"certificate {name} must be a str")
        if not _is_digest(value):
            raise _fork_convergence_invalid(
                f"certificate {name} must be 64 lowercase hex characters"
            )
    status = payload[STATUS]
    if not isinstance(status, str):
        raise TypeError("certificate status must be a str")
    if status not in _FE_STATUSES:
        raise _fork_convergence_invalid("certificate status is not known")
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("certificate version must be an int")
    if version != FORK_CONVERGENCE_VERSION:
        raise _fork_convergence_invalid(
            "certificate version must be the integer 1"
        )

    round_digests = payload[FC_ROUNDS]
    if not isinstance(round_digests, list):
        raise TypeError("certificate rounds must be a list")
    if not round_digests:
        raise _fork_convergence_invalid(
            "certificate rounds must be non-empty"
        )
    for position, digest in enumerate(round_digests):
        if not isinstance(digest, str):
            raise TypeError(
                f"certificate round {position} digest must be a str"
            )
        if not _is_digest(digest):
            raise _fork_convergence_invalid(
                f"certificate round {position} digest must be 64 lowercase "
                "hex characters"
            )

    results = payload[FE_RESULTS]
    if not isinstance(results, list):
        raise TypeError("certificate results must be a list")
    if not results:
        raise _fork_convergence_invalid(
            "certificate results must be non-empty"
        )
    for position, row in enumerate(results):
        where = f"certificate result {position}"
        if not isinstance(row, dict):
            raise TypeError(f"{where} must be an object")
        if set(row.keys()) != _FC_RESULT_ROW_KEYS:
            raise _fork_convergence_invalid(
                f"{where} must contain exactly the keys 'operationId', "
                "'postDigest', 'result', 'settledRound' and 'target'"
            )
        operation_id = row[FE_OPERATION_ID]
        if not isinstance(operation_id, str):
            raise TypeError(f"{where} operationId must be a str")
        if not _is_digest(operation_id):
            raise _fork_convergence_invalid(
                f"{where} operationId must be 64 lowercase hex characters"
            )
        result = row[FE_RESULT]
        if not isinstance(result, str):
            raise TypeError(f"{where} result must be a str")
        if result not in _FC_RESULT_VALUES:
            raise _fork_convergence_invalid(
                f"{where} result is not known"
            )
        post_digest = row[FE_POST_DIGEST]
        if post_digest is not None:
            if not isinstance(post_digest, str):
                raise TypeError(f"{where} postDigest must be a str or null")
            if not _is_digest(post_digest):
                raise _fork_convergence_invalid(
                    f"{where} postDigest must be 64 lowercase hex characters"
                )
        settled_round = row[FC_SETTLED_ROUND]
        if settled_round is not None:
            if isinstance(settled_round, bool) or not isinstance(
                settled_round, int
            ):
                raise TypeError(
                    f"{where} settledRound must be an int or null"
                )
            if settled_round <= 0:
                raise _fork_convergence_invalid(
                    f"{where} settledRound must be positive"
                )
        target = row[FE_TARGET]
        if not isinstance(target, str):
            raise TypeError(f"{where} target must be a str")
        if target == "":
            raise _fork_convergence_invalid(
                f"{where} target must be non-empty"
            )
        if result == FE_RESULT_EXECUTED:
            if post_digest is None or settled_round is None:
                raise _fork_convergence_invalid(
                    f"{where}: an executed result binds its post-state "
                    "digest and settled round"
                )
        elif result == FE_RESULT_FAILED:
            if post_digest is not None or settled_round is not None:
                raise _fork_convergence_invalid(
                    f"{where}: an unconverged result binds no post-state "
                    "digest or settled round"
                )
        elif settled_round is None:
            raise _fork_convergence_invalid(
                f"{where}: a settled or conflicted result binds its "
                "settled round"
            )

    if _checkpoint_compact(data) != raw:
        raise _fork_convergence_invalid(
            "certificate encoding is not the canonical compact form"
        )
    return payload, signature


def _reverified_convergence_certificate(
    payload: dict,
    validated_rounds: list[dict],
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    decision: bytes,
    moment: int,
) -> tuple[str, list[dict], str, list[str]]:
    """Re-check one parsed certificate's content against its round chain.

    This is every binding except the certificate HMAC, shared by
    :func:`_verify_fork_convergence` and the multi-site convergence
    adjudication: the decision digest binding, the certification
    moment, the re-converged plan digest, per-operation results and
    overall status, and the bound round digests.  Returns
    ``(plan_digest, results, status, round_digests)``.  A bad
    confirmation raises :class:`InvalidForkExecutionError`; every other
    content fault raises :class:`InvalidForkConvergenceError`.
    """
    if payload[FE_DECISION_DIGEST] != hashlib.sha256(decision).hexdigest():
        raise _fork_convergence_invalid(
            "certificate is bound to a different fork decision"
        )
    certified_at = payload[FC_CERTIFIED_AT]
    if certified_at > moment:
        raise _fork_convergence_invalid(
            "certification moment must not be later than the verification "
            "moment"
        )

    plan_digest, results, status = _converge_fork_execution(
        validated_rounds, validated_policy, validated_keyring, decision,
        certified_at,
    )
    round_digests = [
        hashlib.sha256(entry[FC_CONFIRMATION]).hexdigest()
        for entry in validated_rounds
    ]
    return plan_digest, results, status, round_digests


def _verify_fork_convergence(
    certificate: bytes,
    validated_rounds: list[dict],
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    decision: bytes,
    moment: int,
) -> dict:
    """Verify one convergence certificate against validated materials."""
    payload, signature = _parse_fork_convergence_certificate(certificate)

    (
        plan_digest, results, status, round_digests
    ) = _reverified_convergence_certificate(
        payload, validated_rounds, validated_policy, validated_keyring,
        decision, moment,
    )
    if payload[FE_PLAN_DIGEST] != plan_digest:
        raise _fork_convergence_invalid(
            "certificate plan digest does not match the converged rounds"
        )
    if payload[FC_ROUNDS] != round_digests:
        raise _fork_convergence_invalid(
            "certificate round digests do not match the offered rounds"
        )
    if payload[FE_RESULTS] != results:
        raise _fork_convergence_invalid(
            "certificate results do not match the re-converged rounds"
        )
    if payload[STATUS] != status:
        raise _fork_convergence_invalid(
            "certificate status does not match the re-converged rounds"
        )

    signing_entry = _usable_checkpoint_key(
        validated_keyring,
        payload[FE_ISSUER],
        payload[KEY_VERSION],
        moment,
    )
    expected_signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _fc_certificate_payload_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError(
            "fork convergence certificate signature does not match"
        )

    return {
        key: value
        for key, value in (
            (FC_CERTIFIED_AT, payload[FC_CERTIFIED_AT]),
            (FC_CERTIFICATE_DIGEST,
             hashlib.sha256(certificate).hexdigest()),
            (FE_DECISION_DIGEST, payload[FE_DECISION_DIGEST]),
            (FE_ISSUER, payload[FE_ISSUER]),
            (KEY_VERSION, payload[KEY_VERSION]),
            (FE_PLAN_DIGEST, plan_digest),
            (FE_RESULTS, copy.deepcopy(results)),
            (FC_ROUNDS, list(round_digests)),
            (STATUS, status),
            (VERSION, FORK_CONVERGENCE_VERSION),
        )
    }


def verify_fork_convergence(
    certificate: bytes,
    rounds: list,
    decision: bytes,
    policy: dict,
    keyring: dict,
    moment: int,
) -> dict:
    """Verify one fork convergence certificate entirely offline.

    Only the certificate bytes, the original ``rounds`` chain, the
    ``decision`` bytes, the expected ``policy``, the current ``keyring``
    and the verification ``moment`` are consulted -- no file is read or
    written and no argument is modified.  Verification re-checks every
    binding: the canonical certificate encoding and key sets, the round
    chain (consecutive sequence numbers from one, each later round
    chaining to the previous confirmation's digest), every confirmation
    through the exact :func:`verify_fork_confirmation` rules at the
    certified moment against the same plan, decision and policy, the
    strictly increasing aggregation moments, the re-converged
    per-operation results and overall status, the bound round, plan and
    decision digests, and a certification moment not later than the
    verification moment.  The HMAC-SHA256 is checked against the key the
    current keyring binds to the payload's exact issuer and version,
    usable at the verification moment, so a later revocation or expiry
    rejects the certificate with no fallback.

    On success a fresh mapping is returned with the fixed keys
    ``certifiedAt``, ``certificateDigest``, ``decisionDigest``,
    ``issuer``, ``keyVersion``, ``planDigest``, ``results``, ``rounds``,
    ``status`` and ``version`` (the integer 1).  A non-bytes certificate
    or a wrong public field type raises :class:`TypeError` (a
    :class:`bool` never poses as an int); an empty round list, a wrong
    round key set, an empty confirmation or an illegal policy, keyring
    or moment raises :class:`ValueError`; a bad confirmation raises
    :class:`InvalidForkExecutionError`; an illegal certificate encoding,
    key set, digest, round chain or convergence relation raises
    :class:`InvalidForkConvergenceError` (a :class:`ValueError`
    subclass); unknown, revoked, not-yet-valid or expired credentials or
    a wrong signature raise :class:`AuthenticationError`.
    """
    if not isinstance(certificate, bytes):
        raise TypeError("certificate must be bytes")
    validated_rounds = _validated_convergence_rounds(rounds)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    return _verify_fork_convergence(
        certificate, validated_rounds, validated_policy, validated_keyring,
        decision, verify_moment,
    )


def _validated_convergence_items(items: object) -> list[dict]:
    """Validate the whole certificate batch before any item is verified.

    Every item's complete round chain is shape-validated here as well
    as the item container, so the key sets, field types, non-bool
    sequence numbers, confirmation packet bytes and non-empty round
    lists of *all* items are checked before any certificate is
    verified: a nested round fault rejects the whole batch
    (container/field type faults :class:`TypeError`; an empty list, an
    empty or duplicate id, a wrong item or round key set or an empty
    round or confirmation :class:`ValueError`).  Only the round chain
    links and the certificates themselves are examined per item later.
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
        if set(item.keys()) != _FC_BATCH_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'certificate', "
                "'id' and 'rounds'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        certificate = item[FC_CERTIFICATE]
        if not isinstance(certificate, bytes):
            raise TypeError(f"{where} certificate must be bytes")
        rounds = item[FC_ROUNDS]
        # Shape-check every round of every item before any certificate
        # is verified; only the chain links remain a per-item concern.
        validated_rounds = _validated_convergence_round_shapes(rounds)
        validated.append({
            FC_CERTIFICATE: certificate,
            ID: item_id,
            FC_ROUNDS: validated_rounds,
        })
    return validated


def _fork_convergence_item_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One convergence batch report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def _verify_fork_convergence_item(
    item: dict,
    validated_policy: dict,
    validated_keyring: dict[str, list[dict]],
    decision: bytes,
    moment: int,
) -> dict:
    """Verify one certificate in isolation and report its outcome."""
    item_id = item[ID]
    try:
        validated_rounds = _validated_convergence_rounds(item[FC_ROUNDS])
        result = _verify_fork_convergence(
            item[FC_CERTIFICATE], validated_rounds, validated_policy,
            validated_keyring, decision, moment,
        )
    except AuthenticationError as exc:
        return _fork_convergence_item_report(
            item_id, _FC_VERIFY_UNAUTHENTICATED, str(exc), None
        )
    except (TypeError, ValueError) as exc:
        # TypeErrors here can only come from wrong field types inside the
        # certificate bytes or the item's round entries; every other
        # value fault is an InvalidForkExecutionError or an
        # InvalidForkConvergenceError.  The public argument types were
        # all validated before the batch ran.
        return _fork_convergence_item_report(
            item_id, _FC_VERIFY_INVALID, str(exc), None
        )
    return _fork_convergence_item_report(
        item_id, _FC_VERIFY_VERIFIED, None, result
    )


def verify_fork_convergences(
    items: list, decision: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a whole batch of fork convergence certificates offline.

    ``items`` is a non-empty list; each item contains exactly a
    non-empty, batch-unique ``id``, the ``certificate`` bytes and the
    item's non-empty ``rounds`` chain.  The batch -- including every
    round chain's key sets, field types, non-bool sequence numbers and
    non-empty confirmation bytes for *all* items -- and the shared
    ``decision``, ``policy``, ``keyring`` and ``moment`` are validated
    in full before any certificate is verified, so only a batch-level
    fault raises (container, element or field type faults
    :class:`TypeError`; an empty list, an empty or duplicate id, a
    wrong item or round key set or an empty round list or confirmation
    :class:`ValueError`).  Only the round-chain links and the
    certificate itself remain a per-item concern.  Each certificate is
    then handled independently, in strict input
    order, through the exact :func:`verify_fork_convergence` rules: one
    item's failure never stops a later item or changes an earlier
    report.  A bad confirmation, an illegal certificate, a broken round
    chain or a convergence mismatch makes the item ``invalid``;
    currently unknown, revoked, not-yet-valid or expired credentials or
    a wrong signature make it ``unauthenticated``; a passing certificate
    is ``verified``.

    The top-level result is a fresh dict with the fixed keys ``items``
    and ``version`` (the integer 1); each report carries, in this key
    order, ``error`` (null exactly when verified), ``id``, ``result``
    (a fresh independent copy of the single-certificate result when
    verified, otherwise null) and ``status``; a failed item keeps a
    definite, non-empty copy of the original exception text.  Repeated
    calls return equal but mutually independent results.  No file is
    read or written and no input is modified.
    """
    validated_items = _validated_convergence_items(items)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    return {
        ITEMS: [
            _verify_fork_convergence_item(
                item, validated_policy, validated_keyring, decision,
                verify_moment,
            )
            for item in validated_items
        ],
        VERSION: FORK_CONVERGENCE_VERSION,
    }


# --- Multi-site offline adjudication of fork convergence certificates ---------

CONVERGENCE_DECISION_VERSION = 1

CD_SITES = ADJ_SITES
CD_THRESHOLD = ADJ_THRESHOLD
CD_CONCLUSION = ADJ_CONCLUSION
CD_DECISION_DIGEST = FE_DECISION_DIGEST
CD_POLICY_DIGEST = FD_POLICY_DIGEST
CD_PLAN_DIGEST = FE_PLAN_DIGEST
CD_CERTIFICATES = "certificates"
CD_CERTIFICATE_DIGEST = FC_CERTIFICATE_DIGEST
CD_PACKET_DIGEST = "convergenceDecisionDigest"
CD_COMMON = "common"
CD_COMMON_DIGEST = "commonDigest"
CD_CONVERGENCE = "convergence"
CD_RESULTS = FE_RESULTS

CD_STATUS_ACCEPTED = ADJ_STATUS_ACCEPTED
CD_STATUS_CONFLICTED = ADJ_STATUS_CONFLICTED
CD_STATUS_INSUFFICIENT = ADJ_STATUS_INSUFFICIENT
_CD_STATUSES = frozenset((
    CD_STATUS_ACCEPTED,
    CD_STATUS_CONFLICTED,
    CD_STATUS_INSUFFICIENT,
))

CD_CONCLUSION_VALID = ADJ_CONCLUSION_VALID
CD_CONCLUSION_INVALID = ADJ_CONCLUSION_INVALID
CD_CONCLUSION_DUPLICATE = ADJ_CONCLUSION_DUPLICATE
CD_CONCLUSION_CONTRADICTION = ADJ_CONCLUSION_CONTRADICTION
_CD_CONCLUSIONS = frozenset((
    CD_CONCLUSION_VALID,
    CD_CONCLUSION_INVALID,
    CD_CONCLUSION_DUPLICATE,
    CD_CONCLUSION_CONTRADICTION,
))
CD_REASON_INVALID_CERTIFICATE = "invalid-proof"
_CD_INVALID_REASONS = frozenset((
    CD_REASON_INVALID_CERTIFICATE,
    REASON_UNAUTHORIZED_SITE,
    REASON_UNAUTHORIZED_VERSION,
    REASON_CREDENTIAL_UNAVAILABLE,
    REASON_REVOKED,
    REASON_NOT_YET_VALID,
    REASON_EXPIRED,
    REASON_BAD_SIGNATURE,
))
_CD_REASONS = _CD_INVALID_REASONS | frozenset((
    REASON_DUPLICATE,
    REASON_CONTRADICTION,
))

_CD_POLICY_KEYS = frozenset((CD_SITES, CD_THRESHOLD))
_CD_ITEM_KEYS = frozenset((FC_CERTIFICATE, ID, FC_ROUNDS))
_CD_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_CD_PAYLOAD_KEYS = frozenset((
    CD_CERTIFICATES,
    CD_COMMON,
    CD_COMMON_DIGEST,
    CD_DECISION_DIGEST,
    VD_ISSUER,
    ITEMS,
    KEY_VERSION,
    CD_PLAN_DIGEST,
    CD_POLICY_DIGEST,
    STATUS,
    VERSION,
))
_CD_ROW_KEYS = frozenset((
    CD_CERTIFICATE_DIGEST,
    CD_CONCLUSION,
    CD_CONVERGENCE,
    ID,
    KEY_VERSION,
    ADJ_REASON,
    ADJ_SITE,
))
_CD_CONVERGENCE_KEYS = frozenset((CD_PLAN_DIGEST, CD_RESULTS, STATUS))
_CD_BATCH_ITEM_KEYS = frozenset((ID, "decision"))
_CD_VERIFY_VERIFIED = "verified"
_CD_VERIFY_INVALID = "invalid"
_CD_VERIFY_UNAUTHENTICATED = "unauthenticated"
_CD_RESULT_KEYS = (
    CD_CERTIFICATES,
    CD_COMMON,
    CD_COMMON_DIGEST,
    CD_PACKET_DIGEST,
    CD_DECISION_DIGEST,
    VD_ISSUER,
    ITEMS,
    KEY_VERSION,
    CD_PLAN_DIGEST,
    CD_POLICY_DIGEST,
    STATUS,
    VERSION,
)


class InvalidConvergenceDecisionError(ValueError):
    """A signed convergence decision fails its canonical or binding contract."""


def _convergence_decision_invalid(message: str) -> InvalidConvergenceDecisionError:
    return InvalidConvergenceDecisionError(
        f"invalid convergence decision: {message}"
    )


def _reject_duplicate_convergence_decision_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate decision keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _convergence_decision_invalid(
                f"duplicate key {key!r} in object"
            )
        result[key] = value
    return result


def _validated_convergence_site_policy(policy: object) -> dict:
    """Validate the convergence site policy into a fresh normalized dict.

    The policy carries exactly ``sites`` and ``threshold``: a non-empty
    mapping of each authorized non-empty signing site to its non-empty
    set of allowed positive key versions, and a positive threshold no
    greater than the number of sites.  Type faults raise
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    key-set or value fault raises :class:`ValueError`.
    """
    if not isinstance(policy, dict):
        raise TypeError("site policy must be a dict")
    if set(policy.keys()) != _CD_POLICY_KEYS:
        raise ValueError(
            "site policy must contain exactly the keys 'sites' and "
            "'threshold'"
        )
    threshold = policy[CD_THRESHOLD]
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise TypeError("site policy threshold must be an int")
    if threshold <= 0:
        raise ValueError("site policy threshold must be a positive integer")
    sites = policy[CD_SITES]
    if not isinstance(sites, dict):
        raise TypeError("site policy sites must be a dict")
    if not sites:
        raise ValueError("site policy sites must be non-empty")
    allowed: dict[str, frozenset[int]] = {}
    for site, versions in sites.items():
        if not isinstance(site, str):
            raise TypeError("site policy site names must be str")
        if site == "":
            raise ValueError("site policy site names must be non-empty")
        if not isinstance(versions, set):
            raise TypeError(
                f"allowed versions for site {site!r} must be a set"
            )
        site_versions: set[int] = set()
        for key_version in versions:
            if isinstance(key_version, bool) or not isinstance(
                key_version, int
            ):
                raise TypeError(
                    f"allowed versions for site {site!r} must be ints"
                )
            if key_version <= 0:
                raise ValueError(
                    f"allowed versions for site {site!r} must be positive"
                )
            site_versions.add(key_version)
        if not site_versions:
            raise ValueError(
                f"site {site!r} must allow at least one key version"
            )
        allowed[site] = frozenset(site_versions)
    if threshold > len(allowed):
        raise ValueError(
            "site policy threshold must not exceed the number of policy sites"
        )
    return {CD_SITES: allowed, CD_THRESHOLD: threshold}


def _convergence_site_policy_bytes(policy: dict) -> bytes:
    """Canonical compact bytes of the normalized convergence site policy.

    Sites are listed ascending with ascending version arrays and every
    key is recursively sorted.
    """
    return _checkpoint_compact({
        CD_SITES: {
            site: sorted(policy[CD_SITES][site])
            for site in sorted(policy[CD_SITES])
        },
        CD_THRESHOLD: policy[CD_THRESHOLD],
    })


def _validated_convergence_result_rows(
    rows: object, invalid: Callable[[str], Exception]
) -> list[dict]:
    """Validate the bound per-operation convergence rows.

    Each row carries exactly ``operationId``, ``postDigest``,
    ``result``, ``settledRound`` and ``target`` with the same contract
    as a fork convergence certificate row.  Field type faults raise
    :class:`TypeError`; ``invalid`` builds the structural error for
    every other fault.
    """
    if not isinstance(rows, list):
        raise TypeError("convergence results must be a list")
    if not rows:
        raise invalid("convergence results must be non-empty")
    validated: list[dict] = []
    for position, row in enumerate(rows):
        where = f"convergence result {position}"
        if not isinstance(row, dict):
            raise TypeError(f"{where} must be an object")
        if set(row.keys()) != _FC_RESULT_ROW_KEYS:
            raise invalid(
                f"{where} must contain exactly the keys 'operationId', "
                "'postDigest', 'result', 'settledRound' and 'target'"
            )
        operation_id = row[FE_OPERATION_ID]
        if not isinstance(operation_id, str):
            raise TypeError(f"{where} operationId must be a str")
        if not _is_digest(operation_id):
            raise invalid(
                f"{where} operationId must be 64 lowercase hex characters"
            )
        result = row[FE_RESULT]
        if not isinstance(result, str):
            raise TypeError(f"{where} result must be a str")
        if result not in _FC_RESULT_VALUES:
            raise invalid(f"{where} result is not known")
        post_digest = row[FE_POST_DIGEST]
        if post_digest is not None:
            if not isinstance(post_digest, str):
                raise TypeError(f"{where} postDigest must be a str or null")
            if not _is_digest(post_digest):
                raise invalid(
                    f"{where} postDigest must be 64 lowercase hex characters"
                )
        settled_round = row[FC_SETTLED_ROUND]
        if settled_round is not None:
            if isinstance(settled_round, bool) or not isinstance(
                settled_round, int
            ):
                raise TypeError(f"{where} settledRound must be an int or null")
            if settled_round <= 0:
                raise invalid(f"{where} settledRound must be positive")
        target = row[FE_TARGET]
        if not isinstance(target, str):
            raise TypeError(f"{where} target must be a str")
        if target == "":
            raise invalid(f"{where} target must be non-empty")
        if result == FE_RESULT_EXECUTED:
            if post_digest is None or settled_round is None:
                raise invalid(
                    f"{where}: an executed result binds its post-state "
                    "digest and settled round"
                )
        elif result == FE_RESULT_FAILED:
            if post_digest is not None or settled_round is not None:
                raise invalid(
                    f"{where}: an unconverged result binds no post-state "
                    "digest or settled round"
                )
        elif settled_round is None:
            raise invalid(
                f"{where}: a settled or conflicted result binds its "
                "settled round"
            )
        validated.append({
            FE_OPERATION_ID: operation_id,
            FE_POST_DIGEST: post_digest,
            FE_RESULT: result,
            FC_SETTLED_ROUND: settled_round,
            FE_TARGET: target,
        })
    return validated


def _convergence_content(
    plan_digest: str, results: list[dict], status: str
) -> dict:
    """The complete convergence result two sites must share to agree."""
    return {
        CD_PLAN_DIGEST: plan_digest,
        CD_RESULTS: copy.deepcopy(results),
        STATUS: status,
    }


def _convergence_decision_row(
    item_id: str,
    certificate_digest: str,
    site: str | None,
    key_version: int | None,
    convergence: dict | None,
    conclusion: str,
    reason: str | None,
) -> dict:
    """One per-certificate decision row with the fixed bound key set."""
    return {
        CD_CERTIFICATE_DIGEST: certificate_digest,
        CD_CONCLUSION: conclusion,
        CD_CONVERGENCE: convergence,
        ID: item_id,
        KEY_VERSION: key_version,
        ADJ_REASON: reason,
        ADJ_SITE: site,
    }


def _adjudicate_convergence_one(
    item: dict,
    decision: bytes,
    validated_policy: dict,
    site_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Review, authorize and authenticate one convergence certificate.

    The certificate is first re-checked through the exact
    single-certificate content rules (structural parsing, the decision
    and certification-moment bindings and a full re-convergence of its
    rounds) without checking its own HMAC; the signing site and key
    version are then authorized exactly against the site policy, the
    credential is located in the current keyring with no fallback and
    the certificate HMAC is checked last.  Any failure rejects just
    this row with one fixed fork-adjudication reason.
    """
    item_id = item[ID]
    raw_certificate = item[FC_CERTIFICATE]
    certificate_digest = hashlib.sha256(raw_certificate).hexdigest()

    def structural_invalid() -> dict:
        return _convergence_decision_row(
            item_id, certificate_digest, None, None, None,
            CD_CONCLUSION_INVALID, CD_REASON_INVALID_CERTIFICATE,
        )

    try:
        validated_rounds = _validated_convergence_rounds(item[FC_ROUNDS])
        payload, signature = _parse_fork_convergence_certificate(
            raw_certificate
        )
        site = payload[FE_ISSUER]
        key_version = payload[KEY_VERSION]
        (
            plan_digest, results, status, round_digests
        ) = _reverified_convergence_certificate(
            payload, validated_rounds, validated_policy, validated_keyring,
            decision, moment,
        )
        if payload[FE_PLAN_DIGEST] != plan_digest:
            raise _fork_convergence_invalid(
                "certificate plan digest does not match the converged rounds"
            )
        if payload[FC_ROUNDS] != round_digests:
            raise _fork_convergence_invalid(
                "certificate round digests do not match the offered rounds"
            )
        if payload[FE_RESULTS] != results:
            raise _fork_convergence_invalid(
                "certificate results do not match the re-converged rounds"
            )
        if payload[STATUS] != status:
            raise _fork_convergence_invalid(
                "certificate status does not match the re-converged rounds"
            )
    except AuthenticationError:
        # A credential named inside the round chain is evidence the
        # certificate cannot independently review; the certificate is
        # rejected structurally without claiming a signing identity.
        return structural_invalid()
    except (TypeError, ValueError):
        return structural_invalid()

    convergence = _convergence_content(plan_digest, results, status)

    def reject(reason: str) -> dict:
        return _convergence_decision_row(
            item_id, certificate_digest, site, key_version,
            copy.deepcopy(convergence), CD_CONCLUSION_INVALID, reason,
        )

    allowed_versions = site_policy[CD_SITES].get(site)
    if allowed_versions is None:
        return reject(REASON_UNAUTHORIZED_SITE)
    if key_version not in allowed_versions:
        return reject(REASON_UNAUTHORIZED_VERSION)

    entry = None
    for candidate in validated_keyring.get(site, ()):
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
        _fc_certificate_payload_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        return reject(REASON_BAD_SIGNATURE)

    return _convergence_decision_row(
        item_id, certificate_digest, site, key_version,
        copy.deepcopy(convergence), CD_CONCLUSION_VALID, None,
    )


def _convergence_content_key(convergence: dict) -> str:
    """Canonical text identifying one complete convergence result."""
    return _checkpoint_compact(convergence).decode("utf-8")


def _tally_convergence_rows(
    rows: list[dict],
) -> tuple[bool, dict[str, dict]]:
    """Group authenticated rows per site by their convergence result.

    Returns ``(contradicted, votes)`` where ``votes`` maps each
    non-contradicting site to its one complete convergence result.
    Same-site certificates are duplicates only when their complete
    convergence results agree field for field (regardless of the
    certificate bytes); any two distinct results from one site are a
    self-contradiction and that site casts no vote.  Row conclusions
    and reasons are assigned in place.
    """
    by_site: dict[str, list[dict]] = {}
    for row in rows:
        if row[CD_CONCLUSION] in (
            CD_CONCLUSION_VALID,
            CD_CONCLUSION_DUPLICATE,
            CD_CONCLUSION_CONTRADICTION,
        ):
            by_site.setdefault(row[ADJ_SITE], []).append(row)

    contradicted = False
    votes: dict[str, dict] = {}
    for site, site_rows in by_site.items():
        groups: dict[str, list[dict]] = {}
        for row in site_rows:
            groups.setdefault(
                _convergence_content_key(row[CD_CONVERGENCE]), []
            ).append(row)
        if len(groups) > 1:
            contradicted = True
            for _content, members_raw in groups.items():
                members = sorted(members_raw, key=lambda row: row[ID])
                members[0][CD_CONCLUSION] = CD_CONCLUSION_CONTRADICTION
                members[0][ADJ_REASON] = REASON_CONTRADICTION
                for extra in members[1:]:
                    extra[CD_CONCLUSION] = CD_CONCLUSION_DUPLICATE
                    extra[ADJ_REASON] = REASON_DUPLICATE
        else:
            members = sorted(
                next(iter(groups.values())), key=lambda row: row[ID]
            )
            members[0][CD_CONCLUSION] = CD_CONCLUSION_VALID
            members[0][ADJ_REASON] = None
            for extra in members[1:]:
                extra[CD_CONCLUSION] = CD_CONCLUSION_DUPLICATE
                extra[ADJ_REASON] = REASON_DUPLICATE
            votes[site] = members[0][CD_CONVERGENCE]
    return contradicted, votes


def adjudicate_convergence(
    items: list,
    decision: bytes,
    policy: dict,
    site_policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Adjudicate multi-site fork convergence certificates offline.

    ``items`` is a non-empty list; each item contains exactly a
    non-empty, batch-unique ``id``, the ``certificate`` bytes and the
    item's non-empty ``rounds`` chain.  ``decision`` is the original
    accepted fork decision bytes and ``policy``/``keyring`` the shared
    fork materials used by the existing single-certificate rules.
    ``site_policy`` carries exactly ``sites`` (a non-empty mapping of
    each authorized non-empty signing site to its non-empty set of
    allowed positive key versions) and ``threshold`` (a positive
    integer no greater than the site count); ``moment`` is the current
    non-negative time and ``issuer``/``version`` name the adjudicator
    signing key.  No file is read or written and no input is modified.

    The item batch (including every round chain's key sets, field
    types, non-bool sequence numbers and confirmation packet bytes),
    the shared materials and the site policy are validated in full
    before any certificate is reviewed: a nested type fault raises
    :class:`TypeError` (a :class:`bool` never poses as an int) and an
    empty round list or confirmation, a duplicate id or an illegal
    policy, threshold, moment, issuer or version raises
    :class:`ValueError`.

    Each certificate is then handled independently through the exact
    single-certificate content rules, authorized by the exact signing
    site and key version against the site policy with no fallback, and
    authenticated against the current keyring.  An invalid
    certificate, unavailable/revoked/not-yet-valid/expired credential,
    unauthorized site or version or wrong signature rejects only that
    item with the fixed fork-adjudication reason (``invalid-proof``,
    ``unauthorized-site``, ``unauthorized-version``,
    ``credential-unavailable``, ``revoked``, ``not-yet-valid``,
    ``expired`` or ``bad-signature``) and never stops a later item.
    For one site an identical complete convergence result -- the plan
    digest, overall status and every operation's result, settled round
    and post-state digest -- counts once and every extra certificate
    is a ``duplicate``; distinct complete results are a
    ``contradiction``.  Distinct sites must agree on the same complete
    convergence result; any self-contradiction or cross-site
    disagreement is ``conflicted`` with the common result null and can
    never be outvoted.  A unique result attested by at least the
    threshold of distinct sites is ``accepted`` and keeps the complete
    convergence result; every other outcome is ``insufficient``.

    The result is one canonical compact UTF-8 JSON object with
    recursively sorted keys, non-ASCII preserved and no trailing byte,
    carrying exactly ``payload`` and ``signature``.  The payload binds
    exactly ``certificates`` (each certificate digest in the original
    input order), ``common`` (the complete shared convergence result,
    null unless accepted) and ``commonDigest`` (its SHA-256, null
    unless accepted), ``issuer``, ``keyVersion``, the per-certificate
    ``items`` (sorted by site then id, each carrying its
    ``certificateDigest``, ``convergence``, ``conclusion``, ``id``,
    ``keyVersion``, ``reason`` and ``site``), ``planDigest`` (the one
    plan digest shared by the counted sites, otherwise null),
    ``policyDigest`` (the SHA-256 of the canonical site policy),
    ``status`` and ``version`` (the integer 1); the signature is the
    lowercase hex HMAC-SHA256 of the canonical compact payload bytes
    under the key bound to the exact adjudicator issuer and version
    with no fallback.  Unknown, revoked, not-yet-valid or expired
    adjudicator credentials raise :class:`AuthenticationError`.
    """
    validated_items = _validated_convergence_items(items)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_policy = _validated_fork_policy(policy)
    validated_site_policy = _validated_convergence_site_policy(site_policy)
    validated_keyring = _validated_keyring(keyring)
    adjudicate_moment = _fe_moment(moment, "moment")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")

    certificate_digests = [
        hashlib.sha256(item[FC_CERTIFICATE]).hexdigest()
        for item in validated_items
    ]
    rows = [
        _adjudicate_convergence_one(
            item, decision, validated_policy, validated_site_policy,
            validated_keyring, adjudicate_moment,
        )
        for item in validated_items
    ]

    contradicted, votes = _tally_convergence_rows(rows)

    contents = {
        _convergence_content_key(convergence): convergence
        for convergence in votes.values()
    }

    if contradicted or len(contents) > 1:
        status = CD_STATUS_CONFLICTED
    elif len(contents) == 1 and len(votes) >= validated_site_policy[
        CD_THRESHOLD
    ]:
        status = CD_STATUS_ACCEPTED
    else:
        status = CD_STATUS_INSUFFICIENT

    if status == CD_STATUS_ACCEPTED:
        common = copy.deepcopy(next(iter(contents.values())))
        common_digest = hashlib.sha256(
            _checkpoint_compact(common)
        ).hexdigest()
        bound_plan_digest = common[CD_PLAN_DIGEST]
    else:
        common = None
        common_digest = None
        bound_plan_digest = None

    rows.sort(
        key=lambda row: (
            row[ADJ_SITE] is not None,
            row[ADJ_SITE] or "",
            row[ID],
        )
    )

    signing_entry = _usable_checkpoint_key(
        validated_keyring, issuer, version, adjudicate_moment
    )
    payload = {
        CD_CERTIFICATES: certificate_digests,
        CD_COMMON: common,
        CD_COMMON_DIGEST: common_digest,
        CD_DECISION_DIGEST: hashlib.sha256(decision).hexdigest(),
        VD_ISSUER: issuer,
        ITEMS: [copy.deepcopy(row) for row in rows],
        KEY_VERSION: version,
        CD_PLAN_DIGEST: bound_plan_digest,
        CD_POLICY_DIGEST: hashlib.sha256(
            _convergence_site_policy_bytes(validated_site_policy)
        ).hexdigest(),
        STATUS: status,
        VERSION: CONVERGENCE_DECISION_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact(
        {TICKET_PAYLOAD: payload, SIGNATURE: signature}
    )


def _parse_convergence_decision(raw: object) -> tuple[dict, str]:
    """Validate convergence decision bytes into ``(payload, signature)``.

    A non-bytes argument or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, digest, ordering or shape fault raises
    :class:`InvalidConvergenceDecisionError`.  The policy, tally and
    credential bindings are checked by
    :func:`verify_convergence_decision`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("decision must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _convergence_decision_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _convergence_decision_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_convergence_decision_keys,
        )
    except json.JSONDecodeError as exc:
        raise _convergence_decision_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise TypeError("decision must be a JSON object")
    if set(data.keys()) != _CD_TOP_KEYS:
        raise _convergence_decision_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("decision signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _convergence_decision_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("decision payload must be an object")
    if set(payload.keys()) != _CD_PAYLOAD_KEYS:
        raise _convergence_decision_invalid(
            "payload must contain exactly the keys 'certificates', 'common', "
            "'commonDigest', 'decisionDigest', 'issuer', 'items', "
            "'keyVersion', 'planDigest', 'policyDigest', 'status' and "
            "'version'"
        )

    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _convergence_decision_invalid(
            "payload issuer must be a non-empty str"
        )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _convergence_decision_invalid(
            "payload keyVersion must be positive"
        )
    policy_digest = payload[CD_POLICY_DIGEST]
    if not isinstance(policy_digest, str):
        raise TypeError("payload policyDigest must be a str")
    if not _is_digest(policy_digest):
        raise _convergence_decision_invalid(
            "payload policyDigest must be 64 lowercase hex characters"
        )
    decision_digest = payload[CD_DECISION_DIGEST]
    if not isinstance(decision_digest, str):
        raise TypeError("payload decisionDigest must be a str")
    if not _is_digest(decision_digest):
        raise _convergence_decision_invalid(
            "payload decisionDigest must be 64 lowercase hex characters"
        )
    plan_digest = payload[CD_PLAN_DIGEST]
    if plan_digest is not None:
        if not isinstance(plan_digest, str):
            raise TypeError("payload planDigest must be a str or null")
        if not _is_digest(plan_digest):
            raise _convergence_decision_invalid(
                "payload planDigest must be 64 lowercase hex characters"
            )
    status = payload[STATUS]
    if not isinstance(status, str):
        raise TypeError("payload status must be a str")
    if status not in _CD_STATUSES:
        raise _convergence_decision_invalid("payload status is not known")
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("payload version must be an int")
    if version != CONVERGENCE_DECISION_VERSION:
        raise _convergence_decision_invalid(
            "payload version must be the integer 1"
        )

    certificates = payload[CD_CERTIFICATES]
    if not isinstance(certificates, list):
        raise TypeError("payload certificates must be a list")
    if not certificates:
        raise _convergence_decision_invalid(
            "payload certificates must be non-empty"
        )
    for position, digest in enumerate(certificates):
        if not isinstance(digest, str):
            raise TypeError(
                f"payload certificate {position} digest must be a str"
            )
        if not _is_digest(digest):
            raise _convergence_decision_invalid(
                f"payload certificate {position} digest must be 64 lowercase "
                "hex characters"
            )

    common = payload[CD_COMMON]
    common_digest = payload[CD_COMMON_DIGEST]
    if common is None:
        if common_digest is not None:
            if not isinstance(common_digest, str):
                raise TypeError(
                    "payload commonDigest must be a str or null"
                )
            raise _convergence_decision_invalid(
                "a null common result binds no common digest"
            )
    else:
        common = _validated_bound_convergence(common, "payload common")
        if not isinstance(common_digest, str):
            raise TypeError("payload commonDigest must be a str")
        if not _is_digest(common_digest):
            raise _convergence_decision_invalid(
                "payload commonDigest must be 64 lowercase hex characters"
            )
        expected_common_digest = hashlib.sha256(
            _checkpoint_compact(common)
        ).hexdigest()
        if common_digest != expected_common_digest:
            raise _convergence_decision_invalid(
                "payload commonDigest does not match the common result"
            )
    if status == CD_STATUS_ACCEPTED:
        if common is None:
            raise _convergence_decision_invalid(
                "an accepted decision must keep the common convergence result"
            )
    elif common is not None:
        raise _convergence_decision_invalid(
            "only an accepted decision may keep a common convergence result"
        )

    parsed_rows = _validated_convergence_decision_rows(payload[ITEMS])

    if common is not None and common[CD_PLAN_DIGEST] != plan_digest:
        raise _convergence_decision_invalid(
            "the common result must share the bound plan digest"
        )

    if _checkpoint_compact(data) != raw:
        raise _convergence_decision_invalid(
            "encoding is not the canonical compact form"
        )
    return payload, signature


def _validated_bound_convergence(value: object, where: str) -> dict:
    """Validate one complete convergence result bound in a decision."""
    if not isinstance(value, dict):
        raise TypeError(f"{where} must be an object")
    if set(value.keys()) != _CD_CONVERGENCE_KEYS:
        raise _convergence_decision_invalid(
            f"{where} must contain exactly the keys 'planDigest', 'results' "
            "and 'status'"
        )
    plan_digest = value[CD_PLAN_DIGEST]
    if not isinstance(plan_digest, str):
        raise TypeError(f"{where} planDigest must be a str")
    if not _is_digest(plan_digest):
        raise _convergence_decision_invalid(
            f"{where} planDigest must be 64 lowercase hex characters"
        )
    convergence_status = value[STATUS]
    if not isinstance(convergence_status, str):
        raise TypeError(f"{where} status must be a str")
    if convergence_status not in _FE_STATUSES:
        raise _convergence_decision_invalid(f"{where} status is not known")
    results = _validated_convergence_result_rows(
        value[CD_RESULTS], _convergence_decision_invalid
    )
    return {
        CD_PLAN_DIGEST: plan_digest,
        CD_RESULTS: results,
        STATUS: convergence_status,
    }


def _validated_convergence_decision_rows(raw_rows: object) -> list[dict]:
    """Validate the per-certificate rows of a parsed decision packet."""
    if not isinstance(raw_rows, list):
        raise TypeError("payload items must be a list")
    if not raw_rows:
        raise _convergence_decision_invalid("payload items must be non-empty")
    parsed_rows: list[dict] = []
    seen_ids: set[str] = set()
    for position, row in enumerate(raw_rows):
        where = f"payload item {position}"
        if not isinstance(row, dict):
            raise TypeError(f"{where} must be an object")
        if set(row.keys()) != _CD_ROW_KEYS:
            raise _convergence_decision_invalid(
                f"{where} must contain exactly the keys 'certificateDigest', "
                "'convergence', 'conclusion', 'id', 'keyVersion', 'reason' "
                "and 'site'"
            )
        row_id = row[ID]
        if not isinstance(row_id, str):
            raise TypeError(f"{where} id must be a str")
        if row_id == "":
            raise _convergence_decision_invalid(f"{where} id must be non-empty")
        if row_id in seen_ids:
            raise _convergence_decision_invalid(f"{where} repeats an id")
        seen_ids.add(row_id)
        certificate_digest = row[CD_CERTIFICATE_DIGEST]
        if not isinstance(certificate_digest, str):
            raise TypeError(f"{where} certificateDigest must be a str")
        if not _is_digest(certificate_digest):
            raise _convergence_decision_invalid(
                f"{where} certificateDigest must be 64 lowercase hex "
                "characters"
            )
        site = row[ADJ_SITE]
        if site is not None:
            if not isinstance(site, str):
                raise TypeError(f"{where} site must be a str or null")
            if site == "":
                raise _convergence_decision_invalid(
                    f"{where} site must be non-empty"
                )
        row_key_version = row[KEY_VERSION]
        if isinstance(row_key_version, bool) or not isinstance(
            row_key_version, int
        ):
            if row_key_version is not None:
                raise TypeError(f"{where} keyVersion must be an int or null")
        elif row_key_version <= 0:
            raise _convergence_decision_invalid(
                f"{where} keyVersion must be positive"
            )
        if (site is None) != (row_key_version is None):
            raise _convergence_decision_invalid(
                f"{where} site and keyVersion must be null together"
            )
        conclusion = row[CD_CONCLUSION]
        if not isinstance(conclusion, str):
            raise TypeError(f"{where} conclusion must be a str")
        if conclusion not in _CD_CONCLUSIONS:
            raise _convergence_decision_invalid(
                f"{where} conclusion is not known"
            )
        reason = row[ADJ_REASON]
        if conclusion == CD_CONCLUSION_VALID:
            if reason is not None:
                raise _convergence_decision_invalid(
                    f"{where} reason must be null for a valid item"
                )
        else:
            if not isinstance(reason, str):
                raise TypeError(f"{where} reason must be a str")
            if reason not in _CD_REASONS:
                raise _convergence_decision_invalid(
                    f"{where} reason is not known"
                )
        if conclusion == CD_CONCLUSION_INVALID:
            if reason not in _CD_INVALID_REASONS:
                raise _convergence_decision_invalid(
                    f"{where} reason does not match an invalid item"
                )
        elif conclusion != CD_CONCLUSION_VALID:
            if reason != conclusion:
                raise _convergence_decision_invalid(
                    f"{where} reason must match its conclusion"
                )
        raw_convergence = row[CD_CONVERGENCE]
        if raw_convergence is not None:
            parsed_convergence = _validated_bound_convergence(
                raw_convergence, f"{where} convergence"
            )
        else:
            parsed_convergence = None
        identity_expected = reason != CD_REASON_INVALID_CERTIFICATE
        if identity_expected:
            if site is None or parsed_convergence is None:
                raise _convergence_decision_invalid(
                    f"{where} an authenticated item must carry its site and "
                    "convergence result"
                )
        else:
            if site is not None or parsed_convergence is not None:
                raise _convergence_decision_invalid(
                    f"{where} an invalid-proof item must carry no site or "
                    "convergence result"
                )
        parsed_rows.append({
            CD_CERTIFICATE_DIGEST: certificate_digest,
            CD_CONCLUSION: conclusion,
            CD_CONVERGENCE: parsed_convergence,
            ID: row_id,
            KEY_VERSION: row_key_version,
            ADJ_REASON: reason,
            ADJ_SITE: site,
        })
    return parsed_rows


def _reconcile_convergence_payload(
    payload: dict, threshold: int
) -> str:
    """Re-derive every aggregate binding of a parsed decision payload.

    Re-tallies the per-certificate rows the signature covers -- row
    ordering, certificate digests, duplicate/contradiction conclusions,
    cross-site agreement, the threshold acceptance, the bound plan
    digest and the common result and digest -- without seeing any
    certificate or round.  Any mismatch raises
    :class:`InvalidConvergenceDecisionError`; otherwise the derived
    status is returned.
    """
    rows = payload[ITEMS]
    certificates = payload[CD_CERTIFICATES]
    if len(rows) != len(certificates):
        raise _convergence_decision_invalid(
            "the items must cover every certificate and vice versa"
        )
    expected_order = sorted(
        rows,
        key=lambda row: (
            row[ADJ_SITE] is not None,
            row[ADJ_SITE] or "",
            row[ID],
        ),
    )
    if [row[ID] for row in expected_order] != [row[ID] for row in rows]:
        raise _convergence_decision_invalid(
            "items must be sorted by site then id"
        )
    row_digests = [row[CD_CERTIFICATE_DIGEST] for row in rows]
    if sorted(row_digests) != sorted(certificates):
        raise _convergence_decision_invalid(
            "the bound certificate digests must equal the per-item digests"
        )

    # Re-derive the same-site duplicate/contradiction markings; a digest
    # never needs to be seen because the complete convergence result is
    # bound verbatim in every row.
    by_site: dict[str, dict[str, list[dict]]] = {}
    for row in rows:
        if row[CD_CONCLUSION] == CD_CONCLUSION_INVALID:
            continue
        by_site.setdefault(row[ADJ_SITE], {}).setdefault(
            _convergence_content_key(row[CD_CONVERGENCE]), []
        ).append(row)

    contradicted = False
    votes: dict[str, dict] = {}
    for site, groups in by_site.items():
        if len(groups) > 1:
            contradicted = True
            expected_conclusion = CD_CONCLUSION_CONTRADICTION
            expected_reason = REASON_CONTRADICTION
        else:
            expected_conclusion = CD_CONCLUSION_VALID
            expected_reason = None
            votes[site] = next(iter(groups.values()))[0][CD_CONVERGENCE]
        for _content, members_raw in groups.items():
            members = sorted(members_raw, key=lambda row: row[ID])
            for index, row in enumerate(members):
                if index == 0:
                    if row[CD_CONCLUSION] != expected_conclusion:
                        raise _convergence_decision_invalid(
                            f"item {row[ID]!r} has the wrong conclusion"
                        )
                    if row[ADJ_REASON] != expected_reason:
                        raise _convergence_decision_invalid(
                            f"item {row[ID]!r} has the wrong reason"
                        )
                else:
                    if row[CD_CONCLUSION] != CD_CONCLUSION_DUPLICATE:
                        raise _convergence_decision_invalid(
                            f"item {row[ID]!r} must be a duplicate"
                        )
                    if row[ADJ_REASON] != REASON_DUPLICATE:
                        raise _convergence_decision_invalid(
                            f"item {row[ID]!r} must carry the duplicate reason"
                        )
            representative = members[0]
            for row in members[1:]:
                if row[CD_CONVERGENCE] != representative[CD_CONVERGENCE]:
                    raise _convergence_decision_invalid(
                        f"item {row[ID]!r} duplicates a different convergence "
                        "result"
                    )

    contents = {
        _convergence_content_key(convergence): convergence
        for convergence in votes.values()
    }
    if contradicted or len(contents) > 1:
        status = CD_STATUS_CONFLICTED
    elif len(contents) == 1 and len(votes) >= threshold:
        status = CD_STATUS_ACCEPTED
    else:
        status = CD_STATUS_INSUFFICIENT

    if status == CD_STATUS_ACCEPTED:
        expected_common = next(iter(contents.values()))
        expected_common_digest = hashlib.sha256(
            _checkpoint_compact(expected_common)
        ).hexdigest()
        expected_plan_digest = expected_common[CD_PLAN_DIGEST]
    else:
        expected_common = None
        expected_common_digest = None
        expected_plan_digest = None
    if payload[CD_PLAN_DIGEST] != expected_plan_digest:
        raise _convergence_decision_invalid(
            "the bound plan digest does not match the tallied items"
        )
    if payload[CD_COMMON] != expected_common:
        raise _convergence_decision_invalid(
            "the bound common result does not match the tallied items"
        )
    if payload[CD_COMMON_DIGEST] != expected_common_digest:
        raise _convergence_decision_invalid(
            "the bound common digest does not match the tallied items"
        )
    if payload[STATUS] != status:
        raise _convergence_decision_invalid(
            "the status does not match the tallied items"
        )
    return status


def _verify_convergence_decision(
    decision_packet: bytes,
    decision: bytes,
    validated_site_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one convergence decision against validated shared materials."""
    payload, signature = _parse_convergence_decision(decision_packet)
    if payload[CD_DECISION_DIGEST] != hashlib.sha256(decision).hexdigest():
        raise _convergence_decision_invalid(
            "decision digest does not match the fork decision"
        )
    expected_policy_digest = hashlib.sha256(
        _convergence_site_policy_bytes(validated_site_policy)
    ).hexdigest()
    if payload[CD_POLICY_DIGEST] != expected_policy_digest:
        raise _convergence_decision_invalid(
            "policy digest does not match the site policy"
        )

    status = _reconcile_convergence_payload(
        payload, validated_site_policy[CD_THRESHOLD]
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
        raise AuthenticationError(
            "convergence decision signature does not match"
        )

    return {
        key: copy.deepcopy(value)
        for key, value in (
            (CD_CERTIFICATES, payload[CD_CERTIFICATES]),
            (CD_COMMON, payload[CD_COMMON]),
            (CD_COMMON_DIGEST, payload[CD_COMMON_DIGEST]),
            (CD_PACKET_DIGEST, hashlib.sha256(decision_packet).hexdigest()),
            (CD_DECISION_DIGEST, payload[CD_DECISION_DIGEST]),
            (VD_ISSUER, payload[VD_ISSUER]),
            (ITEMS, payload[ITEMS]),
            (KEY_VERSION, payload[KEY_VERSION]),
            (CD_PLAN_DIGEST, payload[CD_PLAN_DIGEST]),
            (CD_POLICY_DIGEST, expected_policy_digest),
            (STATUS, status),
            (VERSION, CONVERGENCE_DECISION_VERSION),
        )
    }


def verify_convergence_decision(
    decision_packet: bytes,
    decision: bytes,
    site_policy: dict,
    keyring: dict,
    moment: int,
) -> dict:
    """Verify one signed multi-site convergence decision entirely offline.

    Only the decision packet, the original fork ``decision`` bytes, the
    expected ``site_policy``, the current ``keyring`` and the
    verification ``moment`` are consulted -- no file is read or written
    and no argument is modified.  Verification validates the canonical
    encoding and key sets, recomputes the fork decision and site policy
    digests, re-tallies the bound per-certificate items (row ordering,
    the original-order certificate digest bindings, duplicates,
    contradictions, cross-site agreement, the threshold, the plan
    digest and the common result and digest) purely from the signed
    payload, and checks the HMAC-SHA256 against the key the current
    keyring binds to the payload's exact issuer and version, usable at
    the verification moment, so a later revocation or expiry rejects
    the decision with no fallback.

    On success a fresh mapping is returned with the fixed keys
    ``certificates``, ``common``, ``commonDigest``,
    ``convergenceDecisionDigest`` (the SHA-256 of the decision packet),
    ``decisionDigest`` (the bound SHA-256 of the original fork decision
    bytes), ``issuer``, ``items``, ``keyVersion``, ``planDigest``,
    ``policyDigest``, ``status`` and ``version`` (the integer 1).  A
    non-bytes argument or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); an
    illegal site policy, keyring or moment raises :class:`ValueError`;
    an illegal encoding, key set, digest, ordering, reference or
    binding raises :class:`InvalidConvergenceDecisionError` (a
    :class:`ValueError` subclass); unknown, revoked, not-yet-valid or
    expired credentials or a signature mismatch raise
    :class:`AuthenticationError`.
    """
    if not isinstance(decision_packet, bytes):
        raise TypeError("decision must be bytes")
    if not isinstance(decision, bytes):
        raise TypeError("fork decision must be bytes")
    validated_site_policy = _validated_convergence_site_policy(site_policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    return _verify_convergence_decision(
        decision_packet, decision, validated_site_policy, validated_keyring,
        verify_moment,
    )


def _validated_convergence_decision_batch_items(
    items: object
) -> list[dict]:
    """Validate the decision batch before any decision is verified.

    The argument must be a non-empty list of dicts each holding exactly
    ``id`` (a non-empty str, unique across the batch) and ``decision``
    (bytes).  Container, element and field type faults raise
    :class:`TypeError`; an empty list, an empty or duplicate id or a
    wrong key set raises :class:`ValueError`.
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
        if set(item.keys()) != _CD_BATCH_ITEM_KEYS:
            raise ValueError(
                f"{where} must contain exactly the keys 'decision' and 'id'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        decision_packet = item["decision"]
        if not isinstance(decision_packet, bytes):
            raise TypeError(f"{where} decision must be bytes")
        validated.append({ID: item_id, "decision": decision_packet})
    return validated


def _convergence_decision_item_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One convergence-decision batch report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def _verify_convergence_decision_item(
    item: dict,
    decision: bytes,
    validated_site_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one decision in isolation and report its outcome.

    Unknown, revoked, not-yet-valid or expired credentials or a wrong
    signature make the item ``unauthenticated``; every encoding,
    key-set, digest, ordering, reference or binding fault makes it
    ``invalid``; a passing decision is ``verified``.
    """
    item_id = item[ID]
    decision_packet = item["decision"]
    try:
        result = _verify_convergence_decision(
            decision_packet, decision, validated_site_policy,
            validated_keyring, moment,
        )
    except AuthenticationError as exc:
        return _convergence_decision_item_report(
            item_id, _CD_VERIFY_UNAUTHENTICATED, str(exc), None
        )
    except (InvalidConvergenceDecisionError, TypeError) as exc:
        # A TypeError here can only come from a wrong JSON field type
        # inside the decision bytes; the public argument types were all
        # validated before the batch ran.
        return _convergence_decision_item_report(
            item_id, _CD_VERIFY_INVALID, str(exc), None
        )
    return _convergence_decision_item_report(
        item_id, _CD_VERIFY_VERIFIED, None, result
    )


def verify_convergence_decisions(
    items: list,
    decision: bytes,
    site_policy: dict,
    keyring: dict,
    moment: int,
) -> dict:
    """Verify a whole batch of multi-site convergence decisions offline.

    ``items`` is a non-empty list; each item is a dict with exactly the
    keys ``id`` (a non-empty str, unique across the batch) and
    ``decision`` (the bytes :func:`adjudicate_convergence` produced).
    The batch and the shared fork ``decision`` bytes, ``site_policy``,
    ``keyring`` and ``moment`` are validated in full before any
    decision is verified: container, element or field type faults raise
    :class:`TypeError` (a :class:`bool` never poses as an int) and an
    empty list, an empty or duplicate id or a wrong item key set
    raises :class:`ValueError`; only these batch-level faults raise.

    Each decision is then verified independently, in strict input
    order, through the exact :func:`verify_convergence_decision`
    rules: one decision's failure never stops a later one or alters an
    earlier report.  Currently unknown, revoked, not-yet-valid or
    expired credentials or a wrong signature make the item
    ``unauthenticated``; an illegal encoding, key set, digest,
    ordering, reference or binding makes it ``invalid``; a passing
    decision is ``verified``.

    The top-level result is a fresh dict with the fixed keys ``items``
    and ``version`` (the integer 1); each item report carries, in this
    key order, ``error`` (null exactly when verified), ``id``,
    ``result`` (a fresh independent copy of the single-decision result
    when verified, otherwise null) and ``status``; a failed item keeps
    a definite, non-empty copy of the original exception text.
    Repeated calls return equal but mutually independent results.  No
    file is read or written and no input is modified.
    """
    validated_items = _validated_convergence_decision_batch_items(items)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_site_policy = _validated_convergence_site_policy(site_policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    return {
        ITEMS: [
            _verify_convergence_decision_item(
                item, decision, validated_site_policy, validated_keyring,
                verify_moment,
            )
            for item in validated_items
        ],
        VERSION: CONVERGENCE_DECISION_VERSION,
    }


# --- Supersession chains over multi-site convergence decisions ----------------

SUPERSEDE_VERSION = 1

DS_PREDECESSOR = "predecessor"
DS_EVIDENCE = "evidence"
DS_POLICY = "policy"
DS_OLD_POLICY = "oldPolicy"
DS_NEW_POLICY = "newPolicy"
DS_OLD_POLICY_DIGEST = "oldPolicyDigest"
DS_NEW_POLICY_DIGEST = "newPolicyDigest"
DS_EFFECTIVE_AT = "effectiveAt"
DS_ROOT_DIGEST = "rootDigest"
DS_PREDECESSOR_DIGEST = "predecessorDigest"
DS_HEAD_DIGEST = "headDigest"
DS_HEIGHT = "height"
DS_DECISION_DIGEST = CD_PACKET_DIGEST
DS_POLICY_VERSION = "policyVersion"
DS_BATCH_ROOTS = "roots"
DS_BATCH_SUCCESSORS = "successors"
DS_BATCH_POLICIES = "policies"
DS_ANCHOR_DIGEST = "anchorDigest"

DS_BATCH_ITEM_KEYS = frozenset((ID, "chain"))
DS_CHAIN_KEYS = frozenset((DS_BATCH_ROOTS, DS_BATCH_SUCCESSORS))

_DS_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_DS_PAYLOAD_KEYS = frozenset((
    DS_PREDECESSOR,
    DS_EVIDENCE,
    VD_ISSUER,
    KEY_VERSION,
    DS_NEW_POLICY,
    DS_OLD_POLICY,
    DS_OLD_POLICY_DIGEST,
    DS_NEW_POLICY_DIGEST,
    DS_POLICY_VERSION,
    DS_EFFECTIVE_AT,
    VERSION,
))
_DS_EVIDENCE_ITEM_KEYS = frozenset((FC_CERTIFICATE, ID, FC_ROUNDS))
_DS_POLICY_KEYS = frozenset((CD_SITES, CD_THRESHOLD, DS_POLICY_VERSION))
_DS_VERIFY_VERIFIED = "verified"
_DS_VERIFY_INVALID = "invalid"
_DS_VERIFY_UNAUTHENTICATED = "unauthenticated"
_DS_CHAIN_CONFLICTED = "conflicted"
_DS_CHAIN_ERROR = "forked-successor"

_DS_ANCHOR_TOP_KEYS = frozenset((TICKET_PAYLOAD, SIGNATURE))
_DS_ANCHOR_PAYLOAD_KEYS = frozenset((
    VD_ISSUER,
    KEY_VERSION,
    DS_ROOT_DIGEST,
    DS_HEAD_DIGEST,
    DS_HEIGHT,
    CD_POLICY_DIGEST,
    DS_POLICY_VERSION,
    CP_MOMENT,
    VERSION,
))


class InvalidChainError(ValueError):
    """A supersession successor packet breaks its chain binding contract."""


class InvalidAnchorError(ValueError):
    """A sealed decision head anchor breaks its binding contract."""


def _chain_invalid(message: str) -> InvalidChainError:
    return InvalidChainError(f"invalid decision chain: {message}")


def _anchor_invalid(message: str) -> InvalidAnchorError:
    return InvalidAnchorError(f"invalid decision head anchor: {message}")


def _reject_duplicate_supersede_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate successor keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _chain_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _reject_duplicate_anchor_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate anchor keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _anchor_invalid(f"duplicate key {key!r} in object")
        result[key] = value
    return result


def _validated_decision_policy(policy: object) -> dict:
    """Validate the versioned convergence site policy into fresh form.

    Like :func:`_validated_convergence_site_policy` -- a non-empty
    mapping of each authorized non-empty signing site to its non-empty
    set of allowed positive key versions and a positive threshold no
    greater than the site count -- but additionally carrying exactly a
    positive integer ``policyVersion``.  Type faults raise
    :class:`TypeError`; every key-set or value fault raises
    :class:`ValueError`.
    """
    if not isinstance(policy, dict):
        raise TypeError("policy must be a dict")
    if set(policy.keys()) != _DS_POLICY_KEYS:
        raise ValueError(
            "policy must contain exactly the keys 'sites', 'threshold' and "
            "'policyVersion'"
        )
    policy_version = policy[DS_POLICY_VERSION]
    if isinstance(policy_version, bool) or not isinstance(policy_version, int):
        raise TypeError("policy policyVersion must be an int")
    if policy_version <= 0:
        raise ValueError("policy policyVersion must be a positive integer")
    # The sites/threshold pair shares the exact convergence policy rules.
    base = _validated_convergence_site_policy({
        CD_SITES: policy[CD_SITES],
        CD_THRESHOLD: policy[CD_THRESHOLD],
    })
    base[DS_POLICY_VERSION] = policy_version
    return base


def _decision_policy_bytes(policy: dict) -> bytes:
    """Canonical compact bytes of the normalized versioned site policy."""
    return _checkpoint_compact({
        CD_SITES: {
            site: sorted(policy[CD_SITES][site])
            for site in sorted(policy[CD_SITES])
        },
        CD_THRESHOLD: policy[CD_THRESHOLD],
        DS_POLICY_VERSION: policy[DS_POLICY_VERSION],
    })


def _decision_policy_digest(policy: dict) -> str:
    """SHA-256 of the canonical versioned site policy."""
    return hashlib.sha256(_decision_policy_bytes(policy)).hexdigest()


# -- Evidence shape validation shared by sealing and chain inputs --------------

def _validated_supersede_evidence_items(items: object, where: str) -> list[dict]:
    """Shape-validate one hop's evidence list.

    Each item holds exactly ``certificate`` (bytes), ``id`` (a
    non-empty str, unique within the stage) and ``rounds`` (a list
    whose entries are shape-validated exactly as convergence rounds).
    Container/element/field type faults raise :class:`TypeError`; an
    empty list, an empty or duplicate id, a wrong item/round key set or
    an empty round or confirmation raises :class:`ValueError`.
    Cross-stage prefix and duplication faults are examined per chain.
    """
    if not isinstance(items, list):
        raise TypeError(f"{where} evidence must be a list")
    if not items:
        raise ValueError(f"{where} evidence must be non-empty")
    validated: list[dict] = []
    seen_ids: set[str] = set()
    for position, item in enumerate(items):
        item_where = f"{where} evidence item {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{item_where} must be a dict")
        if set(item.keys()) != _DS_EVIDENCE_ITEM_KEYS:
            raise ValueError(
                f"{item_where} must contain exactly the keys 'certificate', "
                "'id' and 'rounds'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{item_where} id must be a str")
        if item_id == "":
            raise ValueError(f"{item_where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"{item_where} repeats an id")
        seen_ids.add(item_id)
        certificate = item[FC_CERTIFICATE]
        if not isinstance(certificate, bytes):
            raise TypeError(f"{item_where} certificate must be bytes")
        validated_rounds = _validated_convergence_round_shapes(
            item[FC_ROUNDS]
        )
        validated.append({
            FC_CERTIFICATE: certificate,
            ID: item_id,
            FC_ROUNDS: validated_rounds,
        })
    return validated


# -- Recomputing one convergence verdict from raw evidence --------------------

def _recompute_convergence_verdict(
    validated_items: list[dict],
    decision: bytes,
    validated_fork_policy: dict,
    site_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Re-adjudicate raw evidence into the full verdict aggregates.

    Returns the certificate digests in the original input order, the
    per-certificate rows sorted by site then id, the derived overall
    status and (when accepted) the common result, its digest and the
    shared plan digest.
    """
    certificate_digests = [
        hashlib.sha256(item[FC_CERTIFICATE]).hexdigest()
        for item in validated_items
    ]
    rows = [
        _adjudicate_convergence_one(
            item, decision, validated_fork_policy, site_policy,
            validated_keyring, moment,
        )
        for item in validated_items
    ]
    contradicted, votes = _tally_convergence_rows(rows)
    contents = {
        _convergence_content_key(convergence): convergence
        for convergence in votes.values()
    }
    if contradicted or len(contents) > 1:
        status = CD_STATUS_CONFLICTED
    elif len(contents) == 1 and len(votes) >= site_policy[CD_THRESHOLD]:
        status = CD_STATUS_ACCEPTED
    else:
        status = CD_STATUS_INSUFFICIENT
    if status == CD_STATUS_ACCEPTED:
        common = copy.deepcopy(next(iter(contents.values())))
        common_digest = hashlib.sha256(
            _checkpoint_compact(common)
        ).hexdigest()
        plan_digest = common[CD_PLAN_DIGEST]
    else:
        common = None
        common_digest = None
        plan_digest = None
    rows.sort(
        key=lambda row: (
            row[ADJ_SITE] is not None,
            row[ADJ_SITE] or "",
            row[ID],
        )
    )
    return {
        CD_CERTIFICATES: certificate_digests,
        ITEMS: rows,
        STATUS: status,
        CD_COMMON: common,
        CD_COMMON_DIGEST: common_digest,
        CD_PLAN_DIGEST: plan_digest,
    }


def _plain_site_policy(site_policy: dict) -> dict:
    """The unversioned ``{sites, threshold}`` form a root decision binds."""
    return {
        CD_SITES: site_policy[CD_SITES],
        CD_THRESHOLD: site_policy[CD_THRESHOLD],
    }


_HEX_EVEN = re.compile(r"[0-9a-f]*$")


def _hex_bytes(value: str) -> bytes:
    """Decode a canonical even-length lowercase hex string to bytes."""
    if not value or len(value) % 2 or _HEX_EVEN.fullmatch(value) is None:
        raise ValueError("must be non-empty even-length lowercase hex")
    return bytes.fromhex(value)


def _evidence_bound_form(validated_items: list[dict]) -> list[dict]:
    """The raw JSON-bound form of evidence items (bytes as lowercase hex)."""
    return [
        {
            FC_CERTIFICATE: item[FC_CERTIFICATE].hex(),
            ID: item[ID],
            FC_ROUNDS: [
                {
                    FC_CONFIRMATION: round_entry[FC_CONFIRMATION].hex(),
                    FE_PREVIOUS: round_entry[FE_PREVIOUS],
                    FC_SEQ: round_entry[FC_SEQ],
                }
                for round_entry in item[FC_ROUNDS]
            ],
        }
        for item in validated_items
    ]


def _evidence_identity(validated_items: list[dict]) -> list[tuple]:
    """Content identity tuples for evidence prefix comparisons."""
    return [
        (
            item[ID],
            hashlib.sha256(item[FC_CERTIFICATE]).hexdigest(),
            tuple(
                (
                    round_entry[FC_SEQ],
                    round_entry[FE_PREVIOUS],
                    hashlib.sha256(
                        round_entry[FC_CONFIRMATION]
                    ).hexdigest(),
                )
                for round_entry in item[FC_ROUNDS]
            ),
        )
        for item in validated_items
    ]


def _parse_bound_evidence(raw_items: object, where: str) -> list[dict]:
    """Parse the raw evidence increment bound inside a successor packet.

    Bytes ride as non-empty even-length lowercase hex strings.  A field
    of the wrong type raises :class:`TypeError`; every key-set, value,
    empty, duplicate-id or hex-encoding fault raises
    :class:`InvalidChainError`.
    """
    if not isinstance(raw_items, list):
        raise TypeError(f"{where} evidence must be a list")
    if not raw_items:
        raise _chain_invalid(f"{where} evidence must be non-empty")
    validated: list[dict] = []
    seen_ids: set[str] = set()
    for position, item in enumerate(raw_items):
        item_where = f"{where} evidence item {position}"
        if not isinstance(item, dict):
            raise TypeError(f"{item_where} must be an object")
        if set(item.keys()) != _DS_EVIDENCE_ITEM_KEYS:
            raise _chain_invalid(
                f"{item_where} must contain exactly the keys 'certificate', "
                "'id' and 'rounds'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{item_where} id must be a str")
        if item_id == "":
            raise _chain_invalid(f"{item_where} id must be non-empty")
        if item_id in seen_ids:
            raise _chain_invalid(f"{item_where} repeats an id")
        seen_ids.add(item_id)
        certificate_hex = item[FC_CERTIFICATE]
        if not isinstance(certificate_hex, str):
            raise TypeError(f"{item_where} certificate must be a str")
        try:
            certificate = _hex_bytes(certificate_hex)
        except ValueError as exc:
            raise _chain_invalid(
                f"{item_where} certificate must be non-empty even-length "
                "lowercase hex"
            ) from exc
        raw_rounds = item[FC_ROUNDS]
        if not isinstance(raw_rounds, list):
            raise TypeError(f"{item_where} rounds must be a list")
        if not raw_rounds:
            raise _chain_invalid(f"{item_where} rounds must be non-empty")
        rounds: list[dict] = []
        for round_position, round_entry in enumerate(raw_rounds):
            round_where = f"{item_where} round {round_position}"
            if not isinstance(round_entry, dict):
                raise TypeError(f"{round_where} must be an object")
            if set(round_entry.keys()) != _FC_ROUND_KEYS:
                raise _chain_invalid(
                    f"{round_where} must contain exactly the keys "
                    "'confirmation', 'previous' and 'seq'"
                )
            seq = round_entry[FC_SEQ]
            if isinstance(seq, bool) or not isinstance(seq, int):
                raise TypeError(f"{round_where} seq must be an int")
            previous = round_entry[FE_PREVIOUS]
            if previous is not None:
                if not isinstance(previous, str):
                    raise TypeError(
                        f"{round_where} previous must be a str or null"
                    )
                if not _is_digest(previous):
                    raise _chain_invalid(
                        f"{round_where} previous must be 64 lowercase hex "
                        "characters"
                    )
            confirmation_hex = round_entry[FC_CONFIRMATION]
            if not isinstance(confirmation_hex, str):
                raise TypeError(f"{round_where} confirmation must be a str")
            try:
                confirmation = _hex_bytes(confirmation_hex)
            except ValueError as exc:
                raise _chain_invalid(
                    f"{round_where} confirmation must be non-empty even-length "
                    "lowercase hex"
                ) from exc
            rounds.append({
                FC_CONFIRMATION: confirmation,
                FE_PREVIOUS: previous,
                FC_SEQ: seq,
            })
        validated.append({
            FC_CERTIFICATE: certificate,
            ID: item_id,
            FC_ROUNDS: rounds,
        })
    return validated


# -- Successor packet shape ----------------------------------------------------

_DS_SUCCESSOR_PAYLOAD_KEYS = frozenset((
    DS_ROOT_DIGEST,
    DS_PREDECESSOR_DIGEST,
    DS_HEIGHT,
    CD_CERTIFICATES,
    CD_COMMON,
    CD_COMMON_DIGEST,
    CD_PLAN_DIGEST,
    ITEMS,
    STATUS,
    DS_EVIDENCE,
    DS_OLD_POLICY_DIGEST,
    DS_NEW_POLICY_DIGEST,
    DS_POLICY_VERSION,
    DS_EFFECTIVE_AT,
    VD_ISSUER,
    KEY_VERSION,
    VERSION,
))


def _root_decision_view(raw: bytes) -> dict:
    """Structurally parse a root convergence decision predecessor.

    Only the canonical/shape contract of
    :func:`_parse_convergence_decision` is applied (the HMAC and the
    fork-decision/policy bindings are not); the aggregates a successor
    builds on are returned as a fresh view.
    """
    payload, _signature = _parse_convergence_decision(raw)
    return {
        "kind": "root",
        DS_ROOT_DIGEST: hashlib.sha256(raw).hexdigest(),
        DS_HEIGHT: 0,
        STATUS: payload[STATUS],
        CD_COMMON: copy.deepcopy(payload[CD_COMMON]),
        CD_PLAN_DIGEST: payload[CD_PLAN_DIGEST],
        CD_CERTIFICATES: list(payload[CD_CERTIFICATES]),
        ITEMS: copy.deepcopy(payload[ITEMS]),
        "policy_digest": payload[CD_POLICY_DIGEST],
        DS_POLICY_VERSION: CONVERGENCE_DECISION_VERSION,
        DS_EFFECTIVE_AT: None,
        "root_plan_digest": _root_plan_digest(payload),
    }


def _root_plan_digest(root_payload: dict) -> str:
    """The one plan digest a whole chain must keep (accepted root)."""
    if root_payload[CD_PLAN_DIGEST] is not None:
        return root_payload[CD_PLAN_DIGEST]
    # An insufficient/conflicted root binds no aggregate plan digest;
    # every authenticated row nevertheless converges on one plan.
    plan_digests = {
        row[CD_CONVERGENCE][CD_PLAN_DIGEST]
        for row in root_payload[ITEMS]
        if row[CD_CONVERGENCE] is not None
    }
    if len(plan_digests) != 1:
        raise _convergence_decision_invalid(
            "root decision must converge on one plan"
        )
    return next(iter(plan_digests))


def _view_plan_digest(plan_digest: str | None, rows: list[dict]) -> str:
    """The one root plan a predecessor builds on, even when insufficient."""
    if plan_digest is not None:
        return plan_digest
    plan_digests = {
        row[CD_CONVERGENCE][CD_PLAN_DIGEST]
        for row in rows
        if row[CD_CONVERGENCE] is not None
    }
    if len(plan_digests) != 1:
        raise _chain_invalid("successor must converge on one root plan")
    return next(iter(plan_digests))


def _successor_view(raw: bytes) -> dict:
    """Structurally parse a successor predecessor into a fresh view."""
    payload, _signature, evidence = _parse_supersede_packet(raw)
    return {
        "kind": "successor",
        DS_ROOT_DIGEST: payload[DS_ROOT_DIGEST],
        DS_HEIGHT: payload[DS_HEIGHT],
        STATUS: payload[STATUS],
        CD_COMMON: copy.deepcopy(payload[CD_COMMON]),
        CD_PLAN_DIGEST: payload[CD_PLAN_DIGEST],
        CD_CERTIFICATES: list(payload[CD_CERTIFICATES]),
        ITEMS: copy.deepcopy(payload[ITEMS]),
        "policy_digest": payload[DS_NEW_POLICY_DIGEST],
        DS_POLICY_VERSION: payload[DS_POLICY_VERSION],
        DS_EFFECTIVE_AT: payload[DS_EFFECTIVE_AT],
        "evidence": evidence,
        "root_plan_digest": _view_plan_digest(
            payload[CD_PLAN_DIGEST], payload[ITEMS]
        ),
    }


def _packet_payload_keys(raw: bytes) -> frozenset | None:
    """Return a packet's payload key set without any structural validation.

    Returns ``None`` for anything that is not a canonical
    ``{payload, signature}`` JSON envelope so the caller may try both
    packet kinds.
    """
    if not raw:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or TICKET_PAYLOAD not in data:
        return None
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        return None
    return frozenset(payload.keys())


def _predecessor_view(raw: object) -> dict:
    """Parse the predecessor bytes (root decision or successor packet).

    The packet kind is chosen from the payload key set so that a
    malformed root decision raises
    :class:`InvalidConvergenceDecisionError` while a malformed successor
    raises :class:`InvalidChainError`.
    """
    if not isinstance(raw, bytes):
        raise TypeError("predecessor must be bytes")
    keys = _packet_payload_keys(raw)
    if keys is not None and DS_ROOT_DIGEST in keys:
        return _successor_view(raw)
    return _root_decision_view(raw)


def _assert_transition(previous: dict, verdict: dict) -> None:
    """Enforce the per-hop verdict state-machine and fixed plan/root."""
    prev_status = previous[STATUS]
    new_status = verdict[STATUS]
    if prev_status == CD_STATUS_CONFLICTED and new_status != CD_STATUS_CONFLICTED:
        raise _chain_invalid(
            "a conflicted decision can never be outvoted or fall back"
        )
    if prev_status == CD_STATUS_ACCEPTED:
        if new_status == CD_STATUS_INSUFFICIENT:
            raise _chain_invalid(
                "an accepted decision must not fall back to insufficient"
            )
        if new_status == CD_STATUS_ACCEPTED:
            if previous["kind"] == "checkpoint":
                # A checkpoint predecessor keeps only the settlement
                # digest; the recomputed common result must hash to it.
                same_common = hmac.compare_digest(
                    verdict[CD_COMMON_DIGEST], previous[CD_COMMON_DIGEST]
                )
            else:
                same_common = verdict[CD_COMMON] == previous[CD_COMMON]
            if not same_common:
                raise _chain_invalid(
                    "an accepted decision may only keep the same common result"
                )
    # An accepted/conflicted verdict always pins one plan, equal to the
    # chain's root plan; insufficient verdicts pin no aggregate plan.
    if verdict[CD_PLAN_DIGEST] is not None:
        if verdict[CD_PLAN_DIGEST] != previous["root_plan_digest"]:
            raise _chain_invalid(
                "a policy rotation must never change the plan or settled "
                "operations"
            )
    for row in verdict[ITEMS]:
        convergence = row[CD_CONVERGENCE]
        if convergence is not None:
            if convergence[CD_PLAN_DIGEST] != previous["root_plan_digest"]:
                raise _chain_invalid(
                    "every authenticated result must keep the root plan"
                )


def _assert_sealer_authorized(
    old_policy: dict, new_policy: dict, issuer: str, key_version: int
) -> None:
    """The successor sealer must be authorized under both policies.

    Historical evidence from a site a rotation removes still stands in
    the prefix; the one identity acting at this hop is the successor
    signer, and its exact key version must be allowed by the policy
    before and after the rotation.
    """
    if key_version not in old_policy[CD_SITES].get(issuer, frozenset()):
        raise _chain_invalid(
            f"sealer {issuer!r} version {key_version} is not authorized by "
            "the previous policy"
        )
    if key_version not in new_policy[CD_SITES].get(issuer, frozenset()):
        raise _chain_invalid(
            f"sealer {issuer!r} version {key_version} is not authorized by "
            "the rotated policy"
        )


def _root_prefix_matches(
    root_view: dict, evidence: list[dict], require_extension: bool
) -> None:
    """A first successor's evidence must extend the root's certificates."""
    root_digests = root_view[CD_CERTIFICATES]
    if len(evidence) < len(root_digests):
        raise _chain_invalid(
            "the evidence sequence must have the predecessor as a prefix"
        )
    root_id_for = {
        row[CD_CERTIFICATE_DIGEST]: row[ID]
        for row in root_view[ITEMS]
    }
    for position, digest in enumerate(root_digests):
        item = evidence[position]
        if hashlib.sha256(item[FC_CERTIFICATE]).hexdigest() != digest:
            raise _chain_invalid(
                "the evidence sequence must have the root certificates as a "
                "prefix"
            )
        if root_id_for.get(digest) != item[ID]:
            raise _chain_invalid(
                "prefix evidence must keep the root's per-certificate ids"
            )
    if require_extension and len(evidence) == len(root_digests):
        raise _chain_invalid(
            "an unchanged policy must add at least one evidence item"
        )


def _successor_prefix_matches(
    previous: dict, evidence: list[dict], require_extension: bool
) -> None:
    """A later successor's evidence must keep the predecessor as a prefix.

    When the policy is unchanged a hop must additionally add at least
    one item; a policy rotation may re-seal the same evidence sequence
    as a pure prefix.
    """
    prior = _evidence_identity(previous["evidence"])
    current = _evidence_identity(evidence)
    if len(current) < len(prior):
        raise _chain_invalid(
            "the evidence sequence must have the predecessor evidence as a "
            "prefix"
        )
    if current[:len(prior)] != prior:
        raise _chain_invalid(
            "the evidence sequence must have the predecessor evidence as a "
            "prefix; history must not be deleted, changed or reordered"
        )
    if require_extension and len(current) == len(prior):
        raise _chain_invalid(
            "an unchanged policy must add at least one evidence item"
        )


def _assert_evidence_prefix(
    previous: dict, evidence: list[dict], require_extension: bool
) -> None:
    """Dispatch the prefix/extension rule by predecessor kind."""
    if previous["kind"] == "root":
        _root_prefix_matches(previous, evidence, require_extension)
    elif previous["kind"] == "checkpoint":
        _checkpoint_prefix_matches(previous, evidence, require_extension)
    else:
        _successor_prefix_matches(previous, evidence, require_extension)


def supersede_decision(
    predecessor: bytes,
    evidence: list,
    decision: bytes,
    policy: dict,
    old_policy: dict,
    new_policy: dict,
    keyring: dict,
    moment: int,
    effective_at: int,
    issuer: str,
    version: int,
) -> bytes:
    """Issue one signed supersession successor over a convergence decision.

    ``predecessor`` is either an existing convergence decision packet
    (the chain root) or the previous successor packet.  ``evidence`` is
    the stage's non-empty certificate/rounds list in the exact shape of
    :func:`adjudicate_convergence` items; its sequence must have the
    predecessor's evidence as a strict prefix (a first successor keeps
    the root's certificates and ids in order; a later successor keeps
    every prior evidence item) and must add at least one item.
    ``decision`` is the original fork decision bytes and ``policy`` the
    shared fork policy; ``old_policy`` and ``new_policy`` are the
    versioned site policies (each exactly ``sites``, ``threshold`` and a
    positive ``policyVersion``) in force before and at this hop.  A
    changed policy increments ``policyVersion`` by exactly one and
    changes nothing else about the root, plan or settled operations; an
    unchanged policy keeps the same version.  ``effective_at`` is the
    hop's non-negative effective moment and must not move backwards.

    The new verdict is recomputed from scratch from the full evidence
    sequence.  Additional evidence may move ``insufficient`` to
    ``accepted`` or ``conflicted``; an ``accepted`` verdict only keeps
    the identical common result or advances to ``conflicted`` (it never
    falls back to ``insufficient`` or changes conclusion), and a
    ``conflicted`` verdict is never masked by a later majority.  Every
    authenticated evidence identity and key version must be authorized
    by both policies and the credentials must be usable at
    ``effective_at`` and at the verification ``moment``.

    Returns canonical compact UTF-8 JSON with exactly ``payload`` and
    ``signature``.  The payload binds the root digest, predecessor
    digest, chain height, the full recomputed verdict aggregates
    (certificate digests in original order, items sorted by site then
    id, status, common result/digest and plan digest), the bound raw
    evidence increment (bytes as lowercase hex), the old and new policy
    digests, the policy version, the effective moment, the issuer and
    key version and ``version`` (the integer 1); the signature is the
    HMAC-SHA256 of the canonical payload under the exact issuer/version
    key.  Container/field type faults raise :class:`TypeError`; an empty
    value, duplicate id, illegal version or backwards moment raises
    :class:`ValueError`; a malformed root raises
    :class:`InvalidConvergenceDecisionError`; a malformed successor or
    broken chain rule raises :class:`InvalidChainError`; signing or
    evidence credential faults raise :class:`AuthenticationError`.  No
    file is read or written and no input is modified.
    """
    validated_evidence = _validated_supersede_evidence_items(
        evidence, "evidence"
    )
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    if not isinstance(predecessor, bytes):
        raise TypeError("predecessor must be bytes")
    validated_fork_policy = _validated_fork_policy(policy)
    validated_old = _validated_decision_policy(old_policy)
    validated_new = _validated_decision_policy(new_policy)
    validated_keyring = _validated_keyring(keyring)
    sign_moment = _fe_moment(moment, "moment")
    effective = _fe_moment(effective_at, "effectiveAt")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")

    previous = _predecessor_view(predecessor)

    old_digest = _decision_policy_digest(validated_old)
    new_digest = _decision_policy_digest(validated_new)
    old_version = validated_old[DS_POLICY_VERSION]
    if previous["kind"] == "root":
        # The root binds an unversioned {sites,threshold} policy; the
        # first versioned policy over it starts at version 1 and must
        # keep the same sites and threshold.
        if not _policy_sites_threshold_matches_root(validated_old, previous):
            raise _chain_invalid(
                "oldPolicy sites and threshold must match the root decision "
                "policy"
            )
        prior_version = CONVERGENCE_DECISION_VERSION
    else:
        if old_digest != previous["policy_digest"]:
            raise _chain_invalid(
                "oldPolicy must equal the policy bound by the predecessor"
            )
        prior_version = previous[DS_POLICY_VERSION]
    if old_version != prior_version:
        raise _chain_invalid(
            "oldPolicy policyVersion must match the predecessor policy version"
        )
    new_version = validated_new[DS_POLICY_VERSION]
    sites_threshold_unchanged = (
        validated_old[CD_SITES] == validated_new[CD_SITES]
        and validated_old[CD_THRESHOLD] == validated_new[CD_THRESHOLD]
    )
    if sites_threshold_unchanged:
        if new_version != old_version:
            raise _chain_invalid(
                "an unchanged policy must keep its policy version"
            )
    else:
        if new_version != old_version + 1:
            raise _chain_invalid(
                "a changed policy must increment policyVersion by exactly one"
            )

    if previous[DS_EFFECTIVE_AT] is not None and effective < previous[
        DS_EFFECTIVE_AT
    ]:
        raise ValueError("effectiveAt must not move backwards")

    # When the policy is unchanged the history must strictly grow; a
    # rotation may re-seal the identical evidence sequence.
    _assert_evidence_prefix(
        previous, validated_evidence, sites_threshold_unchanged
    )

    verdict = _recompute_convergence_verdict(
        validated_evidence, decision, validated_fork_policy,
        _plain_site_policy(validated_new), validated_keyring, effective,
    )
    _assert_transition(previous, verdict)
    _assert_sealer_authorized(validated_old, validated_new, issuer, version)

    # Evidence credentials must be usable both when the hop takes
    # effect and when it is issued/verified, and the verdict settled at
    # the effective moment must be the one observed now.
    verdict_now = _recompute_convergence_verdict(
        validated_evidence, decision, validated_fork_policy,
        _plain_site_policy(validated_new), validated_keyring, sign_moment,
    )
    if (
        verdict_now[STATUS] != verdict[STATUS]
        or verdict_now[ITEMS] != verdict[ITEMS]
        or verdict_now[CD_COMMON] != verdict[CD_COMMON]
    ):
        raise AuthenticationError(
            "evidence credentials are not all usable at the issuance moment"
        )

    # The signing credential must be usable both when the hop is
    # effective and when it is issued/verified.
    signing_entry = _usable_checkpoint_key(
        validated_keyring, issuer, version, effective
    )
    _usable_checkpoint_key(
        validated_keyring, issuer, version, sign_moment
    )

    root_digest = previous[DS_ROOT_DIGEST]
    height = previous[DS_HEIGHT] + 1
    payload = {
        DS_ROOT_DIGEST: root_digest,
        DS_PREDECESSOR_DIGEST: hashlib.sha256(predecessor).hexdigest(),
        DS_HEIGHT: height,
        CD_CERTIFICATES: verdict[CD_CERTIFICATES],
        CD_COMMON: verdict[CD_COMMON],
        CD_COMMON_DIGEST: verdict[CD_COMMON_DIGEST],
        CD_PLAN_DIGEST: verdict[CD_PLAN_DIGEST],
        ITEMS: [copy.deepcopy(row) for row in verdict[ITEMS]],
        STATUS: verdict[STATUS],
        DS_EVIDENCE: _evidence_bound_form(validated_evidence),
        DS_OLD_POLICY_DIGEST: old_digest,
        DS_NEW_POLICY_DIGEST: new_digest,
        DS_POLICY_VERSION: new_version,
        DS_EFFECTIVE_AT: effective,
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        VERSION: SUPERSEDE_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact(
        {TICKET_PAYLOAD: payload, SIGNATURE: signature}
    )


def _policy_sites_threshold_matches_root(
    old_policy: dict, root_view: dict
) -> bool:
    """Whether a versioned policy's sites/threshold equal the root policy."""
    root_digest = root_view["policy_digest"]
    unversioned = hashlib.sha256(
        _convergence_site_policy_bytes(_plain_site_policy(old_policy))
    ).hexdigest()
    return hmac.compare_digest(root_digest, unversioned)


def _parse_supersede_packet(raw: object) -> tuple[dict, str]:
    """Validate successor packet bytes into ``(payload, signature)``.

    A non-bytes argument or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, version, digest, ordering, shape, evidence or
    binding fault raises :class:`InvalidChainError`.  The predecessor,
    policy, moment and signature bindings are checked by the chain
    verifier.
    """
    if not isinstance(raw, bytes):
        raise TypeError("successor must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _chain_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _chain_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_supersede_keys
        )
    except json.JSONDecodeError as exc:
        raise _chain_invalid("is not valid JSON") from exc

    if not isinstance(data, dict):
        raise TypeError("successor must be a JSON object")
    if set(data.keys()) != _DS_TOP_KEYS:
        raise _chain_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("successor signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _chain_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("successor payload must be an object")
    if set(payload.keys()) != _DS_SUCCESSOR_PAYLOAD_KEYS:
        raise _chain_invalid(
            "payload must contain exactly the keys 'rootDigest', "
            "'predecessorDigest', 'height', 'certificates', 'common', "
            "'commonDigest', 'planDigest', 'items', 'status', 'evidence', "
            "'oldPolicyDigest', 'newPolicyDigest', 'policyVersion', "
            "'effectiveAt', 'issuer', 'keyVersion' and 'version'"
        )

    root_digest = payload[DS_ROOT_DIGEST]
    if not isinstance(root_digest, str):
        raise TypeError("payload rootDigest must be a str")
    if not _is_digest(root_digest):
        raise _chain_invalid(
            "payload rootDigest must be 64 lowercase hex characters"
        )
    predecessor_digest = payload[DS_PREDECESSOR_DIGEST]
    if not isinstance(predecessor_digest, str):
        raise TypeError("payload predecessorDigest must be a str")
    if not _is_digest(predecessor_digest):
        raise _chain_invalid(
            "payload predecessorDigest must be 64 lowercase hex characters"
        )
    height = payload[DS_HEIGHT]
    if isinstance(height, bool) or not isinstance(height, int):
        raise TypeError("payload height must be an int")
    if height < 1:
        raise _chain_invalid("payload height must be a positive integer")

    certificates = payload[CD_CERTIFICATES]
    if not isinstance(certificates, list):
        raise TypeError("payload certificates must be a list")
    if not certificates:
        raise _chain_invalid("payload certificates must be non-empty")
    for position, digest in enumerate(certificates):
        if not isinstance(digest, str):
            raise TypeError(
                f"payload certificate {position} digest must be a str"
            )
        if not _is_digest(digest):
            raise _chain_invalid(
                f"payload certificate {position} digest must be 64 lowercase "
                "hex characters"
            )

    status = payload[STATUS]
    if not isinstance(status, str):
        raise TypeError("payload status must be a str")
    if status not in _CD_STATUSES:
        raise _chain_invalid("payload status is not known")

    common = payload[CD_COMMON]
    common_digest = payload[CD_COMMON_DIGEST]
    if common is None:
        if common_digest is not None:
            if not isinstance(common_digest, str):
                raise TypeError("payload commonDigest must be a str or null")
            raise _chain_invalid("a null common result binds no common digest")
    else:
        common = _validated_bound_convergence(common, "payload common")
        if not isinstance(common_digest, str):
            raise TypeError("payload commonDigest must be a str")
        if not _is_digest(common_digest):
            raise _chain_invalid(
                "payload commonDigest must be 64 lowercase hex characters"
            )
        if common_digest != hashlib.sha256(
            _checkpoint_compact(common)
        ).hexdigest():
            raise _chain_invalid(
                "payload commonDigest does not match the common result"
            )

    plan_digest = payload[CD_PLAN_DIGEST]
    if plan_digest is not None:
        if not isinstance(plan_digest, str):
            raise TypeError("payload planDigest must be a str or null")
        if not _is_digest(plan_digest):
            raise _chain_invalid(
                "payload planDigest must be 64 lowercase hex characters"
            )
    if status == CD_STATUS_ACCEPTED:
        if common is None:
            raise _chain_invalid(
                "an accepted verdict must keep the common convergence result"
            )
    elif common is not None:
        raise _chain_invalid(
            "only an accepted verdict may keep a common convergence result"
        )
    if common is not None and common[CD_PLAN_DIGEST] != plan_digest:
        raise _chain_invalid(
            "the common result must share the bound plan digest"
        )

    parsed_rows = _validated_convergence_decision_rows(payload[ITEMS])

    for key in (DS_OLD_POLICY_DIGEST, DS_NEW_POLICY_DIGEST):
        value = payload[key]
        if not isinstance(value, str):
            raise TypeError(f"payload {key} must be a str")
        if not _is_digest(value):
            raise _chain_invalid(
                f"payload {key} must be 64 lowercase hex characters"
            )
    policy_version = payload[DS_POLICY_VERSION]
    if isinstance(policy_version, bool) or not isinstance(policy_version, int):
        raise TypeError("payload policyVersion must be an int")
    if policy_version <= 0:
        raise _chain_invalid("payload policyVersion must be positive")
    effective = payload[DS_EFFECTIVE_AT]
    if isinstance(effective, bool) or not isinstance(effective, int):
        raise TypeError("payload effectiveAt must be an int")
    if effective < 0:
        raise _chain_invalid("payload effectiveAt must be non-negative")
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _chain_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _chain_invalid("payload keyVersion must be positive")
    version = payload[VERSION]
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("payload version must be an int")
    if version != SUPERSEDE_VERSION:
        raise _chain_invalid("payload version must be the integer 1")

    evidence = _parse_bound_evidence(payload[DS_EVIDENCE], "payload")

    if _checkpoint_compact(data) != raw:
        raise _chain_invalid("encoding is not the canonical compact form")

    # The signed payload keeps its canonical bound form (evidence rides
    # as hex); the decoded raw evidence is returned separately so the
    # canonical bytes stay byte-identical for the HMAC check.
    return payload, signature, evidence


# -- Offline chain verification -----------------------------------------------

def _validated_policy_sequence(policies: object) -> list[dict]:
    """Validate a chain's versioned policy sequence (one more than hops)."""
    if not isinstance(policies, list):
        raise TypeError("policies must be a list")
    if not policies:
        raise ValueError("policies must be a non-empty list")
    return [_validated_decision_policy(policy) for policy in policies]


def _chain_root_policy(versioned_policy: dict) -> dict:
    """The unversioned site policy a root decision was signed under."""
    return _plain_site_policy(versioned_policy)


def _verify_chain_hop(
    successor: bytes,
    previous_view: dict,
    previous_digest: str,
    root_packet_digest: str,
    root_plan_digest: str,
    decision: bytes,
    validated_fork_policy: dict,
    old_policy: dict,
    new_policy: dict,
    validated_keyring: dict[str, list[dict]],
    moment: int,
) -> dict:
    """Verify one successor packet against its predecessor and policies."""
    payload, signature, evidence = _parse_supersede_packet(successor)

    if payload[DS_ROOT_DIGEST] != root_packet_digest:
        raise _chain_invalid("root digest does not match the chain root")
    if payload[DS_PREDECESSOR_DIGEST] != previous_digest:
        raise _chain_invalid(
            "predecessor digest does not match the previous packet"
        )
    expected_height = previous_view[DS_HEIGHT] + 1
    if payload[DS_HEIGHT] != expected_height:
        raise _chain_invalid("height must increase by exactly one")

    old_digest = _decision_policy_digest(old_policy)
    new_digest = _decision_policy_digest(new_policy)
    if previous_view["kind"] == "root":
        if not _policy_sites_threshold_matches_root(old_policy, previous_view):
            raise _chain_invalid(
                "oldPolicy sites and threshold must match the root policy"
            )
        prior_version = CONVERGENCE_DECISION_VERSION
    else:
        if old_digest != previous_view["policy_digest"]:
            raise _chain_invalid(
                "oldPolicy must equal the policy bound by the predecessor"
            )
        prior_version = previous_view[DS_POLICY_VERSION]
    old_version = old_policy[DS_POLICY_VERSION]
    if old_version != prior_version:
        raise _chain_invalid(
            "oldPolicy policyVersion must match the predecessor version"
        )
    if payload[DS_OLD_POLICY_DIGEST] != old_digest:
        raise _chain_invalid("bound oldPolicyDigest does not match")
    if payload[DS_NEW_POLICY_DIGEST] != new_digest:
        raise _chain_invalid("bound newPolicyDigest does not match")
    unchanged = (
        old_policy[CD_SITES] == new_policy[CD_SITES]
        and old_policy[CD_THRESHOLD] == new_policy[CD_THRESHOLD]
    )
    new_version = new_policy[DS_POLICY_VERSION]
    if unchanged:
        if new_version != old_version:
            raise _chain_invalid(
                "an unchanged policy must keep its policy version"
            )
    elif new_version != old_version + 1:
        raise _chain_invalid(
            "a changed policy must increment policyVersion by exactly one"
        )
    if payload[DS_POLICY_VERSION] != new_version:
        raise _chain_invalid("bound policyVersion does not match the policy")

    effective = payload[DS_EFFECTIVE_AT]
    if previous_view[DS_EFFECTIVE_AT] is not None and effective < previous_view[
        DS_EFFECTIVE_AT
    ]:
        raise _chain_invalid("effectiveAt must not move backwards")

    _assert_evidence_prefix(previous_view, evidence, unchanged)

    verdict = _recompute_convergence_verdict(
        evidence, decision, validated_fork_policy,
        _plain_site_policy(new_policy), validated_keyring, effective,
    )
    # Credentials must still be usable at the verification moment, and
    # the verdict must be the same one that was settled at effective time.
    verdict_now = _recompute_convergence_verdict(
        evidence, decision, validated_fork_policy,
        _plain_site_policy(new_policy), validated_keyring, moment,
    )
    view = {**previous_view, "root_plan_digest": root_plan_digest}
    _assert_transition(view, verdict)
    _assert_sealer_authorized(
        old_policy, new_policy, payload[VD_ISSUER], payload[KEY_VERSION]
    )

    if payload[CD_CERTIFICATES] != verdict[CD_CERTIFICATES]:
        raise _chain_invalid(
            "bound certificate digests do not match the recomputed evidence"
        )
    if payload[ITEMS] != verdict[ITEMS]:
        raise _chain_invalid(
            "bound items do not match the recomputed verdict"
        )
    if payload[STATUS] != verdict[STATUS]:
        raise _chain_invalid("bound status does not match the recomputed verdict")
    if payload[CD_COMMON] != verdict[CD_COMMON]:
        raise _chain_invalid("bound common result does not match")
    if payload[CD_COMMON_DIGEST] != verdict[CD_COMMON_DIGEST]:
        raise _chain_invalid("bound common digest does not match")
    if payload[CD_PLAN_DIGEST] != verdict[CD_PLAN_DIGEST]:
        raise _chain_invalid("bound plan digest does not match")
    if verdict_now[STATUS] != verdict[STATUS] or verdict_now[ITEMS] != verdict[
        ITEMS
    ] or verdict_now[CD_COMMON] != verdict[CD_COMMON]:
        raise AuthenticationError(
            "evidence credentials are not all usable at the verification "
            "moment"
        )

    entry = _usable_checkpoint_key(
        validated_keyring, payload[VD_ISSUER], payload[KEY_VERSION], effective
    )
    _usable_checkpoint_key(
        validated_keyring, payload[VD_ISSUER], payload[KEY_VERSION], moment
    )
    expected_signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError(
            "decision successor signature does not match"
        )

    return {
        "packet": successor,
        "view": _successor_view_from_payload(payload, evidence, root_plan_digest),
    }


def _successor_view_from_payload(
    payload: dict, evidence: list[dict], root_plan_digest: str
) -> dict:
    """Build a predecessor view from an already-verified successor."""
    return {
        "kind": "successor",
        DS_ROOT_DIGEST: payload[DS_ROOT_DIGEST],
        DS_HEIGHT: payload[DS_HEIGHT],
        STATUS: payload[STATUS],
        CD_COMMON: copy.deepcopy(payload[CD_COMMON]),
        CD_PLAN_DIGEST: payload[CD_PLAN_DIGEST],
        CD_CERTIFICATES: list(payload[CD_CERTIFICATES]),
        ITEMS: copy.deepcopy(payload[ITEMS]),
        "policy_digest": payload[DS_NEW_POLICY_DIGEST],
        DS_POLICY_VERSION: payload[DS_POLICY_VERSION],
        DS_EFFECTIVE_AT: payload[DS_EFFECTIVE_AT],
        "evidence": evidence,
        "root_plan_digest": root_plan_digest,
    }


def verify_decision_chain(
    root: bytes,
    successors: list,
    decision: bytes,
    policy: dict,
    policies: list,
    keyring: dict,
    moment: int,
) -> dict:
    """Verify one supersession chain hop by hop, entirely offline.

    ``root`` is the chain's convergence decision packet and
    ``successors`` the ordered successor packets (possibly empty for a
    height-zero chain).  ``decision`` is the original fork decision and
    ``policy`` the shared fork policy; ``policies`` is one versioned
    site policy per stage (the root policy plus one per successor), so
    its length is ``len(successors) + 1``.  The root is verified under
    the first policy's sites and threshold at the verification
    ``moment``; every successor re-recomputes its verdict from the bound
    full evidence under its new policy, checks the predecessor, root,
    height, policy-version and effective-moment bindings and the
    verdict state machine, and verifies the HMAC with a credential
    usable both at the hop's effective moment and at ``moment``.

    Returns a fresh mapping with exactly ``rootDigest``, ``headDigest``,
    ``height`` (0 for a bare root), ``policyVersion`` (the head policy's
    version, 1 for a bare root) and ``status``.  A non-bytes argument
    or wrong field type raises :class:`TypeError`; an empty value,
    duplicate id, illegal version or backwards moment raises
    :class:`ValueError`; a bad root raises
    :class:`InvalidConvergenceDecisionError`; a bad successor raises
    :class:`InvalidChainError`; a signature or credential fault raises
    :class:`AuthenticationError`.  No file is read or written and no
    input is modified.
    """
    if not isinstance(root, bytes):
        raise TypeError("root must be bytes")
    if not isinstance(successors, list):
        raise TypeError("successors must be a list")
    for index, successor in enumerate(successors):
        if not isinstance(successor, bytes):
            raise TypeError(f"successor {index} must be bytes")
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_fork_policy = _validated_fork_policy(policy)
    validated_policies = _validated_policy_sequence(policies)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    if len(validated_policies) != len(successors) + 1:
        raise ValueError(
            "policies must provide one entry per chain stage (one more than "
            "the number of successors)"
        )
    if validated_policies[0][DS_POLICY_VERSION] != 1:
        raise ValueError(
            "the root stage policy must carry policyVersion 1"
        )

    root_result = _verify_convergence_decision(
        root, decision, _chain_root_policy(validated_policies[0]),
        validated_keyring, verify_moment,
    )
    root_payload, _root_sig = _parse_convergence_decision(root)
    root_digest = hashlib.sha256(root).hexdigest()
    root_plan_digest = _root_plan_digest(root_payload)
    view = _root_decision_view(root)
    head_packet = root
    head_status = root_result[STATUS]
    head_policy_version = validated_policies[0][DS_POLICY_VERSION]

    previous_packet = root
    for index, successor in enumerate(successors):
        hop = _verify_chain_hop(
            successor, view, hashlib.sha256(previous_packet).hexdigest(),
            root_digest, root_plan_digest,
            decision, validated_fork_policy, validated_policies[index],
            validated_policies[index + 1], validated_keyring, verify_moment,
        )
        view = hop["view"]
        previous_packet = successor
        head_packet = successor
        head_status = view[STATUS]
        head_policy_version = view[DS_POLICY_VERSION]

    return {
        DS_ROOT_DIGEST: root_digest,
        DS_HEAD_DIGEST: hashlib.sha256(head_packet).hexdigest(),
        DS_HEIGHT: view[DS_HEIGHT],
        DS_POLICY_VERSION: head_policy_version,
        STATUS: head_status,
    }


# -- Offline batch verification of decision chains ----------------------------

def _validated_decision_chain_batch(items: object) -> list[dict]:
    """Validate the chain batch before any chain is verified.

    Each item holds exactly ``id`` (a non-empty str, unique across the
    batch), ``roots`` (bytes), ``successors`` (a list of bytes) and
    ``policies`` (a non-empty list).  Container/element/field type
    faults raise :class:`TypeError`; an empty list, empty or duplicate
    id or a wrong key set raises :class:`ValueError`.
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
        if set(item.keys()) != {
            ID, DS_BATCH_ROOTS, DS_BATCH_SUCCESSORS, DS_BATCH_POLICIES
        }:
            raise ValueError(
                f"{where} must contain exactly the keys 'id', 'roots', "
                "'successors' and 'policies'"
            )
        item_id = item[ID]
        if not isinstance(item_id, str):
            raise TypeError(f"{where} id must be a str")
        if item_id == "":
            raise ValueError(f"{where} id must be non-empty")
        if item_id in seen_ids:
            raise ValueError(f"duplicate id {item_id!r}")
        seen_ids.add(item_id)
        root = item[DS_BATCH_ROOTS]
        if not isinstance(root, bytes):
            raise TypeError(f"{where} root must be bytes")
        successors = item[DS_BATCH_SUCCESSORS]
        if not isinstance(successors, list):
            raise TypeError(f"{where} successors must be a list")
        for hop_index, successor in enumerate(successors):
            if not isinstance(successor, bytes):
                raise TypeError(f"{where} successor {hop_index} must be bytes")
        policies = item[DS_BATCH_POLICIES]
        if not isinstance(policies, list):
            raise TypeError(f"{where} policies must be a list")
        if not policies:
            raise ValueError(f"{where} policies must be non-empty")
        validated.append({
            ID: item_id,
            DS_BATCH_ROOTS: root,
            DS_BATCH_SUCCESSORS: list(successors),
            DS_BATCH_POLICIES: list(policies),
        })
    return validated


def _chain_edge_nodes(item: dict) -> list[str]:
    """The digest chain a batch item walks: root then each successor."""
    nodes = [hashlib.sha256(item[DS_BATCH_ROOTS]).hexdigest()]
    for successor in item[DS_BATCH_SUCCESSORS]:
        nodes.append(hashlib.sha256(successor).hexdigest())
    return nodes


def _decision_chain_item_report(
    item_id: str, status: str, error: str | None, result: dict | None
) -> dict:
    """One decision-chain batch report with the fixed key order."""
    return {
        CHECKPOINT_ITEM_ERROR: error,
        ID: item_id,
        VERDICT_ITEM_RESULT: result,
        STATUS: status,
    }


def verify_decision_chains(
    items: list, decision: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a batch of supersession chains and spot successor forks.

    Each item holds exactly a unique ``id``, its ``roots`` packet, its
    ordered ``successors`` packets and its per-stage ``policies``
    sequence.  The whole batch, fork ``decision``/``policy``, keyring
    and moment are validated before any chain runs; only these
    batch-level faults raise (container/element/field type faults
    :class:`TypeError`; an empty list, empty or duplicate id or wrong
    key set :class:`ValueError`).

    Each chain is then verified independently, in strict input order,
    through the exact :func:`verify_decision_chain` rules: one chain's
    failure never stops a later chain or changes an earlier report.
    Encoding, key-set, digest, ordering, reference, binding or
    state-machine faults report ``invalid``; signature or credential
    faults report ``unauthenticated``; a passing chain reports
    ``verified``.

    After verification, the same predecessor digest pointing at two
    distinct successor packets is a fork (a mere prefix extension --
    the same chain growing longer -- is not).  Every verified chain
    crossing a forking edge is reclassified ``conflicted`` with its
    verified result kept; invalid/unauthenticated chains are never
    reclassified.

    Returns a fresh dict with fixed keys ``items`` and ``version``
    (the integer 1); each item report carries, in this key order,
    ``error`` (null exactly when verified), ``id``, ``result`` (a fresh
    copy of the chain summary when verified, otherwise null) and
    ``status``.  No file is read or written and no input is modified.
    """
    validated_items = _validated_decision_chain_batch(items)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_fork_policy = _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")

    reports: list[dict] = []
    results: list[dict | None] = []
    for item in validated_items:
        item_id = item[ID]
        try:
            result = verify_decision_chain(
                item[DS_BATCH_ROOTS], item[DS_BATCH_SUCCESSORS], decision,
                policy, item[DS_BATCH_POLICIES], keyring, verify_moment,
            )
        except AuthenticationError as exc:
            reports.append(_decision_chain_item_report(
                item_id, _DS_VERIFY_UNAUTHENTICATED, str(exc), None
            ))
            results.append(None)
        except (InvalidConvergenceDecisionError, InvalidChainError,
                TypeError, ValueError) as exc:
            # A TypeError here is a wrong field type inside a packet;
            # the public argument types were all validated up front.
            reports.append(_decision_chain_item_report(
                item_id, _DS_VERIFY_INVALID, str(exc), None
            ))
            results.append(None)
        else:
            reports.append(_decision_chain_item_report(
                item_id, _DS_VERIFY_VERIFIED, None, result
            ))
            results.append(result)

    # Fork detection: one predecessor digest pointing at two distinct
    # successor digests, ignoring chains that did not verify.
    children: dict[str, set[str]] = {}
    for item, result in zip(validated_items, results):
        if result is None:
            continue
        nodes = _chain_edge_nodes(item)
        for upstream, downstream in zip(nodes, nodes[1:]):
            children.setdefault(upstream, set()).add(downstream)
    fork_edges = {
        upstream for upstream, digests in children.items()
        if len(digests) > 1
    }
    if fork_edges:
        for item, report, result in zip(validated_items, reports, results):
            if result is None:
                continue
            nodes = _chain_edge_nodes(item)
            if any(upstream in fork_edges for upstream in nodes[:-1]):
                report[STATUS] = _DS_CHAIN_CONFLICTED
                report[CHECKPOINT_ITEM_ERROR] = _DS_CHAIN_ERROR

    return {
        ITEMS: reports,
        VERSION: SUPERSEDE_VERSION,
    }


# -- Stable head anchors for verified, accepted, unforked chains ---------------

def seal_decision_head(
    items: list,
    target: str,
    decision: bytes,
    policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Seal a stable anchor over one target head within the batch.

    The batch is first run through the exact
    :func:`verify_decision_chains` rules.  An anchor is only sealed for
    the ``target`` chain when it is ``verified`` -- never merely
    conflicted by a fork in this batch, invalid or unauthenticated --
    and its head is ``accepted``; otherwise sealing raises
    :class:`ValueError`.  Other chains in the batch are still checked
    for forks (a fork reclassifies the target when it shares an edge)
    but their own failures do not stop the target's anchor.  The
    anchor binds that chain's root digest, head digest and height
    together with the head policy digest, the head policy version and
    the sealing moment.  The signature is the HMAC-SHA256 of the
    canonical anchor payload under the exact ``issuer``/``version``
    key, usable at ``moment``.

    Returns canonical compact UTF-8 JSON with exactly ``payload`` and
    ``signature``.  Container/field type faults raise :class:`TypeError`;
    an empty value, an unknown target id, an illegal version or a target
    that is not clean, unforked and accepted raises :class:`ValueError`;
    a signing credential fault raises :class:`AuthenticationError`.  No
    file is read or written and no input is modified.
    """
    validated_items = _validated_decision_chain_batch(items)
    if not isinstance(target, str):
        raise TypeError("target must be a str")
    if target == "":
        raise ValueError("target must be non-empty")
    target_index = None
    for position, item in enumerate(validated_items):
        if item[ID] == target:
            target_index = position
            break
    if target_index is None:
        raise ValueError(f"unknown target id {target!r}")
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    seal_moment = _fe_moment(moment, "moment")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")

    report = verify_decision_chains(
        items, decision, policy, keyring, seal_moment
    )
    # The target alone must be verified (never conflicted by a fork in
    # this batch, invalid or unauthenticated) and accepted; an unrelated
    # failing chain never stops its anchor.
    entry_report = report[ITEMS][target_index]
    if entry_report[STATUS] != _DS_VERIFY_VERIFIED:
        raise ValueError(
            "an anchor seals only a verified target with no fork"
        )
    result = entry_report[VERDICT_ITEM_RESULT]
    if result[STATUS] != CD_STATUS_ACCEPTED:
        raise ValueError("an anchor seals only an accepted head")
    target_item = validated_items[target_index]
    head_packet = (
        target_item[DS_BATCH_SUCCESSORS][-1]
        if target_item[DS_BATCH_SUCCESSORS] else target_item[DS_BATCH_ROOTS]
    )
    head_policy = _validated_decision_policy(
        target_item[DS_BATCH_POLICIES][-1]
    )
    if result[DS_HEAD_DIGEST] != hashlib.sha256(head_packet).hexdigest():
        raise ValueError("the sealed head digest does not match its packet")
    signing_entry = _usable_checkpoint_key(
        validated_keyring, issuer, version, seal_moment
    )
    payload = {
        DS_ROOT_DIGEST: result[DS_ROOT_DIGEST],
        DS_HEAD_DIGEST: result[DS_HEAD_DIGEST],
        DS_HEIGHT: result[DS_HEIGHT],
        CD_POLICY_DIGEST: _decision_policy_digest(head_policy),
        DS_POLICY_VERSION: result[DS_POLICY_VERSION],
        CP_MOMENT: seal_moment,
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        VERSION: SUPERSEDE_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact(
        {TICKET_PAYLOAD: payload, SIGNATURE: signature}
    )


def _parse_decision_anchor(raw: object) -> tuple[dict, str]:
    """Validate anchor bytes structurally into ``(payload, signature)``."""
    if not isinstance(raw, bytes):
        raise TypeError("anchor must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _anchor_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _anchor_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_anchor_keys
        )
    except json.JSONDecodeError as exc:
        raise _anchor_invalid("is not valid JSON") from exc
    if not isinstance(data, dict):
        raise TypeError("anchor must be a JSON object")
    if set(data.keys()) != _DS_ANCHOR_TOP_KEYS:
        raise _anchor_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("anchor signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _anchor_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("anchor payload must be an object")
    if set(payload.keys()) != _DS_ANCHOR_PAYLOAD_KEYS:
        raise _anchor_invalid(
            "payload must contain exactly the keys 'rootDigest', "
            "'headDigest', 'height', 'policyDigest', 'policyVersion', "
            "'moment', 'issuer', 'keyVersion' and 'version'"
        )
    for key in (DS_ROOT_DIGEST, DS_HEAD_DIGEST, CD_POLICY_DIGEST):
        value = payload[key]
        if not isinstance(value, str):
            raise TypeError(f"payload {key} must be a str")
        if not _is_digest(value):
            raise _anchor_invalid(
                f"payload {key} must be 64 lowercase hex characters"
            )
    height = payload[DS_HEIGHT]
    if isinstance(height, bool) or not isinstance(height, int):
        raise TypeError("payload height must be an int")
    if height < 0:
        raise _anchor_invalid("payload height must be non-negative")
    policy_version = payload[DS_POLICY_VERSION]
    if isinstance(policy_version, bool) or not isinstance(policy_version, int):
        raise TypeError("payload policyVersion must be an int")
    if policy_version <= 0:
        raise _anchor_invalid("payload policyVersion must be positive")
    moment = payload[CP_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("payload moment must be an int")
    if moment < 0:
        raise _anchor_invalid("payload moment must be non-negative")
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _anchor_invalid("payload issuer must be a non-empty str")
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _anchor_invalid("payload keyVersion must be positive")
    anchor_version = payload[VERSION]
    if isinstance(anchor_version, bool) or not isinstance(
        anchor_version, int
    ):
        raise TypeError("payload version must be an int")
    if anchor_version != SUPERSEDE_VERSION:
        raise _anchor_invalid("payload version must be the integer 1")
    if _checkpoint_compact(data) != raw:
        raise _anchor_invalid("encoding is not the canonical compact form")
    return payload, signature


def verify_decision_head(
    anchor: bytes,
    items: list,
    target: str,
    decision: bytes,
    policy: dict,
    keyring: dict,
    moment: int,
) -> dict:
    """Re-verify a sealed anchor against its original batch and keys.

    The anchor is checked structurally and its HMAC verified against
    the current keyring key bound to its exact issuer and version,
    usable at the verification ``moment``.  The original batch (with
    ``target`` naming the anchored chain) is then re-run through
    :func:`verify_decision_chains`; every chain must again verify with
    no fork and an accepted head, and the target chain's root digest,
    head digest, height and policy version must equal the anchor
    bindings while the bound policy digest must equal the digest of the
    target's head policy.

    Returns a fresh mapping with fixed keys ``rootDigest``,
    ``headDigest``, ``height``, ``policyDigest``, ``policyVersion`` and
    ``anchorDigest`` (the SHA-256 of the anchor bytes).  A non-bytes or
    wrong-type argument raises :class:`TypeError`; an empty value,
    duplicate or unknown target id or an illegal version raises
    :class:`ValueError`; a bad anchor raises :class:`InvalidAnchorError`;
    a batch that no longer verifies raises the underlying
    :class:`InvalidConvergenceDecisionError` or :class:`InvalidChainError`;
    a signature or credential fault raises :class:`AuthenticationError`.
    No file is read or written and no input is modified.
    """
    if not isinstance(anchor, bytes):
        raise TypeError("anchor must be bytes")
    payload, signature = _parse_decision_anchor(anchor)
    validated_items = _validated_decision_chain_batch(items)
    if not isinstance(target, str):
        raise TypeError("target must be a str")
    if target == "":
        raise ValueError("target must be non-empty")
    target_index = None
    for position, item in enumerate(validated_items):
        if item[ID] == target:
            target_index = position
            break
    if target_index is None:
        raise ValueError(f"unknown target id {target!r}")
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")

    entry = _usable_checkpoint_key(
        validated_keyring, payload[VD_ISSUER], payload[KEY_VERSION],
        verify_moment,
    )
    expected_signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError("decision head anchor signature does not match")

    report = verify_decision_chains(
        items, decision, policy, keyring, verify_moment
    )
    entry_report = report[ITEMS][target_index]
    if entry_report[STATUS] != _DS_VERIFY_VERIFIED:
        raise _anchor_invalid(
            "the anchored target no longer verifies without a fork"
        )
    result = entry_report[VERDICT_ITEM_RESULT]
    if result[STATUS] != CD_STATUS_ACCEPTED:
        raise _anchor_invalid("the anchored head is no longer accepted")
    target_item = validated_items[target_index]
    head_policy = _validated_decision_policy(
        target_item[DS_BATCH_POLICIES][-1]
    )
    head_policy_digest = _decision_policy_digest(head_policy)
    if result[DS_ROOT_DIGEST] != payload[DS_ROOT_DIGEST]:
        raise _anchor_invalid("root digest does not match the anchor")
    if result[DS_HEAD_DIGEST] != payload[DS_HEAD_DIGEST]:
        raise _anchor_invalid("head digest does not match the anchor")
    if result[DS_HEIGHT] != payload[DS_HEIGHT]:
        raise _anchor_invalid("height does not match the anchor")
    if result[DS_POLICY_VERSION] != payload[DS_POLICY_VERSION]:
        raise _anchor_invalid("policy version does not match the anchor")
    if head_policy_digest != payload[CD_POLICY_DIGEST]:
        raise _anchor_invalid("policy digest does not match the anchor")
    return {
        DS_ROOT_DIGEST: payload[DS_ROOT_DIGEST],
        DS_HEAD_DIGEST: payload[DS_HEAD_DIGEST],
        DS_HEIGHT: payload[DS_HEIGHT],
        CD_POLICY_DIGEST: head_policy_digest,
        DS_POLICY_VERSION: payload[DS_POLICY_VERSION],
        DS_ANCHOR_DIGEST: hashlib.sha256(anchor).hexdigest(),
    }


# -- Chain checkpoints over pruned prefixes ------------------------------------

DS_PACKETS = "packets"
DS_POLICY_HISTORY = "policies"
DS_CHECKPOINT_DIGEST = "checkpointDigest"

_DS_CHECKPOINT_PAYLOAD_KEYS = frozenset((
    DS_ROOT_DIGEST,
    DS_HEAD_DIGEST,
    DS_HEIGHT,
    STATUS,
    CD_COMMON_DIGEST,
    CD_PLAN_DIGEST,
    CD_POLICY_DIGEST,
    DS_POLICY_VERSION,
    DS_EFFECTIVE_AT,
    DS_PACKETS,
    DS_POLICY_HISTORY,
    DS_EVIDENCE,
    CP_MOMENT,
    VD_ISSUER,
    KEY_VERSION,
    VERSION,
))

_DS_SUFFIX_INVALID_CHECKPOINT = "invalid-checkpoint"
_DS_SUFFIX_INVALID_SUFFIX = "invalid-suffix"


class InvalidCheckpointError(ValueError):
    """A chain checkpoint packet breaks its binding contract."""


def _chain_checkpoint_invalid(message: str) -> InvalidCheckpointError:
    return InvalidCheckpointError(f"invalid chain checkpoint: {message}")


def _reject_duplicate_chain_checkpoint_keys(pairs: list[tuple]) -> dict:
    """``object_pairs_hook`` turning duplicate checkpoint keys into an error."""
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise _chain_checkpoint_invalid(
                f"duplicate key {key!r} in object"
            )
        result[key] = value
    return result


def seal_chain_checkpoint(
    items: list,
    target: str,
    decision: bytes,
    policy: dict,
    keyring: dict,
    moment: int,
    issuer: str,
    version: int,
) -> bytes:
    """Seal a pruned checkpoint over one verified, accepted chain head.

    The batch is first run through the exact
    :func:`verify_decision_chains` rules.  A checkpoint is only sealed
    for the ``target`` chain when it is ``verified`` -- never merely
    conflicted by a fork in this batch, invalid or unauthenticated --
    and its head is ``accepted``; otherwise sealing raises
    :class:`ValueError`.  Other chains in the batch are still checked
    for forks (a fork reclassifies the target when it shares an edge)
    but their own failures do not stop the target's checkpoint.

    The checkpoint binds the chain's root digest, stable head digest,
    height, head status, settlement (``commonDigest``) and plan
    digests, the head policy digest and version, the head effective
    moment and the sealing moment, and keeps the ordered packet
    digests, the per-stage policy digest history and the ordered
    evidence prefix digests; the pruned certificates and rounds are
    never carried.  The signature is the HMAC-SHA256 of the canonical
    checkpoint payload under the exact ``issuer``/``version`` key,
    usable at ``moment``.

    Returns canonical compact UTF-8 JSON with exactly ``payload`` and
    ``signature``.  Container/field type faults raise
    :class:`TypeError`; an empty value, an unknown target id, an
    illegal version or a target that is not clean, unforked and
    accepted raises :class:`ValueError`; a signing credential fault
    raises :class:`AuthenticationError`.  No file is read or written
    and no input is modified.
    """
    validated_items = _validated_decision_chain_batch(items)
    if not isinstance(target, str):
        raise TypeError("target must be a str")
    if target == "":
        raise ValueError("target must be non-empty")
    target_index = None
    for position, item in enumerate(validated_items):
        if item[ID] == target:
            target_index = position
            break
    if target_index is None:
        raise ValueError(f"unknown target id {target!r}")
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    _validated_fork_policy(policy)
    validated_keyring = _validated_keyring(keyring)
    seal_moment = _fe_moment(moment, "moment")
    if not isinstance(issuer, str):
        raise TypeError("issuer must be a str")
    if issuer == "":
        raise ValueError("issuer must be non-empty")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("version must be an int")
    if version <= 0:
        raise ValueError("version must be positive")

    report = verify_decision_chains(
        items, decision, policy, keyring, seal_moment
    )
    # The target alone must be verified (never conflicted by a fork in
    # this batch, invalid or unauthenticated) and accepted; an
    # unrelated failing chain never stops its checkpoint.
    entry_report = report[ITEMS][target_index]
    if entry_report[STATUS] != _DS_VERIFY_VERIFIED:
        raise ValueError(
            "a checkpoint seals only a verified target with no fork"
        )
    result = entry_report[VERDICT_ITEM_RESULT]
    if result[STATUS] != CD_STATUS_ACCEPTED:
        raise ValueError("a checkpoint seals only an accepted head")
    target_item = validated_items[target_index]
    root_packet = target_item[DS_BATCH_ROOTS]
    successors = target_item[DS_BATCH_SUCCESSORS]
    packet_digests = [hashlib.sha256(root_packet).hexdigest()]
    packet_digests.extend(
        hashlib.sha256(successor).hexdigest() for successor in successors
    )
    head_packet = successors[-1] if successors else root_packet
    if result[DS_HEAD_DIGEST] != hashlib.sha256(head_packet).hexdigest():
        raise ValueError(
            "the checkpoint head digest does not match its packet"
        )
    if successors:
        head_payload, _head_sig, _head_evidence = _parse_supersede_packet(
            head_packet
        )
        head_effective = head_payload[DS_EFFECTIVE_AT]
    else:
        head_payload, _head_sig = _parse_convergence_decision(head_packet)
        head_effective = None
    policy_digests = [
        _decision_policy_digest(_validated_decision_policy(stage_policy))
        for stage_policy in target_item[DS_BATCH_POLICIES]
    ]
    signing_entry = _usable_checkpoint_key(
        validated_keyring, issuer, version, seal_moment
    )
    payload = {
        DS_ROOT_DIGEST: result[DS_ROOT_DIGEST],
        DS_HEAD_DIGEST: result[DS_HEAD_DIGEST],
        DS_HEIGHT: result[DS_HEIGHT],
        STATUS: result[STATUS],
        CD_COMMON_DIGEST: head_payload[CD_COMMON_DIGEST],
        CD_PLAN_DIGEST: head_payload[CD_PLAN_DIGEST],
        CD_POLICY_DIGEST: policy_digests[-1],
        DS_POLICY_VERSION: result[DS_POLICY_VERSION],
        DS_EFFECTIVE_AT: head_effective,
        DS_PACKETS: packet_digests,
        DS_POLICY_HISTORY: policy_digests,
        DS_EVIDENCE: list(head_payload[CD_CERTIFICATES]),
        CP_MOMENT: seal_moment,
        VD_ISSUER: issuer,
        KEY_VERSION: version,
        VERSION: SUPERSEDE_VERSION,
    }
    signature = hmac.new(
        bytes.fromhex(signing_entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    return _checkpoint_compact(
        {TICKET_PAYLOAD: payload, SIGNATURE: signature}
    )


def _parse_chain_checkpoint(raw: object) -> tuple[dict, str]:
    """Validate checkpoint bytes structurally into ``(payload, signature)``.

    A non-bytes argument or a field of the wrong type raises
    :class:`TypeError` (a :class:`bool` never poses as an int); every
    encoding, key-set, digest, shape or cross-binding fault raises
    :class:`InvalidCheckpointError`.  The signature itself is checked
    by the suffix verifier.
    """
    if not isinstance(raw, bytes):
        raise TypeError("checkpoint must be bytes")
    if not raw or raw[-1:] in (b"\n", b"\r", b" ", b"\t"):
        raise _chain_checkpoint_invalid(
            "must end with the closing brace, no trailing byte"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _chain_checkpoint_invalid("is not valid UTF-8") from exc
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicate_chain_checkpoint_keys
        )
    except json.JSONDecodeError as exc:
        raise _chain_checkpoint_invalid("is not valid JSON") from exc
    if not isinstance(data, dict):
        raise TypeError("checkpoint must be a JSON object")
    if set(data.keys()) != _DS_TOP_KEYS:
        raise _chain_checkpoint_invalid(
            "must contain exactly the keys 'payload' and 'signature'"
        )
    signature = data[SIGNATURE]
    if not isinstance(signature, str):
        raise TypeError("checkpoint signature must be a str")
    if _HEX64.fullmatch(signature) is None:
        raise _chain_checkpoint_invalid(
            "signature must be 64 lowercase hex characters"
        )
    payload = data[TICKET_PAYLOAD]
    if not isinstance(payload, dict):
        raise TypeError("checkpoint payload must be an object")
    if set(payload.keys()) != _DS_CHECKPOINT_PAYLOAD_KEYS:
        raise _chain_checkpoint_invalid(
            "payload must contain exactly the keys 'rootDigest', "
            "'headDigest', 'height', 'status', 'commonDigest', "
            "'planDigest', 'policyDigest', 'policyVersion', 'effectiveAt', "
            "'packets', 'policies', 'evidence', 'moment', 'issuer', "
            "'keyVersion' and 'version'"
        )
    for key in (
        DS_ROOT_DIGEST, DS_HEAD_DIGEST, CD_COMMON_DIGEST, CD_PLAN_DIGEST,
        CD_POLICY_DIGEST,
    ):
        value = payload[key]
        if not isinstance(value, str):
            raise TypeError(f"payload {key} must be a str")
        if not _is_digest(value):
            raise _chain_checkpoint_invalid(
                f"payload {key} must be 64 lowercase hex characters"
            )
    height = payload[DS_HEIGHT]
    if isinstance(height, bool) or not isinstance(height, int):
        raise TypeError("payload height must be an int")
    if height < 0:
        raise _chain_checkpoint_invalid("payload height must be non-negative")
    status = payload[STATUS]
    if not isinstance(status, str):
        raise TypeError("payload status must be a str")
    if status != CD_STATUS_ACCEPTED:
        raise _chain_checkpoint_invalid(
            "payload status seals only an accepted head"
        )
    policy_version = payload[DS_POLICY_VERSION]
    if isinstance(policy_version, bool) or not isinstance(
        policy_version, int
    ):
        raise TypeError("payload policyVersion must be an int")
    if policy_version <= 0:
        raise _chain_checkpoint_invalid(
            "payload policyVersion must be positive"
        )
    effective = payload[DS_EFFECTIVE_AT]
    if effective is None:
        if height != 0:
            raise _chain_checkpoint_invalid(
                "payload effectiveAt is null only at height zero"
            )
    else:
        if isinstance(effective, bool) or not isinstance(effective, int):
            raise TypeError("payload effectiveAt must be an int or null")
        if effective < 0:
            raise _chain_checkpoint_invalid(
                "payload effectiveAt must be non-negative"
            )
        if height == 0:
            raise _chain_checkpoint_invalid(
                "payload effectiveAt must be null at height zero"
            )
    for key in (DS_PACKETS, DS_POLICY_HISTORY, DS_EVIDENCE):
        digests = payload[key]
        if not isinstance(digests, list):
            raise TypeError(f"payload {key} must be a list")
        if not digests:
            raise _chain_checkpoint_invalid(f"payload {key} must be non-empty")
        for position, digest in enumerate(digests):
            if not isinstance(digest, str):
                raise TypeError(f"payload {key} {position} must be a str")
            if not _is_digest(digest):
                raise _chain_checkpoint_invalid(
                    f"payload {key} {position} must be 64 lowercase hex "
                    "characters"
                )
    packets = payload[DS_PACKETS]
    if len(packets) != height + 1:
        raise _chain_checkpoint_invalid(
            "payload packets must hold one digest per chain packet"
        )
    if packets[0] != payload[DS_ROOT_DIGEST]:
        raise _chain_checkpoint_invalid(
            "payload packets must start at the root digest"
        )
    if packets[-1] != payload[DS_HEAD_DIGEST]:
        raise _chain_checkpoint_invalid(
            "payload packets must end at the head digest"
        )
    policies = payload[DS_POLICY_HISTORY]
    if len(policies) != height + 1:
        raise _chain_checkpoint_invalid(
            "payload policies must hold one digest per chain stage"
        )
    if policies[-1] != payload[CD_POLICY_DIGEST]:
        raise _chain_checkpoint_invalid(
            "payload policies must end at the head policy digest"
        )
    moment = payload[CP_MOMENT]
    if isinstance(moment, bool) or not isinstance(moment, int):
        raise TypeError("payload moment must be an int")
    if moment < 0:
        raise _chain_checkpoint_invalid("payload moment must be non-negative")
    issuer = payload[VD_ISSUER]
    if not isinstance(issuer, str):
        raise TypeError("payload issuer must be a str")
    if issuer == "":
        raise _chain_checkpoint_invalid(
            "payload issuer must be a non-empty str"
        )
    key_version = payload[KEY_VERSION]
    if isinstance(key_version, bool) or not isinstance(key_version, int):
        raise TypeError("payload keyVersion must be an int")
    if key_version <= 0:
        raise _chain_checkpoint_invalid("payload keyVersion must be positive")
    checkpoint_version = payload[VERSION]
    if isinstance(checkpoint_version, bool) or not isinstance(
        checkpoint_version, int
    ):
        raise TypeError("payload version must be an int")
    if checkpoint_version != SUPERSEDE_VERSION:
        raise _chain_checkpoint_invalid(
            "payload version must be the integer 1"
        )
    if _checkpoint_compact(data) != raw:
        raise _chain_checkpoint_invalid(
            "encoding is not the canonical compact form"
        )
    return payload, signature


def _checkpoint_prefix_matches(
    checkpoint_view: dict, evidence: list[dict], require_extension: bool
) -> None:
    """A suffix's first hop must extend the checkpoint's evidence digests.

    The checkpoint keeps only the ordered evidence certificate digests
    (the certificates and rounds are pruned), so the prefix is compared
    by digest: the bound evidence must cover the checkpoint prefix in
    order, and an unchanged policy must still add at least one item.
    """
    digests = checkpoint_view["evidence_digests"]
    if len(evidence) < len(digests):
        raise _chain_invalid(
            "the evidence sequence must have the checkpoint evidence as a "
            "prefix"
        )
    for position, digest in enumerate(digests):
        if hashlib.sha256(
            evidence[position][FC_CERTIFICATE]
        ).hexdigest() != digest:
            raise _chain_invalid(
                "the evidence sequence must have the checkpoint evidence as "
                "a prefix; history must not be deleted, changed or reordered"
            )
    if require_extension and len(evidence) == len(digests):
        raise _chain_invalid(
            "an unchanged policy must add at least one evidence item"
        )


def verify_chain_suffix(
    checkpoint: bytes,
    successors: list,
    policies: list,
    decision: bytes,
    policy: dict,
    keyring: dict,
    moment: int,
) -> dict:
    """Continue chain verification offline from a sealed checkpoint.

    ``checkpoint`` is a :func:`seal_chain_checkpoint` packet; it is
    checked structurally and its HMAC verified against the current
    keyring (exact issuer/version, usable at ``moment``).
    ``successors`` is the ordered list of successor packets past the
    checkpoint head (possibly empty) and ``policies`` the per-stage
    versioned policies, starting at the checkpoint head policy, so its
    length is ``len(successors) + 1``.  ``decision``, ``policy``,
    ``keyring`` and ``moment`` are the shared chain material.

    An empty suffix simply returns the sealed stable head.  Otherwise
    the first successor's predecessor digest must equal the checkpoint
    head digest, its evidence prefix count and digests must match the
    checkpoint evidence (history must not be deleted, changed or
    reordered) and every hop then follows the exact
    :func:`verify_decision_chain` root, plan, evidence-growth,
    policy-version, effective-moment and state-machine rules; a policy
    version regression is always rejected.

    Returns a fresh mapping with exactly ``rootDigest``, ``headDigest``,
    ``height``, ``policyVersion``, ``status`` and ``checkpointDigest``
    (the SHA-256 of the checkpoint bytes).  A non-bytes argument or
    wrong field type raises :class:`TypeError`; an empty value or a
    policy count mismatch raises :class:`ValueError`; a bad checkpoint
    or a stage policy that does not start at the checkpoint head policy
    raises :class:`InvalidCheckpointError`; a bad successor raises
    :class:`InvalidChainError`; a signature or credential fault raises
    :class:`AuthenticationError`.  No file is read or written and no
    input is modified.
    """
    if not isinstance(checkpoint, bytes):
        raise TypeError("checkpoint must be bytes")
    payload, signature = _parse_chain_checkpoint(checkpoint)
    if not isinstance(successors, list):
        raise TypeError("successors must be a list")
    for index, successor in enumerate(successors):
        if not isinstance(successor, bytes):
            raise TypeError(f"successor {index} must be bytes")
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    validated_fork_policy = _validated_fork_policy(policy)
    validated_policies = _validated_policy_sequence(policies)
    validated_keyring = _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")
    if len(validated_policies) != len(successors) + 1:
        raise ValueError(
            "policies must provide one entry per chain stage (one more "
            "than the number of successors)"
        )

    entry = _usable_checkpoint_key(
        validated_keyring, payload[VD_ISSUER], payload[KEY_VERSION],
        verify_moment,
    )
    expected_signature = hmac.new(
        bytes.fromhex(entry[SECRET]),
        _checkpoint_compact(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AuthenticationError(
            "chain checkpoint signature does not match"
        )

    head_policy = validated_policies[0]
    if _decision_policy_digest(head_policy) != payload[CD_POLICY_DIGEST]:
        raise _chain_checkpoint_invalid(
            "the stage policy sequence must start at the checkpoint head "
            "policy"
        )
    if head_policy[DS_POLICY_VERSION] != payload[DS_POLICY_VERSION]:
        raise _chain_checkpoint_invalid(
            "the stage policy sequence must start at the checkpoint head "
            "policy version"
        )

    checkpoint_digest = hashlib.sha256(checkpoint).hexdigest()
    if not successors:
        return {
            DS_ROOT_DIGEST: payload[DS_ROOT_DIGEST],
            DS_HEAD_DIGEST: payload[DS_HEAD_DIGEST],
            DS_HEIGHT: payload[DS_HEIGHT],
            DS_POLICY_VERSION: payload[DS_POLICY_VERSION],
            STATUS: payload[STATUS],
            DS_CHECKPOINT_DIGEST: checkpoint_digest,
        }

    view = {
        "kind": "checkpoint",
        DS_ROOT_DIGEST: payload[DS_ROOT_DIGEST],
        DS_HEIGHT: payload[DS_HEIGHT],
        STATUS: payload[STATUS],
        CD_COMMON_DIGEST: payload[CD_COMMON_DIGEST],
        "policy_digest": payload[CD_POLICY_DIGEST],
        DS_POLICY_VERSION: payload[DS_POLICY_VERSION],
        DS_EFFECTIVE_AT: payload[DS_EFFECTIVE_AT],
        "evidence_digests": list(payload[DS_EVIDENCE]),
    }
    head_digest = payload[DS_HEAD_DIGEST]
    for index, successor in enumerate(successors):
        hop = _verify_chain_hop(
            successor, view, head_digest, payload[DS_ROOT_DIGEST],
            payload[CD_PLAN_DIGEST], decision, validated_fork_policy,
            validated_policies[index], validated_policies[index + 1],
            validated_keyring, verify_moment,
        )
        view = hop["view"]
        head_digest = hashlib.sha256(successor).hexdigest()

    return {
        DS_ROOT_DIGEST: payload[DS_ROOT_DIGEST],
        DS_HEAD_DIGEST: head_digest,
        DS_HEIGHT: view[DS_HEIGHT],
        DS_POLICY_VERSION: view[DS_POLICY_VERSION],
        STATUS: view[STATUS],
        DS_CHECKPOINT_DIGEST: checkpoint_digest,
    }


# -- Offline batch verification of chain suffixes ------------------------------

def _validated_suffix_batch(items: object) -> list[dict]:
    """Validate the suffix batch before any item is verified.

    Each item holds exactly ``id`` (a non-empty str, unique across the
    batch), ``checkpoint`` (bytes), ``successors`` (a list of bytes)
    and ``policies`` (a non-empty list with exactly one entry per chain
    stage).  Container/element/field type faults raise
    :class:`TypeError`; an empty list, an empty or duplicate id, a
    wrong key set or a policy count mismatch raises
    :class:`ValueError`.
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
        if set(item.keys()) != {
            ID, CHECKPOINT_ITEM_CHECKPOINT, DS_BATCH_SUCCESSORS,
            DS_BATCH_POLICIES,
        }:
            raise ValueError(
                f"{where} must contain exactly the keys 'id', 'checkpoint', "
                "'successors' and 'policies'"
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
        successors = item[DS_BATCH_SUCCESSORS]
        if not isinstance(successors, list):
            raise TypeError(f"{where} successors must be a list")
        for hop_index, successor in enumerate(successors):
            if not isinstance(successor, bytes):
                raise TypeError(
                    f"{where} successor {hop_index} must be bytes"
                )
        policies = item[DS_BATCH_POLICIES]
        if not isinstance(policies, list):
            raise TypeError(f"{where} policies must be a list")
        if not policies:
            raise ValueError(f"{where} policies must be non-empty")
        if len(policies) != len(successors) + 1:
            raise ValueError(
                f"{where} policies must provide one entry per chain stage "
                "(one more than the number of successors)"
            )
        validated.append({
            ID: item_id,
            CHECKPOINT_ITEM_CHECKPOINT: checkpoint,
            DS_BATCH_SUCCESSORS: list(successors),
            DS_BATCH_POLICIES: list(policies),
        })
    return validated


def _suffix_edge_nodes(item: dict) -> list[str]:
    """The digest trajectory a suffix item walks: checkpoint then hops."""
    payload, _signature = _parse_chain_checkpoint(
        item[CHECKPOINT_ITEM_CHECKPOINT]
    )
    nodes = list(payload[DS_PACKETS])
    for successor in item[DS_BATCH_SUCCESSORS]:
        nodes.append(hashlib.sha256(successor).hexdigest())
    return nodes


def verify_chain_suffixes(
    items: list, decision: bytes, policy: dict, keyring: dict, moment: int
) -> dict:
    """Verify a batch of checkpoint continuations and spot forks.

    Each item holds exactly a unique ``id``, its ``checkpoint`` bytes,
    its ordered ``successors`` packets past the checkpoint head and its
    per-stage ``policies`` sequence (one more than the successors).
    The whole batch and the shared ``decision``/``policy``, keyring and
    moment are validated before any item runs; only these batch-level
    faults raise (container/element/field type faults
    :class:`TypeError`; an empty list, an empty or duplicate id, a
    wrong key set or a policy count mismatch :class:`ValueError`).

    Each item is then verified independently, in strict input order,
    through the exact :func:`verify_chain_suffix` rules: one item's
    failure never stops a later item or changes an earlier report, and
    each report keeps the deterministic text of the underlying error.
    A checkpoint binding fault reports ``invalid-checkpoint``, a suffix
    fault ``invalid-suffix``, a signature or credential fault
    ``unauthenticated`` and a passing item ``verified``.

    After verification, the same predecessor digest pointing at two
    distinct successor packets across the verified trajectories (the
    checkpoint's ordered packet digests followed by the suffix) is a
    fork -- a mere prefix extension, the same chain growing longer, is
    not.  Every verified item crossing a forking edge is reclassified
    ``conflicted`` with its verified result kept; failed items are
    never reclassified.

    Returns a fresh dict with fixed keys ``items`` and ``version``
    (the integer 1); each item report carries, in this key order,
    ``error`` (null exactly when verified), ``id``, ``result`` (a fresh
    copy of the suffix summary when verified, otherwise null) and
    ``status``.  No file is read or written and no input is modified.
    """
    validated_items = _validated_suffix_batch(items)
    if not isinstance(decision, bytes):
        raise TypeError("decision must be bytes")
    _validated_fork_policy(policy)
    _validated_keyring(keyring)
    verify_moment = _fe_moment(moment, "moment")

    reports: list[dict] = []
    results: list[dict | None] = []
    for item in validated_items:
        item_id = item[ID]
        try:
            result = verify_chain_suffix(
                item[CHECKPOINT_ITEM_CHECKPOINT], item[DS_BATCH_SUCCESSORS],
                item[DS_BATCH_POLICIES], decision, policy, keyring,
                verify_moment,
            )
        except AuthenticationError as exc:
            reports.append(_decision_chain_item_report(
                item_id, _DS_VERIFY_UNAUTHENTICATED, str(exc), None
            ))
            results.append(None)
        except InvalidCheckpointError as exc:
            reports.append(_decision_chain_item_report(
                item_id, _DS_SUFFIX_INVALID_CHECKPOINT, str(exc), None
            ))
            results.append(None)
        except (InvalidChainError, TypeError, ValueError) as exc:
            # A TypeError here is a wrong field type inside a packet or
            # policy; the public argument types were validated up front.
            reports.append(_decision_chain_item_report(
                item_id, _DS_SUFFIX_INVALID_SUFFIX, str(exc), None
            ))
            results.append(None)
        else:
            reports.append(_decision_chain_item_report(
                item_id, _DS_VERIFY_VERIFIED, None, result
            ))
            results.append(result)

    # Fork detection: one predecessor digest pointing at two distinct
    # successor digests, ignoring items that did not verify.
    children: dict[str, set[str]] = {}
    for item, result in zip(validated_items, results):
        if result is None:
            continue
        nodes = _suffix_edge_nodes(item)
        for upstream, downstream in zip(nodes, nodes[1:]):
            children.setdefault(upstream, set()).add(downstream)
    fork_edges = {
        upstream for upstream, digests in children.items()
        if len(digests) > 1
    }
    if fork_edges:
        for item, report, result in zip(validated_items, reports, results):
            if result is None:
                continue
            nodes = _suffix_edge_nodes(item)
            if any(upstream in fork_edges for upstream in nodes[:-1]):
                report[STATUS] = _DS_CHAIN_CONFLICTED
                report[CHECKPOINT_ITEM_ERROR] = _DS_CHAIN_ERROR

    return {
        ITEMS: reports,
        VERSION: SUPERSEDE_VERSION,
    }
