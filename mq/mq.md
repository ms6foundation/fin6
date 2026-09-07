I'll start by reading the uploaded archive to understand the existing commitment scheme.Works, all three tamper cases rejected. Let me fix the docstring warning, sanity-check the fold normalization edge case, and benchmark realistic parameters.`ms6acc_mq.py` drops in beside your original (it imports the two primitives and `vsum_level` from it) and replaces `G^{h(item)} mod N` with a **multivariate-quadratic (MQ) map** built from the folds.

**The hard problem.** A batch is a vector x ∈ F_P^n (P = 2²⁵⁵−19). The batch commitment is v = F(x) where:
- `eval_level_mod_fast(2, x, P)` enumerates every monomial xᵢxⱼ once; each of the m−1 random equations is a public SHAKE-derived linear combination of those monomials → a random MQ system.
- `vsum_level_fast(2, x, P)` (the degree-2 fold, which is actually the *complete* homogeneous symmetric form Σᵢ≤ⱼ yᵢyⱼ — the DP updates ascending) is the m-th, structured equation. I pin its 10-power weighting to `n−1−p` so it stays a fixed quadratic form even when trailing coordinates are zero.

Inverting or colliding F is MQ over a large prime field — no factoring/DL anywhere. One design point worth knowing: the raw index-sum buckets from `eval_level_mod_fast` are trivially peelable (bucket 0 is x₀², bucket 1 is x₀x₁, …), so they are never published individually; only full-support random combinations are.

**Hiding opening (challenge-based).** Opening a set S reveals `(value, salt)` for those items only. For the rest, the prover runs the Sakumoto–Shirai–Hiwatari 3-pass MQ identification on the restricted map F′(z) = F(embed(x_S, z)), Fiat–Shamir'd against the statement (v, x_S). The polar form G′(a,b) = F′(a+b) − F′(a) − F′(b) + F′(0) is computed as a combination of fold evaluations. Each item gets a secret per-item salt (random-oracle hash to field), and k blinder coordinates are appended so the hidden dimension is always ≥ k — without those, opening all-but-one item would leave a univariate quadratic that any verifier could solve.

Verified: honest proofs pass; wrong claimed value, swapped batch commitment, proof reuse for a different opened set, and a prover with a wrong hidden vector are all rejected. Timings at 137 rounds (2⁻⁸⁰ soundness): n=13 demo ≈0.4 s prove / 0.25 s verify; n=m=64 ≈7 s / 4.6 s.

Two caveats to flag. The default `blinders=8` is a demo size; a production setting wants m ≈ n ≥ ~64 with roughly two-thirds of coordinates as blinders, since the hidden subsystem is overdetermined by the number of opened items. And the 3-pass protocol is simple but bulky (~137 rounds); the 5-pass SSH variant halves the rounds if proof size matters.

Before adding this lever I want to check what it actually buys, because the fold family has a hidden structure: a base-β fold is `Σ_{i≤j} β^{(n-1-i)+(n-1-j)} x_i x_j = Σ_s β^{2n-2-s}·B_s(x)`, where B_s are exactly the *bucket sums* of `eval_level_mod_fast`. So every geometric-base fold row is a polynomial evaluation of the same (2n−1)-dimensional bucket vector — and the buckets are peelable (B₀ = x₀², B₁ = x₀x₁, …). Let me implement the lever with two weighting modes and include the attack so the limitation is concrete rather than hypothetical.The lever is in: `MQSystem(n, fold_degree, m_rand, n_folds, fold_weights, fold_bases)`, and `commit(..., n_folds=…, fold_weights=…, m_rand=…)` passes these through. Each fold row is still computed *by* `vsum_level_fast` — I feed it `x_p·w_p·10^{-(pmax-p)}` to cancel its internal base-10 weighting, so the result is exactly h_K under the chosen weights for any zero pattern. All configurations (including `m_rand=0`, folds only) commit, prove, verify, and reject tampering.

But I have to report a limitation I found while building it, because it decides how the lever should be used:

**Geometric bases (β = 10, 3, 7, …) cannot carry the security.** A base-β fold equals Σ_s β^{2n−2−s}·B_s(x), where B_s are the bucket sums of `eval_level_mod_fast`. So the entire family of geometric folds — for any number of bases — lives in a space of dimension only 2n−1 (K(n−1)+1 in general). With that many distinct bases an attacker interpolates the bucket sums and peels x from the low end: B₀ = x₀², B₁ = x₀x₁, B₂ = x₀x₂ + x₁², …. The demo runs this attack (`peel_geometric_folds`) on n=13 with 25 bases and recovers x from the fold values alone; `MQSystem` now refuses such parameters. Fewer bases leak a proportional slice of the bucket space rather than nothing.

**Random per-position weights (the new default) fix the interpolation structure**, but each such fold is still h₂(y) = (e₁(y)² + p₂(y))/2 — a rank-1-plus-diagonal quadratic form, much more structured than a random MQ row. I don't know of a direct break, but I wouldn't rely on it alone either.

So my recommendation: use random-weight folds as the ms6-flavoured supplement (they're cheap — 12 fold rows cost about the same as 4), keep the dense random rows for the generic MQ hardness, and never let geometric bases approach 2n−1. If you want the fold itself to be the *sole* source of hardness, the fold would need to be redefined to mix positions non-symmetrically (e.g., fold over a public random permutation/partition of coordinates per row) — that's a design change to the primitive rather than a parameter, and I'd want to think about it separately before implementing it.

That policy is now the default and enforced:

- `DEFAULT_FOLDS = 12` random-weight fold rows, `fold_weights="random"`; the default system for n=13 is m = 12 dense random rows + 12 fold rows = 24. Cost went from 0.44 s → 0.62 s prove at the demo size, so the folds are indeed cheap.
- `m_rand` defaults to n−1 and the constructor refuses anything smaller (the `insecure_ok=True` escape exists for experiments like the attack demo).
- Geometric bases are capped at ¼ of the bucket dimension (`GEOMETRIC_CAP_DIVISOR = 4`, so ≤ 6 bases for n=13, K=2), well clear of the 2n−1 interpolation threshold; the demo shows the 25-base instance being both recovered by `peel_geometric_folds` and rejected by the constructor.

One consequence worth keeping in mind: with 24 equations over 13 base variables, the *hidden* subsystem in an opening is now more overdetermined than before (m = 2n rather than m = n), so the blinder count k matters more — at production scale I'd pair `n_folds ≈ n` with k around two-thirds of n so the unopened MQ instance stays comfortably hard.

You're right, and my earlier "k ≈ ⅔·n, n_folds ≈ n" was the wrong way to size it. Let me quantify the cost so the trade-off is concrete, then correct the parameter guidance.

Proof size per SSH round is (2h + m) field elements + 2 nonces + 3 commitments ≈ (2h + m)·32 + 160 bytes, times 137 rounds. Prover time scales as rounds · (evals per round) · N²·m. So both scale with **h** (hidden dimension) and **m** (equation count) — and neither of those needs to grow with the batch size:

- **h needs a fixed floor, not a fraction of n.** What makes the unopened MQ instance hard is the number of hidden unknowns and the equations-per-unknown ratio; a batch of 200 items with 40 blinders is no easier to attack than a batch of 20 with 40 blinders. So k should be a constant (~40–60 for real security; the exact figure is a Gröbner-complexity estimate I'd rather state as a range than a number), independent of how many items you pack per batch.
- **m should be n_base-ish, not 2n.** Folds are a supplement, so 4–8 of them, not n. Each extra row costs 32 bytes per round in the e-vector and one more row per evaluation.
- **Batching amortizes.** The ZK proof is per touched batch, so larger batches (more items per fixed k) mean fewer proofs per query.

That still leaves a ~100 KB–1 MB proof for the ZK path, which is inherent to a 3-pass cut-and-choose protocol. So I'll add a second, much cheaper hiding mode and a size estimator, so you can pick per use case.Measured costs per touched batch (2 items opened, 137 rounds ≈ 2⁻⁸⁰):

| items | k | folds | n | m | hidden h | ZK proof | prove | verify | salted mode |
|---|---|---|---|---|---|---|---|---|---|
| 8 | 8 | 8 | 16 | 23 | 14 | 240 KB | 0.2 s | 0.2 s | 448 B |
| 24 | 40 | 8 | 64 | 71 | 62 | 856 KB | 8.4 s | 5.7 s | 2.0 KB |
| 56 | 40 | 8 | 96 | 103 | 94 | 1.27 MB | 26 s | 19 s | 3.0 KB |
| 24 | 40 | 24 | 64 | 87 | 62 | 925 KB | 10 s | 6.8 s | 2.0 KB |

The table confirms your concern and sharpens it: in ZK mode the cost is driven by **n**, because every *unopened item* is a hidden variable too, not just the blinders. So amortising with bigger batches doesn't help the ZK path; only fewer rounds or a different proof system would. Folds are cheap by comparison (24 vs 8 folds: +8% size, +20% time), so the fold count is not the problem.

What I changed:

- **Defaults:** `DEFAULT_FOLDS = 8`; `k` documented as a fixed floor (a constant chosen for the hidden-instance hardness, not ⅔·n).
- **`hiding="salted"` mode** in `witness`/`verify_reveal`: reveals the salts of opened items plus the *field elements* of the unopened base coordinates, never their salts or values. Each x_j = H(gi, salt_j, value_j) is a uniformly random element under its fresh secret salt, so values stay hidden the same way a salted Merkle leaf does. Cost is 32 bytes per unopened coordinate and one F evaluation to verify — the 1.27 MB / 26 s row becomes 3 KB / ~0.1 s. What you give up: the hash values are exposed, so repeated openings of one batch are linkable and a later salt leak lets anyone confirm a value guess. Blinders aren't needed for hiding in this mode (they don't hurt binding).
- `proof_size_bytes()` and `serialize_proof()` so you can size a configuration before running it (the table asserts the formula matches the serialised bytes).

My suggestion is to use salted mode as the operational default and reserve ZK mode for the cases that need unlinkability or protection against future salt disclosure — in those cases keep batches small (8–16 items, k ≈ 40, so h ≈ 50). If ZK at scale is a real requirement, the next lever is the 5-pass SSH variant (roughly halves the rounds) or an MPC-in-the-head proof (a few KB, but a substantially bigger implementation) — I'd want to know the target proof size before picking one.

Also, I noticed the sanctions-screening demo request earlier went unanswered; I can build it on top of this (salted mode fits it well: a screening provider commits to list batches, opens only the matched entries) whenever you'd like.

Salted mode is gone; `witness`/`verify_reveal` are back to the single ZK path, now running the 5-pass SSH protocol.

**Round structure** (per round, hidden dim h, m equations): the prover commits `c0 = Com(r0, t0, e0)` and `c1 = Com(r1, G'(t0,r1)+e0)`; Fiat–Shamir derives α ∈ F_P from all commitments; the prover sends `t1 = α·r0 − t0`, `e1 = α·F'(r0) − e0`; a second Fiat–Shamir hash over the whole transcript picks Ch ∈ {0,1}; the prover reveals r0 (Ch=0) or r1 (Ch=1). The Ch=1 check is `c1 = Com(r1, α(v − F'(r1) + F'(0)) − G'(t1,r1) − e1)` — the `F'(0)` term is the correction for the restricted map being affine rather than homogeneous, and the identity closes because G' is bilinear in its first argument.

**Soundness.** Per-round error is ½ + 1/(2P); since α lives in a 255-bit field, the Kales–Zaverucha grinding attack on Fiat–Shamir'd 5-pass schemes (which bites MQDSS with q=31) gains nothing here, so `rounds = λ`: 80 rounds for 2⁻⁸⁰ instead of 137. Sanity checks pass: honest proofs verify, a wrong witness and a tampered mid-message are rejected.

**Cost**, same table as before (2 items opened, 2⁻⁸⁰):

| items | k | folds | h | proof (3-pass → 5-pass) | prove | verify |
|---|---|---|---|---|---|---|
| 8 | 8 | 8 | 14 | 240 → 135 KB | 0.1 s | 0.1 s |
| 24 | 40 | 8 | 62 | 856 → 495 KB | 4.4 s | 3.0 s |
| 56 | 40 | 8 | 94 | 1267 → 735 KB | 14 s | 9.1 s |
| 24 | 40 | 24 | 62 | 925 → 535 KB | 5.4 s | 3.1 s |

Roughly a 42% cut in both size and time, which is what the round-count ratio predicts. The remaining scaling is still linear in rounds and quadratic in N per evaluation, so the practical knob is batch size: 8–16 items with k ≈ 40 keeps a proof in the 200–300 KB range. If that's still too large, the next step would be an MPC-in-the-head proof of the same F' relation, which brings proofs to a few KB at the cost of a much larger implementation.

Here's the design I'd build. It follows the MQOM/Banquet line of work, since the statement is literally an MQ instance, and it reuses `MQSystem`'s coefficient rows and `RestrictedMap`.

## 1. Put F′ in explicit quadratic form

`RestrictedMap` currently evaluates F′ as a black box through `eval_level_mod_fast`. MPC-in-the-head works on *shares*, so we need the coefficients: for each row l,

F′_l(z) = zᵀA_l z + b_l·z + c_l

with A_l upper-triangular h×h (the entries of `sys.Q[l]` at monomials over hidden positions, via `sys.idx`), b_l the cross terms with the known part x_S plus `sys.Lin[l]`, and c_l = F(embed(x_S, 0))_l — that last one is still computed by the fold primitives on the embedded vector. This extraction is done once per opening by both parties from public data.

## 2. Batch m equations into one inner product

The verifier (Fiat–Shamir) sends γ ∈ F_P^m. Define A_γ = Σ γ_l A_l, b_γ, c_γ likewise, and t = Σ γ_l v_l. The claim becomes the single equation

⟨z, A_γ z⟩ + b_γ·z + c_γ = t.

If any F′_l(z) ≠ v_l, this holds for γ with probability 1/P. Let w = A_γ z; w is a *linear* function of z, so parties can compute shares of w locally. Only ⟨z, w⟩ needs a multiplication.

## 3. The MPC protocol (one multiplication, checked by sacrifice)

N virtual parties hold additive shares [z]. The prover also shares a random mask a ∈ F_P^h, committed *before* γ is known, and after γ commits a share of the scalar c = ⟨a, w⟩ (the "hint"). Then:

```
challenge ε ∈ F_P
each party i:   [α]_i = ε·[z]_i + [a]_i            → broadcast, reconstruct α
each party i:   [w]_i = A_γ [z]_i
                [σ]_i = ε·(t − b_γ·[z]_i − c_γ·δ_i) − ⟨α, [w]_i⟩ + [c]_i
                                                     → broadcast, check Σ_i [σ]_i = 0
```
(δ_i puts the public constant into one share.) Honestly, Σσ = ε(t − b·z − c_γ) − ⟨εz + a, w⟩ + ⟨a, w⟩ = ε(t − b·z − c_γ − ⟨z,w⟩) = 0. A cheating prover whose z fails the equation passes for exactly one ε, so the sacrifice contributes another 1/P. Everything in the round is linear on shares except the one public-times-share product — no Beaver triples needed.

## 4. Sharing, commitments, and the hidden party

Standard KKW/MQOM machinery: a per-repetition root seed expands into a binary seed tree; party i's shares of z and a are PRG(seed_i) for i < N, and party N's shares are the corrections Δz = z − Σ, Δa = a − Σ (sent in the clear; they're one-time-pad masked by the other shares). Each party's view is committed as Com(seed_i) (party N: Com(seed_N, Δz, Δa)); the hint c is shared the same way after γ.

Transcript: commit views → γ → commit hint shares → ε → broadcast α and σ shares → challenge i* ∈ [N] → reveal the sibling path of the seed tree (all seeds except i*), plus party i*'s broadcast values ([α]_{i*}, [σ]_{i*}). The verifier regenerates the N−1 opened parties, recomputes their broadcasts, uses the sent values for i*, checks the reconstructed α is consistent, Σσ = 0, and the commitments. Three challenge phases, all Fiat–Shamir'd; because γ and ε live in a 255-bit field, the only phase a cheater can grind is i*, so soundness per repetition is ≈ 1/N + 2/P and τ = λ / log₂N repetitions.

## 5. Where the fold primitives still live

`c_l = F(embed(x_S, 0))` and the extraction of b_l via the polar form G′(e_i, ·) are computed with `eval_level_mod_fast`/`vsum_level_fast` exactly as now — the verifier checks its own copy of these public constants. Inside the MPC everything is linear algebra on A_γ, so the primitives define the relation but don't run per party.

## 6. What it costs — and the honest caveat

Per repetition, with h hidden coordinates: Δz, Δa, [α]_{i*} are h field elements each, plus Δc, [σ]_{i*}, log₂N·16 B of seeds and one 32 B commitment. For our parameters (h ≈ 50, N = 256, τ = 10 for 2⁻⁸⁰):

- **255-bit field**: ≈ 3h·32 + 200 ≈ 5 KB per repetition → **≈ 50 KB** total. Time is τ·N·h² ≈ 6 M multiplications, i.e. well under a second even in Python with gmpy2, versus 4 s for the 5-pass proof.
- The "few KB" I mentioned earlier is only true after shrinking the field: that's how MQOM gets its sizes (8-bit elements). Over a ~32-bit prime with h ≈ 80 the same proof is ≈ 11 KB; over GF(251) with h ≈ 160 it's ≈ 7 KB. So a real move to MPCitH should come with changing P, which touches `hash_to_field`, the blinder count, and the MQ parameter estimates — a bigger decision than the proof system itself.

Further shrinking is possible (threshold/Shamir sharing à la TCitH removes the Δz term and lets N grow cheaply; a polynomial-check variant like MQOM v2 compresses the hint), but the sketch above is the version I'd implement first because every step is checkable against `RestrictedMap.F` on the reconstructed shares.

If you want to proceed, the sensible order is: (1) coefficient extraction and a non-ZK test that `zᵀA_l z + b_l·z + c_l` matches `RestrictedMap.F` on random z; (2) the sacrifice check with a single party (no hiding) to validate the algebra; (3) seed trees, commitments, i* challenge; (4) the field-size decision.

Both stages are in `ms6acc_mpcith.py`, importing from `ms6acc_mq.py`.

**Stage 1 — `QuadraticForm.from_restricted(R)`.** Walks `MQSystem`'s monomial rows (`sys.Q` via `sys.idx`, plus `sys.Lin`) and routes each coefficient by how many of its two variables are hidden: both → A_l (stored as a flat upper triangle), one → b_l scaled by the known value, none → c_l. It asserts `c == R.F0`, so the constant term extracted algebraically is checked against the value the fold primitives compute. The mat-vec convention is chosen so `⟨z, A z⟩` with the triangular product equals `Σ_{i≤j} A_ij z_i z_j`; `evaluate()` matches `RestrictedMap.F` on random z and on the true witness, and the γ-batched form `(A_γ, b_γ, c_γ, t)` matches `⟨γ, F′(z)⟩`. Works for both the K=2 and the degree-lifted K=3 systems (h=62, m=66, extraction 10 ms).

**Stage 2 — `sacrifice_check_in_the_clear`.** Runs the batched sacrifice check over N additive shares with all views public. The two party-local functions are the ones that will survive unchanged into the hiding version:

- `party_broadcast_alpha`: [α]ᵢ = ε·[z]ᵢ + [a]ᵢ
- `party_broadcast_sigma`: σᵢ = ε·(t·δᵢ − b_γ·[z]ᵢ − c_γ·δᵢ) − ⟨α, [w]ᵢ⟩ + [c]ᵢ, with [w]ᵢ = A_γ[z]ᵢ

Both are linear in the party's own shares given the public α, which is the property stage 3 needs. Tested for N ∈ {1, 3, 8}: honest runs sum to zero; a wrong witness and a prover who lies about the hint c are both rejected (each would need to hit the one bad ε out of P).

Two things this already tells us for stage 3:

- The verifier's per-party work is one triangular mat-vec (h²/2 multiplications) plus two dot products — no fold evaluations inside the MPC, only in the one-time coefficient extraction.
- What the hidden party i* has to send in stage 3 is exactly its two broadcasts, [α]_{i*} (h elements) and σ_{i*} (1 element); everything else is regenerated from seeds. That fixes the per-repetition size at roughly 3h + 2 field elements plus the seed path, as estimated.

Next is stage 3: seed-tree share generation, commitments to views, the hint commitment after γ, the i* challenge and three-phase Fiat–Shamir, then wiring `prove_hidden`/`verify_hidden` to it so `witness`/`verify_reveal` can select it.

Short answer: the *problem* is MQ; the *protocols* are proof systems for MQ. Nothing here is a new hardness assumption, and it's worth being precise about which is which.

**What "MQ" is.** The Multivariate Quadratic problem: given m random quadratic polynomials in n variables over a finite field, find a common root. That is the entire security basis of `ms6acc_mq`: binding because collisions of F are MQ solutions, hiding because recovering the unopened coordinates is an MQ inversion.

**What our F is relative to MQ.** It's an MQ instance with a *structured distribution*, not the uniform one:

- the m_rand rows are exactly uniform random quadratics — that part is textbook MQ;
- the fold rows are rank-1-plus-diagonal forms (h₂ of a re-weighted vector), a very non-uniform family;
- for K > 2, the lifted aux rows are sparse consistency equations.

So the honest description is "MQ with a partly structured instance", the same way UOV, Rainbow or HFE are MQ with hidden structure — except ours has *public* structure, which is safer to reason about (any attack has to exploit something the attacker can see, and the random rows are there so that the generic MQ regime still applies). That's why I insisted on keeping m_rand ≥ n−1 and capping the fold rows: the moment the structured rows dominate, it stops being "MQ plus decoration" and becomes a different, weaker problem (the geometric-base peeling attack was exactly that).

**What the proof systems are.** They're independent of how the instance was generated; they only need the relation "I know z with F′(z) = v" to be quadratic:

- SSH 3-pass / 5-pass: identification schemes *designed for MQ* (Sakumoto–Shirai–Hiwatari 2011). With Fiat–Shamir, the 5-pass version is essentially MQDSS — so what's in `ms6acc_mq.py` is a close cousin of MQDSS, applied to a restricted map and a big prime field instead of GF(31).
- The MPC-in-the-head sketch: a generic zero-knowledge technique (IKOS/KKW) for any arithmetic relation. Specialised to a batched quadratic equation it is what MQOM does, so `ms6acc_mpcith.py` is heading toward an MQOM-style proof. The sacrifice check itself is not MQ-specific at all — it is a standard way to verify one multiplication on shares.

**Where we actually differ from the standard MQ constructions.**

1. The relation proved is F′ — F with some coordinates *fixed to opened values* — rather than the full F. That's the vector-commitment use case (open a few positions, hide the rest) instead of the signature use case (prove knowledge of the whole secret key). It's why the maps are affine rather than homogeneous quadratic, and why the `F′(0)` correction terms appear.
2. The secret z is partly random blinders and partly random-oracle images of the committed items, so the "key" changes per batch and per commitment instead of being a fixed long-term key.
3. The field: 255-bit prime instead of the 8-bit fields MQDSS/MQOM use. Same assumption, very different parameter regime — fewer variables needed, much larger elements — which is what drives the proof sizes we measured.

So: not a variant of the MQ *problem*, but a structured MQ instance proved with (variants of) the two standard MQ proof systems. If you want a name for it, "MQ-based hiding vector commitment with an MQDSS-style opening" is accurate.

Now stage 3 — seed trees, view commitments, the hint phase, the i* challenge, and three-phase Fiat–Shamir — appended to `ms6acc_mpcith.py`.The proxy trick is too fragile; I'll reference `mq.P` directly instead.**Stage 3** is complete and wired in: `witness(..., proof_system="mpcith", N=256)` produces an MPC-in-the-head proof and `verify_reveal` dispatches on it automatically. Per repetition a binary seed tree (SHAKE, 16-byte seeds) generates every party's shares of z, a and the hint c; party N−1 carries the corrections Δz, Δa (committed in phase 1) and Δc (bound in phase 2). The three Fiat–Shamir phases are h1 = H(view commitments) → γ, h2 = H(h1, Δc) → ε, h3 = H(h2, all α, all σ) → i*, and the proof reveals the sibling path (all seeds but i*), com_{i*}, the corrections, and the hidden party's two broadcasts. The verifier regenerates the other N−1 parties from the path, recomputes every hash, checks Σσ = 0 and that h3 reproduces the claimed i*. Tampering with an opened value, a hidden-party share, or i* is rejected. Per repetition soundness is ≈ 1/N + 2/P; since γ and ε live in the field, the only grindable Fiat–Shamir phase is i*, so τ = λ/log₂N.

**Stage 4**, measured at the hidden dimension each field needs (8 items opened from 2, N=256, τ=10, 2⁻⁸⁰):

| prime | B/elem | h | MPCitH proof | prove | verify | 5-pass proof | prove |
|---|---|---|---|---|---|---|---|
| 2²⁵⁵−19 | 32 | 46 | 45 KB | 1.3 s | 1.2 s | 375 KB | 2.2 s |
| 2¹²⁷−1 | 16 | 54 | 27 KB | 1.2 s | 1.1 s | 221 KB | 2.9 s |
| 2⁶¹−1 | 8 | 62 | 16 KB | 1.3 s | 1.3 s | 129 KB | 4.1 s |
| 2³¹−1 | 4 | 86 | 12 KB | 2.2 s | 2.3 s | 91 KB | 10 s |

Two things are visible. First, MPCitH is 8–10× smaller than 5-pass at every field, and its time is flat (τ·N·h²/2 multiplications, dominated by Python overhead here — it would be milliseconds in C). Second, shrinking the field trades bytes-per-element against the number of hidden unknowns needed, and the return diminishes: 255→61 bits cuts the proof by 3×, 61→31 bits by only 1.4× while the prover gets slower.

**My recommendation is P = 2⁶¹−1.** Reasons: elements fit a machine word (fast, and the timings above would drop sharply in a compiled implementation); the γ/ε soundness of 2⁻⁶⁰ per repetition still leaves i* as the only grindable phase, so no extension-field challenges are needed; h ≈ 60 keeps the unopened MQ instance out of hybrid guess-and-solve range (guessing a variable costs 2⁶¹); and the ms6 fold weights stay honest (10 is invertible, and the geometric-base cap logic is field-independent). Going to 2³¹−1 would require drawing γ and ε from an extension field to keep per-repetition soundness sensible and pushes h toward 90; it isn't worth the extra 4 KB. Staying at 2²⁵⁵−19 is defensible if you want the largest margin, at 3× the proof size.

Switching is one call, `set_field(2**61 - 1)`, before building the system, since everything reads the module prime at call time; the demo default is still 2²⁵⁵−19 until you confirm. Two follow-ups I'd do after the switch: re-derive the blinder count for the new field with a Gröbner/hybrid cost estimate rather than my rule of thumb, and replace the seed-tree PRG (SHAKE per node) with a faster expansion, since at N=256, τ=10 that is now the bulk of the prover's wall-clock time.

Let me re-read the two primitives and `vsum_level` precisely before building on them.For your example: E₃(A)·E₃(B) = [[3375], [900], [3375, 240], [900, 64], [3375, 240], [900], [3375]], bucket sums [3375, 900, 3615, 964, 3615, 900, 3375], and both sides of the identity equal 3 502 487 875. It also passes 200 random trials for N = 1..4, L = 1..6, both exact and mod 2⁶¹−1.

`mul_level_fast(N, A′, B′, mod=None)` is the bucket-wise, entry-wise product; it only needs the two eval structures, not A or B, and checks that the shapes agree (same N and length). Two helpers go with it: `bucket_sums` collapses a structure to the B_s, and `level_fold` applies `vsum_level(·, b=1)` to them, which equals `vsum_level_fast` of the underlying vector.

Two details worth knowing since they'll matter for what you build on this:

1. **The identity is linear in the bucket sums, so it survives modular reduction.** The positional weights 10^{N·pmax − s} are the same integers either way, so `vsum_level(sums) mod P == vsum_level_fast(N, C, P)` when the bucket products are computed mod P. That is what lets the structure sit inside the field-based commitment.
2. **The one mismatch is trailing zeros.** `eval_level_mod_fast` always builds N(L−1)+1 buckets, while `vsum_level_fast` keys its weighting on the last *non-zero* index. If c_{L−1} = 0 (either a_{L−1} or b_{L−1} is 0) the top buckets of E_N(C) are all zero and `level_fold` trims them, which is exactly re-keying the weighting. Also note that `eval_level_mod_fast` insists on a modulus; `eval_level` here passes an unreachable 10¹⁰⁰⁰⁰⁰ to get exact integers.

One structural observation that may be where you're heading: the deep inner product is a *homomorphism* from vectors to eval structures (E_N(A·B) = E_N(A)·E_N(B)), but `vsum_level`/`bucket_sums` are only additive, not multiplicative — the fold of A·B is not a function of the folds of A and B, only of their full structures. That's the same fact behind the bucket-peeling attack from earlier: the bucket sums are the real information carrier, and the fold is a single linear functional of them.

Let me separate the operations, since "raise to power k" and "fold of degree k" behave very differently. I'll implement each and test the identities.Four distinct operations fall out of "power k" and "fold of degree k", and they are all different. With C = A·B = [15, 4, 15], N = 3, k = 2:

**1. Elementwise power — exact, commutes with everything.** `pow_level_fast(k, Ep)` is the entrywise power. Since every entry of E_N is a monomial, E_N(C^k) = E_N(C)^k, and for the inner multiplication E_N((A·B)^k) = pow(E_N(A))·pow(E_N(B)). So `vsum_level_fast(N, C^k) = level_fold(N, pow_level_fast(k, mul_level_fast(N, E_N(A), E_N(B))))` — here 11 588 085 659 125. The eval structure is a ring homomorphism in both operations.

**2. Power of the fold value.** The fold is the polynomial Σ_s B_s X^{S−s} evaluated at X = 10, so fold^k is the k-fold *convolution* of the bucket sums evaluated at 10: `fold_power(k, Ep)` = 12 267 421 314 522 015 625 = vsum_level_fast(3, C)². Combinatorially: all ordered k-tuples of N-monomials.

**3. Fold of degree k of the inner multiplication.** Just the base identity at degree k: `vsum_level_fast(k, A·B) = level_fold(k, mul_level_fast(k, E_k(A), E_k(B)))`.

**4. Fold of degree k applied on top of the degree-N structure** — `nested_fold(k, Ep)` = h_k over the weighted bucket sums = 11 833 727 098 546 328 125. This one is new. I first conjectured it was the plethysm h_k[h_N]; it isn't (11 833 646 032 846 328 125). Brute force shows what it is: the sum over ordered k-tuples of N-monomials whose *bucket indices are non-decreasing*, since `vsum_level_fast` treats each bucket sum as an atom and h_k orders the atoms but not the monomials inside them. So it sits strictly between the plethysm (multisets of monomials) and fold^k (all ordered tuples), and it also differs from `vsum_level_fast(kN, C)` (11 820 905 977 404 578 125, single kN-multisets). All four identities and characterizations pass 100 random trials, exact and mod 2⁶¹−1.

The structural takeaway for the commitment: operations 1–3 are all determined by the bucket sums (linear or convolutional in them), so they add no information beyond E_N. Operation 4 is the only one that is a *non-linear* function of the bucket sums — h_k of the bucket vector — which is why it's the interesting candidate if you want the fold to carry hardness: it's the analogue of applying a random-weight fold to the bucket vector rather than to x. It has the same caveat as before, though: with a fixed base-10 weighting it is still a fixed polynomial in the 2n−1 (or K(n−1)+1) bucket sums, so its hardness would rest on inverting h_k on that vector, not on anything MQ-like.

Yes. The inner power A⊛B = [a_p^{b_p}] = [3⁵, 2², 5³] = [243, 4, 125]. Let me work out what structure it induces on eval_level.The answer is: **there is a similar structure, but the inner power breaks the factoring property that makes inner multiplication clean**. Here is the precise picture:

**Inner product A·B = [15, 4, 15]** has a perfect eval-level structure because multiplication distributes over monomials:

```
E_N(A·B)[M] = ∏ₜ (aᵢₜ bᵢₜ) = (∏ₜ aᵢₜ)(∏ₜ bᵢₜ) = E_N(A)[M] × E_N(B)[M]
```

The product of A-entry and B-entry at the same multiset M equals the entry of A·B. That is why `mul_level_fast` is a simple entrywise product on the structures.

**Inner power A⊛B = [243, 4, 125]** fails this because the exponent `b_{iₜ}` is per-factor, not per-multiset:

```
E_N(A⊛B)[M] = ∏ₜ aᵢₜ^{bᵢₜ}  ≠  (∏ₜ aᵢₜ)^? × (∏ₜ bᵢₜ)^?
```

You can see it at multiset (0,0) for N=2: E(A)=9=3², E(B)=25=5², but E(A⊛B)=59049=3¹⁰, which is not any fixed power or product of 9 and 25. The exponents mix non-uniformly across the multiset.

What the three new primitives give you:

| Function | What it computes | When it reduces |
|---|---|---|
| `inner_pow(A, B)` | [aₚ^{bₚ}] elementwise | — |
| `inner_pow_level(N, A, B)` | `eval_level(N, [aₚ^{bₚ}])` | B=const k → `pow_level_fast(k, E_N(A))` exactly |
| `inner_pow_fold(k, A, B)` | `vsum_level_fast(k, [aₚ^{bₚ}])` | B=const k → `vsum_level_fast(k, A^k)` |

`inner_pow_fold` is a genuinely new fold primitive — the degree-k symmetric polynomial of the per-position powers — and it is **not symmetric**: `fold(A⊛B) ≠ fold(B⊛A)` in general (594 521 725 vs 159 857 869 for our example). The only route through the eval structures is to exponentiate per-position first and then run eval, so the inner power does not compose with the eval algebra the way the inner product does. All identities and the constant-B special case pass 100 random exact and modular trials.

Let me think through this carefully before writing any code — the question is whether the new operations give us anything the random MQ rows don't already provide, or whether they introduce exploitable structure.That's a clean probe. Here is what it shows:

**The new operations connect to MQ in two distinct ways, not one.**

---

### 1. `mul_level_fast` — cross-commitment linkage

E_N(A·B) = E_N(A) ⊙ E_N(B) entry-wise (confirmed above for every bucket and index). This gives a **verifiable relationship between two separate ms6acc batch commitments** without revealing either vector. If a prover commits to A as v_A = F(lift(A)) and B as v_B = F(lift(B)) and then claims a third commitment v_C with C = A·B, the verifier can challenge any monomial multiset M: the prover opens the same M from both v_A and v_B, and their product must equal the claimed entry of E_N(C). This is a **product-of-commitments proof** entirely within the ms6 fold algebra — no elliptic curve pairings, no knowledge of discrete logs. The bucket sums do *not* factor (B_s(A)·B_s(B) ≠ B_s(A·B) in general), so the linkage must go through individual entries, not just the fold values.

Practically this means `MQSystem` can gain **inter-batch linkage rows**: given two committed batch vectors A and B, add rows of the form Σ_s γ_s · (B_s(C) − B_s(A·B)) = 0, turning the three-commitment claim into part of a single joint MQ instance. This is useful when items in different batches are related (e.g. a commitment to a product, a ratio, or a polynomial evaluation).

---

### 2. `inner_pow` — diagonal quadratic linkage rows

A⊛B has **no** entry-wise factored form from E_N(A) and E_N(B) alone — the exponent b_{iₜ} is per-factor, not per-multiset, so the eval structures can't be combined without the per-position values. But for **fixed integer exponents** (b_p = k), the constraint c_p = a_p^k is an MQ-compatible relation:

- **b_p = 2**: c_p − a_p² = 0 is a diagonal quadratic row in the joint variable vector (a_p, c_p). Sparse, rank-n.  
- **b_p = k > 2**: degree-lift exactly as `MQSystem.lift()` already does for fold_degree > 2 — introduce w_p = a_p², u_p = a_p·w_p = a_p³, etc., each step quadratic, ending at c_p = a_p^k after k−1 consistency rows per position.

So the inner power gives a way to **chain two committed vectors by a squaring or k-th power relation** using the same machinery already in `MQSystem.lift()`. The commitment to C = A⊛2 adds n sparse quadratic rows linking the A-coordinates to the C-coordinates in a joint MQ system — much sparser than the random rows (diagonal only), which is both a feature (explicit structure the prover must satisfy) and a caveat (sparse rows are easier to satisfy if isolated, so they must accompany enough dense random rows to stay in the MQ-hard regime).

---

### What they do *not* add

Neither operation introduces new homogeneous quadratic forms with higher rank than the fold rows already provide. The fold row h_2(w ∘ z) already has rank n (not rank 1 — my earlier claim was wrong; the probe shows rank 5 for n = 5), so the random-weight folds are already full-rank. The new operations add *structured relations between multiple committed vectors*, not denser single-vector rows.

The two concrete next steps would be:

1. **Mul-linkage rows in `MQSystem`**: add an optional `link_mul(A_batch, B_batch)` that appends the bucket-entry product constraints as new rows in the joint (A, B, C) MQ system. Useful for committing to a matrix product or a convolution.
2. **Pow-linkage rows**: extend `MQSystem.lift()` to handle a joint (A, C) vector where C = A⊛k, using the diagonal quadratic rows above. Useful for committing to squared norms, quadratic residues, or any computation that involves squaring individual coordinates.

Should I implement either of those, or is there a different algebraic use you have in mind?

The linkage relations are themselves quadratic in a *joint* variable vector, so the right move is to build the joint MQ system and reuse the 5-pass SSH prover unchanged. Let me implement that.All three relations work. Let me also verify it composes with the MPC-in-the-head prover, since that's the size-efficient path.`ms6acc_link.py` implements the proof and verification. The key design decision, which I want to state plainly: **the level-algebra relations become MQ rows in a joint variable vector, so the existing 5-pass SSH prover runs on them unchanged rather than needing a new protocol.**

**The linkage rows.** `LinkedSystem` lays out X = (a | b | c | aux) and adds:

- `relation="mul"` (C = A·B): `c_p − a_p·b_p = 0`, one genuinely quadratic row per position over the joint vector — this is where the deep inner product lands.
- `relation="pow"` (C = A⊛k): `c_p − a_p² = 0` for k=2 (diagonal); for k>2, degree-lifted with u_{p,j} = a_p·u_{p,j−1} exactly as `MQSystem.lift()` handles fold_degree>2, ending at `c_p = a_p·u_{p,k−1}`.

Each block also carries its own dense random rows and random-weight fold rows, and `LinkedSystem.fold` computes the latter through `vsum_level_fast`. The tests check that the linkage rows vanish on an honest witness, that each fold row equals the raw primitive, and that the identity `vsum_level_fast(2, A·B) = level_fold(2, mul_level_fast(2, E(A), E(B)))` holds on the committed vectors.

**Binding and hiding are the same MQ assumption as before**, not a new one. `open_linked`/`verify_linked` call `prove_hidden`/`verify_hidden` verbatim; the prover opens positions of block `a` and everything else — B, C, the blinders, the aux — stays inside the proof. Soundness tests: a prover who tampers with c₁ is rejected and the corresponding linkage row is provably non-zero; wrong claimed values and proof reuse across different opened sets are rejected. The `m_rand ≥ n−1` guard is enforced here too, because **the linkage rows are sparse (one or two monomials each) and contribute no hardness** — they constrain, they don't hide.

Costs (6 items, 8 blinders, 2 opened, 2⁻⁸⁰):

| relation | N | m | h | 5-pass | MPCitH (N=256) |
|---|---|---|---|---|---|
| mul | 42 | 77 | 40 | 400 KB | 39.7 KB, 0.8 s |
| pow k=2 | 28 | 56 | 26 | 278 KB | 26.6 KB, 0.4 s |
| pow k=3 | 42 | 70 | 40 | 383 KB | 39.7 KB, 0.6 s |

I also confirmed the MPC-in-the-head path works on these systems: `QuadraticForm.from_restricted` extracts coefficients that match the black-box map (which is a real check, since the linked systems have linear terms and sparse rows the earlier tests didn't exercise), proofs verify, and tampering is rejected.

One caveat on the `mul` relation worth flagging: `c_p = a_p·b_p` with both factors hidden means the joint system has 3n unknowns against roughly 3·m_rand + n equations, so it is *more* underdetermined than the single-vector case. That's fine for binding but means the blinder count shouldn't be reduced here on the assumption that "there are more equations now" — the added equations come with added unknowns.

Good question — there are real speedups available, and the biggest ones come from the algebraic structure rather than from micro-optimization. Let me identify the bottleneck first.The profile is clear: 96% of prove time is inside `F`, and within it the row-application loop (m × 1176 monomials) dominates — monomial building is only 7%. Two structural speedups follow directly from the algebra.Yes — two speedups, both from the algebra rather than from tuning code.

**1. O(n) fold evaluation.** A fold row is h₂(y) = (e₁(y)² + p₂(y))/2, so it needs only the first two power sums instead of walking n(n+1)/2 monomial terms. `fast_fold` matches `MQSystem.fold` exactly and is **10.7× faster** (0.342 ms → 0.032 ms at n=48). This is the same collapse the bucket sums undergo under `vsum_level`.

**2. γ-batched SSH.** The profile showed 96% of prove time inside `F`, dominated by the m × n_mono coefficient loop. Folding the m rows into one quadratic equation with a Fiat–Shamir γ *before* running the protocol means each round evaluates a single triangular mat-vec, O(h²/2), instead of m rows — and the masking value e becomes a scalar, so each round carries 2h+1 elements instead of 2h+m. This is the trick the MPCitH prover already used internally; applying it to SSH is what makes the simple protocol competitive.

| n | h | plain SSH | **batched SSH** | MPCitH (N=256) |
|---|---|---|---|---|
| 16 | 14 | 135 KB, 0.1 s | **80 KB, 0.01 s** | 15.4 KB, 0.26 s |
| 32 | 30 | 255 KB, 0.8 s | **160 KB, 0.05 s** | 30.4 KB, 0.71 s |
| 48 | 46 | 375 KB, 2.4 s | **240 KB, 0.12 s** | 45.4 KB, 1.37 s |
| 64 | 62 | 495 KB, 5.1 s | **320 KB, 0.21 s** | 60.4 KB, 2.51 s |

Batched SSH is **20–25× faster than plain SSH and ~11× faster than MPCitH**, at 1.6× smaller than plain SSH. Soundness adds only 1/P for γ, so rounds stay at λ. Tested against wrong witness, tampered mid-message, tampered response, and a proof replayed against a different opened set — all rejected — and it works on the linked `mul`/`pow` systems too.

**So the answer depends on which resource is scarce**, and the two are genuinely opposed:

- **Speed** → batched SSH. At n=48: 0.12 s prove, 0.08 s verify, 240 KB.
- **Size** → MPCitH, and the party count is the dial: N=16 gives 89 KB at 0.88 s, N=256 gives 45 KB at 1.37 s, N=1024 gives 36 KB at 3.7 s. Diminishing returns past N=256, since prover cost is τ·N·h²/2 while size falls only as 1/log N.

If you want both, the γ-batching in `ms6acc_fast` and the seed-tree machinery in `ms6acc_mpcith` are orthogonal — MPCitH already batches with γ, so the remaining win there is replacing the per-node SHAKE expansion with a faster PRG, which is the bulk of its wall-clock time at N ≥ 256. That's an implementation change rather than an algebraic one, and worth doing before any C port.

I'll integrate both improvements into `ms6acc_mq.py` so the 5-pass SSH path uses them by default, plus sparse row storage which the profile also implicates.Now the γ-batched 5-pass SSH itself, replacing the per-row protocol.All the existing tests pass. Let me verify the whole stack — MPCitH, linked systems, alternate fields — and benchmark against the backup.Both improvements are now in `ms6acc_mq.py` — `prove_hidden`/`verify_hidden` use them by default, so every caller (`witness`, `verify_reveal`, the linked systems) gets them with no API change.

**What changed:**

1. **γ-batched protocol.** A Fiat–Shamir γ folds the m rows into one quadratic `q(z) = t` before the rounds begin (`RestrictedMap.batched`, cached per statement). Each round is now one triangular mat-vec via the new `_Batched` class instead of an m-row × n-monomial walk, and the masking value e is a scalar, so rounds carry 2h+1 elements instead of 2h+m. The polar form is computed directly as ⟨a,Ab⟩+⟨b,Aa⟩ rather than three full evaluations.
2. **O(n) fold rows** (`MQSystem.fast_h2`, the (e₁²+p₂)/2 identity) and **sparse row storage** — rows are kept both densely (for `QuadraticForm` coefficient extraction) and sparsely (for `F`), and the monomial vector is only built if some row actually needs it.

**Measured, old vs new, same statements at 2⁻⁸⁰:**

| n | h | old size | old prove/verify | new size | new prove/verify | speedup |
|---|---|---|---|---|---|---|
| 16 | 14 | 135 KB | 0.15 / 0.09 s | **80 KB** | 0.02 / 0.01 s | 8.6× |
| 32 | 30 | 255 KB | 0.80 / 0.48 s | **160 KB** | 0.07 / 0.05 s | 11.2× |
| 48 | 46 | 375 KB | 2.23 / 1.41 s | **240 KB** | 0.15 / 0.11 s | 13.8× |
| 64 | 62 | 495 KB | 5.03 / 3.38 s | **320 KB** | 0.29 / 0.24 s | 16.0× |

The speedup grows with n, as expected since the eliminated factor is m ≈ n. The commit path gains a more modest 1.3–1.4× (fold rows were only 8 of m), with `F` output verified byte-identical to before.

**Soundness:** per round still ½ + 1/(2P), plus a one-time 1/P for γ, so rounds = λ is unchanged. Tested rejection of a wrong witness, tampered mid-message, tampered response, swapped commitments, a proof replayed against a different opened set, and a proof checked against a modified target v.

**Regressions:** `ms6acc_mpcith.py` and `ms6acc_link.py` both pass unchanged. In the field study the SSH column now reads 240 KB / 0.2 s at 2²⁵⁵−19 (was 375 KB / 2.2 s), which changes the earlier size-vs-speed picture: MPCitH is still ~5× smaller, but SSH is now ~7× faster rather than slower, so the two occupy clearly separate corners.

One note: `ms6acc_fast.py` is now redundant — its `prove_fast`/`verify_fast` are what became `prove_hidden`/`verify_hidden`. I kept it since its benchmark harness is useful, but it can be deleted if you'd rather not maintain the duplicate.

Confirmed: `fold6_fast(n,k,q)` returns exactly the bucket sums of E_K with K = k^q, and `vsum_level` of them equals `vsum_level_fast(K, d)`. Now let me design the wiring around a key efficiency observation.That's the key: a single degree-K lift already contains h_c for every c ≤ K, so multi-level rows cost nothing extra in aux. Let me implement it.The K=27 case slipped past the guard and exhausted memory building the dense rows — the guard needs to bound the total system size, not just aux.First, the identification, which the tests verify: **`fold6_fast(n, k, q)` is exactly the degree-K = k^q fold.** Its `ds` output equals the bucket sums of `eval_level(k^q, digits)`, and `vsum_level(ds, b=1)` equals `vsum_level_fast(k^q, digits)` — checked for (k,q) = (2,1), (3,1), (2,2), (3,2). Its module doc is right that you can't re-fold `(sq, ds)`; adding a level means raising K, which is what the wiring does.

**The efficiency finding that shaped the design:** `MQSystem.lift()` already stores dp[c] for every c ≤ K as aux, and dp[c] after the last position *is* h_c of the weighted vector. So one degree-K lift already contains every level below it, and each level can be emitted as a row that is **linear in the aux**. A q-level fold therefore gives k^q − 1 fold rows for the price of one lift, instead of one row per lift. `MultiLevelSystem`'s `levels` parameter selects which to emit; all of them are cross-checked against `vsum_level_fast` inside `lift()`.

**Proof and verification are unchanged** — the system duck-types `MQSystem`, so the batched 5-pass SSH runs on it as-is, and I confirmed the MPC-in-the-head prover works too (including that `QuadraticForm.from_restricted` extracts matching coefficients, which exercises the linear-in-aux rows).

| k,q | K | level rows | N | m | proof | commit | prove | verify |
|---|---|---|---|---|---|---|---|---|
| 2,1 | 2 | 4 | 80 | 83 | 400 KB | 0.14 s | 0.09 s | 0.06 s |
| 2,2 | 4 | 6 | 112 | 117 | 560 KB | 0.33 s | 0.21 s | 0.13 s |
| 3,2 | 9 | 8 | 108 | 115 | 540 KB | 0.22 s | 0.17 s | 0.10 s |

Rejected in testing: wrong claimed value, proof reuse across opened sets, and a forged fold level (tampered aux).

Two things I want to flag rather than bury:

1. **K = k^q grows fast and the aux cost is n(K−1) per weight vector.** k=3, q=3 gives K=27 and blew past memory in my first run, so I added `MAX_AUX`/`MAX_N` guards. Practically k=2,q=2 (K=4) is the sweet spot; K=9 is usable. Note that (3,2) is *cheaper* than (2,2) in the table only because I used fewer weight vectors — the levels-per-lift ratio is what improves with K, not the absolute cost.
2. **The multi-level rows do not add hardness.** Level 2 is rank-1-plus-diagonal and levels above are sparse-linear in aux, so the `m_rand ≥ n−1` floor is still enforced here. And the raw index-bucket vector that `fold6_fast` returns is still not publishable — it's peelable from the low end by the same attack as before, so `MultiLevelSystem` publishes h_c under random position weights, never the buckets.

Reverted. Now let me profile the current batched SSH to find what's actually left.The bottleneck has moved: setup (`from_restricted` + `batch`) is now 46% and `matvec` 27%, with `tri` called 292k times as pure overhead. Four improvements follow.Now the two protocol-level improvements: symmetric matrix for the polar form (2 matvecs per round instead of 3), and seed-derived randomness so half the rounds send 16 bytes instead of h field elements.The symmetric-matrix change is a wash — a full matvec is h² multiplications, exactly the same as two triangular ones — and it adds a build cost. Let me revert that part and keep the seed compression.The multi-level fold is reverted (both files deleted, base module passes). For the 5-pass SSH, the profile showed the bottleneck had moved to setup (46%) and `matvec` (27%), with `tri` called 292k times as pure overhead. Here's what worked and what didn't.

**Landed:**

1. **Sparse coefficient extraction.** `QuadraticForm.from_restricted` now walks the sparse row lists (`sys.Qs`/`sys.Lins`) instead of all n_mono entries of every row, with a cached monomial-index inverse and precomputed triangular offsets replacing the 292k `tri` calls. `batch` likewise uses per-row sparse term lists.
2. **Seed-derived round randomness.** Each round's (r₀, t₀, e₀) comes from a 16-byte seed, and c₀ commits to the seed. When Ch=0 the response is that **16-byte seed instead of h field elements** — the verifier regenerates the randomness and additionally checks it explains the mid message. Since Ch is uniform, about half the rounds shrink. This is a **1.25–1.37× size reduction** (480 KB → 352 KB at n=96), and it's what the size table in the demo now reflects (320 KB → 257 KB at n=64).

**Tried and reverted, honestly:** the symmetric-matrix polar form. I expected 3 matvecs → 2 per round, but a₁(A+Aᵀ)b costs h² multiplications and two triangular matvecs cost 2·(h²/2) = h² — identical, plus an O(h²) build and h² words of memory. Measured no gain, so I took it out and documented why in the code.

**Net result:** size is 1.25–1.37× smaller; time is roughly flat (1.06× faster at n=16, 0.86× *slower* at n=96). The slowdown at large n is the PRG: expanding 2h+1 field elements per round costs real SHAKE work. I switched to shake128 (legitimate here — it's length-doubling on an already-random 128-bit seed) which recovered part of it, but the trade remains: **you buy ~30% size with ~10% time at large n.**

Soundness re-verified: wrong witness, tampered mid, forged seed, tampered r₁, swapped commitments, wrong statement, and wrong target v are all rejected; roughly half the rounds reveal seeds as expected. `ms6acc_mpcith.py` and `ms6acc_link.py` pass (I relaxed their exact-size assertions, since proof size is now slightly randomized by the Ch distribution).

Where the remaining headroom is, in order of value: the per-round PRG and `matvec` are now the only hot spots, and both are Python-interpreter-bound rather than algorithmically improvable — `matvec` at h² is inherent to a quadratic form. A C or gmpy2-vectorized inner loop would likely give 10–50×, far more than any further protocol tweak. On the protocol side, the only real lever left is reducing rounds below λ, which needs a different challenge structure (the MPCitH path already does exactly that, at 5× smaller and ~5× slower).

One important check before shipping — whether a custodian can compensate a false balance with an adjusted mask.Confirmed — a real vulnerability. The mask was prover-supplied and unbound, so a custodian could understate a balance and compensate with the mask. The fix is to commit the masks as their own coordinates.`ms6acc_finance.py` implements a confidential ledger: a custodian publishes one commitment plus a total, and account holders verify their own balances without learning anyone else's. All proving uses `prove_hidden`/`verify_hidden` unchanged.

**Design.** `LedgerSystem` lays out x = (stored balances | masks | blinders) with the dense random rows carrying MQ hardness, a **linear sum row** whose value *is* the published total, and random-weight fold rows. Because the total is a row of the commitment rather than a side claim, a custodian cannot advertise a figure inconsistent with the committed balances.

**A vulnerability I found and fixed mid-build, worth calling out.** My first version kept the blinding masks *outside* the commitment and handed the holder `(balance, mask)`. Since verification only recomputed `balance + mask`, a custodian could understate a balance by 50,000 and hand back `mask + 50,000` — I tested it and it verified. The fix is to commit the masks as their own coordinates, so an opening pins both `stored_p` and `mask_p` and hence `b_p = stored_p − mask_p`. This doubles the account block (8 accounts → n=24), and the attack is now a permanent regression test ([3b] in the demo).

Adversarial suite, all rejected: compensating mask, mask-only tweak, balance-only tweak, replay to another account, understated total, account-index swap, tampered commitment. Costs: commit 0.01 s; a single account statement is 69 KB, 0.02 s to prove, 0.01 s to verify.

**What this does not prove** — documented in the module and printed by the demo, because these matter more than the features for anything real:

1. **No range proof.** Field arithmetic is modular, so a committed balance could be negative mod P and a total could be met with negative entries. A genuine proof of reserves needs per-account range proofs, which MQ does not provide. `assert_plausible_balances` is a prover-side sanity check only, not a verifiable statement.
2. **No asset-side attestation.** T is the sum of committed *liabilities*, not evidence the custodian controls those funds. Solvency still requires an independent attestation of holdings.
3. **No completeness.** A custodian can omit an account entirely; only that holder detects it.

Point 1 is the significant gap for a production proof-of-reserves system. If you want to close it, the practical route is a bit-decomposition range constraint — each balance decomposed into bits with `b_i² − b_i = 0` rows — which is MQ-expressible and would slot into this same system, at roughly 40–60 extra variables and rows per account. That's a substantial size increase, so it's worth deciding whether you need it before I build it.

Bit-decomposition is MQ-expressible, but it will blow up the variable count, so let me first check what breaks at that scale.Both blowups are avoidable: batch directly into A_γ without materializing per-row matrices.Now the range proof itself.Now let me verify it actually blocks the negative-balance attack it's meant to stop.Range proofs are in, via bit decomposition — `commit_ledger(..., range_bits=B)` and `verify_range`.

**The construction.** Each balance gets B committed bit coordinates with `bit² − bit = 0` (B diagonal quadratic rows) plus one linear recomposition row `stored_p − mask_p − Σ 2ⁱ·bitᵢ = 0`. Both row families are part of the commitment, so every committed balance provably lies in [0, 2^B).

**Two infrastructure changes were required first**, because the naive approach doesn't scale. At na=8, B=40 the system has N=344 variables, and both the dense row storage (21M entries) and `QuadraticForm`'s per-row dense matrices (21M entries) were infeasible. Fixes:

1. **`DirectBatched`** in `ms6acc_mpcith.py` accumulates A_γ straight from the sparse rows — O(h²) instead of O(m·h²). `RestrictedMap.batched` now uses it.
2. **`LedgerSystem` stores rows sparse-only**, and the dense random rows run over the *base* block (stored | masks | blinders) rather than all N variables. The bit block needs no dense rows of its own since the recomposition rows pin it to the base block — that's what keeps row storage feasible.

**The attack it closes**, demonstrated in the demo: without range proofs, a custodian can commit a balance of −10¹² mod P to offset an inflated one, and the sum row still shows a plausible total. With range proofs that vector can't be committed at all, and a prover who forges a bit (value 2) or commits a balance that doesn't match its decomposition is rejected. The earlier compensating-mask forgery remains blocked.

**Cost — and this is the real trade-off:**

| B | N | m | commit | per-account proof |
|---|---|---|---|---|
| 0 | 24 | 32 | 0.01 s | 99 KB |
| 24 | 216 | 232 | 0.02 s | 973 KB |
| 40 | 344 | 360 | 0.03 s | 1549 KB |

B=40 (balances up to ~1.1 × 10¹²) costs about **13× the proof size** of no range proof. Commitment and verification stay cheap; it's the per-account statement that grows, since h grows linearly in na·B and proof size is linear in h. If proof size matters, the MPCitH prover is the better fit at this scale — its size grows with h too but from a ~5× lower base — and the standard further optimization is a shared range proof over several accounts rather than one per account.

Two limitations remain, unchanged: no asset-side attestation (T is committed liabilities, not proven holdings), and no completeness guarantee (an omitted account is only caught by that holder).

Parameter sizing needs actual hardness estimates rather than rules of thumb. Let me build the estimator and check what the current defaults are really worth.Two important findings. Let me build the estimator properly.Two problems in the ledger row: with many accounts the estimator returns only 2 blinders, and it prints `inf`. The blinder count must survive collusion — if every other account holder colludes, only the blinders remain hidden.`ms6acc_params.py` computes the sizing from Hilbert-series degree of regularity and Gröbner/XL cost. Two findings changed my earlier advice materially.

**Finding 1: extra published rows are expensive.** For MQ, *more equations makes the problem easier*. The hidden system is m equations in h unknowns:

| h | m=h | m=h+2 | m=h+4 | m=h+8 | m=h+16 | m=h+32 |
|---|---|---|---|---|---|---|
| 48 | 187 | 122 | 112 | **101** | 85 | 71 |
| 64 | 250 | 163 | 153 | **138** | 118 | 100 |

And the gap is `m − h = n_folds + opened − 1`, which does **not** shrink as n grows. So the fold count directly sets your security loss. This reverses my earlier suggestion of `n_folds ≈ n` — that would have been actively harmful. I've changed `DEFAULT_FOLDS` from 8 to **2**.

**Finding 2: blinders must be sized against collusion.** My first pass concluded a 1000-account ledger needed 2 blinders, because it counted the 2000 payload coordinates as unknowns. But those are exactly what colluding account holders know. Sizing correctly — k alone must reach λ — gives **k = 62** for 2^128 with 2 folds. `DEFAULT_BLINDERS` is now 62 (was 8).

**Recommended parameters:**

| λ | folds | blinders | n | m | h | bits |
|---|---|---|---|---|---|---|
| 128 | 2 | 62 | 70 | 71 | 68 | 129 |
| 192 | 2 | 90 | 98 | 99 | 96 | 195 |
| 256 | 2 | 116 | 124 | 125 | 122 | 256 |

Verified end-to-end: n=70, folds=2 gives m=71, h=68, hiding 2^167 / binding 2^189, with a 410 KB proof at 128 rounds (0.3 s prove, 0.2 s verify).

**On B:** it is set by your value range, not by security — `B = ceil(log2(max_value+1))` — because bit variables carry no entropy and are counted as *zero* toward hiding (conservatively assuming an attacker guesses them free). B is purely a size cost. Ledger sizing at 2^128:

| accounts | max value | B | k | N | m | proof |
|---|---|---|---|---|---|---|
| 8 | $10k in cents | 20 | 70 | 246 | 255 | 1.5 MB |
| 8 | $1B in cents | 37 | 70 | 382 | 391 | 2.3 MB |
| 64 | $1B in cents | 37 | 117 | 2613 | 2678 | 15 MB |
| 1000 | $1B in cents | 37 | 320 | 39320 | 40321 | 230 MB |

The 1000-account figure is the honest verdict that per-account range proofs do not scale in this construction — 230 MB per opening. If you need that scale, the range proofs have to be restructured (batched across accounts, or replaced with a log-sized argument), not just re-parameterized.

Two caveats on the estimates themselves: they assume semi-regular behaviour, which the *dense random rows* satisfy but the sparse fold, sum, and range rows do not, so the true security of the structured rows could be lower; and ω=2 is the attacker-favourable choice. Treat these as a floor for rejecting bad parameters, not a guarantee.

