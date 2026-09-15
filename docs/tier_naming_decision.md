# Naming the tiers: a superlative cannot count, and these names are in the hash

*Decision plus the places the names are committed. Raised against parts two and
twelve; **pre-genesis**, for the reason in §1. **Scheme A is the decision taken,
and it is applied** — see §8.*

The three tiers are called **local**, **super** and **supreme**. They are also
called tier 0, tier 1 and tier 2, and the number of them is a field called
`tiers` whose value is 1, 2 or 3. That is three naming systems for one idea, and
one of them is inside the chain id.

## 1. The finding: the names are committed

This looked like a style question and is not. `proof_policy` is a field of
`ChainParams`:

```python
# chain/params.py:122
proof_policy: tuple = ((0, "mpcith"), (1, "ssh5"),
                       (2, "ssh3"))
```

`ChainParams` minus `chain_id` **is** `params_fields`, `params_fields` is in
`GenesisDocument.body()`, and `chain_id = "fin6:" + H(body)`. So the three
string literals are inside the hash the chain is named after. Renaming them
after genesis does not rename anything; it produces a different chain.

Three more sites commit the names by way of grid ids, which are strings:

| site | what commits it |
|---|---|
| `tiers.py:1576` — `grid_id="supreme"` | `CeremonyBlockHeader.grid_id` → the block hash |
| `tiers.py:1495` — `sid = f"super-{j}"` | the same, per tier-1 grid |
| `AttendanceRoll.digest`, `GridRegister.root()` | both take `grid_id` → `roll_digest` and `register_root` in the header |
| `tiers.py:1564`, `net/node.py:520` — `h_hex("view", base_seed, epoch, gid, view)` | the view seed, and therefore who is seated and who leads |

Tier-0 ids are safe: `Topology` builds them as `f"{region}-{j}"`, so they carry
a region and no tier name. Only tiers 1 and 2 hard-code the words — and the
view-seed line means changing them reseats every upper-tier ceremony that has
ever run, which is another way of saying the same thing.

**So this decision expires at genesis.** It costs a day now and is unavailable
afterwards, which is exactly the shape of every other item on the pre-genesis
list.

## 2. What is wrong with the three names

**They do not compose with a variable tier count.** `tiers` is not a constant —
it is computed per epoch:

```python
tiers = 3 if len(groups.finalised) >= 2 else 2
```

so when one tier-1 grid finalises, the tier above *"collapses onto it — which
is now the same seating rather than a special case"*. One ceremony is then
simultaneously the tier-1 grid and the tier above. At one tier the code said it
outright — *"the same ceremony is both the local one and the supreme one"* —
and the single grid ran with tier 0's proof backend *"whatever the block it ends
up emitting is called"*. Names that need a disclaimer about what a thing is
called are not naming it.

**A superlative cannot extend.** There is no word above supreme. If a fourth
level is ever wanted, the scheme has no room, and the only moves are to rename
everything — which §1 says is impossible by then — or to add a name that
undercuts the one above it.

**`local` is overloaded three ways**: the tier; the `LOCAL` preset, which is a
laptop-sized configuration and has nothing to do with tiers; and `locality.py`,
which is about partitions. `GridWorkload` is the tier; `local` in
`backend_for(0)` is the tier; `--preset local` is not.

**`super` collides with the language.** `super()` is a Python builtin, and the
tree already holds `supervisor`, `superseded`, `supersedes`, `group_root`,
`super_owner` and `block.supers` — which reads, to a Python eye, as
superclasses. `f"super-{j}"` also collides with a region genuinely named
`super`, since tier-0 ids are `{region}-{j}`.

**They rank instead of describing.** The one distinction that matters — *only
the top tier computes the global roots* — is invisible. "Supreme" says it is
important; it does not say what it does.

## 3. Two schemes

| | today | **A — the number is the name** | **B — name the job** |
|---|---|---|---|
| any tier's body | local / super / supreme grid | **grid**, qualified: "a tier-1 grid" | **grid** |
| tier 0 | local | tier 0 | **partition grid** |
| tier 1 | super | tier 1 | **aggregating grid** |
| tier 2 | supreme | **the top tier** | **root grid** |
| `proof_policy` keys | `"local"`, `"super"`, `"supreme"` | `0`, `1`, `2` | `0`, `1`, `2` |
| tier-1 / tier-2 grid ids | `"super-j"`, `"supreme"` | `"t1-j"`, `"t2"` | `"t1-j"`, `"t2"` |
| blocks | `CeremonyBlock` / `NetworkBlock` | unchanged | unchanged |

A is the smaller change and removes all three overloaded words. Its cost is
prose: *"the supreme grid is a global stall point"* becomes *"the top tier is a
global stall point"*, which is fine, but *"a tier-1 grid"* is duller than a name
and the documents are written to be read.

B keeps the documents readable and says what each tier does, at the cost of
three new words to learn and a mild redundancy with the numbers.

**Scheme A is what was chosen**, and prose says *tier 0*, *tier 1* and *the top
tier* rather than inventing three more words:

> **Numbers everywhere, and the number is the authority. The highest tier a
> network runs is "the top tier", which is a position and not a name.**

`proof_policy` is keyed by `0, 1, 2`. Grid ids are `t1-j` and `t2`. `TIER_ORDER`
is gone, replaced by `TOP_TIER = 2` and by `range(tiers)` where the validator
used to slice a tuple of names. `PhaseResult.tier` and the `behaviours` keys in
`net.json` take numbers, neither being hashed.

An integer key is also better on its own terms in a field that is inside the
chain id: `0` cannot be spelled two ways, and `("local", "mpcith")` ordered
against `("super", …)` sorts by an accident of the alphabet.

## 4. The rule, for whatever comes next

One concept, one word. The tier index is the authority and every name is a gloss
on it. No superlatives, because they cannot count. Nothing that is also a preset
name, a Python builtin, or a module name.

`grid`, `seat`, `row`, `ceremony`, `register`, `roll` and `turn` already satisfy
this and do not change.

## 5. Collateral renames

None of these is hashed; all are mechanical.

| now | proposed |
|---|---|
| `GridWorkload` | `GridWorkload` |
| `RootWorkload` | `RootWorkload` |
| `NetworkBlock.supers` | `NetworkBlock.groups` |
| `NetworkBlockHeader.group_root` | `group_root` |
| `super_owner`, `super_id` | `group_owner`, `group_id` |
| `TOP_VIEWS`, `supreme_quorum`, `supreme_members` | `TOP_VIEWS`, `top_quorum`, `top_members` |
| `status` key `tier1_grids` | `tier1_grids` |
| `TIER_ORDER` | kept, as prose only |

`LOCAL` the preset keeps its name, and stops being ambiguous the moment the
tier stops being called local.

## 6. What it costs

Roughly 540 occurrences across `chain/`, `wallet/`, `client/` and `fin6/`, and
216 across `docs/` — but the great majority are prose and mechanical
identifiers. The work that needs care is small and known:

| | |
|---|---|
| 1 | `proof_policy` keyed by int, and `backend_for(tier: int)` — **the chain-id change** |
| 2 | grid ids for tiers 1 and 2, and the view seeds that take them |
| 3 | `TIER_ORDER` demoted to prose; `PhaseResult.tier` and `behaviours` keyed by int |
| 4 | the collateral renames in §5 |
| 5 | regenerate `config/era0-7.json`, `config/mint-7.json`, `config/genesis-7.json` and the shipped document — the chain id moves, so the fixtures move with it |
| 6 | the documents, where the function words of §3 replace the old names |

A day, and the tests are the check: the suites pass or the rename was not
mechanical after all.

## 7. What this does not decide

| item | why it is open |
|---|---|
| **Whether prose gets function words at all** | §3's combination is a recommendation, not a finding. Numbers alone (scheme A) are defensible and cheaper; somebody has to prefer one. |
| **What a fourth tier would be called** | The rule makes room for one. It does not say what it is, and nothing in the design needs one today. |
| **`NetworkBlock` versus a "tier-2 block"** | The two block classes already name the two real kinds and are not renamed here, which leaves one place where the hierarchy is named by structure rather than by number. That reads well and is a deliberate exception. |
| **Grid ids are still structured strings** | `{region}-{j}`, `t1-j`, `t2` are conventions a reader must know, and they are hashed. A typed id would be better and is a larger change than this one. |

## 8. What was applied

Scheme A, in full, at `e2a76d9`+1. What moved, beyond §5's list:

| | |
|---|---|
| `proof_policy` | keyed `0, 1, 2` in every preset — **the chain id moved** |
| `backend_for(tier: int)` | and `assess()` iterates `range(tiers)` |
| `TIER_ORDER` | deleted; `TOP_TIER = 2` in its place |
| grid ids | `"supreme"` → `"t2"`, `f"super-{j}"` → `f"t1-{j}"`, and the view seed with them |
| domain separators | `"super-header"`, `"super-children"`, `"super-dropped"`, `"network-supers"` → `group-*`, `network-groups` — **block hashes moved** |
| workload classes | `name = "local"` etc. → `tier = 0`, `1`, `2` |
| `TieredEpochResult` | `.local`, `.supers`, `.supreme` → `.tier0`, `.tier1`, `.tier2` |
| fixtures | `config/mint-7.*` and `config/genesis-7.json` rebuilt; `config/era0-7.json` unchanged, because era 0 depends on the network name and the hardening parameters and not on the policy |
| prose | code comments, `docs/`, `plan/`, both READMEs |

The new chain id for the shipped seven-node document is
`fin6:ed7c42edcf9a9e66f31b8030553901b49a57b11d414cce6afed51e23ecf1821e`.

Two things deliberately did **not** change. Document *filenames* keep their
historical titles — `docs/supreme_tier_design.md` is still called that, because
renaming a file that four other documents and two code comments cite is a
separate change with no benefit to the hash. And `NetworkBlock` and
`CeremonyBlock` keep their names, per §7.
