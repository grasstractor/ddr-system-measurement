# Data and counting conventions

The data describe the October 2026 measurement from Singapore and Los Angeles.
The study contains three analysis tasks: endpoint validation, rule comparison,
and functional comparison. Each task uses the population shown below.

## Measurement units

| Task | Singapore | Los Angeles | Cross-site population |
| --- | ---: | ---: | ---: |
| Endpoint validation: qualifying SVCB addresses | 347,357 | 348,769 | Union: 351,897 |
| Rule comparison: qualifying SVCB addresses | 319,589 | 320,946 | Intersection: 316,880; union: 323,655 |
| Functional comparison: original addresses | 112 | 112 | 112 |
| Functional comparison: recorded query pairs | 32,405 | 32,428 | Kept by site |
| Functional comparison: comparable query pairs | 32,035 | 32,035 | Kept by site |

An address count refers to the original resolver IP, written as `R_0` in the
paper. Existing JSON fields named `A` mean the same original address. `F` is
the encrypted destination IP, and `T` is the SVCB target name. IPv4 and IPv6
addresses are counted separately; an address succeeds when at least one
candidate path completes the profile.

The endpoint-validation DoH success unions are Windows 84, Android 74, and
macOS 84. Their union contains 112 addresses and their three-way intersection
contains 45. Los Angeles alone has 73 Android successes in endpoint validation.
The rule-comparison baseline is 84/74/84 at both sites. Percentages use the
denominator for the corresponding task and site.

Public results execute the measured client profiles. The macOS batch profile
uses supplied hints directly; the native target-bootstrap controls are reported
separately in the paper. Windows and macOS baseline profiles require the
original IP SAN as well as trusted-chain and target-name authentication;
Android's baseline authenticates the target and restricts destinations to its
original resolver list. R5 removes the desktop original-IP SAN condition, while
R6 changes Android's destination restriction. Both retain target authentication.

## Files

All paths in this document are relative to the repository root.

| Files | Contents and use |
| --- | --- |
| `data/summary.json` | Endpoint-validation populations and per-site profile results. |
| `data/ipv{4,6}-{windows,android,macos}-success-union.txt` | Six unique-address lists used to recompute profile success sets and their intersections. |
| `data/ipv{4,6}-{any-system,all-systems}-success.txt` | Published unions and three-way intersections. |
| `data/los-angeles-failure-analysis.json` | Failure-stage counts, with an address assigned to the furthest stage reached. |
| `data/discovery-{singapore,los-angeles}-summary.json` | Discovery input sizes and response counts, including preserved run metadata. |
| `data/transport-announcements.json` | Unique-address counts for exact `dot` and `doq` ALPN advertisements. |
| `data/ip-san-summary.json` | Address sets passing the recorded certificate conditions. |
| `data/windows-dot-all-summary.json`, `data/windows-dot-all-success.txt` | Desktop DoT verification summary and its 80 successful addresses. |
| `data/windows-doh-to-dot-success.txt` | The corresponding saved DoT success list; identical to the final 80-address list. |
| `data/extensions-20261005/completed-rules-analysis.json` | Sixteen rule settings, cross-site intersections, unions, and matched-population agreement. |
| `data/extensions-20261005/{site}-rules-summary.json` | Successes, gains, and losses relative to each profile's baseline. |
| `data/extensions-20261005/{site}-export-summary.json` | Bit definitions, address-family counts, successful target groups, endpoint groups, and certificate-binding counts. |
| `data/extensions-20261005/full-semantics-analysis.json` | Query-class results and repeated answer differences. |
| `data/extensions-20261005/{site}-stage-status.json` | Completion totals and query-pair accounting. |
| `data/extensions-20261005/http-factorial-analysis.json` | GET/POST × original-IP/target-name authority controls. |
| `data/extensions/figure-evidence.json` | Frozen figure inputs, including compact native Mac results. |
| `data/records/{site}/outcomes.jsonl.gz` | One success bit mask per original address in the rule-comparison population. |
| `data/records/{site}/full-semantics-pairs.jsonl.gz` | Individual plaintext/encrypted query pairs and their response evidence. |
| `data/records/manifest.json` | Record counts, compressed sizes, and SHA-256 hashes for the four record files. |

Here `{site}` is `singapore` or `los-angeles`. Directory dates, timestamps,
seeds, and existing JSON field names preserve the original run metadata.

### Rule outcome records

Each line of `outcomes.jsonl.gz` is a JSON array:

```text
[original_resolver_ip, success_bit_mask]
```

The zero-based bit order is the `keys` array in the corresponding
`{site}-export-summary.json`. Each key is a `[profile, variant]` pair:

```text
0  windows/baseline       8  android/R2+R3
1  windows/R1            9  android/R2+R6
2  windows/R5           10  android/R3+R6
3  windows/R1+R5        11  android/R2+R3+R6
4  android/baseline     12  macos/baseline
5  android/R2           13  macos/R4
6  android/R3           14  macos/R5
7  android/R6           15  macos/R4+R5
```

For bit `i`, success is `bool(mask & (1 << i))`. These records support
recomputation of success counts, baseline gains and losses, conditional gains,
cross-site set operations, and binary agreement on the shared input population.
All sixteen counts at each site were recomputed and matched the export summary.

Target-group counts in `export-summary.json` count original addresses with a
successful path to that target. An address associated with several targets is
included in each target group.

### Functional query-pair records

Each line of `full-semantics-pairs.jsonl.gz` is one JSON object. Important fields
are:

- `spec`: original address, destination, target, port, protocol, profile,
  authority, method, and DoH template.
- `test`: `[query_class, qname, qtype, DO, CD]`.
- `round`: repetition index `0`, `1`, or `2`; this is a repeated query within
  the measurement.
- `order`: order of the plaintext and encrypted probes.
- `plain` and `encrypted`: exchange results, DNS content, timing, and the
  encrypted path's certificate and HTTP checks.
- `comparable`: both sides supplied complete matching DNS responses and the
  encrypted path passed its identity and transport conditions.
- `answer_equal`, `rcode_equal`, and `ad_equal`: comparisons for comparable
  pairs.

The positive-query prechecks are retained in repetition 0, so repetitions have
different record counts. Answer comparison removes TTL, record order, and
RRSIG records while retaining DNS answer content. RCODE and AD are compared
separately. Empty answers and negative responses remain functional outcomes.

Stable DNS64 loss covers four original addresses and 127 profile-labeled paths
that reproduce the same difference in all three repetitions at both sites.
Those paths comprise 95 H2 and 32 DoT paths. These are path counts, rather than
127 distinct original addresses.

### Native Mac controls

`data/extensions/figure-evidence.json` contains the compact `mac` object:
16 cases, 96 queries, 69 DoH queries, and 27 plaintext queries. Each case retains
its condition, query count, transport counts, API/wire agreement, and test
results. This supplies the authority-routing and DNS64 native figures.

## Figure inputs and hashes

The statistical figures require ten input files: `summary.json`,
`los-angeles-failure-analysis.json`, `extensions/figure-evidence.json`, the six
per-profile IPv4/IPv6 success lists, and `windows-dot-all-success.txt`.
The flow diagram is defined in the drawing script. Figure generation also
produces `data/derived.json`, which records recomputed intersections and totals.

`data/records/manifest.json` verifies the distributed record files. Their
compressed bytes match the original analysis-input hashes. Existing
`source_sha256` and `completed-analysis-input-sha256.json` entries retain
provenance for the source experiment artifacts.

`data/SHA256SUMS` covers all frozen data inputs. Run `python scripts/verify_artifact.py` to verify those hashes and the main figure counts. Generated `data/derived.json` is recomputed from the frozen inputs.
