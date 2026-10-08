# Measurement code

This directory contains the public copy of the probes and analysis used in the paper. Python 3.11 is the reference runtime. The entry points below take explicit input and output locations; run them from the repository root. The examples use a POSIX shell. The Python commands also work on Windows with suitable paths.

## Install

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-measurement.txt
```

The requirements file records the versions used to validate this public copy. `discovery_engine.py ipv4-zmap` additionally requires a Linux ZMap build with the DNS probe and raw-packet privileges. The other probes use ordinary DNS, TLS, and QUIC sockets. The paper's figure script provides the publication figures; the analysis scripts here recompute measurement summaries.

## Recompute the published results offline

The checked-in records and summaries can be analyzed directly:

```sh
OUT=/path/to/recomputed-results
python measurement/extensions/analyze_completed_rules.py --input-root data/records --summary-root data/extensions-20261005 --output "$OUT/rules"
python measurement/extensions/analyze_full_semantics.py --input-root data/records --output "$OUT/functions"
```

These commands read saved observations and send no network queries. The resulting analysis JSON files reproduce their counterparts under `data/extensions-20261005/`.

## Validate an existing resolver list

The input is UTF-8 text with one IPv4 or IPv6 address per line and no header. Use distinct addresses and omit blank lines. Choose an output directory outside the source tree:

```sh
RUN=/path/to/measurement-output
python measurement/validation/validate.py init --root "$RUN/validation" --input /path/to/resolvers.txt --vantage singapore
python measurement/validation/validate.py refresh --root "$RUN/validation" --vantage singapore
python measurement/validation/validate.py endpoints --root "$RUN/validation" --vantage singapore
python measurement/validation/validate.py summarize --root "$RUN/validation" --vantage singapore
python measurement/validation/analyze_results.py --database "$RUN/validation/evidence.sqlite" --output "$RUN/endpoint-analysis"
```

`init` copies the input and CA bundle and creates an SQLite database. `refresh` collects `_dns.resolver.arpa` SVCB replies. `endpoints` executes the Windows, Android, and macOS profiles. `summarize` exports per-profile address lists and a summary. Completed rows and endpoint observations are reused when a phase is restarted. Use a new output directory for a new measurement. `--input-seed` and `--discovery-source` record optional input provenance; they do not shuffle or modify the input.

Run the desktop DoT validation against the same database:

```sh
python measurement/validation/windows_dot_all.py --database "$RUN/validation/evidence.sqlite" --output "$RUN/dot"
```

An optional `--previous-summary /path/to/summary.json` adds a comparison with a previous `success_addresses` array.

## Discovery with ZMap and an IPv6 hitlist

IPv4 discovery first collects ordinary DNS responses and then tests their source addresses for DDR. Provide a ZMap configuration file (an empty file uses the command-line configuration) and an address-exclusion file:

```sh
python measurement/validation/discovery_engine.py ipv4-zmap --root "$RUN/discovery" --vantage singapore --zmap-binary /path/to/zmap --zmap-config /path/to/empty.conf --blocklist /path/to/blocklist.conf
python measurement/validation/discovery_engine.py ipv4-ddr --root "$RUN/discovery" --vantage singapore
```

The two processes share the same root. The DDR consumer reads completed ZMap shards as they become available. `--seed` and `--shards` default to the campaign's values, 20261003 and 256. `--zmap-rate`, `--qps`, `--workers`, and `--timeout` expose the existing measurement controls; their defaults retain the experiment configuration.

For IPv6, supply a directory containing `manifest.json` and sorted `*.txt.gz` chunks. Each gzip file contains one IPv6 address per line. The manifest records the hitlist source and preparation metadata; the scanner checks its presence. The scanner filters non-global and multicast addresses.

```sh
python measurement/validation/discovery_engine.py ipv6-ddr --root "$RUN/discovery" --ipv6-parts /path/to/hitlist-chunks --vantage singapore
python measurement/validation/discovery_engine.py status --root "$RUN/discovery"
```

The immutable discovery chunks contain compressed JSON Lines observations and `done.json` counts. A newline address list extracted from qualifying observations can be passed to the validation pipeline above. When starting with a known resolver list, use the validation pipeline directly.

## Compare client rules

The source database must contain the completed `refresh` phase. Rules use the saved SVCB responses from that database, so variants share an input population and advertisements.

```sh
python measurement/extensions/rules.py --database "$RUN/validation/evidence.sqlite" --output "$RUN/rules" --vantage singapore
python measurement/extensions/export_rule_results.py --root "$RUN/rules" --output "$RUN/exports/singapore"
```

The default engine location is the sibling `measurement/validation` directory. `--engine-root` can select another copy. The rule output contains `rules-plan.json`, `rules-summary.json`, and an SQLite database with `rule_results`. Leave `--defer-macos-r5` unset to execute all 16 variants.

The compact export has two files:

- `outcomes.jsonl.gz`: each line is `["original-IP", integer_bitmask]`.
- `export-summary.json`: `keys` maps each bit position to `[profile, variant]`; `counts`, `cohort`, `families`, and target/endpoint summaries describe the same records.

Place each site's exports below an input directory named `singapore/` and `los-angeles/`, then recompute the cross-site comparison:

```sh
python measurement/extensions/analyze_completed_rules.py --input-root "$RUN/exports" --output "$RUN/rule-analysis"
```

This produces `completed-rules-analysis.json` and hashes of the four input export files.

## Compare resolver functions

The input is a JSON array of original resolver address strings, for example `["1.1.1.1", "9.9.9.9"]`. Use the successful-address cohort for the paper's functional comparison.

```sh
python measurement/extensions/semantics.py --input /path/to/successful-addresses.json --output "$RUN/functions/singapore" --vantage singapore --mode all --preflight --rounds 3
```

`--mode all` retains every eligible profile path; `pilot` selects one representative per profile. `--preflight` requires a successful positive query before functional comparisons. The query set covers a positive answer, filtering tests, DNS64, DNSSEC, checking-disabled behavior, and NXDOMAIN. `--matrix` instead performs the GET/POST by original-IP/target-authority control.

`pairs.jsonl.gz` contains the paired records. Each row includes `spec` (original address, destination, target, protocol, profile, request settings), `test`, repetition index `round`, the `plain` and `encrypted` outcomes, and comparability/equality fields. DNS messages and normalized answers are preserved. The legacy field `A` denotes the paper's original resolver address $R_0$; `F` and `T` denote destination and target.

For the two-site analyzer, copy or rename each `pairs.jsonl.gz` to `full-semantics-pairs.jsonl.gz` under `singapore/` and `los-angeles/` within an input root:

```sh
python measurement/extensions/analyze_full_semantics.py --input-root "$RUN/functional-inputs" --output "$RUN/functional-analysis"
```

The stable-path calculation requires three repetitions with the same answer/RCODE transition at each site, matching the paper. It writes `full-semantics-analysis.json`.

## Outputs and TLS key logs

TLS key logs are disabled by default. Set `DDR_TLS_KEYLOG=1` explicitly to produce local `tls.keys` files; the generic `SSLKEYLOGFILE` variable is ignored by these probes. Key logs are not part of the public dataset. The validator stores generated probe artifacts in the SQLite `artifacts` table, so enabling this option also places key logs in that database. The public result exports omit that table.

Publicly shared summaries and compact rule/paired-query exports support the aggregate analyses. Native macOS capture decoding and host-control scripts are outside this code subset; the repository includes the corresponding summarized results.

## Changes from the campaign copy

- Input/output directories, the ZMap executable/configuration, and the engine location use CLI arguments rather than machine-specific paths.
- Entry points expose `--help` without starting measurement or writing outputs.
- TLS key logging is explicitly enabled through `DDR_TLS_KEYLOG=1`.
- The historical DoT comparison is optional, and the macOS certificate metadata reflects the completed native controls.
- Summary analysis reads explicit export roots. Publication figure generation remains in the paper's plotting script.

Protocol selection, address extraction, certificate checks, request construction, query contents, rate/concurrency defaults, and success/failure classification retain the campaign logic. The engine and functional transport copies differ in accepting a caller-provided DNS query for H2/H3. The public copy has passed syntax compilation and all 11 `--help` entry points. An empty-cohort workflow checks initialization, phase transitions, DoT, rule export, and functional export. Offline fixtures verify artifact storage and key-log behavior with network connections blocked. Recomputing the published rule and functional records produces JSON objects identical to both checked-in analysis summaries.
