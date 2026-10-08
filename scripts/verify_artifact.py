"""Check frozen figure evidence and generated PDF manifests offline.

Uses only the Python standard library; run from any working directory.
"""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'
PROFILES = ('windows', 'android', 'macos')


def check(condition, description):
    if not condition:
        raise ValueError(description)


def load(name):
    return json.loads((DATA / name).read_text(encoding='utf-8'))


def main():
    hashes = (DATA / 'SHA256SUMS').read_text(encoding='utf-8').splitlines()
    for line in hashes:
        digest, relative = line.split('  ', 1)
        path = ROOT / relative
        check(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
              f'Frozen data SHA-256: {relative}')
    print(f'Frozen data: all {len(hashes)} SHA-256 hashes verified.')
    summary = load('summary.json')
    sets = {}
    for profile in PROFILES:
        sets[profile] = set().union(*(
            set((DATA / f'ipv{version}-{profile}-success-union.txt').read_text().split())
            for version in (4, 6)
        ))
    check({p: len(s) for p, s in sets.items()} ==
          {'windows': 84, 'android': 74, 'macos': 84}, 'System success-set sizes')
    check(len(set.union(*sets.values())) == 112, 'Any-system success union')
    check(len(set.intersection(*sets.values())) == 45, 'All-system intersection')
    cohort = sum(summary['cross_vantage'][f'ipv{v}']['current_svcb_cohort']['union']
                 for v in (4, 6))
    check(cohort == 351897, 'Endpoint-validation cohort')
    stages = load('los-angeles-failure-analysis.json')['stages']
    for profile in PROFILES:
        combined = Counter()
        for version in (4, 6):
            combined.update(stages[f'ipv{version}'][profile])
        check(sum(combined.values()) == 348769, f'LA stage total: {profile}')
        expected = 73 if profile == 'android' else 84
        check(combined['pass'] == expected, f'LA endpoint-validation passes: {profile}')
    print('Endpoint validation: 351,897 addresses; success union 112; intersection 45.')

    evidence = load('extensions/figure-evidence.json')
    check(evidence['cohorts'] == {'singapore': 319589, 'los-angeles': 320946},
          'Rule-comparison cohorts')
    for profile, expected in [('windows', 84), ('android', 74), ('macos', 84)]:
        baseline = evidence['rules']['comparison'][profile + '/baseline']
        check(all(baseline[site] == expected for site in ('singapore', 'los_angeles')),
              f'Rule-comparison baseline: {profile}')
    print('Rule comparison: SG 319,589; LA 320,946; baselines 84 / 74 / 84 at both sites.')

    stable = evidence['stable_dns64']
    check(stable['count'] == len(stable['paths']) == 127, 'DNS64 path count')
    counts = defaultdict(Counter)
    for path in stable['paths']:
        plain, encrypted = path['plain'], path['encrypted']
        check(plain['rcode'] == encrypted['rcode'] == 'NOERROR', 'DNS64 response codes')
        check(sum(len(rr[2]) for rr in plain['answer'] if rr[1] == 'AAAA') == 2,
              'Plaintext DNS64 synthesized answers')
        check(not encrypted['answer'], 'Encrypted DNS64 empty answers')
        counts[path['key'][1]][path['key'][5]] += 1
    expected_paths = {
        '208.67.220.64': {'h2': 24, 'dot': 8},
        '208.67.222.64': {'h2': 24, 'dot': 8},
        '2620:119:35::64': {'h2': 24, 'dot': 8},
        '2620:119:53::64': {'h2': 23, 'dot': 8},
    }
    check(dict(counts) == expected_paths, 'DNS64 per-address protocol counts')
    check(stable['protocols'] == {'h2': 95, 'dot': 32}, 'DNS64 protocol totals')
    print('Public DNS64: four original addresses; 95 H2 + 32 DoT paths; AAAA 2 -> 0.')

    cases = {case['case']: case for case in evidence['mac']['cases']}
    for name in ('M63', 'M64', 'M65', 'M66'):
        queries = cases[name]['test_results']['v4only']
        check(len(queries) == 3 and all(q['rcode'] == '0' for q in queries),
              f'Native DNS64 repetitions and response codes: {name}')
        synthesized = sum(any(a.startswith('64:ff9b:') for a in q['addresses'])
                          for q in queries)
        check(synthesized == (0 if name == 'M65' else 3),
              f'Native DNS64 synthesized answers: {name}')
        if name == 'M65':
            check(all(not q['addresses'] for q in queries), 'M65 empty address answers')
    print('Native DNS64: M63 / M64 / M66 synthesized in 3/3; M65 NODATA in 3/3.')

    for language in ('en', 'zh'):
        folder = ROOT / 'figures' if language == 'en' else ROOT / 'zh' / 'figures'
        manifest = json.loads((folder / 'figure-manifest.json').read_text(encoding='utf-8'))
        check(manifest['vector_pdf_count'] == len(manifest['figures']) == 8,
              f'{language} figure count')
        for name, record in manifest['figures'].items():
            pdf = folder / name
            check(pdf.stat().st_size == record['bytes'], f'PDF byte count: {language}/{name}')
            digest = hashlib.sha256(pdf.read_bytes()).hexdigest()
            check(digest == record['sha256'], f'PDF SHA-256: {language}/{name}')
            check(pdf.with_suffix('.png').is_file(), f'PNG preview: {language}/{name}')
        print(f'{language}: all eight PDF hashes and PNG preview files verified.')
    print('Artifact checks passed.')


if __name__ == '__main__':
    main()
