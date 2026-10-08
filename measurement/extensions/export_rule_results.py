"""Export completed rule evidence without changing the measurement database."""
import argparse
import collections, gzip, json, pathlib, sqlite3, sys, zlib

def main(args):
    root=args.root.resolve()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    db = sqlite3.connect('file:' + str(root/'evidence.sqlite') + '?mode=ro', uri=True)
    summary = json.loads((root/'rules-summary.json').read_text())
    assert summary['complete']
    keys = [(p, k) for p, variants in json.loads((root/'rules-plan.json').read_text())['scenarios'].items() for k in variants]
    counts = collections.Counter()
    families = collections.defaultdict(collections.Counter)
    targets = collections.defaultdict(collections.Counter)
    endpoints = collections.defaultdict(set)
    examples = collections.defaultdict(list)
    binding = collections.defaultdict(collections.Counter)
    n = 0
    with gzip.open(output/'outcomes.jsonl.gz', 'wt') as out:
        for blob, in db.execute('SELECT data FROM rule_results'):
            r = json.loads(zlib.decompress(blob)); ip = r['A']; n += 1
            mask = sum((1 << i) for i, (p, k) in enumerate(keys) if r['outcomes'][p][k])
            out.write(json.dumps([ip, mask])+'\n')
            family = 'ipv6' if ':' in ip else 'ipv4'
            families['cohort'][family] += 1
            per_row = collections.defaultdict(set)
            per_binding = collections.defaultdict(set)
            for path in r['paths']:
                s = path['spec']
                if not (path['chain_target_ok'] and path['positive_dns']): continue
                assert path['http_status'] == 200
                for u in path['uses']:
                    if u['require_ip'] and not path['ip_san_ok']: continue
                    label = u['profile']+'/'+u['scenario']
                    per_row[label].add(s['T'])
                    endpoints[label].add((s['T'], s['F'], s['port'], s['protocol']))
                    per_binding[label].add('ip_san' if path['ip_san_ok'] else 'no_ip_san')
            for p, k in keys:
                label = p+'/'+k
                if r['outcomes'][p][k]:
                    assert per_row[label]
                    counts[label] += 1; families[label][family] += 1
                    targets[label].update(per_row[label])
                    binding[label].update(per_binding[label])
                if k == 'baseline' and r['outcomes'][p][k] or k != 'baseline' and r['outcomes'][p][k] != r['outcomes'][p]['baseline']:
                    if len(examples[label]) < 150:
                        examples[label].append({'A': ip, 'success':r['outcomes'][p][k], 'targets':sorted(per_row[label])})
            if n % 50000 == 0: print(n, flush=True)
    assert n == summary['cohort']
    for p, k in keys: assert counts[p+'/'+k] == summary['success'].get(p,{}).get(k,0)
    result = {'cohort':n, 'keys':keys, 'counts':counts, 'families':families,
              'targets':{k:dict(v.most_common()) for k,v in targets.items()},
              'endpoints':{k:[list(x) for x in sorted(v)] for k,v in endpoints.items()},
              'binding':binding, 'examples':examples,
              'error_rows':db.execute('SELECT COUNT(*) FROM errors').fetchone()[0]}
    (output/'export-summary.json').write_text(json.dumps(result,indent=2))
    print('Export complete:', n, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, required=True, help='Completed rule measurement directory')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    main(parser.parse_args())
