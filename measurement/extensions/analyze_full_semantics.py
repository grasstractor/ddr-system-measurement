"""Reproduce semantic differences and repetition counts from saved paired replies."""
import argparse
import collections, gzip, json, pathlib

def main(args):
    CAP=args.input_root.resolve()
    OUT=args.output.resolve();OUT.mkdir(parents=True,exist_ok=True)
    all_sites={}; stable_sets={}
    for site in ['singapore','los-angeles']:
        tests=collections.defaultdict(collections.Counter)
        changed_ips=collections.defaultdict(set)
        groups=collections.defaultdict(list)
        transitions=collections.defaultdict(collections.Counter)
        originals=set()
        with gzip.open(CAP/site/'full-semantics-pairs.jsonl.gz','rt') as f:
            for r in map(json.loads,f):
                s=r['spec'];t=r['test'][0];originals.add(s['A']);c=tests[t];c['pairs']+=1
                if not r['comparable']:c['not_comparable']+=1;continue
                c['comparable']+=1
                for field in ['answer','rcode','ad']:
                    if not r[field+'_equal']:
                        c[field+'_differences']+=1;changed_ips[t+'/'+field].add(s['A'])
                key=(t,)+tuple(s.get(k) for k in ['A','F','T','port','protocol','authority','method','template','profile'])
                def sig(d):return json.dumps({k:d[k] for k in ['rcode','answer','ad']},sort_keys=True)
                p,e=r['plain']['dns'],r['encrypted']['dns']
                groups[key].append({'round':r['round'],'answer_equal':r['answer_equal'], 'rcode_equal':r['rcode_equal'], 'ad_equal':r['ad_equal'], 'plain':sig(p),'encrypted':sig(e)})
                if not r['answer_equal'] or not r['rcode_equal']:
                    label=(s['A'],t,p['rcode'],e['rcode'],s['T'])
                    transitions[label]['pairs']+=1
        stable=[];changed=[]
        for key,rows in groups.items():
            different=[r for r in rows if not r['answer_equal'] or not r['rcode_equal']]
            if not different:continue
            rounds={r['round'] for r in rows}
            bad_rounds={r['round'] for r in different}
            same_effect=len({(r['plain'],r['encrypted']) for r in different})==1
            item={'key':key,'comparable_pairs':len(rows),'different_pairs':len(different),'rounds':sorted(rounds),'different_rounds':sorted(bad_rounds),'consistent_signature':same_effect,'example':different[0]}
            changed.append(item)
            if len(rounds)==3 and rounds==bad_rounds and same_effect:stable.append(item)
        stable_sets[site]={tuple(r['key']):(r['example']['plain'],r['example']['encrypted']) for r in stable}
        all_sites[site]={'tests':dict(tests),'originals':len(originals),'changed_originals':{k:sorted(v) for k,v in changed_ips.items()},
          'stable_three_round_paths':dict(collections.Counter(r['key'][0] for r in stable)),
          'stable_three_round_originals':{t:sorted({r['key'][1] for r in stable if r['key'][0]==t}) for t in tests},
          'transitions':[{'key':k,**c} for k,c in sorted(transitions.items())], 'changed_paths':changed}
    common={k for k in stable_sets['singapore'].keys()&stable_sets['los-angeles'].keys()
            if stable_sets['singapore'][k]==stable_sets['los-angeles'][k]}
    all_sites['both_sites_stable']={'paths_by_test':dict(collections.Counter(k[0] for k in common)),
     'originals_by_test':{t:sorted({k[1] for k in common if k[0]==t}) for t in {k[0] for k in common}}}
    (OUT/'full-semantics-analysis.json').write_text(json.dumps(all_sites,ensure_ascii=False,indent=2),encoding='utf-8')
    for site,d in all_sites.items():
        print(site,json.dumps({k:v for k,v in d.items() if k not in ['changed_paths','transitions']},ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-root', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    main(parser.parse_args())
