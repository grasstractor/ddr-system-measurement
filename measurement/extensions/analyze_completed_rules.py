"""Compare both completed rule cohorts and compute cross-site comparisons."""
import argparse
import collections, gzip, hashlib, json, pathlib

def main(args):
    CAP=args.input_root.resolve()
    OUT=args.output.resolve();OUT.mkdir(parents=True,exist_ok=True)
    sites=['singapore','los-angeles']; exports={}; data={}; sets={}
    for site in sites:
        summary_path = args.summary_root / (site + '-export-summary.json') if args.summary_root else CAP/site/'export-summary.json'
        exports[site]=json.loads(summary_path.read_text())
        with gzip.open(CAP/site/'outcomes.jsonl.gz','rt') as f: data[site]=dict(map(json.loads,f))
        d=exports[site]; assert len(data[site])==d['cohort']
        sets[site]={p+'/'+k:{ip for ip,mask in data[site].items() if mask&(1<<i)} for i,(p,k) in enumerate(d['keys'])}
        for k,v in sets[site].items():assert len(v)==d['counts'][k]
    common=data[sites[0]].keys()&data[sites[1]].keys()
    union=data[sites[0]].keys()|data[sites[1]].keys()
    comparison={}
    for k in sets[sites[0]]:
        a,b=[sets[s][k] for s in sites]
        comparison[k]={'singapore':len(a),'los_angeles':len(b),'intersection':len(a&b),'union':len(a|b),
          'same_cohort_sg':len(a&common),'same_cohort_la':len(b&common),'same_cohort_disagree':len((a^b)&common),
          'same_cohort_agreement_pct':100*(1-len((a^b)&common)/len(common))}
    baseline_union={s:set().union(*(sets[s][p+'/baseline'] for p in ['windows','android','macos'])) for s in sites}
    result={'cohort_intersection':len(common),'cohort_union':len(union),'comparison':comparison,
     'baseline_union':{s:len(v) for s,v in baseline_union.items()},
     'baseline_windows_macos':{s:{'both':len(sets[s]['windows/baseline']&sets[s]['macos/baseline']),
     'windows_only':sorted(sets[s]['windows/baseline']-sets[s]['macos/baseline']),
     'macos_only':sorted(sets[s]['macos/baseline']-sets[s]['windows/baseline'])} for s in sites}}
    (OUT/'completed-rules-analysis.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    sources = {site + '/outcomes.jsonl.gz': CAP/site/'outcomes.jsonl.gz' for site in sites}
    sources.update({site + '/export-summary.json': args.summary_root/(site + '-export-summary.json') if args.summary_root else CAP/site/'export-summary.json' for site in sites})
    (OUT/'completed-analysis-input-sha256.json').write_text(json.dumps({name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in sources.items()},indent=2))
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Recompute rule comparisons from both site exports')
    parser.add_argument('--input-root', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--summary-root', type=pathlib.Path, help='Optional directory containing SITE-export-summary.json')
    main(parser.parse_args())
