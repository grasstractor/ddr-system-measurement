"""Summarize furthest reached stage per resolver and OS profile."""
import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import sqlite3
import zlib

def main(args):
    root=args.output.resolve();root.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect('file:'+str(args.database.resolve())+'?mode=ro',uri=True)
    probes={key:json.loads(zlib.decompress(data)) for key,data in db.execute('SELECT key,data FROM probes')}
    groups={family:{p:Counter() for p in ['windows','android','macos']} for family in ['ipv4','ipv6']}
    reasons={family:{p:Counter() for p in ['windows','android','macos']} for family in groups}
    targets=Counter()
    success_rows=[]
    for ip,data in db.execute('SELECT ip,data FROM resolvers'):
        row=json.loads(zlib.decompress(data))
        family='ipv'+str(ipaddress.ip_address(ip).version)
        targets.update(set(s['target'] for s in row['services']))
        if any(s=='pass' for s in row['profiles'].values()):
            success_rows.append(row)
        for profile,outcome in row['profiles'].items():
            checks=[s['profiles'][profile] for s in row['services']]
            if outcome!='endpoint_conditions_failed':
                groups[family][profile][outcome]+=1
                if outcome=='no_compatible_service':
                    reasons[family][profile].update(set(c.get('reason','unspecified') for c in checks))
                continue
            paths=[path for c in checks for path in c['paths']]
            stages=[]
            for path in paths:
                key=path.get('tls_evidence') or path.get('http_evidence')
                cert=probes.get(key,{})
                if path.get('certificate_ok'):
                    stages.append((5,'http_or_dns_failure'))
                elif cert.get('chain_valid') and cert.get('target_name_match') and profile!='android' and ip not in cert.get('certificate_ip_san',[]):
                    stages.append((4,'missing_original_ip_san'))
                elif cert.get('chain_valid') and not cert.get('target_name_match'):
                    stages.append((3,'target_name_mismatch'))
                elif cert.get('error_type')=='SSLCertVerificationError':
                    stages.append((2,'certificate_chain_failure'))
                else:
                    stages.append((1,'connect_or_handshake_failure'))
            groups[family][profile][max(stages)[1] if stages else 'no_path']+=1
    value={'stage_rule':'One category per IP and profile; if multiple paths fail, report furthest stage reached',
           'stages':groups,'incompatible_service_reasons':reasons,'most_announced_targets':targets.most_common(20)}
    (root/'failure-analysis.json').write_text(json.dumps(value,indent=2))
    (root/'successful-resolvers.json').write_text(json.dumps(success_rows,indent=2))
    print(json.dumps(value,indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args())
