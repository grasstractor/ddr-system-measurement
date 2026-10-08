"""Verify Windows DoT across the saved current-round SVCB cohort, deduplicating endpoints."""
import argparse,os
# Only DDR_TLS_KEYLOG explicitly enables local key-log output.
os.environ.pop('SSLKEYLOGFILE', None)
import concurrent.futures,collections,gzip,hashlib,ipaddress,json,pathlib,socket,sqlite3,ssl,struct,threading,time,zlib
import certifi,dns.message,dns.flags,dns.rdata,dns.rdataclass,dns.rdatatype
from cryptography import x509

def main(args):
    OUT=args.output.resolve();OUT.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect('file:'+str(args.database.resolve())+'?mode=ro',uri=True)
    states={};endpoints={};links=collections.defaultdict(set)
    for ip,data in db.execute("SELECT r.ip,r.data FROM resolvers r JOIN discovery d ON r.ip=d.ip WHERE d.outcome='svcb_answer'"):
        row=json.loads(zlib.decompress(data));state='no_dot_announcement';has_dot=False
        for s in row['services']:
            if 'dot' not in s['alpn']:continue
            has_dot=True
            record=dns.rdata.from_text(1,64,s['text']);params=record.params
            if record.priority==0 or s['target'] in ['.','resolver.arpa.']:continue
            if any(k not in params or k not in {0,1,2,3,4,6,7} for k in s['mandatory']):continue
            if state!='endpoint_pending':state='no_eligible_address'
            candidates=s['target_additional_addresses']+s['ipv4hint']+s['ipv6hint']
            port=params[3].port if 3 in params else 853
            if not 1<=port<=65535:continue
            for address in dict.fromkeys(candidates):
                if not ipaddress.ip_address(address).is_global:continue
                target=s['target'].rstrip('.');key=hashlib.sha256(json.dumps([address,port,target]).encode()).hexdigest()[:24]
                endpoints[key]=(address,port,target);links[key].add(ip);state='endpoint_pending'
        if has_dot and state=='no_dot_announcement':state='invalid_dot_service'
        states[ip]=state
    (OUT/'endpoint-originals.json.gz').write_bytes(gzip.compress(json.dumps({k:sorted(v) for k,v in links.items()}).encode()))
    (OUT/'plan.json').write_text(json.dumps({'cohort':len(states),'initial_states':dict(collections.Counter(states.values())),'unique_endpoints':len(endpoints),'workers':16,'per_destination':2,'tls':'TLS1.2; SNI=T; no ALPN; certifi trust; A IP SAN required','source':'saved current-round SVCB services and target Additional; shared endpoint certificate checked separately against every original IP'},indent=2))
    print((OUT/'plan.json').read_text(),flush=True)
    locks={ip:threading.Semaphore(2) for ip,port,target in endpoints.values()}
    def receive(sock,n):
        data=b''
        while len(data)<n:
            part=sock.recv(n-len(data))
            if not part:raise EOFError('peer closed')
            data+=part
        return data
    def probe(item):
        key,(ip,port,target)=item;folder=OUT/key;folder.mkdir(exist_ok=True)
        if (folder/'result.json').exists():return key,json.loads((folder/'result.json').read_text())
        result={'F':ip,'port':port,'T':target,'success':False,'stage':'connect','utc_epoch':time.time()}
        with locks[ip]:
            try:
                ctx=ssl.create_default_context(cafile=certifi.where());ctx.maximum_version=ssl.TLSVersion.TLSv1_2;ctx.keylog_filename=str(folder/'tls.keys') if os.environ.get('DDR_TLS_KEYLOG') == '1' else None
                with socket.create_connection((ip,port),timeout=6) as raw:
                    result['stage']='tls'
                    with ctx.wrap_socket(raw,server_hostname=target) as tls:
                        result.update(chain_and_target_valid=True,tls_version=tls.version(),alpn=tls.selected_alpn_protocol(),stage='certificate')
                        der=tls.getpeercert(True);(folder/'certificate.der').write_bytes(der)
                        cert=x509.load_der_x509_certificate(der);san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                        result['ip_san']=[str(v) for v in san.get_values_for_type(x509.IPAddress)];result['dns_san']=san.get_values_for_type(x509.DNSName)
                        matches=links[key].intersection(result['ip_san']);result['matching_originals']=sorted(matches)
                        if matches:
                            result['stage']='dns';q=dns.message.make_query('example.com','A');q.id=0;wire=q.to_wire();tls.sendall(struct.pack('!H',len(wire))+wire)
                            body=receive(tls,int.from_bytes(receive(tls,2),'big'));answer=dns.message.from_wire(body)
                            (folder/'query.bin').write_bytes(wire);(folder/'answer.bin').write_bytes(body)
                            result.update(dns_answer=answer.to_text(),success=q.is_response(answer) and not bool(answer.flags&dns.flags.TC) and answer.rcode()==0 and bool(answer.answer),stage='complete')
            except Exception as e:result.update(error_type=type(e).__name__,error=str(e))
            time.sleep(.15)
        (folder/'result.json').write_text(json.dumps(result,indent=2));return key,result
    results={}
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        for key,result in pool.map(probe,endpoints.items()):
            results[key]=result
            if len(results)%100==0:print('ENDPOINTS',len(results),len(endpoints),flush=True)
    rank={'endpoint_pending':0,'connect_or_handshake_failure':1,'missing_original_ip_san':2,'dns_failure':3,'pass':4}
    for key,r in results.items():
        for ip in links[key]:
            state='connect_or_handshake_failure'
            if r.get('chain_and_target_valid'):
                state='missing_original_ip_san' if ip not in r.get('ip_san',[]) else 'pass' if r['success'] else 'dns_failure'
            if rank.get(state,0)>rank.get(states[ip],0):states[ip]=state
    success=sorted(ip for ip,state in states.items() if state=='pass')
    old=set(json.loads(args.previous_summary.read_text())['success_addresses']) if args.previous_summary else set()
    summary={'cohort':len(states),'endpoints':len(endpoints),'stages':{f'ipv{v}':dict(collections.Counter(state for ip,state in states.items() if ipaddress.ip_address(ip).version==v)) for v in [4,6]},'success':len(success),'success_addresses':success}
    if args.previous_summary:
        summary.update(additional_to_previous=sorted(set(success)-old), previous_not_reconfirmed=sorted(old-set(success)))
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2));(OUT/'cohort-status.json.gz').write_bytes(gzip.compress(json.dumps(states).encode()));(OUT/'endpoint-results.json').write_text(json.dumps(results,indent=2));print(json.dumps(summary),flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--previous-summary', type=pathlib.Path, help='Optional prior DoT summary for comparison')
    main(parser.parse_args())
