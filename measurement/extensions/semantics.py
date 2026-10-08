"""Paired plaintext/encrypted DNS observations with fresh DDR and wire evidence."""
import os
# Only DDR_TLS_KEYLOG explicitly enables local key-log output.
os.environ.pop('SSLKEYLOGFILE', None)
import argparse,asyncio,base64,collections,gzip,hashlib,ipaddress,json,pathlib,random,shutil,socket,sqlite3,ssl,struct,time,zlib
from types import SimpleNamespace
import certifi,dns.asyncquery,dns.flags,dns.message,dns.rcode,dns.rdatatype
import transport as e

PILOT=['1.1.1.1','1.1.1.2','1.1.1.3','9.9.9.9','9.9.9.10','2001:4860:4860::64','2001:4860:4860::6464','51.44.65.29','54.73.98.29','194.180.189.33']
QUERIES=[('positive','example.com.','A',False,False),
 ('filter_malware','malware.testcategory.com.','A',False,False),
 ('filter_adult','nudity.testcategory.com.','A',False,False),
 ('dns64','ipv4only.arpa.','AAAA',False,False),
 ('signed_valid','cloudflare.com.','A',True,False),
 ('signed_bogus','dnssec-failed.org.','A',True,False),
 ('signed_bogus_cd','dnssec-failed.org.','A',True,True),
 ('nxdomain','ddr-extension-20261005.invalid.','A',False,False)]

def write(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_suffix(path.suffix+'.tmp');tmp.write_text(json.dumps(value,indent=2));tmp.replace(path)

def normalize(q,wire):
 r=dns.message.from_wire(wire)
 if not q.is_response(r):raise ValueError('unmatched DNS response')
 answer=[]
 for rr in r.answer:
  if rr.rdtype==dns.rdatatype.RRSIG:continue
  answer.append([rr.name.to_text().lower(),dns.rdatatype.to_text(rr.rdtype),sorted(x.to_text().lower() for x in rr)])
 answer.sort()
 return {'valid_dns':True,'rcode':dns.rcode.to_text(r.rcode()),'answer':answer,
  'ad':bool(r.flags&dns.flags.AD),'cd':bool(r.flags&dns.flags.CD),'tc':bool(r.flags&dns.flags.TC),
  'options':[x.to_text() for x in r.options], 'text':r.to_text()}

def dot_probe(spec,q,folder,timeout):
 folder.mkdir(parents=True,exist_ok=True);(folder/'dns-query.bin').write_bytes(q.to_wire());r={'utc':e.utc(),'chain_valid':False}
 def read(sock,n):
  b=b''
  while len(b)<n:
   x=sock.recv(n-len(b))
   if not x:raise EOFError()
   b+=x
  return b
 try:
  ctx=ssl.create_default_context(cafile=certifi.where());ctx.maximum_version=ssl.TLSVersion.TLSv1_2;ctx.keylog_filename=str(folder/'tls.keys') if os.environ.get('DDR_TLS_KEYLOG') == '1' else None
  with socket.create_connection((spec['F'],spec['port']),timeout=timeout) as raw:
   with ctx.wrap_socket(raw,server_hostname=spec['T'].rstrip('.')) as tls:
    r.update(chain_valid=True,**e.save_tls_peer(tls,folder,spec['T']))
    wire=q.to_wire();tls.sendall(struct.pack('!H',len(wire))+wire)
    body=read(tls,int.from_bytes(read(tls,2),'big'));(folder/'dns-response.bin').write_bytes(body)
 except Exception as ex:r.update(error=type(ex).__name__+': '+str(ex))
 return r

async def run(a):
 out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=True)
 ca=out/'ca-bundle.pem'
 if not ca.exists():shutil.copyfile(certifi.where(),ca)
 certifi.where=lambda:str(ca.resolve())
 db=sqlite3.connect(out/'pairs.sqlite');db.execute('PRAGMA journal_mode=WAL')
 db.execute('CREATE TABLE IF NOT EXISTS pairs(id TEXT PRIMARY KEY, data BLOB)');db.commit()
 done={x[0] for x in db.execute('SELECT id FROM pairs')}
 ips=json.loads(pathlib.Path(a.input).read_text()) if a.input else PILOT
 survey=e.Survey(SimpleNamespace(output=str(out/'discovery'),connections=8,timeout=a.timeout))
 planned=[];refresh={};sem=asyncio.Semaphore(8)
 async def discover(ip):
  async with sem:
   folder=out/'refresh'/ip.replace(':','_'); saved=folder/'services.json'
   if saved.exists():rr=json.loads(saved.read_text())
   else:
    evidence=[];response=await survey.dns_query(ip,'_dns.resolver.arpa.','SVCB',evidence)
    services=[];notes=[];lookups={}
    if response is not None and response.rcode()==0:
     found,notes=await survey.get_services(ip,response,'_dns.resolver.arpa.',evidence)
     for s,r in found:
      s.update(additional_addresses=e.addresses(r.additional),target_additional_addresses=e.addresses(r.additional,s['target']))
      if not s['ipv4hint'] and s['target'] not in lookups:
       addresses=[]
       for qt in ['A','AAAA']:
        resp=await survey.dns_query(ip,s['target'],qt,evidence)
        if resp is not None and resp.rcode()==0:addresses+=e.answer_addresses(resp,s['target'])
       lookups[s['target']]=e.unique(addresses)
      services.append(s)
    rr={'A':ip,'utc':e.utc(),'services':services,'lookups':lookups,'evidence':evidence,'notes':notes};write(saved,rr)
   refresh[ip]={'services':len(rr['services']),'utc':rr['utc']}
   paths=[]
   for s in rr['services']:
    hints=s['ipv4hint']+s['ipv6hint'];direct=e.unique(s['target_additional_addresses']+hints)
    for profile in ['windows','android','macos']:
     if s['issues']:continue
     wanted='h3' if profile=='android' else 'h2'
     if wanted not in s['alpn'] and not(profile=='windows' and 'h3' in s['alpn']):continue
     pool=direct if profile=='windows' else [x for x in (s['additional_addresses'] or hints) if x==ip] if profile=='android' else direct if s['ipv4hint'] else e.unique(rr['lookups'].get(s['target'],[])+s['ipv6hint'])
     for f in pool:
      if not e.public_address(f):continue
      auth=ip if profile=='macos' else s['target'].rstrip('.')
      if ':' in auth:auth='['+auth+']'
      if s['port']!=443:auth+=':'+str(s['port'])
      paths.append({'A':ip,'F':f,'T':s['target'],'port':s['port'],'protocol':wanted,'authority':auth,'method':'POST' if profile=='windows' else 'GET','template':s['dohpath'],'profile':profile,'source_service':s['text']})
    if 'dot' in s['alpn']:
     record=__import__('dns.rdata',fromlist=['from_text']).from_text(1,64,s['text'])
     if s['target'] in ['.','resolver.arpa.'] or any(k not in record.params or k not in {0,1,2,3,4,6,7} for k in s['mandatory']):continue
     for f in direct:
      if e.public_address(f):paths.append({'A':ip,'F':f,'T':s['target'],'port':record.params[3].port if 3 in record.params else 853,'protocol':'dot','profile':'desktop_dot','source_service':s['text']})
   if a.mode=='pilot':
    selected={}
    # One explicitly recorded representative per profile; prefer same address, then same family.
    for spec in sorted(paths,key=lambda x:(x['F']!=ip,ipaddress.ip_address(x['F']).version!=ipaddress.ip_address(ip).version,x['F'])):
     selected.setdefault(spec['profile'],spec)
    paths=list(selected.values())
   planned.extend(paths)
 await asyncio.gather(*(discover(ip) for ip in ips))
 if a.matrix:
  extra=[]
  for s in planned:
   if s['protocol']!='h2':continue
   for method in ['GET','POST']:
    for kind in ['T','A']:
     auth=s[kind].rstrip('.')
     if ':' in auth:auth='['+auth+']'
     if s['port']!=443:auth+=':'+str(s['port'])
     extra.append(dict(s,method=method,authority=auth,profile='http_matrix',parent_profile=s['profile']))
  planned=extra
 # Keep profile associations; equivalent network pairs may be re-used in later analysis only.
 planned=list({e.digest(s):s for s in planned}.values())
 write(out/'plan.json',{'utc':e.utc(),'vantage':a.vantage,'mode':a.mode,'originals':len(ips),'paths':len(planned),'refresh':refresh,'rounds':a.rounds,'queries':QUERIES if not a.matrix else QUERIES[:1],'limits':{'pairs':8,'per_ip':1,'pause_seconds':.2},'native_os_execution':False,'source_hashes':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in pathlib.Path(__file__).parent.glob('*.py')}})
 write(out/'paths.json',planned)
 locks={};completed=0;started=time.time()
 async def encrypted(spec,q,folder):
  t=time.time()
  if spec['protocol']=='h2':r=await asyncio.to_thread(e.h2_probe,spec['F'],spec['port'],spec['T'],spec['authority'],spec['method'],spec['template'],folder,a.timeout,q)
  elif spec['protocol']=='h3':r=await e.h3_probe(spec['F'],spec['port'],spec['T'],spec['authority'],spec['template'],folder,a.timeout,q)
  else:r=await asyncio.to_thread(dot_probe,spec,q,folder,a.timeout)
  r['elapsed_ms']=round((time.time()-t)*1000,2)
  r['identity_ok']=bool(r.get('chain_valid') and r.get('target_name_match') and (spec['profile']=='android' or spec['A'] in r.get('certificate_ip_san',[])))
  if spec['profile']=='http_matrix':r['identity_ok']=bool(r.get('chain_valid') and r.get('target_name_match') and spec['A'] in r.get('certificate_ip_san',[]))
  if (folder/'dns-response.bin').exists():
   try:r['dns']=normalize(q,(folder/'dns-response.bin').read_bytes())
   except Exception as ex:r['parse_error']=str(ex)
  r['exchange_ok']=bool(r.get('dns',{}).get('valid_dns') and not r['dns']['tc'] and (spec['protocol']=='dot' or r.get('doh_protocol_valid')))
  return r
 async def plain(spec,q,folder):
  folder.mkdir(parents=True,exist_ok=True);(folder/'dns-query.bin').write_bytes(q.to_wire());r={'utc':e.utc(),'attempts':[]};t=time.time()
  for proto in ['udp','tcp']:
   try:
    ans=await getattr(dns.asyncquery,proto)(q,spec['A'],timeout=a.timeout)
    wire=ans.to_wire();(folder/('dns-response-'+proto+'.bin')).write_bytes(wire);r['attempts'].append({'transport':proto,'dns':normalize(q,wire)})
    if not ans.flags&dns.flags.TC:r.update(dns=normalize(q,wire),exchange_ok=True);break
   except Exception as ex:r['attempts'].append({'transport':proto,'error':type(ex).__name__+': '+str(ex)})
  r['elapsed_ms']=round((time.time()-t)*1000,2);return r
 async def pair(spec,test,roundno):
  nonlocal completed
  ident=e.digest([spec,test,roundno]);folder=out/'wire'/ident
  if ident in done:return
  q=dns.message.make_query(test[1],test[2],use_edns=0,payload=1232,want_dnssec=test[3]);q.id=0
  if test[4]:q.flags|=dns.flags.CD
  addresses=sorted(set([spec['A'],spec['F']]))
  async with sem:
   held=[]
   try:
    for address in addresses:
     lock=locks.setdefault(address,asyncio.Lock());await lock.acquire();held.append(lock)
    order=['plain','encrypted'];random.Random(ident).shuffle(order)
    r={'id':ident,'spec':spec,'test':test,'round':roundno,'order':order,'started_utc':e.utc()}
    for name in order:
     r[name]=await (plain(spec,q,folder/name) if name=='plain' else encrypted(spec,q,folder/name));await asyncio.sleep(.2)
    r['comparable']=bool(r['plain'].get('exchange_ok') and r['encrypted'].get('exchange_ok') and r['encrypted'].get('identity_ok'))
    if r['comparable']:
     x,y=r['plain']['dns'],r['encrypted']['dns'];r['rcode_equal']=x['rcode']==y['rcode'];r['answer_equal']=x['answer']==y['answer'];r['ad_equal']=x['ad']==y['ad']
    write(folder/'pair.json',r)
    db.execute('INSERT OR REPLACE INTO pairs VALUES (?,?)',(ident,zlib.compress(json.dumps(r).encode())));db.commit()
    completed+=1
    if completed%10==0:write(out/'progress.json',{'utc':e.utc(),'completed_new':completed,'total_saved':db.execute('SELECT COUNT(*) FROM pairs').fetchone()[0],'elapsed_seconds':round(time.time()-started,1)})
   finally:
    for lock in reversed(held):lock.release()
 tests=QUERIES[:1] if a.matrix else QUERIES
 rejected=[]
 if a.preflight:
  for i in range(0,len(planned),32):await asyncio.gather(*(pair(s,QUERIES[0],0) for s in planned[i:i+32]))
  viable=[]
  for s in planned:
   saved=db.execute('SELECT data FROM pairs WHERE id=?',(e.digest([s,QUERIES[0],0]),)).fetchone()
   r=json.loads(zlib.decompress(saved[0]))
   if r['comparable']:viable.append(s)
   else:rejected.append({'spec':s,'pair_id':r['id']})
  write(out/'preflight-rejected.json',rejected);planned=viable
  done.update(x[0] for x in db.execute('SELECT id FROM pairs'))
 jobs=[(s,q,r) for r in range(a.rounds) for s in planned for q in tests];random.Random(20261005).shuffle(jobs)
 # Bounded task batches, retaining resume support.
 for i in range(0,len(jobs),64):await asyncio.gather(*(pair(*j) for j in jobs[i:i+64]))
 rows=[json.loads(zlib.decompress(x[0])) for x in db.execute('SELECT data FROM pairs')]
 counts=collections.Counter();by_test=collections.defaultdict(collections.Counter);diffs=[]
 for r in rows:
  c=by_test[r['test'][0]];counts['pairs']+=1;c['pairs']+=1
  if r['comparable']:
   counts['comparable']+=1;c['comparable']+=1
   if not r['rcode_equal']:counts['rcode_differences']+=1;c['rcode_differences']+=1
   if not r['answer_equal']:counts['answer_differences']+=1;c['answer_differences']+=1
   if not r['rcode_equal'] or not r['answer_equal']:diffs.append(r)
  else:counts['not_comparable']+=1;c['not_comparable']+=1
 write(out/'summary.json',{'complete':True,'vantage':a.vantage,'counts':dict(counts),'tests':{k:dict(v) for k,v in by_test.items()},'paths':len(planned),'preflight_rejected_paths':len(rejected),'originals':len(ips),'utc':e.utc(),'ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()})
 write(out/'differences.json',diffs)
 with gzip.open(out/'pairs.jsonl.gz','wt') as f:
  for r in rows:f.write(json.dumps(r)+'\n')
 print(json.dumps({'complete':True,'counts':counts}),flush=True)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--vantage',required=True);p.add_argument('--mode',choices=['pilot','all'],default='pilot');p.add_argument('--matrix',action='store_true');p.add_argument('--preflight',action='store_true');p.add_argument('--input');p.add_argument('--rounds',type=int,default=3);p.add_argument('--timeout',type=float,default=5)
 asyncio.run(run(p.parse_args()))
