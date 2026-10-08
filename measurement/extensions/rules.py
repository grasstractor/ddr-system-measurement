"""Evaluate baseline and six interventions on one fresh SVCB cohort.

All scenario successes require a complete single path. No historical HTTP
result is mixed into the fresh round. Original-IP binding changes are explicit.
"""
import argparse,asyncio,base64,collections,hashlib,json,pathlib,shutil,sqlite3,sys,time,zlib
from types import SimpleNamespace

SCENARIOS={
 'windows':{'baseline':(), 'R1':('lookup',),'R5':('no_ip_san',),'R1+R5':('lookup','no_ip_san')},
 'android':{'baseline':(),'R2':('additional',),'R3':('h2',),'R6':('other_ip',),
  'R2+R3':('additional','h2'),'R2+R6':('additional','other_ip'),'R3+R6':('h2','other_ip'),'R2+R3+R6':('additional','h2','other_ip')},
 'macos':{'baseline':(),'R4':('domain_authority',),'R5':('no_ip_san',),'R4+R5':('domain_authority','no_ip_san')}}

async def main(a):
 sys.path.insert(0,str(pathlib.Path(a.engine_root)))
 import engine as e,validate as v,dns.message
 root=pathlib.Path(a.output);root.mkdir(parents=True,exist_ok=True)
 db=v.database(root);db.execute('CREATE TABLE IF NOT EXISTS rule_results(ip TEXT PRIMARY KEY,data BLOB)');db.commit()
 source=sqlite3.connect('file:'+str(pathlib.Path(a.database).resolve())+'?mode=ro',uri=True,timeout=60)
 args=SimpleNamespace(output=str(root),connections=a.connections,timeout=a.timeout)
 survey=v.Validator(args,db)
 ca=root/'ca-bundle.pem'
 if not ca.exists():shutil.copyfile(e.certifi.where(),ca)
 e.certifi.where=lambda:str(ca.resolve())
 completed={r[0] for r in db.execute('SELECT ip FROM rule_results')}
 manifest={'utc':e.utc(),'vantage':a.vantage,'scenarios':SCENARIOS,'source_database':a.database,'connections':a.connections,'workers':a.workers,'per_ip_connections':2,'macos_R5':not a.defer_macos_r5,'native_os_execution':False,'script_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'ca_sha256':hashlib.sha256(ca.read_bytes()).hexdigest()}
 v.save(root/'rules-plan.json',manifest)
 processed=0;started=time.time();failures=0
 async def process(raw):
  r=v.unpack(raw);ip=r['A'];ev=[]
  responses=[x for x in r['attempts'] if 'response_b64' in x]
  response=dns.message.from_wire(base64.b64decode(responses[-1]['response_b64']))
  services,notes=await survey.get_services(ip,response,'_dns.resolver.arpa.',ev)
  lookups={};specs={};outcomes={p:{k:False for k in group if not(a.defer_macos_r5 and p=='macos' and k=='R5')} for p,group in SCENARIOS.items()}
  async def lookup(target):
   if target not in lookups:
    addresses=[]
    for qt in ['A','AAAA']:
     ans=await survey.dns_query(ip,target,qt,ev)
     if ans is not None and ans.rcode()==0:addresses+=e.answer_addresses(ans,target)
    lookups[target]=e.unique(addresses)
   return lookups[target]
  for s,resp in services:
   if s['issues'] or not s['dohpath']:continue
   hints=s['ipv4hint']+s['ipv6hint'];any_add=e.addresses(resp.additional);matched=e.addresses(resp.additional,s['target']);direct=e.unique(matched+hints)
   for profile,variants in SCENARIOS.items():
    for scenario,changes in variants.items():
     if scenario not in outcomes[profile]:continue
     if profile=='windows':
      protocols=['h2'] if any(x in s['alpn'] for x in ['h2','h3']) else []
      candidates=direct
      if protocols and not candidates and 'lookup' in changes:candidates=await lookup(s['target'])
     elif profile=='android':
      protocols=(['h3'] if 'h3' in s['alpn'] else [])+(['h2'] if 'h2' in changes and 'h2' in s['alpn'] else [])
      candidates=direct if 'additional' in changes else e.unique(any_add or hints)
      if 'other_ip' not in changes:candidates=[f for f in candidates if f==ip]
     else:
      protocols=['h2'] if 'h2' in s['alpn'] else []
      candidates=direct if s['ipv4hint'] else e.unique((await lookup(s['target']) if protocols else [])+s['ipv6hint'])
     authority=ip if profile=='macos' and 'domain_authority' not in changes else s['target'].rstrip('.')
     if ':' in authority:authority='['+authority+']'
     if s['port']!=443:authority+=':'+str(s['port'])
     for protocol in protocols:
      for f in candidates:
       if not e.public_address(f):continue
       spec={'F':f,'port':s['port'],'T':s['target'],'protocol':protocol,'authority':authority,'method':'POST' if profile=='windows' else 'GET','template':s['dohpath']}
       key=e.digest(spec)
       entry=specs.setdefault(key,{'spec':spec,'uses':[]})
       entry['uses'].append({'profile':profile,'scenario':scenario,'require_ip':profile!='android' and 'no_ip_san' not in changes})
  observations=[]
  # Fully evaluate each unique candidate, keeping all evidence for minimal-change sets.
  for entry in specs.values():
   s=entry['spec'];uses=entry['uses'];ipf=s['F'];port=s['port'];target=s['T'];folder_key=None
   if s['protocol']=='h2':
    tlskey,cert=await survey.cached('tls',[ipf,port,target],lambda folder:asyncio.to_thread(e.tls_probe,ipf,port,target,folder,a.timeout))
    chain=bool(cert.get('chain_valid') and cert.get('target_name_match'));ips=cert.get('certificate_ip_san',[])
    eligible=[u for u in uses if chain and (not u['require_ip'] or ip in ips)]
    result={};httpkey=None
    if eligible:
     httpkey,result=await survey.cached('h2',[ipf,port,target,s['authority'],s['method'],s['template']],lambda folder:asyncio.to_thread(e.h2_probe,ipf,port,target,s['authority'],s['method'],s['template'],folder,a.timeout))
     chain=bool(result.get('chain_valid') and result.get('target_name_match'));ips=result.get('certificate_ip_san',[])
    observation={'spec':s,'uses':uses,'tls_evidence':tlskey,'http_evidence':httpkey,'chain_target_ok':chain,'ip_san_ok':ip in ips,'http_status':result.get('http_status'),'positive_dns':result.get('positive_dns_answer',False)}
   else:
    httpkey,result=await survey.cached('h3',[ipf,port,target,s['authority'],s['template']],lambda folder:e.h3_probe(ipf,port,target,s['authority'],s['template'],folder,a.timeout))
    chain=bool(result.get('chain_valid') and result.get('target_name_match'));ips=result.get('certificate_ip_san',[])
    observation={'spec':s,'uses':uses,'http_evidence':httpkey,'chain_target_ok':chain,'ip_san_ok':ip in ips,'http_status':result.get('http_status'),'positive_dns':result.get('positive_dns_answer',False)}
   for u in uses:
    if chain and (not u['require_ip'] or ip in ips) and result.get('positive_dns_answer'):
     outcomes[u['profile']][u['scenario']]=True
   observations.append(observation)
  data={'A':ip,'vantage':a.vantage,'utc':e.utc(),'outcomes':outcomes,'paths':observations,'followup_dns':ev,'notes':notes}
  with db:db.execute('INSERT OR REPLACE INTO rule_results VALUES (?,?)',(ip,v.pack(data)))
 async def one(ip,raw):
  nonlocal processed,failures
  try:await process(raw)
  except Exception as ex:
   failures+=1
   with db:db.execute('INSERT OR REPLACE INTO errors VALUES (?,?)',(ip,json.dumps({'type':type(ex).__name__,'error':str(ex)})))
   raise
  else:completed.add(ip);processed+=1
 async def reporter():
  while True:
   v.save(root/'rules-progress.json',{'utc':e.utc(),'completed':len(completed),'new':processed,'errors':failures,'new_probes':survey.new_probes,'elapsed_seconds':round(time.time()-started,1)})
   await asyncio.sleep(20)
 report=asyncio.create_task(reporter())
 cursor=0
 try:
  while True:
   fetched=source.execute("SELECT rowid,ip,data FROM discovery WHERE rowid>? AND outcome='svcb_answer' ORDER BY rowid LIMIT ?",(cursor,a.workers)).fetchall()
   batch=[]
   for rowid,ip,raw in fetched:
    cursor=rowid
    if ip not in completed:batch.append((ip,raw))
   if batch:
    before=len(completed);await asyncio.gather(*(one(*item) for item in batch))
    if len(completed)==before:raise RuntimeError('batch made no progress; inspect errors table')
   else:
    if fetched:continue
    flag=source.execute("SELECT value FROM meta WHERE key='refresh_complete'").fetchone()
    if flag:
     remaining=source.execute("SELECT 1 FROM discovery WHERE rowid>? AND outcome='svcb_answer' LIMIT 1",(cursor,)).fetchone()
     if not remaining:break
    await asyncio.sleep(10)
 finally:report.cancel()
 counts=collections.defaultdict(collections.Counter);gains=collections.defaultdict(collections.Counter);losses=collections.defaultdict(collections.Counter)
 for raw, in db.execute('SELECT data FROM rule_results'):
  row=v.unpack(raw)
  for p,variants in row['outcomes'].items():
   for k,ok in variants.items():
    if ok:counts[p][k]+=1
    if ok and not variants['baseline']:gains[p][k]+=1
    if not ok and variants['baseline']:losses[p][k]+=1
 v.save(root/'rules-summary.json',{'complete':True,'vantage':a.vantage,'cohort':len(completed),'success':{k:dict(vv) for k,vv in counts.items()},'gains':{k:dict(vv) for k,vv in gains.items()},'losses':{k:dict(vv) for k,vv in losses.items()},'deferred':['macos R5 alone'] if a.defer_macos_r5 else [],'errors':failures})

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--database',required=True);p.add_argument('--output',required=True);p.add_argument('--vantage',required=True);p.add_argument('--engine-root',default=str(pathlib.Path(__file__).resolve().parents[1]/'validation'));p.add_argument('--workers',type=int,default=48);p.add_argument('--connections',type=int,default=24);p.add_argument('--timeout',type=float,default=6);p.add_argument('--defer-macos-r5',action='store_true')
 asyncio.run(main(p.parse_args()))
