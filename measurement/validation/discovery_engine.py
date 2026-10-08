"""Resumable IPv4 ZMap -> DDR and IPv6 Hitlist -> DNS -> DDR measurement.

Each finished chunk is immutable. A killed chunk is replayed into a fresh
temporary file, then atomically replaces that chunk's output on completion.
"""
import argparse
import asyncio
import base64
from collections import Counter
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import time

import dns.asyncquery
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

ROOT = Path.cwd()  # Replaced by the required --root before any file operation.
SEED = 20261003
SHARDS = 256
DDR_NAME = dns.name.from_text('_dns.resolver.arpa.')


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic(path, data):
    path = Path(path)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(data, indent=2))
    temp.replace(path)


def disk_check():
    free = shutil.disk_usage(ROOT).free
    if free < 2 * 1024**3:
        raise RuntimeError(f'Free disk below 2 GiB: {free} bytes')


class Rate:
    def __init__(self, qps):
        self.interval = 1.0 / qps
        self.next = 0.0

    async def wait(self):
        now = time.monotonic()
        when = max(now, self.next)
        self.next = when + self.interval
        if when > now:
            await asyncio.sleep(when - now)


def classify(response):
    if response is None or response.flags & dns.flags.TC:
        return 'no_complete_response', []
    if response.rcode() != dns.rcode.NOERROR:
        return 'rcode_' + dns.rcode.to_text(response.rcode()), []
    owners = {DDR_NAME}
    for _ in range(16):
        before = len(owners)
        for rr in response.answer:
            if rr.name in owners and rr.rdtype == dns.rdatatype.CNAME:
                owners.update(r.target for r in rr)
        if len(owners) == before:
            break
    records = []
    for rr in response.answer:
        if rr.rdtype != dns.rdatatype.SVCB or rr.name not in owners:
            continue
        for r in rr:
            alpn = r.params.get(1)
            protocols = [p.decode('ascii', 'replace') for p in alpn.ids] if alpn else []
            records.append({'owner': rr.name.to_text(), 'ttl': rr.ttl,
                            'priority': r.priority, 'target': r.target.to_text(),
                            'rdata': r.to_text(), 'alpn': protocols,
                            'doh_candidate': r.priority > 0 and r.target != dns.name.root
                            and 7 in r.params and any(p == 'h2' or p == 'h3' or p.startswith('h3-') for p in protocols),
                            'alias': r.priority == 0})
    return ('svcb_answer' if records else 'no_svcb_answer'), records


async def exchange(query, ip, transport, limiter, timeout):
    await limiter.wait()
    attempt = {'transport': transport, 'utc': utc()}
    start = time.monotonic()
    response = None
    try:
        method = dns.asyncquery.udp if transport == 'udp' else dns.asyncquery.tcp
        kwargs = {'timeout': timeout}
        if transport == 'udp':
            kwargs['ignore_unexpected'] = True
        response = await method(query, ip, **kwargs)
        # dnspython checks the remote endpoint, transaction ID and question.
        attempt.update(response_b64=base64.b64encode(response.wire or response.to_wire()).decode(),
                       rcode=dns.rcode.to_text(response.rcode()),
                       tc=bool(response.flags & dns.flags.TC))
    except Exception as exc:
        attempt.update(error=type(exc).__name__, message=str(exc)[:240])
    attempt['elapsed_ms'] = round((time.monotonic() - start) * 1000, 2)
    return response, attempt


async def ddr(ip, limiter, args):
    query = dns.message.make_query(DDR_NAME, 'SVCB', use_edns=0, payload=1232)
    row = {'A': ip, 'vantage': args.vantage, 'utc': utc(),
           'query_b64': base64.b64encode(query.to_wire()).decode(), 'attempts': []}
    final = None
    for transport in ['udp', 'udp', 'udp', 'tcp']:
        response, attempt = await exchange(query, ip, transport, limiter, args.timeout)
        row['attempts'].append(attempt)
        if response is not None:
            final = response
            if not response.flags & dns.flags.TC:
                break
            # A truncated answer needs TCP, not more UDP attempts.
            if transport == 'udp':
                final, attempt = await exchange(query, ip, 'tcp', limiter, args.timeout)
                row['attempts'].append(attempt)
                break
    row['outcome'], row['records'] = classify(final)
    if row['records']:
        row['response_text'] = final.to_text()
    return row


def progress(role, data):
    atomic(ROOT / f'{role}-progress.json', {'utc': utc(), **data})


async def measure_chunk(ips, output, args, ipv6=False):
    output.mkdir(exist_ok=True, parents=True)
    limiter = Rate(args.qps)
    counts = Counter()
    queue = asyncio.Queue()
    for ip in ips:
        queue.put_nowait(ip)
    started = time.monotonic()
    files = {name: gzip.open(output / (name + '.jsonl.gz.tmp'), 'wt', compresslevel=1)
             for name in ['results', 'positive', 'dns-positive']}

    async def worker():
        while True:
            try:
                ip = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if ipv6:
                query = dns.message.make_query('www.google.com.', 'A')
                response, attempt = await exchange(query, ip, 'udp', limiter, args.timeout)
                qualification = {'A': ip, 'query_b64': base64.b64encode(query.to_wire()).decode(),
                                 'attempt': attempt, 'utc': utc(), 'vantage': args.vantage}
                if response is None:
                    counts['dns_no_response'] += 1
                    # Every candidate has an outcome; avoid duplicating long timeout text 28M times.
                    files['results'].write(json.dumps({'A': ip, 'outcome': 'dns_no_response',
                        'utc': qualification['utc'], 'error': attempt.get('error')}) + '\n')
                    queue.task_done()
                    continue
                counts['dns_response'] += 1
                files['dns-positive'].write(json.dumps(qualification) + '\n')
            row = await ddr(ip, limiter, args)
            files['results'].write(json.dumps(row) + '\n')
            if row['outcome'] == 'svcb_answer':
                files['positive'].write(json.dumps(row) + '\n')
                if any(r['doh_candidate'] for r in row['records']):
                    counts['doh_candidate'] += 1
            counts[row['outcome']] += 1
            queue.task_done()

    async def report():
        while True:
            progress(args.role, {'state': 'running', 'chunk': output.name, 'total_in_chunk': len(ips),
                     'pending_in_chunk': queue.qsize(), 'counts_in_chunk': dict(counts),
                     'qps_limit': args.qps, 'workers': args.workers,
                     'elapsed_chunk_seconds': round(time.monotonic() - started, 1)})
            disk_check()
            await asyncio.sleep(15)

    reporter = asyncio.create_task(report())
    workers = asyncio.gather(*(worker() for _ in range(args.workers)))
    try:
        done, _ = await asyncio.wait([workers, reporter], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        await workers
    finally:
        reporter.cancel()
        if not workers.done():
            workers.cancel()
            await asyncio.gather(workers, return_exceptions=True)
        for stream in files.values():
            stream.close()
    for name in files:
        (output / (name + '.jsonl.gz.tmp')).replace(output / (name + '.jsonl.gz'))
    atomic(output / 'done.json', {'utc': utc(), 'inputs': len(ips), 'counts': dict(counts),
           'elapsed_seconds': round(time.monotonic() - started, 2)})


def zmap_producer(args):
    directory = ROOT / 'ipv4-zmap'
    directory.mkdir(exist_ok=True)
    for shard in range(SHARDS):
        name = f'{shard:04d}'
        done = directory / f'{name}.done.json'
        if done.exists():
            continue
        disk_check()
        partial = directory / f'{name}.jsonl.gz.tmp'
        command = [args.zmap_binary, '-C', str(args.zmap_config),
                   '-b', str(args.blocklist), '-M', 'dns', '-p', '53',
                   '--probe-args=A,www.google.com', '-O', 'json',
                   '-f', 'saddr,dns_rcode,dns_qr,dns_tc,dns_ra,timestamp_str,raw_data',
                   '--output-filter=success = 1 && dns_qr = 1 && repeat = 0',
                   '-r', str(args.zmap_rate), '--batch=16', '-T', '1', '-c', '15', '-s', '44000',
                   '-e', str(SEED), '--shards', str(SHARDS), '--shard', str(shard), '-q',
                   '-o', '-', '-m', str(directory / f'{name}.meta.json'),
                   '-l', str(directory / f'{name}.log'), '-u', str(directory / f'{name}.status.csv')]
        progress(args.role, {'state': 'running', 'shard': shard, 'total_shards': SHARDS,
                            'rate': args.zmap_rate, 'command': command})
        count = 0
        with gzip.open(partial, 'wb', compresslevel=1) as stream:
            with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
                try:
                    for line in process.stdout:
                        stream.write(line)
                        count += 1
                        if count % 10000 == 0:
                            disk_check()
                    code = process.wait()
                    if code:
                        raise RuntimeError(f'ZMap exited {code} at shard {shard}')
                except BaseException:
                    process.terminate()
                    raise
        partial.replace(directory / f'{name}.jsonl.gz')
        meta = json.loads((directory / f'{name}.meta.json').read_text())
        atomic(done, {'utc': utc(), 'candidates': count, 'rate': args.zmap_rate, 'shard': shard,
                     'metadata': meta})
    progress(args.role, {'state': 'complete', 'total_shards': SHARDS})


async def ipv4_consumer(args):
    source = ROOT / 'ipv4-zmap'
    for shard in range(SHARDS):
        name = f'{shard:04d}'
        output = ROOT / 'ipv4-ddr' / name
        if (output / 'done.json').exists():
            continue
        while not (source / f'{name}.done.json').exists():
            progress(args.role, {'state': 'waiting_for_zmap', 'shard': shard})
            await asyncio.sleep(10)
        ips = set()
        with gzip.open(source / f'{name}.jsonl.gz', 'rt') as stream:
            for line in stream:
                ips.add(json.loads(line)['saddr'])
        await measure_chunk(sorted(ips), output, args)
    progress(args.role, {'state': 'complete', 'total_shards': SHARDS})


async def ipv6_scan(args):
    source = args.ipv6_parts or ROOT / 'input/ipv6-parts'
    if not (source / 'manifest.json').exists():
        raise RuntimeError('The shuffled IPv6 input is not ready')
    skipped = 0
    for index, file in enumerate(sorted(source.glob('*.txt.gz'))):
        output = ROOT / 'ipv6-ddr' / f'{index:04d}'
        if (output / 'done.json').exists():
            continue
        ips = []
        with gzip.open(file, 'rt') as stream:
            for line in stream:
                address = ipaddress.ip_address(line.strip())
                if address.version != 6 or not address.is_global or address.is_multicast:
                    skipped += 1
                    continue
                ips.append(str(address))
        await measure_chunk(ips, output, args, ipv6=True)
    progress(args.role, {'state': 'complete', 'total_chunks': len(list(source.glob('*.txt.gz'))), 'nonpublic_skipped_this_run': skipped})


def status():
    state = {'utc': utc(), 'disk_free_gib': round(shutil.disk_usage(ROOT).free / 1024**3, 2)}
    for role in ['ipv4-zmap', 'ipv4-ddr', 'ipv6-ddr']:
        files = list((ROOT / role).glob('*.done.json' if role == 'ipv4-zmap' else '*/done.json'))
        counts = Counter()
        for file in files:
            row = json.loads(file.read_text())
            if role == 'ipv4-zmap':
                counts['dns_responses'] += row['candidates']
                for key in ['packets_sent', 'targets_scanned', 'pcap_drop', 'pcap_ifdrop', 'send_to_failures']:
                    counts[key] += row['metadata'].get(key, 0)
            else:
                counts['inputs'] += row['inputs']
                counts.update(row['counts'])
        state[role] = {'completed_chunks': len(files), 'counts': dict(counts)}
        file = ROOT / f'{role}-progress.json'
        if file.exists():
            state[role]['progress'] = json.loads(file.read_text())
    print(json.dumps(state, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['ipv4-zmap', 'ipv4-ddr', 'ipv6-ddr', 'status'])
    parser.add_argument('--root', type=Path, required=True, help='Measurement output directory')
    parser.add_argument('--zmap-binary', default='zmap')
    parser.add_argument('--zmap-config', type=Path, help='ZMap configuration file; an empty file preserves CLI-only settings')
    parser.add_argument('--blocklist', type=Path, help='ZMap address exclusion file')
    parser.add_argument('--ipv6-parts', type=Path, help='Directory with manifest.json and gzip address chunks')
    parser.add_argument('--seed', type=int, default=SEED)
    parser.add_argument('--shards', type=int, default=SHARDS)
    parser.add_argument('--vantage', default='unspecified')
    parser.add_argument('--qps', type=float, default=1500)
    parser.add_argument('--workers', type=int, default=4096)
    parser.add_argument('--timeout', type=float, default=2.5)
    parser.add_argument('--zmap-rate', type=int, default=60000)
    args = parser.parse_args()
    if args.role == 'ipv4-zmap' and (args.zmap_config is None or args.blocklist is None):
        parser.error('ipv4-zmap requires --zmap-config and --blocklist')
    if args.shards < 1:
        parser.error('--shards must be positive')
    ROOT = args.root.resolve()
    ROOT.mkdir(parents=True, exist_ok=True)
    SEED, SHARDS = args.seed, args.shards
    if args.role == 'ipv4-zmap':
        zmap_producer(args)
    elif args.role == 'ipv4-ddr':
        asyncio.run(ipv4_consumer(args))
    elif args.role == 'ipv6-ddr':
        asyncio.run(ipv6_scan(args))
    else:
        status()
