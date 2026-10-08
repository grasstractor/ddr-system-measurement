"""Bounded dual-stack DDR validation with durable, compressed SQLite evidence."""
import argparse
import asyncio
import base64
from collections import Counter, OrderedDict
import datetime as dt
import gzip
import hashlib
import importlib.metadata
import ipaddress
import json
from pathlib import Path
import shutil
import sqlite3
import time
import traceback
import zlib

import certifi
import engine
import discovery_engine as discovery

ROOT = Path(__file__).resolve().parent


def pack(value):
    return zlib.compress(json.dumps(value, ensure_ascii=True).encode(), 3)


def unpack(value):
    return json.loads(zlib.decompress(value))


def save(path, value):
    path.parent.mkdir(exist_ok=True, parents=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2))
    temporary.replace(path)


def database(root):
    root.mkdir(exist_ok=True, parents=True)
    db = sqlite3.connect(root / 'evidence.sqlite', timeout=60)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS discovery(
        ip TEXT PRIMARY KEY, family INTEGER, outcome TEXT, data BLOB,
        checked INTEGER DEFAULT 0, failures INTEGER DEFAULT 0);
      CREATE INDEX IF NOT EXISTS discovery_pending ON discovery(checked, failures);
      CREATE INDEX IF NOT EXISTS discovery_outcomes ON discovery(family, outcome);
      CREATE TABLE IF NOT EXISTS resolvers(
        ip TEXT PRIMARY KEY, family INTEGER, windows TEXT, android TEXT, macos TEXT, data BLOB);
      CREATE TABLE IF NOT EXISTS probes(key TEXT PRIMARY KEY, category TEXT, data BLOB);
      CREATE INDEX IF NOT EXISTS resolver_windows ON resolvers(family,windows);
      CREATE INDEX IF NOT EXISTS resolver_android ON resolvers(family,android);
      CREATE INDEX IF NOT EXISTS resolver_macos ON resolvers(family,macos);
      CREATE TABLE IF NOT EXISTS artifacts(key TEXT, name TEXT, data BLOB, PRIMARY KEY(key,name));
      CREATE TABLE IF NOT EXISTS errors(ip TEXT PRIMARY KEY, data TEXT);
      CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
    ''')
    db.commit()
    return db


def set_meta(db, key, value):
    with db:
        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value)))


def get_meta(db, key):
    row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else None


def free_disk(root):
    if shutil.disk_usage(root).free < 2 * 1024**3:
        raise RuntimeError('Less than 2 GiB free disk')


def store_resolver(db, row):
    ip = row['A']
    values = [row['profiles'][p] for p in ['windows', 'android', 'macos']]
    with db:
        db.execute('INSERT OR REPLACE INTO resolvers VALUES (?,?,?,?,?,?)',
                   (ip, ipaddress.ip_address(ip).version, *values, pack(row)))
        db.execute('UPDATE discovery SET checked=1 WHERE ip=?', (ip,))
        db.execute('DELETE FROM errors WHERE ip=?', (ip,))


class Validator(engine.Survey):
    def __init__(self, args, db):
        super().__init__(args)
        self.db = db
        self.cache = {}  # In-flight tasks only; completed observations live in SQLite.
        self.lru = OrderedDict()
        self.dns_semaphore = asyncio.Semaphore(96)
        self.new_probes = 0

    async def cached(self, category, values, action):
        key = category + '-' + engine.digest(values)
        if key in self.lru:
            self.lru.move_to_end(key)
            return key, self.lru[key]
        found = self.db.execute('SELECT data FROM probes WHERE key=?', (key,)).fetchone()
        if found:
            result = unpack(found[0])
            self.remember(key, result)
            return key, result
        if key not in self.cache:
            async def execute():
                semaphore = self.endpoints.setdefault(values[0], asyncio.Semaphore(2))
                async with semaphore, self.connections:
                    free_disk(self.out)
                    folder = self.out / 'temporary' / key
                    folder.mkdir(exist_ok=True, parents=True)
                    result = await action(folder)
                    artifacts = [(key, p.name, zlib.compress(p.read_bytes(), 3))
                                 for p in folder.iterdir() if p.is_file() and p.name != 'result.json']
                    with self.db:
                        self.db.executemany('INSERT OR REPLACE INTO artifacts VALUES (?,?,?)', artifacts)
                        self.db.execute('INSERT OR REPLACE INTO probes VALUES (?,?,?)', (key, category, pack(result)))
                    # All files in this dedicated temporary folder are now stored in SQLite.
                    for path in folder.iterdir():
                        path.unlink()
                    folder.rmdir()
                    self.new_probes += 1
                    await asyncio.sleep(0.2)
                    return result
            self.cache[key] = asyncio.create_task(execute())
        task = self.cache[key]
        try:
            result = await task
            self.remember(key, result)
            return key, result
        finally:
            if task.done() and self.cache.get(key) is task:
                self.cache.pop(key, None)

    def remember(self, key, result):
        self.lru[key] = result
        if len(self.lru) > 4096:
            self.lru.popitem(last=False)


async def refresh(args, db):
    inputs = (args.root / 'input-union.txt').read_text().splitlines()
    finished = {row[0] for row in db.execute('SELECT ip FROM discovery')}
    queue = asyncio.Queue()
    for ip in inputs:
        if ip not in finished:
            queue.put_nowait(ip)
    limiter = discovery.Rate(args.qps)
    counts = Counter(dict(db.execute('SELECT outcome,COUNT(*) FROM discovery GROUP BY outcome')))
    started = time.monotonic()

    async def worker():
        while True:
            try:
                ip = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            row = await discovery.ddr(ip, limiter, args)
            with db:
                db.execute('INSERT OR IGNORE INTO discovery(ip,family,outcome,data) VALUES (?,?,?,?)',
                           (ip, ipaddress.ip_address(ip).version, row['outcome'], pack(row)))
                if row['outcome'] != 'svcb_answer':
                    store_resolver(db, {'A': ip, 'vantage': args.vantage, 'utc': discovery.utc(),
                        'native_os_execution': False, 'services': [], 'followup_dns': [],
                        'discovery_outcome': row['outcome'],
                        'profiles': {p: 'no_current_svcb' for p in ['windows', 'android', 'macos']}})
            counts[row['outcome']] += 1
            queue.task_done()

    async def reporter():
        while True:
            free_disk(args.root)
            save(args.root / 'refresh-progress.json', {'utc': discovery.utc(), 'complete': False,
                 'total': len(inputs), 'finished': sum(counts.values()), 'counts': dict(counts),
                 'elapsed_seconds': time.monotonic() - started, 'qps': args.qps})
            await asyncio.sleep(20)

    report = asyncio.create_task(reporter())
    tasks = asyncio.gather(*(worker() for _ in range(args.refresh_workers)))
    try:
        done, _ = await asyncio.wait([report, tasks], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        await tasks
    finally:
        report.cancel()
        if not tasks.done():
            tasks.cancel()
            await asyncio.gather(tasks, return_exceptions=True)
    assert db.execute('SELECT COUNT(*) FROM discovery').fetchone()[0] == len(inputs)
    set_meta(db, 'refresh_complete', {'utc': discovery.utc(), 'total': len(inputs)})
    save(args.root / 'refresh-progress.json', {'utc': discovery.utc(), 'complete': True,
         'total': len(inputs), 'finished': sum(counts.values()), 'counts': dict(counts)})


def counts(db):
    output = {}
    for family in [4, 6]:
        group = {'discovery': dict(db.execute('SELECT outcome,COUNT(*) FROM discovery WHERE family=? GROUP BY outcome', (family,)))}
        for profile in ['windows', 'android', 'macos']:
            group[profile] = dict(db.execute(f'SELECT {profile},COUNT(*) FROM resolvers WHERE family=? GROUP BY {profile}', (family,)))
        output['ipv' + str(family)] = group
    output['probes'] = dict(db.execute('SELECT category,COUNT(*) FROM probes GROUP BY category'))
    output['errors'] = db.execute('SELECT COUNT(*) FROM errors').fetchone()[0]
    return output


async def endpoints(args, db):
    args.output = str(args.root)
    survey = Validator(args, db)
    original_store = engine.store

    def capture_store(path, value):
        if path.parent.name == 'resolvers':
            store_resolver(db, value)
        else:
            original_store(path, value)
    engine.store = capture_store

    async def worker(row):
        ip, payload = row
        try:
            result = await survey.process(unpack(payload))
            if result is None:
                raise ValueError('Positive discovery produced no profile result')
        except Exception:
            error = traceback.format_exc()
            print(ip, error, flush=True)
            with db:
                db.execute('INSERT OR REPLACE INTO errors VALUES (?,?)', (ip, error))
                db.execute('UPDATE discovery SET failures=failures+1 WHERE ip=?', (ip,))

    async def reporter():
        while True:
            free_disk(args.root)
            state = {'utc': discovery.utc(), 'complete': False, 'counts': counts(db),
                     'pending': db.execute('SELECT COUNT(*) FROM discovery WHERE checked=0').fetchone()[0],
                     'inflight_probes': len(survey.cache)}
            save(args.root / 'endpoint-progress.json', state)
            await asyncio.sleep(30)

    async def consume():
        running = {}
        while True:
            rows = db.execute("SELECT ip,data FROM discovery WHERE checked=0 AND failures<3 AND outcome='svcb_answer' LIMIT ?", (args.workers * 2,)).fetchall()
            for row in rows:
                if len(running) >= args.workers:
                    break
                if row[0] not in running:
                    running[row[0]] = asyncio.create_task(worker(row))
            if running:
                done, _ = await asyncio.wait(running.values(), return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                running = {ip: task for ip, task in running.items() if not task.done()}
                continue
            if get_meta(db, 'refresh_complete'):
                break
            await asyncio.sleep(5)
        if db.execute('SELECT COUNT(*) FROM discovery WHERE checked=0').fetchone()[0]:
            raise RuntimeError('Unprocessed resolvers remain; inspect errors table')

    reporter_task = asyncio.create_task(reporter())
    consumer = asyncio.create_task(consume())
    try:
        done, _ = await asyncio.wait([reporter_task, consumer], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        await consumer
    finally:
        reporter_task.cancel()
        if not consumer.done():
            consumer.cancel()
            await asyncio.gather(consumer, return_exceptions=True)
    set_meta(db, 'endpoints_complete', {'utc': discovery.utc()})
    save(args.root / 'endpoint-progress.json', {'utc': discovery.utc(), 'complete': True, 'counts': counts(db)})
    summarize(args, db)


def summarize(args, db):
    summary = {'utc': discovery.utc(), 'complete': bool(get_meta(db, 'endpoints_complete')),
               'vantage': args.vantage, 'counts': counts(db), 'native_os_execution': False}
    if not summary['complete']:
        raise RuntimeError('Validation is still running')
    hashes = {}
    for family in [4, 6]:
        for profile in ['windows', 'android', 'macos']:
            path = args.root / f'ipv{family}-{profile}-success.txt'
            ips = [r[0] for r in db.execute(f"SELECT ip FROM resolvers WHERE family=? AND {profile}='pass' ORDER BY ip", (family,))]
            path.write_text(''.join(ip + '\n' for ip in ips))
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    output = args.root / 'resolvers.jsonl.gz'
    with gzip.open(output.with_suffix('.gz.tmp'), 'wt', compresslevel=6) as stream:
        for (payload,) in db.execute('SELECT data FROM resolvers ORDER BY ip'):
            stream.write(zlib.decompress(payload).decode() + '\n')
    output.with_suffix('.gz.tmp').replace(output)
    hashes[output.name] = hashlib.sha256(output.read_bytes()).hexdigest()
    summary['sha256'] = hashes
    save(args.root / 'summary.json', summary)
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')


def plan(args, db):
    target = args.root / 'ca-bundle.pem'
    if not target.exists():
        shutil.copyfile(certifi.where(), target)
    original = args.root / 'plan.json'
    if not original.exists():
        value = {'created_utc': discovery.utc(), 'vantage': args.vantage,
            'input_sha256': hashlib.sha256((args.root / 'input-union.txt').read_bytes()).hexdigest(),
            'total_candidates': len((args.root / 'input-union.txt').read_text().splitlines()),
            'input_shuffle_seed': args.input_seed,
            'discovery_source': args.discovery_source,
            'refresh': 'Fresh SVCB at each candidate independently at each node; up to 3 UDP then TCP',
            'limits': {'dns_qps': args.qps, 'refresh_workers': args.refresh_workers,
                       'resolver_workers': args.workers, 'connections': args.connections,
                       'per_endpoint_connections': 2, 'timeout_seconds': args.timeout},
            'profiles': {'windows': 'H2 POST; authority T; chain, T and original IP SAN',
                         'android': 'DDR enabled; H3 GET; authority T; F equals original IP; chain and T',
                         'macos': 'H2 GET; authority original IP; chain, T and original IP SAN; no ipv4hint triggers target lookup'},
            'ipv6_authority': 'Bracketed literal for macOS; domain authority for Windows and Android',
            'model_notes': ['Native macOS domain-only certificate controls confirm the original-IP SAN requirement',
                            'IPv6 transport uses the same behavioral models; a separate native IPv6 OS matrix has not been run'],
            'native_os_execution': False, 'trust': 'Frozen certifi Mozilla CA bundle',
            'ca_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'sources': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in ROOT.glob('*.py')},
            'versions': {n: importlib.metadata.version(n) for n in ['dnspython','h2','aioquic','cryptography','certifi','uritemplate']}}
        save(original, value)
    engine.certifi.where = lambda: str(target)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('role', choices=['init','refresh','endpoints','status','summarize'])
    p.add_argument('--root', type=Path, required=True, help='Measurement output directory')
    p.add_argument('--input', type=Path, help='Newline-delimited original resolver IPs; copied into --root on initialization')
    p.add_argument('--input-seed', type=int, help='Optional provenance for an externally shuffled input')
    p.add_argument('--discovery-source', default='user-supplied address list')
    p.add_argument('--vantage', required=True)
    p.add_argument('--qps', type=float, default=500)
    p.add_argument('--refresh-workers', type=int, default=1024)
    p.add_argument('--workers', type=int, default=96)
    p.add_argument('--connections', type=int, default=48)
    p.add_argument('--timeout', type=float, default=6)
    args = p.parse_args()
    args.root = args.root.resolve()
    args.root.mkdir(parents=True, exist_ok=True)
    if args.input is not None:
        source = args.input.resolve()
        target = args.root / 'input-union.txt'
        if source != target:
            if target.exists() and target.read_bytes() != source.read_bytes():
                p.error('The supplied input differs from the existing output directory input')
            if not target.exists():
                shutil.copyfile(source, target)
    if args.role != 'status' and not (args.root / 'input-union.txt').is_file():
        p.error('Supply --input when initializing a new output directory')
    db = database(args.root)
    if args.role == 'status':
        print(json.dumps({'utc': discovery.utc(), 'counts': counts(db),
             'refresh_complete': get_meta(db,'refresh_complete'),
             'endpoints_complete': get_meta(db,'endpoints_complete'),
             'database_mib': round((args.root/'evidence.sqlite').stat().st_size/1024**2,1)}, indent=2))
    else:
        plan(args, db)
        if args.role == 'refresh':
            asyncio.run(refresh(args,db))
        elif args.role == 'endpoints':
            asyncio.run(endpoints(args,db))
        elif args.role == 'summarize':
            summarize(args,db)
