#!/usr/bin/env python3
"""Local Cisco Secure Access usage explorer. Python standard library + curl."""
import argparse
import base64
import http.client
from collections import OrderedDict
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import csv
import datetime as dt
import gzip
import getpass
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
UTC = dt.timezone.utc
BUCKET = None
PREFIX = None
REGION = None
NS = {'s': 'http://s3.amazonaws.com/doc/2006-03-01/'}
def sync_progress(phase=None):
    return {'processed':0,'total':0,'skipped':0,'downloaded':0,'listed':0,
            'policyError':None,'directoriesDone':0,'directoriesTotal':62,'phase':phase,'durationSeconds':0}


STATE = {'running': False, 'error': None, 'lastSync': None, **sync_progress()}
LOCK = threading.Lock()
RUNTIME_LOCK = threading.RLock()
SETTINGS_LOCK = threading.Lock()
CSRF_TOKEN = secrets.token_urlsafe(32)
CONFIG_PATH = None
ACTIVE_SETTINGS = None
DB = ROOT / '.cache' / 'traffic.sqlite'
CREDENTIALS = None
HISTORY_DAYS = 30
IMPORT_WORKERS = 4


def user_directory():
    if sys.platform == 'darwin':
        return Path.home() / 'Library' / 'Application Support' / 'CSA Traffic'
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'CSA Traffic'
    return Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'csa-traffic'


def write_private_json(path, data):
    path = Path(path)
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not parent_existed:
        path.parent.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix='.write-')
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_settings(path):
    path = Path(path).expanduser().resolve()
    with path.open(encoding='utf-8') as handle:
        data = json.load(handle)
    return validate_settings(data, path)


def sync_days(value):
    if type(value) is not int or not 1 <= value <= HISTORY_DAYS:
        raise ValueError('invalidSyncDays')
    return value


def validate_settings(data, path):
    path = Path(path).expanduser().resolve()
    if not isinstance(data,dict) or any(not isinstance(data.get(key,''),str) for key in ['s3Path','region','credentialsFile']):
        raise ValueError('Invalid configuration')
    location = urllib.parse.urlsplit(data.get('s3Path', '').strip())
    bucket = location.netloc
    if location.scheme != 's3' or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket) or location.query or location.fragment:
        raise ValueError('Invalid s3Path. Use s3://bucket/customer-prefix/')
    prefix = location.path.lstrip('/')
    if prefix and not prefix.endswith('/'):
        prefix += '/'
    region = data.get('region', '').strip()
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+', region):
        raise ValueError('Invalid AWS region')
    credentials = Path(data.get('credentialsFile', 'credentials.json')).expanduser()
    if not credentials.is_absolute():
        credentials = path.parent / credentials
    directory=data.get('cacheDirectory','')
    if not isinstance(directory,str):
        raise ValueError('cachePathInvalid')
    directory=directory.strip()
    root=path.parent/'cache'
    if directory:
        root=Path(directory).expanduser()
        if not root.is_absolute():
            raise ValueError('cachePathInvalid')
        root=root.resolve()
        directory=str(root)
    # Keep different tenants in separate caches, even after changing configuration.
    fingerprint = hashlib.sha256((region+'\n'+bucket+'\n'+prefix).encode()).hexdigest()[:16]
    return {'syncDays':sync_days(data.get('syncDays', HISTORY_DAYS)), 'bucket': bucket, 'prefix': prefix, 'region': region, 'credentials': credentials.resolve(), 'cacheDirectory':directory, 'database': root / fingerprint / 'traffic.sqlite'}


def cache_id(settings):
    database=settings['database']
    if settings.get('cacheDirectory'):
        return hashlib.sha256(os.fsencode(database)).hexdigest()
    return database.parent.name


def policy_key_path(settings):
    return CONFIG_PATH.parent / ('credentials-policy-'+settings['database'].parent.name+'.json')


def public_settings():
    with LOCK:
        settings = ACTIVE_SETTINGS
        return {
            'configured': settings is not None,
            'cacheDirectory':(settings or {}).get('cacheDirectory',''),
            'defaultCacheDirectory':str(CONFIG_PATH.parent/'cache') if CONFIG_PATH else '',
            'databasePath':str(settings['database']) if settings else '',
            'cacheId': cache_id(settings) if settings else None,
            'syncDays': (settings or {}).get('syncDays', HISTORY_DAYS),
            's3Path': 's3://'+settings['bucket']+'/'+settings['prefix'] if settings else '',
            'region': settings['region'] if settings else 'eu-central-1',
            'hasPolicyCredentials': bool(settings and policy_key_path(settings).is_file()),
            'hasCredentials': bool(settings and settings['credentials'].is_file()),
            'csrfToken': CSRF_TOKEN,
        }


def create_backup():
    """Explicit, CSRF-protected export only; never part of public settings."""
    with SETTINGS_LOCK:
        with LOCK:
            settings = ACTIVE_SETTINGS
        if not settings:
            raise ValueError('backupNotConfigured')
        with settings['credentials'].open(encoding='utf-8') as handle:
            values = json.load(handle)
        if any(not isinstance(values.get(k),str) or not values[k].strip() for k in ['accessKeyId','secretAccessKey']):
            raise ValueError('backupInvalid')
        return {
            'format':'csa-traffic-settings', 'version':1,
            'createdAt':utc_now().isoformat(),
            'settings':{'syncDays':settings.get('syncDays', HISTORY_DAYS),'s3Path':'s3://'+settings['bucket']+'/'+settings['prefix'],'region':settings['region']},
            'credentials':{'accessKeyId':values['accessKeyId'],'secretAccessKey':values['secretAccessKey']},
        }


def restore_backup(data):
    if not isinstance(data,dict) or data.get('format')!='csa-traffic-settings' or type(data.get('version')) is not int or data['version']!=1:
        raise ValueError('backupInvalid')
    settings, credentials = data.get('settings'), data.get('credentials')
    if not isinstance(settings,dict) or not isinstance(credentials,dict):
        raise ValueError('backupInvalid')
    candidate={k:settings.get(k,'') for k in ['s3Path','region']}
    candidate.update({k:credentials.get(k,'') for k in ['accessKeyId','secretAccessKey']})
    # A restore may not silently fall back to the current machine's saved keys.
    if any(not isinstance(value,str) or not value.strip() for value in candidate.values()):
        raise ValueError('backupInvalid')
    candidate['syncDays']=sync_days(settings.get('syncDays', HISTORY_DAYS))
    result=update_connection(candidate,save=True)
    preferences=data.get('preferences')
    if isinstance(preferences,dict) and preferences.get('language') in ['cs','en']:
        result['language']=preferences['language']
    return result


def activate_settings(settings, last_sync=None):
    global ACTIVE_SETTINGS, BUCKET, PREFIX, REGION, CREDENTIALS, DB
    with LOCK:
        ACTIVE_SETTINGS = settings
        BUCKET, PREFIX, REGION = settings['bucket'], settings['prefix'], settings['region']
        CREDENTIALS, DB = settings['credentials'], settings['database']
        STATE.update(running=False, error=None, lastSync=last_sync, **sync_progress())


def connection_candidate(data):
    if not isinstance(data, dict) or any(not isinstance(data.get(k, ''), str) for k in ['s3Path','region','accessKeyId','secretAccessKey']):
        raise ValueError('settingsInvalid')
    try:
        directory=data.get('cacheDirectory',(ACTIVE_SETTINGS or {}).get('cacheDirectory',''))
        settings = validate_settings({'cacheDirectory':directory,'s3Path':data.get('s3Path',''), 'region':data.get('region',''), 'credentialsFile':'credentials.json'}, CONFIG_PATH)
    except (ValueError, TypeError) as error:
        if str(error)=='cachePathInvalid':
            raise
        raise ValueError('settingsInvalid') from None
    settings['syncDays'] = sync_days(data.get('syncDays', (ACTIVE_SETTINGS or {}).get('syncDays', HISTORY_DAYS)))
    access, secret = data.get('accessKeyId','').strip(), data.get('secretAccessKey','').strip()
    old = ACTIVE_SETTINGS
    if not access and not secret:
        if not old or any(settings[k] != old[k] for k in ['bucket','prefix','region']):
            raise ValueError('settingsKeysRequired')
        with old['credentials'].open(encoding='utf-8') as handle:
            values = json.load(handle)
        settings['credentials'] = old['credentials']
    elif not access or not secret:
        raise ValueError('settingsKeysRequired')
    else:
        values = {'accessKeyId':access,'secretAccessKey':secret}
    if any(not isinstance(values.get(k),str) or not values[k].strip() or any(c.isspace() for c in values[k]) for k in ['accessKeyId','secretAccessKey']):
        raise ValueError('settingsKeysRequired')
    return settings, values, bool(access and secret)


def update_connection(data, save=False):
    with SETTINGS_LOCK:
        with LOCK:
            if STATE['running']:
                raise ValueError('settingsBusy')
        settings, values, new_keys = connection_candidate(data)
        if settings['cacheDirectory']:
            directory=Path(settings['cacheDirectory'])
            if not directory.is_dir() or not os.access(directory,os.W_OK|os.X_OK):
                raise ValueError('cachePathUnavailable')
        client = S3(values=values, settings=settings)
        query = urllib.parse.urlencode({'list-type':'2','prefix':settings['prefix'],'max-keys':'1'})
        root = ET.fromstring(client.get('?'+query, timeout=20))
        if root.tag != '{'+NS['s']+'}ListBucketResult':
            raise ValueError('settingsProbeFailed')
        if not save:
            return {'ok':True}
        with settings_runtime():
            with LOCK:
                if STATE['running']:
                    raise ValueError('settingsBusy')
            with connect(settings['database']) as db:
                previous = db.execute("SELECT value FROM metadata WHERE key='lastSync'").fetchone()
            staged = None
            old = ACTIVE_SETTINGS
            if new_keys:
                staged = CONFIG_PATH.parent / ('credentials-'+secrets.token_hex(8)+'.json')
                write_private_json(staged, values)
                settings['credentials'] = staged
            credential_path = settings['credentials']
            credential_ref = credential_path.name if credential_path.parent == CONFIG_PATH.parent else str(credential_path)
            try:
                write_private_json(CONFIG_PATH, {'cacheDirectory':settings['cacheDirectory'],'syncDays':settings['syncDays'],'s3Path':'s3://'+settings['bucket']+'/'+settings['prefix'], 'region':settings['region'], 'credentialsFile':credential_ref})
            except Exception:
                if staged:
                    staged.unlink(missing_ok=True)
                raise
            activate_settings(settings, previous[0] if previous else None)
            # Remove only superseded key files managed by this application's config directory.
            if new_keys and old:
                old_path = old['credentials']
                if old_path != credential_path and old_path.parent == CONFIG_PATH.parent and (old_path.name == 'credentials.json' or re.fullmatch(r'credentials-[a-f0-9]{16}\.json',old_path.name)):
                    try:
                        old_path.unlink(missing_ok=True)
                    except OSError:
                        pass
        return {'ok':True, **public_settings()}


@contextmanager
def settings_runtime():
    if not RUNTIME_LOCK.acquire(blocking=False):
        raise ValueError('settingsBusy')
    try:
        yield
    finally:
        RUNTIME_LOCK.release()


def setup_configuration(path):
    path = Path(path).expanduser().resolve()
    credentials = path.parent / 'credentials.json'
    print('CSA Traffic setup / První nastavení')
    if path.exists() or credentials.exists():
        if input('Replace existing configuration and credentials? / Přepsat? [y/N]: ').strip().lower() not in ['y','yes','ano']:
            return
    data = {'s3Path': input('S3 data path (s3://bucket/prefix/): ').strip(), 'region': input('AWS region [eu-central-1]: ').strip() or 'eu-central-1', 'credentialsFile': 'credentials.json'}
    # Validate before replacing a working configuration.
    parsed = urllib.parse.urlsplit(data['s3Path'])
    if parsed.scheme != 's3' or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', parsed.netloc) or parsed.query or parsed.fragment or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+', data['region']):
        raise ValueError('Invalid S3 path or region')
    access = getpass.getpass('S3 Access Key ID (hidden / skryté): ').strip()
    secret = getpass.getpass('S3 Secret Access Key (hidden / skryté): ').strip()
    if not access or not secret:
        raise ValueError('Both S3 credentials are required')
    write_private_json(credentials, {'accessKeyId':access, 'secretAccessKey':secret})
    write_private_json(path, data)
    print('Configuration saved / Nastavení uloženo: '+str(path))


def utc_now():
    return dt.datetime.now(UTC)


def parse_ip_filter(value):
    """Union of CIDRs, full address ranges and IPv4 octet boxes; no enumeration."""
    value = re.sub(r'\s*[-–—]\s*', '-', value.strip())
    if not value:
        return []
    parts = [p for p in re.split(r'[,;\s]+', value) if p]
    if len(parts) > 1000:
        raise ValueError('Použij nejvýše 1000 položek v IP filtru')
    ranges, boxes = [], []
    for part in parts:
        try:
            if '-' in part and ':' not in part and len(part.split('.')) == 4:
                bounds = []
                for octet in part.split('.'):
                    if not re.fullmatch(r'(?:0|[1-9][0-9]{0,2})(?:-(?:0|[1-9][0-9]{0,2}))?',octet):
                        raise ValueError()
                    ends = [int(x) for x in octet.split('-')]
                    lo, hi = ends[0], ends[-1]
                    if not 0 <= lo <= hi <= 255:
                        raise ValueError()
                    bounds.append((lo,hi))
                boxes.append((4,tuple(lo for lo,_ in bounds),tuple(hi for _,hi in bounds)))
                continue
            elif '-' in part:
                left, right = part.split('-', 1)
                low, high = ipaddress.ip_address(left), ipaddress.ip_address(right)
                if low.version != high.version or int(low) > int(high):
                    raise ValueError()
            else:
                network = ipaddress.ip_network(part, strict=False)
                low, high = network.network_address, network.broadcast_address
        except ValueError:
            raise ValueError('Neplatná položka IP filtru: ' + part[:100] + '. Použij IP, CIDR, rozsah dvou adres nebo rozsahy oktetů (např. 10-11.30-33.1-2.3-50).') from None
        ranges.append((low.version, int(low), int(high)))
    merged = []
    for version, low, high in sorted(ranges):
        if merged and merged[-1][0] == version and low <= merged[-1][2] + 1:
            merged[-1] = (version, merged[-1][1], max(high, merged[-1][2]))
        else:
            merged.append((version, low, high))
    return merged+list(dict.fromkeys(boxes))


def matches_ip(value, ranges):
    if not ranges:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    numeric, octets = int(address), address.packed
    for version, low, high in ranges:
        if address.version != version:
            continue
        if isinstance(low,tuple):
            if all(lo <= octet <= hi for octet,lo,hi in zip(octets,low,high)):
                return True
        elif low <= numeric <= high:
            return True
    return False


@contextmanager
def connect(database=None):
    path = Path(database) if database else DB
    default_root=CONFIG_PATH.parent/'cache' if CONFIG_PATH else None
    if path.parent.parent==default_root:
        default_root.mkdir(parents=True,exist_ok=True,mode=0o700)
    # Create only the connection directory. Never recreate a missing external volume.
    try:
        path.parent.mkdir(exist_ok=True,mode=0o700)
    except OSError:
        raise ValueError('cachePathUnavailable') from None
    path.parent.chmod(0o700)
    db = sqlite3.connect(path, timeout=30)
    path.chmod(0o600)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS files (key TEXT PRIMARY KEY, etag TEXT, imported TEXT);
      CREATE TABLE IF NOT EXISTS events (
        file TEXT, rownum INTEGER, source TEXT, ts REAL, ip TEXT, identities TEXT,
        sent INTEGER, received INTEGER, scope TEXT, PRIMARY KEY(file,rownum));
      CREATE INDEX IF NOT EXISTS event_time ON events(source,ts);
      CREATE INDEX IF NOT EXISTS event_ip_time ON events(source,ip,ts);
      CREATE TABLE IF NOT EXISTS event_details (
        file TEXT, rownum INTEGER, details TEXT NOT NULL, PRIMARY KEY(file,rownum));
      CREATE TABLE IF NOT EXISTS omitted_history (file TEXT PRIMARY KEY, newest REAL NOT NULL);
      CREATE TABLE IF NOT EXISTS detailed_files (key TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
    ''')
    try:
        with db:
            yield db
    finally:
        db.close()


def norm(value):
    return ''.join(c for c in value.lower() if c.isalnum())


def timestamp(value):
    value = value.strip()
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()
    except ValueError:
        raise ValueError('Neplatný čas záznamu') from None


def byte_value(value):
    if value is None or not value.strip():
        return None
    try:
        result = int(value)
    except ValueError:
        raise ValueError('Neplatné počítadlo bajtů') from None
    if result < 0:
        raise ValueError('Záporné počítadlo bajtů')
    return result


def identity_values(value):
    value = value.strip()
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list) and all(isinstance(x, (str, int)) for x in parsed):
            return list(dict.fromkeys(str(x) for x in parsed))
    except (ValueError, TypeError):
        pass
    # Preserve CSV identity labels verbatim: commas can belong to a label.
    return [value]


DETAIL_FIELDS = set('timestamp direction protocol sourceip sourceport destinationip destinationport fqdns hostname servername action ruleid rulesetid firstpackettimestamp lastpackettimestamp packetssent packetsreceived bytessent bytesreceived destinationcountry sourcecountry awsregion datacenter appid applicationids applicationentityname privateappgroupid privateflow trafficsource internalclientip externalclientip requestmethod url statuscode contenttype requestsize responsesize responsebodysize identities policyidentitylabel identitytypes identitytype fwblockreason forwardingmethod egressip egress'.split())


def parse_log(blob, source, key, details=None):
    raw = io.BytesIO(blob) if isinstance(blob, (bytes,bytearray)) else open(blob,'rb')
    with raw, io.TextIOWrapper(gzip.GzipFile(fileobj=raw), encoding='utf-8-sig', newline='') as stream:
        # Cisco v10 positional fields; only exact documented widths are accepted.
        positional = {
            'firewall': 'timestamp,origin ids,identities,identity type,direction,protocol,packet size,source ip,source port,destination ip,destination port,data center,rule id,action,fqdns,destination list ids,first packet timestamp,last packet timestamp,packets sent,packets received,bytes sent,bytes received,fw event id,destination country,aws region,app id,private app group id,private flow,posture id,casi category ids,traffic source,content category ids,content category list ids,organization id'.split(','),
            'proxy': 'timestamp,policy identity label,internal client ip,external client ip,destination ip,content type,action,url,referer,user agent,status code,request size,response size,response body size,sha-sha256,categories,av detections,puas,amp disposition,amp malware name,amp score,policy identity type,blocked categories,identities,identity types,request method,dlp status,certificate errors,file name,ruleset id,rule id,destination list ids,isolate action,file action,warn status,forwarding method,producer,msp organization id,geo location of blocked destination countries,application ids,hostname,data center,egress,server name,time based rule,security overridden,detected response file type,warn categories,organization id'.split(','),
        }
        extension = {
            'firewall': 'egress ip,egress,event correlation id,destination sgt origin id,fw block reason,source country'.split(','),
            'proxy': 'application entity name,application entity category,egress ip,ai model name,ai supply chain categories,event correlation id,isolation profile id,source country'.split(','),
        }
        layouts = {len(positional[source]): positional[source], len(positional[source])+len(extension[source]): positional[source]+extension[source]}
        reader = csv.reader(stream)
        required = ['timestamp', 'sourceip', 'bytessent', 'bytesreceived'] if source == 'firewall' else ['timestamp', 'internalclientip', 'requestsize', 'responsesize']
        header = None
        result = []
        for index, values in enumerate(reader, 1):
            if not values:
                continue
            if norm(values[0]) == 'timestamp':
                header = [norm(x) for x in values]
                if any(x not in header for x in required):
                    raise ValueError('Chybí povinné sloupce v ' + source + ' logu')
                continue
            # Cisco may mix v10/v17 rows in one export during an upgrade.
            names = header if header and len(header) == len(values) else layouts.get(len(values))
            if not names:
                raise ValueError('Nepodporovaný počet CSV sloupců: ' + str(len(values)))
            row = dict(zip((norm(x) for x in names), values))
            def get(name):
                return (row.get(name) or '').strip()
            ts = timestamp(get('timestamp'))
            ip = get('sourceip' if source == 'firewall' else 'internalclientip')
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                ip = ''
            sent = byte_value(get('bytessent' if source == 'firewall' else 'requestsize'))
            received = byte_value(get('bytesreceived' if source == 'firewall' else 'responsesize'))
            flow = get('privateflow').lower()
            scope = ('private' if flow == 'true' else 'internet' if flow == 'false' else 'unknown') if source == 'firewall' else 'internet'
            identities = identity_values(get('identities') or get('policyidentitylabel'))
            result.append((key, index, source, ts, ip, json.dumps(identities, ensure_ascii=False), sent, received, scope))
            if details is not None:
                fields = {name: value.strip() for name, value in row.items() if name in DETAIL_FIELDS and value.strip()}
                truncated = [name for name, value in fields.items() if len(value) > 16384]
                fields = {name: value[:16384] for name, value in fields.items()}
                details.append((key, index, json.dumps({'fields': fields, 'truncated': truncated}, ensure_ascii=False)))
        return result


class S3:
    def __init__(self, credentials=None, *, values=None, settings=None):
        if values is None:
            with open(credentials) as f:
                data = json.load(f)
        else:
            data = values
        self.region = settings['region'] if settings else REGION
        self.bucket = settings['bucket'] if settings else BUCKET
        self.auth = data['accessKeyId'].strip() + ':' + data['secretAccessKey'].strip()
        if not all(data.get(k, '').strip() for k in ['accessKeyId', 'secretAccessKey']):
            raise ValueError('Soubor s přístupovými údaji není vyplněný')

    def _request(self, path, timeout=90, destination=None):
        config = 'user = ' + json.dumps(self.auth) + '\n'
        suffix = 'amazonaws.com.cn' if self.region.startswith('cn-') else 'amazonaws.com'
        output = ['--output',str(destination)] if destination is not None else []
        proc = subprocess.run(['curl', '--silent', '--show-error', '--connect-timeout', '10', '--max-time', str(timeout), '--max-filesize', '150000000', '--aws-sigv4', 'aws:amz:'+self.region+':s3', '--config', '-', '--write-out', '\n%{http_code}', *output, 'https://s3.'+self.region+'.'+suffix+'/'+self.bucket+'/'+path], input=config.encode(), capture_output=True)
        if proc.returncode:
            raise RuntimeError('Připojení k S3 selhalo (curl ' + str(proc.returncode) + ')')
        body, status = proc.stdout.rsplit(b'\n', 1)
        if status != b'200':
            try:
                if destination is not None:
                    with open(destination,'rb') as handle:
                        body = handle.read(65536)
                code = ET.fromstring(body).findtext('Code') or 'Unknown'
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9]{0,80}',code):
                    code = 'Unknown'
            except ET.ParseError:
                code = 'Unknown'
            raise RuntimeError('S3 HTTP ' + status.decode() + ': ' + code)
        return body

    def get(self, path, timeout=90):
        return self._request(path,timeout)

    def download(self, path, destination):
        self._request(path,destination=destination)

    def list(self, prefix):
        token = None
        while True:
            args = {'list-type': '2', 'prefix': prefix, 'max-keys': '1000'}
            if token:
                args['continuation-token'] = token
            root = ET.fromstring(self.get('?' + urllib.parse.urlencode(args)))
            for item in root.findall('s:Contents', NS):
                key = item.findtext('s:Key', namespaces=NS)
                if key.endswith('.csv.gz'):
                    yield key, item.findtext('s:ETag', namespaces=NS)
            if root.findtext('s:IsTruncated', namespaces=NS) != 'true':
                break
            token = root.findtext('s:NextContinuationToken', namespaces=NS)
            if not token:
                raise RuntimeError('S3 nevrátilo pokračovací token')


def ingest():
    with RUNTIME_LOCK:
        ingest_unlocked()


def parallel_results(executor, items, function):
    """Bound both network requests and completed files waiting for the DB writer."""
    iterator = iter(items)
    pending = {}
    def submit_one():
        try:
            item = next(iterator)
        except StopIteration:
            return
        pending[executor.submit(function,item)] = item
    for _ in range(IMPORT_WORKERS):
        submit_one()
    try:
        while pending:
            done, _ = wait(pending,return_when=FIRST_COMPLETED)
            for future in done:
                item = pending.pop(future)
                yield item, future.result()
                submit_one()
    finally:
        for future in pending:
            future.cancel()


# Read progress without taking the database writer lock.
PRUNE_PROGRESS = {'phase':'idle'}


def prune_phase(phase, **values):
    with LOCK:
        PRUNE_PROGRESS.clear()
        PRUNE_PROGRESS.update(phase=phase, started=time.monotonic(), **values)


def prune_status():
    with LOCK:
        state = dict(PRUNE_PROGRESS)
    if 'started' in state:
        elapsed = time.monotonic() - state.pop('started')
        state['elapsed'] = int(elapsed)
        if state['phase'] == 'deleting' and state['done'] and elapsed >= 1:
            state['remaining'] = round(elapsed * (state['total'] - state['done']) / state['done'])
        elif state['phase'] == 'compacting' and state.get('estimate'):
            remaining = state['estimate'] - elapsed
            if remaining >= 1:
                state['remaining'] = round(remaining)
    return state


def prune_cache(cutoff):
    prune_phase('counting')
    try:
        with connect() as db:
            with db:
                db.execute('BEGIN IMMEDIATE')
                files = db.execute('SELECT file, COUNT(*), MAX(ts) FROM events WHERE ts < ? GROUP BY file',
                                   (cutoff,)).fetchall()
                total = sum(row[1] for row in files)
                removed = 0
                prune_phase('deleting', done=0, total=total)
                for key, count, newest in files:
                    db.execute("""INSERT INTO omitted_history VALUES (?,?)
                                  ON CONFLICT(file) DO UPDATE SET newest=MAX(newest,excluded.newest)""",
                               (key,newest))
                    db.execute("""DELETE FROM event_details WHERE file=? AND rownum IN
                                  (SELECT rownum FROM events WHERE file=? AND ts < ?)""", (key,key,cutoff))
                    db.execute('DELETE FROM events WHERE file=? AND ts < ?', (key,cutoff))
                    removed += count
                    with LOCK:
                        PRUNE_PROGRESS['done'] = removed
                if removed:
                    db.execute("INSERT INTO metadata VALUES ('cacheRevision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")
            if removed:
                pages = db.execute('PRAGMA page_count').fetchone()[0] - db.execute('PRAGMA freelist_count').fetchone()[0]
                previous = db.execute("SELECT value FROM metadata WHERE key='vacuumPagesPerSecond'").fetchone()
                estimate = pages / float(previous[0]) if previous and float(previous[0]) > 0 else None
                prune_phase('compacting', estimate=estimate)
                start = time.monotonic()
                db.execute('VACUUM')
                speed = pages / max(time.monotonic() - start, 0.001)
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('vacuumPagesPerSecond',?)", (speed,))
        return {'removed':removed}
    finally:
        prune_phase('idle')


def update_sync_window(data, prune=False):
    if not isinstance(data, dict):
        raise ValueError('invalidSyncDays')
    days = sync_days(data.get('syncDays'))
    with SETTINGS_LOCK, settings_runtime():
        with LOCK:
            if STATE['running']:
                raise ValueError('settingsBusy')
            if not ACTIVE_SETTINGS:
                raise ValueError('setupRequired')
        if data.get('cacheId') != cache_id(ACTIVE_SETTINGS):
            raise ValueError('settingsReload')
        if not prune:
            with CONFIG_PATH.open(encoding='utf-8') as handle:
                config = json.load(handle)
            config['syncDays'] = days
            write_private_json(CONFIG_PATH, config)
            with LOCK:
                ACTIVE_SETTINGS['syncDays'] = days
            return {'syncDays': days}
        if days != ACTIVE_SETTINGS.get('syncDays', HISTORY_DAYS):
            raise ValueError('saveWindowFirst')
        cutoff = (utc_now() - dt.timedelta(days=days)).timestamp()
        return prune_cache(cutoff)


def ingest_unlocked():
    started = time.perf_counter()
    with LOCK:
        STATE.update(running=True,error=None,**sync_progress('listing'))
    try:
        if ACTIVE_SETTINGS and policy_key_path(ACTIVE_SETTINGS).is_file():
            with LOCK:
                STATE['phase']='policy'
            try:
                refresh_access_policy({'cacheId':cache_id(ACTIVE_SETTINGS)})
            except (ValueError,OSError,sqlite3.Error) as error:
                with LOCK:
                    STATE['policyError']=str(error) if isinstance(error,ValueError) else 'settingsFailed'
            with LOCK:
                STATE['phase']='listing'
        client = S3(CREDENTIALS)
        now = utc_now()
        days_back = (ACTIVE_SETTINGS or {}).get('syncDays', HISTORY_DAYS)
        cutoff_ts = (now - dt.timedelta(days=days_back)).timestamp()
        today = now.date()
        directories = [(source,PREFIX+folder+'/'+(today-dt.timedelta(days=days)).isoformat()+'/')
                       for days in range(days_back,-1,-1)
                       for source,folder in [('firewall','firewalllogs'),('proxy','proxylogs')]]
        with LOCK:
            STATE['directoriesTotal'] = len(directories)
        with connect() as db:
            known = {row['key']:row['etag'] for row in db.execute('SELECT key,etag FROM files LEFT JOIN omitted_history ON file=key WHERE newest IS NULL OR newest < ?', (cutoff_ts,))}
        # A private temporary directory holds at most four compressed files. Only
        # one file is parsed in memory, and only this thread writes SQLite.
        with tempfile.TemporaryDirectory(prefix='csa-import-',dir=DB.parent) as temporary, ThreadPoolExecutor(max_workers=IMPORT_WORKERS) as executor:
            files = {}
            for (source,_), listed in parallel_results(executor,directories,lambda item:list(client.list(item[1]))):
                for key,etag in listed:
                    files[key] = (source,key,etag)
                with LOCK:
                    STATE['directoriesDone'] += 1
                    STATE['listed'] = len(files)
            pending = sorted((item for item in files.values() if item[1] not in known or not item[2] or known[item[1]] != item[2]),key=lambda item:(item[1].split('/')[-2],item[1]),reverse=True)
            with LOCK:
                STATE.update(phase='downloading',total=len(pending),skipped=len(files)-len(pending))
            def download(item):
                _,key,_ = item
                descriptor,path = tempfile.mkstemp(suffix='.csv.gz',dir=temporary)
                os.close(descriptor)
                if hasattr(client,'download'):
                    client.download(urllib.parse.quote(key,safe='/'),path)
                else:
                    # Simple in-memory clients are also useful in offline tests.
                    Path(path).write_bytes(client.get(urllib.parse.quote(key,safe='/')))
                return path
            with connect() as db:
                for (source,key,etag),path in parallel_results(executor,pending,download):
                    try:
                        details = []
                        rows = parse_log(path,source,key,details)
                        excluded = [r[3] for r in rows if r[3] < cutoff_ts]
                        if excluded:
                            rows = [r for r in rows if r[3] >= cutoff_ts]
                            kept = {r[1] for r in rows}
                            details = [r for r in details if r[1] in kept]
                        with db:
                            db.execute('DELETE FROM omitted_history WHERE file=?', (key,))
                            if excluded:
                                db.execute('INSERT INTO omitted_history VALUES (?,?)', (key,max(excluded)))
                            db.execute('DELETE FROM events WHERE file=?',(key,))
                            db.execute('DELETE FROM event_details WHERE file=?',(key,))
                            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',rows)
                            db.executemany('INSERT INTO event_details VALUES (?,?,?)',details)
                            db.execute('INSERT OR REPLACE INTO detailed_files VALUES (?)',(key,))
                            db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?)',(key,etag,utc_now().isoformat()))
                            db.execute("INSERT INTO metadata VALUES ('cacheRevision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")
                    finally:
                        Path(path).unlink(missing_ok=True)
                    with LOCK:
                        STATE['processed'] += 1
                        STATE['downloaded'] += 1
                    del rows, details
                with LOCK:
                    STATE['phase'] = 'cleanup'
                synced = utc_now().isoformat()
                with db:
                    cutoff = utc_now()-dt.timedelta(days=HISTORY_DAYS+1)
                    db.execute("DELETE FROM event_details WHERE (file,rownum) IN (SELECT file,rownum FROM events WHERE source IN ('firewall','proxy') AND ts < ?)",(cutoff.timestamp(),))
                    db.execute("DELETE FROM events WHERE source IN ('firewall','proxy') AND ts < ?",(cutoff.timestamp(),))
                    # Keep recent empty-file manifests too, so empty logs are not
                    # repeatedly downloaded. Old manifests without events expire.
                    db.execute("DELETE FROM files WHERE key NOT IN (SELECT DISTINCT file FROM events) AND (julianday(imported) IS NULL OR julianday(imported)<julianday(?))",(cutoff.isoformat(),))
                    db.execute('DELETE FROM detailed_files WHERE key NOT IN (SELECT key FROM files)')
                    db.execute('DELETE FROM omitted_history WHERE file NOT IN (SELECT key FROM files)')
                    db.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)',('lastSync',synced))
                    db.execute("INSERT INTO metadata VALUES ('cacheRevision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")
                with LOCK:
                    STATE.update(lastSync=synced,phase='complete')
    except Exception as error:
        # Do not echo credentials, response bodies, or arbitrary exception text.
        message = str(error) if isinstance(error,(RuntimeError,ValueError)) else type(error).__name__
        with LOCK:
            STATE.update(error=message,phase='failed')
    finally:
        with LOCK:
            STATE.update(running=False,durationSeconds=round(time.perf_counter()-started,2))


def start_sync():
    if not RUNTIME_LOCK.acquire(blocking=False):
        return
    try:
        with LOCK:
            if STATE['running']:
                return
            if not ACTIVE_SETTINGS:
                raise ValueError('setupRequired')
            STATE.update(running=True,error=None,**sync_progress('listing'))
        threading.Thread(target=ingest, daemon=True).start()
    finally:
        RUNTIME_LOCK.release()


def report_selection(params):
    source = params.get('source', 'firewall')
    if source not in ['firewall', 'proxy']:
        raise ValueError('Neplatný zdroj')
    start = dt.datetime.fromisoformat(params['from'])
    end = dt.datetime.fromisoformat(params['to'])
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError('Čas musí obsahovat časové pásmo')
    if not dt.timedelta(0) < end - start <= dt.timedelta(days=HISTORY_DAYS):
        raise ValueError('Vyber interval delší než 0 a nejvýše 30 dní')
    now = utc_now()
    earliest = now.replace(second=0, microsecond=0) - dt.timedelta(days=HISTORY_DAYS)
    if start < earliest or end > now:
        raise ValueError('Celý interval musí ležet v posledních 30 dnech a nesmí sahat do budoucnosti')
    subnet = params.get('subnet', '').strip()
    ranges = parse_ip_filter(subnet)
    identity = params.get('identity', '')
    scope = params.get('scope', 'all')
    if scope not in ['all', 'internet', 'private', 'unknown']:
        raise ValueError('Neplatný druh provozu')
    return source, start, end, subnet, ranges, identity, scope


def history_bounds(db, source):
    if source not in ('firewall', 'proxy'):
        raise ValueError('Neplatný zdroj')
    # Separate endpoints let SQLite seek to each edge of (source, ts).
    row = db.execute("""SELECT (SELECT MIN(ts) FROM events WHERE source=?),
                               (SELECT MAX(ts) FROM events WHERE source=?)""",
                     (source, source)).fetchone()
    return {'from':row[0], 'to':row[1]}


def rule_mappings(db):
    row = db.execute("SELECT value FROM metadata WHERE key='ruleMappings'").fetchone()
    return json.loads(row[0]) if row else []


class PolicyResponseError(ValueError):
    """Only controlled stage/reason/status values may reach the client."""
    def __init__(self,stage,reason,status=0,structure=''):
        self.structure=structure
        super().__init__(f'policyResponse/{stage}/{reason}/{status}')


def policy_payload(value, stage):
    """Unwrap rule containers while retaining pagination from enclosing objects."""
    wrappers=('result','results','data','rules','items','rule','response')
    node=value
    count=None
    path=[]
    while isinstance(node,dict):
        if stage=='detail' and 'ruleId' in node:
            return node
        if stage=='list' and count is None:
            count=node.get('count')
        field=next((key for key in wrappers if isinstance(node.get(key),(list,dict))),None)
        if field is None or len(path)>=8:
            break
        path.append(field)
        node=node[field]
    if isinstance(node,list):
        if all(isinstance(row,dict) and 'ruleId' in row for row in node):
            return {'result':node,'count':count}
    elif stage=='detail' and isinstance(node,dict):
        # A sparse or missing detail can still be resolved from the catalog.
        return {}
    # Report only predefined schema names and JSON types, never response values.
    known=wrappers+('count','meta','metadata','error','message','status','pagination')
    fields=', '.join(k+'='+type(node[k]).__name__ for k in known if k in node) if isinstance(node,dict) else ''
    structure='.'.join(['$']+path)+' ('+(fields or type(node).__name__)+')'
    raise PolicyResponseError(stage,'shape',200,structure)


def policy_request(method,path,authorization,body=None):
    conn = http.client.HTTPSConnection('api.sse.cisco.com', timeout=20)
    stage='org' if path=='/deployments/v2/roamingcomputers/orgInfo' else 'token' if method=='POST' else 'list' if '?' in path else 'detail'
    headers = {'Authorization':authorization,'Accept':'application/json'}
    if body is not None:
        headers['Content-Type']='application/x-www-form-urlencoded'
    try:
        conn.request(method,path,body,headers)
        response = conn.getresponse()
        if response.status==404 and stage=='detail':
            return {}
        if response.status!=200:
            raise PolicyResponseError(stage,'http',response.status)
        raw=response.read(2_000_001)
        if len(raw)>2_000_000:
            raise PolicyResponseError(stage,'size',response.status)
        result=json.loads(raw)
        if stage=='org':
            org_id=result.get('organizationId') if isinstance(result,dict) else None
            if not re.fullmatch(r'[0-9]{1,20}',str(org_id)):
                raise PolicyResponseError(stage,'shape',200)
            return {'organizationId':str(org_id)}
        if stage!='token':
            return policy_payload(result,stage)
        if not isinstance(result,dict):
            raise PolicyResponseError(stage,'shape',response.status)
        return result
    except (json.JSONDecodeError,UnicodeError):
        raise PolicyResponseError(stage,'json',response.status) from None
    except (OSError,http.client.HTTPException):
        raise PolicyResponseError(stage,'connection') from None
    finally:
        conn.close()


def policy_scope(rule):
    signals=set()
    if rule.get('ruleAccess') in ('internet','private'):
        signals.add(rule['ruleAccess'])
    for setting in rule.get('ruleSettings') or []:
        if setting.get('settingName')=='umbrella.default.traffic':
            scope={'PUBLIC_INTERNET':'internet','PRIVATE_NETWORK':'private'}.get(setting.get('settingValue'))
            if scope:
                signals.add(scope)
    # A positive match restricted exclusively to named private resources is
    # evidence even on rules whose API representation omits ruleAccess.
    destinations=[c for c in rule.get('ruleConditions') or []
                  if str(c.get('attributeName','')).startswith('umbrella.destination.')]
    private={'umbrella.destination.private_resource_ids','umbrella.destination.private_application_ids'}
    if destinations and all(c.get('attributeName') in private and c.get('attributeOperator')=='INTERSECT'
                            and isinstance(c.get('attributeValue'),list) and c['attributeValue']
                            and all(str(v).isdigit() and int(v)>0 for v in c['attributeValue'])
                            for c in destinations):
        signals.add('private')
    return signals.pop() if len(signals)==1 else None


def lookup_policy_rules(data):
    if not isinstance(data,dict):
        raise ValueError('invalidRules')
    whole=data.get('wholePolicy') is True
    ids=[] if whole else data.get('ids')
    if not whole and (not isinstance(ids,list) or not 1<=len(ids)<=10 or any(not isinstance(i,str) or not re.fullmatch(r'[0-9]{1,20}',i) for i in ids)):
        raise ValueError('policyIds')
    with LOCK:
        settings=ACTIVE_SETTINGS
        if not settings or data.get('cacheId')!=cache_id(settings):
            raise ValueError('settingsReload')
    # Cisco-managed S3 prefixes start with the organization's numeric ID.
    org=re.match(r'^(\d+)_',settings['prefix']) if settings['bucket'].startswith('cisco-managed-') else None
    key,secret=data.get('clientId'),data.get('clientSecret')
    if not key and not secret and policy_key_path(settings).is_file():
        saved=json.loads(policy_key_path(settings).read_text(encoding='utf-8'))
        key,secret=saved.get('clientId'),saved.get('clientSecret')
    if not all(isinstance(v,str) and v.strip() for v in (key,secret)):
        raise ValueError('policyDenied')
    basic=base64.b64encode((key+':'+secret).encode()).decode()
    token=policy_request('POST','/auth/v2/token','Basic '+basic,'grant_type=client_credentials').get('access_token')
    if not isinstance(token,str) or not token or not token.isascii() or any(c.isspace() for c in token):
        raise ValueError('policyDenied')
    auth='Bearer '+token
    results=[]
    catalog=None
    catalog_failure=None
    token_org=None
    org_failure=None
    wanted=set(ids)
    def matching_list_rules():
        found={}
        offset=0
        seen_pages=set()
        while True:
            page=policy_request('GET','/policies/v2/rules?limit=100&offset='+str(offset),auth)
            rows=page.get('result')
            if not isinstance(rows,list):
                raise PolicyResponseError('list','shape',200)
            page_ids=tuple(str(item.get('ruleId')) for item in rows)
            if page_ids in seen_pages:
                raise PolicyResponseError('list','shape',200,'offset')
            seen_pages.add(page_ids)
            for item in rows:
                if whole or str(item.get('ruleId')) in wanted:
                    found[str(item['ruleId'])]=item
            offset+=len(rows)
            count=page.get('count')
            if not isinstance(count,(str,int)) or not re.fullmatch(r'[0-9]{1,18}',str(count)):
                count=None
            if not rows or (not whole and len(found)==len(wanted)) or (offset>=int(count) if count is not None else len(rows)<100):
                return found

    if whole:
        catalog=matching_list_rules()
        ids=list(catalog)

    for rule_id in dict.fromkeys(ids):
        rule={}
        try:
            if not re.fullmatch(r'[0-9]{1,20}',rule_id):
                raise ValueError('policyWrongId')
            listed=catalog[rule_id] if whole else {}
            if org and listed.get('organizationId') is not None and str(listed['organizationId'])!=org.group(1):
                raise ValueError('policyOrg')
            if whole and policy_scope(listed) and (listed.get('modifiedAt') or listed.get('createdAt')):
                response=listed
            else:
                response=policy_request('GET','/policies/v2/rules/'+rule_id,auth)
            rule=response.get('result',response)
            if isinstance(rule,list):
                rule=next((r for r in rule if isinstance(r,dict) and str(r.get('ruleId'))==rule_id),{})
            if not isinstance(rule,dict):
                raise PolicyResponseError('detail','shape',200)
            if rule.get('ruleId') is not None and str(rule['ruleId'])!=rule_id:
                raise ValueError('policyWrongId')
            if org and rule.get('organizationId') is not None and str(rule['organizationId'])!=org.group(1):
                raise ValueError('policyOrg')
            if whole or not rule.get('ruleId') or not (rule.get('ruleAccess') or policy_scope(rule)) or (org and rule.get('organizationId') is None):
                if catalog_failure is not None:
                    raise catalog_failure
                if catalog is None:
                    try:
                        catalog=matching_list_rules()
                    except PolicyResponseError as error:
                        catalog_failure=error
                        raise
                item=catalog.get(rule_id,{})
                if org and item.get('organizationId') is not None and str(item['organizationId'])!=org.group(1):
                    raise ValueError('policyOrg')
                if not rule.get('ruleId'):
                    rule=item.copy()
                else:
                    rule={**item,**{k:v for k,v in rule.items() if v is not None}}
            if not rule.get('ruleId'):
                raise ValueError('policyNotFound')
            if org and rule.get('organizationId') is None:
                if org_failure is not None:
                    raise org_failure
                if token_org is None:
                    try:
                        info=policy_request('GET','/deployments/v2/roamingcomputers/orgInfo',auth)
                        token_org=str(info['organizationId'])
                    except PolicyResponseError as error:
                        org_failure=error
                        raise
                if token_org!=org.group(1):
                    raise ValueError('policyOrg')
            scope=policy_scope(rule)
            results.append({'id':rule_id,'scope':scope,'name':rule.get('ruleName',''),
                            'modified':rule.get('modifiedAt') or rule.get('createdAt') or ''})
        except PolicyResponseError as error:
            results.append({'id':rule_id,'scope':None,'error':str(error),'structure':error.structure})
            if isinstance(rule,dict) and str(rule.get('ruleId'))==rule_id and (not org or str(rule.get('organizationId'))==org.group(1)):
                results[-1]['name']=rule.get('ruleName','')
            if str(error).endswith('/429'):
                for remaining in dict.fromkeys(ids):
                    if not any(r['id']==remaining for r in results):
                        results.append({'id':remaining,'scope':None,'error':'policyRateSkipped'})
                break
        except ValueError as error:
            message=str(error)
            results.append({'id':rule_id,'scope':None,'error':message if message in
                            ('policyDenied','policyUnavailable','policyOrg','policyWrongId','policyNotFound','policyNoOrg') else 'policyUnavailable'})
    return {'rules':results}


def refresh_access_policy(data):
    settings=ACTIVE_SETTINGS
    if not isinstance(data,dict) or not settings or data.get('cacheId')!=cache_id(settings):
        raise ValueError('settingsReload')
    result=lookup_policy_rules({**data,'wholePolicy':True})
    policy={}
    for rule in result['rules']:
        if rule.get('error'):
            raise ValueError(rule['error'])
        if rule['scope'] and rule['modified']:
            policy[rule['id']]=[timestamp(rule['modified']),rule['scope']]
    snapshot=json.dumps(policy,sort_keys=True)
    with connect(settings['database']) as db:
        db.execute('BEGIN IMMEDIATE')
        previous=db.execute("SELECT value FROM metadata WHERE key='accessPolicy'").fetchone()
        if not previous or previous[0]!=snapshot:
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('accessPolicy',?)",(snapshot,))
            db.execute("INSERT INTO metadata VALUES ('cacheRevision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")
        revision=db.execute("SELECT value FROM metadata WHERE key='cacheRevision'").fetchone()
    if data.get('clientId') and data.get('clientSecret'):
        write_private_json(policy_key_path(settings),{k:data[k] for k in ('clientId','clientSecret')})
    return {'mapped':len(policy),'total':len(result['rules']),'revision':revision[0] if revision else '0'}


def save_rule_mappings(data):
    rules = data.get('rules') if isinstance(data,dict) else None
    if not isinstance(rules,list):
        raise ValueError('invalidRules')
    clean = []
    intervals={}
    for rule in rules:
        if not isinstance(rule,dict) or not re.fullmatch(r'[0-9]{1,20}',str(rule.get('id',''))) or rule.get('scope') not in ('private','internet'):
            raise ValueError('invalidRules')
        start,end = rule.get('from'),rule.get('to')
        for date in (start,end):
            if date != '':
                try:
                    if dt.date.fromisoformat(date).isoformat()!=date:
                        raise ValueError()
                except (TypeError,ValueError):
                    raise ValueError('invalidRules') from None
        key = str(rule['id'])
        if start and end and end<start or any((not stop or stop>=start) and (not end or begin<=end) for begin,stop in intervals.get(key,())):
            raise ValueError('invalidRules')
        intervals.setdefault(key,[]).append((start,end))
        clean.append({'id':key,'scope':rule['scope'],'from':start,'to':end})
    with SETTINGS_LOCK, settings_runtime():
        if not ACTIVE_SETTINGS or data.get('cacheId')!=cache_id(ACTIVE_SETTINGS):
            raise ValueError('settingsReload')
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if rule_mappings(db)!=data.get('previous'):
                raise ValueError('settingsReload')
            db.execute("INSERT OR REPLACE INTO metadata VALUES ('ruleMappings',?)",(json.dumps(clean),))
            db.execute("INSERT INTO metadata VALUES ('cacheRevision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")
    return {'rules':clean}


def scope_expression(db, source):
    rules = rule_mappings(db) if source=='firewall' else []
    snapshot=db.execute("SELECT value FROM metadata WHERE key='accessPolicy'").fetchone() if source=='firewall' else None
    policy=json.loads(snapshot[0]) if snapshot else {}
    if not rules and not policy:
        return 'e.scope'
    by_id = {}
    for rule in rules:
        start = timestamp(rule['from']) if rule['from'] else float('-inf')
        end = timestamp(rule['to'])+86400 if rule['to'] else float('inf')
        by_id.setdefault(rule['id'],[]).append((start,end,rule['scope']))
    def mapped(rule_id,ts):
        current=policy.get(str(rule_id))
        if current and ts>=current[0]:
            return current[1]
        for start,end,scope in by_id.get(str(rule_id),()):
            if start<=ts<end:
                return scope
        return 'unknown'
    db.create_function('CSA_RULE_SCOPE',2,mapped,deterministic=True)
    return """CASE WHEN e.scope='unknown' AND COALESCE(json_extract(d.details,'$.fields.privateflow'),'')=''
              THEN CSA_RULE_SCOPE(json_extract(d.details,'$.fields.ruleid'),e.ts) ELSE e.scope END"""


def connection_filters(params):
    conditions,values=[],[]
    for key in ('protocol','action','destinationip','destinationport','servername','ruleid'):
        value=params.get(key,'').strip().lower()
        if not value:
            continue
        fields=('requestmethod',) if key=='protocol' and params.get('source')=='proxy' else (key,)
        candidates=[value]
        if key=='protocol' and params.get('source')!='proxy':
            number={'tcp':'6','udp':'17','icmp':'1','icmpv6':'58'}.get(value.split()[0])
            if number:
                candidates.append(number)
        expressions=[]
        for field in fields:
            column="lower(CAST(json_extract(d.details,'$.fields."+field+"') AS TEXT))"
            if key=='servername':
                expressions.append('instr('+column+',?)>0')
            else:
                expressions.append(column+' IN ('+','.join('?' for _ in candidates)+')')
            values.extend(candidates)
        conditions.append('('+' OR '.join(expressions)+')')
    return conditions,values


def unknown_rules(params,database):
    source,start,end,_,ranges,identity,_ = report_selection(params)
    with connect(database) as db:
        db.execute('BEGIN')
        revision = db.execute("SELECT value FROM metadata WHERE key='cacheRevision'").fetchone()
        if params.get('revision')!=(revision[0] if revision else '0'):
            raise ValueError('transfersChanged')
        conditions = ['e.source=?','e.ts>=?','e.ts<?',"e.scope='unknown'"]
        values = [source,start.timestamp(),end.timestamp()]
        if ranges:
            db.create_function('CSA_MATCH_IP',1,lambda ip:matches_ip(ip,ranges))
            conditions.append('CSA_MATCH_IP(e.ip)')
        if identity:
            conditions.append('EXISTS(SELECT 1 FROM json_each(e.identities) WHERE value=?)')
            values.append(identity)
        extra,args=connection_filters(params)
        conditions.extend(extra)
        values.extend(args)
        conditions.append("("+scope_expression(db,source)+")='unknown'")
        rows = db.execute("""SELECT json_extract(d.details,'$.fields.ruleid') AS id,count(*) AS records,
                          sum(coalesce(e.sent,0)+coalesce(e.received,0)) AS bytes
                          FROM events e LEFT JOIN event_details d ON d.file=e.file AND d.rownum=e.rownum
                          WHERE """+' AND '.join(conditions)+' GROUP BY id ORDER BY records DESC,id LIMIT 10',values)
        return [dict(row) for row in rows]


# Cache compact hourly aggregates, including the exact boundaries of partial hours.
# Serialized entries give the shared cache a predictable payload size.
REPORT_PARTS = OrderedDict()
REPORT_PART_BYTES = 0
REPORT_CACHE_LOCK = threading.Lock()
REPORT_CACHE_LIMIT = 24 * 1024 * 1024


def report_part(key, calculate):
    global REPORT_PART_BYTES
    if key is None:
        return calculate()
    with REPORT_CACHE_LOCK:
        payload = REPORT_PARTS.get(key)
        if payload is not None:
            REPORT_PARTS.move_to_end(key)
    if payload is not None:
        return json.loads(payload)
    result = calculate()
    payload = json.dumps(result,separators=(',',':')).encode()
    if len(payload)<=REPORT_CACHE_LIMIT:
        with REPORT_CACHE_LOCK:
            previous = REPORT_PARTS.pop(key,b'')
            REPORT_PARTS[key] = payload
            REPORT_PART_BYTES += len(payload)-len(previous)
            while REPORT_PART_BYTES>REPORT_CACHE_LIMIT or len(REPORT_PARTS)>2048:
                REPORT_PART_BYTES -= len(REPORT_PARTS.popitem(last=False)[1])
    return result


def report(params, database=None):
    limit=params.get('topLimit','20')
    if limit not in ('20','50','100','250','500'):
        raise ValueError('invalidTopLimit')
    top_limit=int(limit)
    source, start, end, subnet, ranges, identity, scope = report_selection(params)
    buckets = {}
    cursor = int(start.timestamp() // 3600) * 3600
    while cursor < end.timestamp():
        buckets[cursor] = {'ts': cursor, 'sent': 0, 'received': 0}
        cursor += 3600
    totals = {'sent': 0, 'received': 0, 'records': 0, 'missing': 0, 'unknown': 0}
    top = {}
    options = set()
    identities = {}
    breakdown = {key:{'records':0,'bytes':0} for key in ('internet','private','mappedInternet','mappedPrivate','unknown')}
    with connect(database) as db:
        db.execute('BEGIN')
        bounds = history_bounds(db, source)
        last = db.execute("SELECT value FROM metadata WHERE key='lastSync'").fetchone()
        revision = db.execute("SELECT value FROM metadata WHERE key='cacheRevision'").fetchone()
        cache_key=(str(Path(database or DB).resolve()),source,revision[0]) if revision else None
        bounds['records']=report_part(cache_key and cache_key+('count',),lambda:
            db.execute('SELECT COUNT(*) FROM events WHERE source=?',(source,)).fetchone()[0])
        effective = scope_expression(db,source)
        extra,args=connection_filters(params)
        if extra:
            detail_rev=db.execute("SELECT value FROM metadata WHERE key='detailRevision'").fetchone()
            cache_key=cache_key and cache_key+(detail_rev[0] if detail_rev else '0',)
            details=' LEFT JOIN event_details d ON d.file=e.file AND d.rownum=e.rownum'
        else:
            details = '' if effective=='e.scope' else " LEFT JOIN event_details d ON e.scope='unknown' AND d.file=e.file AND d.rownum=e.rownum"
        sql = """SELECT e.ip,e.identities,e.scope,"""+effective+""" AS effective_scope,
                        COUNT(*) AS records,SUM(e.sent IS NULL OR e.received IS NULL) AS missing,
                        SUM(e.sent) AS sent,SUM(e.received) AS received
                 FROM events e"""+details+""" WHERE e.source=? AND e.ts>=? AND e.ts<? """+''.join(' AND '+term for term in extra)+"""
                 GROUP BY e.ip,e.identities,e.scope,effective_scope ORDER BY MIN(e.ts),MIN(e.rowid)"""
        for hour,bucket in buckets.items():
            left=max(hour,start.timestamp())
            right=min(hour+3600,end.timestamp())
            rows=report_part(cache_key and cache_key+(left,right,tuple(extra),tuple(args)),lambda:
                [dict(row) for row in db.execute(sql,(source,left,right,*args))])
            for row in rows:
                encoded = row['identities']
                labels = identities.get(encoded)
                if labels is None:
                    labels = json.loads(encoded)
                    options.update(labels)
                    if len(identities) >= 2048:
                        identities.clear()
                    identities[encoded] = labels
                if not matches_ip(row['ip'], ranges):
                    continue
                if identity and identity not in labels:
                    continue
                category = row['effective_scope']
                if source=='firewall':
                    key = category if category==row['scope'] else 'mapped'+category.title()
                    breakdown[key]['records'] += row['records']
                    breakdown[key]['bytes'] += (row['sent'] or 0)+(row['received'] or 0)
                if scope != 'all' and category != scope:
                    continue
                totals['records'] += row['records']
                totals['unknown'] += row['records'] if category == 'unknown' else 0
                totals['missing'] += row['missing']
                sent, received = row['sent'] or 0, row['received'] or 0
                totals['sent'] += sent
                totals['received'] += received
                bucket['sent'] += sent
                bucket['received'] += received
                label = row['ip'] or 'Neznámá IP'
                item = top.setdefault(label, {'label': label, 'sent': 0, 'received': 0, 'records': 0, 'missing': 0})
                item['sent'] += sent
                item['received'] += received
                item['missing'] += row['missing']
                item['records'] += row['records']
    return {'classification':breakdown if source=='firewall' else None,'totals': totals, 'series': list(buckets.values()), 'sourceCount':len(top), 'top': sorted(top.values(), key=lambda x: x['sent']+x['received'], reverse=True)[:top_limit], 'identities': sorted(options), 'coverage': bounds, 'lastSync': last[0] if last else None, 'subnet': subnet or None, 'revision': revision[0] if revision else '0'}


def transfer_revision(row):
    # Do not expose the S3 key/customer prefix; protect against reused SQLite row IDs.
    values = [row[k] for k in ['file','rownum','source','ts','ip','identities','sent','received','scope']]
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()


def transfer_destination_sort(value):
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
        return bytes([address.version])+address.packed
    except ValueError:
        return b'\x07'+value.casefold().encode('utf-8')


TRANSFER_SORTS = {'time','scope','destination','protocol','action','received','sent','total'}
TRANSFER_DETAIL_SORTS = {'destination','protocol','action'}


def transfers(params, database=None):
    source, start, end, subnet, ranges, identity, scope = report_selection(params)
    ip = params.get('ip')
    if ip is None:
        raise ValueError('transferIPRequired')
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError('transferIPRequired') from None
    try:
        page = int(params.get('page', '1'))
        event = int(params['event']) if 'event' in params else None
        if page < 1 or page > 1000000 or (event is not None and event < 1):
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('transferInvalidPage') from None
    sort = {'latest':'time','volume':'total'}.get(params.get('sort','latest'),params.get('sort','time'))
    direction = params.get('direction','desc' if sort in ['time','received','sent','total'] else 'asc')
    destination_view = params.get('destinationView','ip')
    if sort not in TRANSFER_SORTS or direction not in ['asc','desc'] or destination_view not in ['ip','url','server']:
        raise ValueError('transferInvalidPage')
    where = ['e.source=?','e.ts>=?','e.ts<?','e.ip=?']
    values = [source, start.timestamp(), end.timestamp(), ip]
    extra,args=connection_filters(params)
    where.extend(extra)
    values.extend(args)
    if not matches_ip(ip, ranges):
        where.append('0')
    if identity:
        where.append('EXISTS(SELECT 1 FROM json_each(e.identities) j WHERE j.value=?)')
        values.append(identity)
    with connect(database) as db:
        db.execute('BEGIN')
        effective = scope_expression(db,source)
        if scope != 'all':
            where.append('('+effective+')=?')
            values.append(scope)
        join = ' FROM events e LEFT JOIN event_details d ON d.file=e.file AND d.rownum=e.rownum WHERE '+' AND '.join(where)
        revision = db.execute("SELECT value FROM metadata WHERE key='cacheRevision'").fetchone()
        revision = revision[0] if revision else '0'
        detail_revision = db.execute("SELECT value FROM metadata WHERE key='detailRevision'").fetchone()
        detail_revision = detail_revision[0] if detail_revision else '0'
        if params.get('revision', revision) != revision:
            raise ValueError('transfersChanged')
        if event is not None:
            row = db.execute('SELECT e.rowid AS event_id,e.*,d.details'+join+' AND e.rowid=?', [*values,event]).fetchone()
            if row is None or params.get('eventRevision') != transfer_revision(row):
                raise ValueError('transferUnavailable')
            detail = json.loads(row['details']) if row['details'] else {'fields':{},'truncated':[]}
            return {'fields':detail['fields'],'truncated':detail['truncated'],'available':bool(row['details']),'detailsRevision':detail_revision}
        if sort in TRANSFER_DETAIL_SORTS and params.get('detailsRevision',detail_revision) != detail_revision:
            raise ValueError('transferSortChanged')
        part = params.get('part','full')
        if part not in ('full','items','preview','summary'):
            raise ValueError('transferInvalidPage')
        summary = {}
        key=(str(Path(database or DB).resolve()),'transfers',revision,detail_revision,tuple(where),tuple(values))
        if part in ('full','summary'):
            totals = report_part(key+('totals',), lambda: dict(db.execute('SELECT COUNT(*) AS records,COALESCE(SUM(e.sent),0) AS sent,COALESCE(SUM(e.received),0) AS received,SUM(e.sent IS NULL OR e.received IS NULL) AS missing,COUNT(d.file) AS detailed'+join, values).fetchone()))
            summary = {'totals':dict(totals),'pages':max(1,(totals['records']+49)//50)}
            if part=='summary':
                return summary
        db.create_function('CSA_IP_SORT',1,transfer_destination_sort,deterministic=True)
        field = lambda name: "NULLIF(json_extract(d.details,'$.fields."+name+"'),'')"
        destination_fields = {'url':['url','servername','fqdns','destinationip'],
                              'server':['servername','fqdns','destinationip'],
                              'ip':['destinationip','hostname','servername','fqdns']}[destination_view]
        destination = 'CSA_IP_SORT(COALESCE('+','.join(field(k) for k in destination_fields)+'))'
        protocol = 'COALESCE('+field('protocol')+','+field('requestmethod')+')'
        protocol_label = "CASE "+protocol+" WHEN '6' THEN 'TCP (6)' WHEN '17' THEN 'UDP (17)' WHEN '1' THEN 'ICMP (1)' WHEN '58' THEN 'ICMPv6 (58)' ELSE "+protocol+' END'
        expressions = {'time':'e.ts','scope':"NULLIF("+effective+",'unknown')",'destination':destination,'protocol':'LOWER('+protocol_label+')','action':'LOWER('+field('action')+')',
                       'received':'e.received','sent':'e.sent','total':'CASE WHEN e.sent IS NULL AND e.received IS NULL THEN NULL ELSE COALESCE(e.sent,0)+COALESCE(e.received,0) END'}
        expression = expressions[sort]
        # Only allowlisted expressions/directions enter SQL. Unknown values stay
        # last in either direction; stable tie-breakers apply before pagination.
        order = expression+' IS NULL ASC,'+expression+' '+direction.upper()
        if sort == 'destination' and destination_view == 'ip':
            port = field('destinationport')
            order += ','+port+' IS NULL ASC,CAST('+port+' AS INTEGER) '+direction.upper()
            order += ',LOWER(COALESCE('+','.join(field(k) for k in ['hostname','servername','fqdns'])+",'')) "+direction.upper()
        order += ',e.ts DESC,e.rowid DESC'
        if sort == 'time':
            # The interval excludes NULL timestamps. This order can seek directly
            # into (source,ip,ts,rowid), including a reverse scan for newest first.
            order = 'e.ts '+direction.upper()+',e.rowid DESC'
        limit=51 if part=='preview' else 50
        sql='SELECT e.rowid AS event_id,e.*,d.details,'+effective+' AS effective'+join+' ORDER BY '+order+' LIMIT ? OFFSET ?'
        def page_rows():
            return [dict(row) for row in db.execute(sql,[*values,limit,(page-1)*50])]
        rows=report_part(key+('page',sort,direction,destination_view,page),page_rows) if part=='preview' else page_rows()
        if part=='preview':
            summary['hasNext']=len(rows)>50
            rows=rows[:50]
            if page==1 and not summary['hasNext']:
                summary['pages']=1
                summary['totals']={'records':len(rows),'sent':sum(r['sent'] or 0 for r in rows),
                                  'received':sum(r['received'] or 0 for r in rows),
                                  'missing':sum(r['sent'] is None or r['received'] is None for r in rows),
                                  'detailed':sum(bool(r['details']) for r in rows)}
    items = []
    for row in rows:
        detail = json.loads(row['details'])['fields'] if row['details'] else {}
        items.append({'id':row['event_id'],'eventRevision':transfer_revision(row),'ts':row['ts'],'ip':row['ip'],
                      'identities':json.loads(row['identities']),'sent':row['sent'],'received':row['received'],'scope':row['effective'],'mapped':row['scope']!=row['effective'],
                      'destination':detail.get('destinationip',''),'port':detail.get('destinationport',''),
                      'url':detail.get('url',''),'servername':detail.get('servername',''),'fqdns':detail.get('fqdns',''),
                      'hostname':(detail.get('hostname') or detail.get('servername') or detail.get('fqdns',''))[:500],
                      'protocol':detail.get('protocol') or detail.get('requestmethod',''),'action':detail.get('action',''),
                      'available':bool(row['details'])})
    return {'items':items,**summary,'page':page,'pageSize':50,'revision':revision,'detailsRevision':detail_revision,'sort':sort,'direction':direction,'destinationView':destination_view}


def hydrate_transfer(params, database):
    """Backfill one existing source file on an explicit record-detail request."""
    if not RUNTIME_LOCK.acquire(blocking=False):
        raise ValueError('settingsBusy')
    try:
        if not ACTIVE_SETTINGS or Path(database).resolve() != Path(DB).resolve():
            raise ValueError('transfersChanged')
        # Validate the same filters, cache revision and record fingerprint again.
        current = transfers(params, database)
        if current['available']:
            return current
        with connect(database) as db:
            row = db.execute('SELECT file,source FROM events WHERE rowid=?', (int(params['event']),)).fetchone()
        if not row or not row['file'].startswith(PREFIX):
            raise ValueError('transferUnavailable')
        details = []
        rows = parse_log(S3(CREDENTIALS).get(urllib.parse.quote(row['file'],safe='/')),row['source'],row['file'],details)
        with connect(database) as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT * FROM events WHERE file=? ORDER BY rownum', (row['file'],)).fetchall()
            # Never attach fields from a changed file to an older aggregate record.
            omitted = db.execute('SELECT newest FROM omitted_history WHERE file=?', (row['file'],)).fetchone()
            if omitted:
                rows = [r for r in rows if r[3] > omitted[0]]
                kept = {r[1] for r in rows}
                details = [r for r in details if r[1] in kept]
            if [tuple(r) for r in existing] != rows:
                raise ValueError('transfersChanged')
            db.executemany('INSERT OR REPLACE INTO event_details VALUES (?,?,?)', details)
            db.execute('INSERT OR REPLACE INTO detailed_files VALUES (?)', (row['file'],))
            if row['source']=='firewall' and scope_expression(db,'firewall')!='e.scope':
                db.execute("INSERT INTO metadata VALUES ('cacheRevision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")
            db.execute("INSERT INTO metadata VALUES ('detailRevision','1') ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")
        return transfers(params, database)
    finally:
        RUNTIME_LOCK.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, status, body, mime='application/json; charset=utf-8'):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # The client left while this response was being written.
            self.close_connection = True

    def trusted(self):
        return self.headers.get('Host', '') in [f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}']

    def do_GET(self):
        if not self.trusted():
            return self.send(403, {'error': 'Nepovolený host'})
        url = urllib.parse.urlsplit(self.path)
        try:
            if url.path == '/api/cache/prune-status':
                return self.send(200, prune_status())
            if url.path == '/api/status':
                with LOCK:
                    return self.send(200, dict(STATE))
            if url.path == '/api/settings':
                return self.send(200, public_settings())
            if url.path in ['/api/rules','/api/unknown-rules','/api/history','/api/report','/api/transfers']:
                params = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
                with LOCK:
                    if not ACTIVE_SETTINGS:
                        return self.send(409, {'error':'setupRequired'})
                    database = DB
                    selected_cache=cache_id(ACTIVE_SETTINGS)
                if url.path == '/api/rules':
                    with connect(database) as db:
                        policy=db.execute("SELECT value FROM metadata WHERE key='accessPolicy'").fetchone()
                        return self.send(200,{'cacheId':selected_cache,'rules':rule_mappings(db),
                                              'policyCount':len(json.loads(policy[0])) if policy else None})
                if url.path == '/api/unknown-rules':
                    return self.send(200,unknown_rules(params,database))
                if url.path == '/api/history':
                    with connect(database) as db:
                        bounds = history_bounds(db, params.get('source', 'firewall'))
                    return self.send(200, bounds)
                data = (transfers if url.path == '/api/transfers' else report)(params, database)
                if url.path == '/api/transfers' and 'event' in params and params.get('hydrate') == '1' and not data['available']:
                    data = hydrate_transfer(params, database)
                return self.send(200, data)
            files = {'/time.js': ('time.js', 'text/javascript; charset=utf-8'), '/filters.js': ('filters.js', 'text/javascript; charset=utf-8'), '/transfers.js': ('transfers.js', 'text/javascript; charset=utf-8'), '/exports.js': ('exports.js', 'text/javascript; charset=utf-8'), '/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/settings.js': ('settings.js', 'text/javascript; charset=utf-8'), '/backup.js': ('backup.js', 'text/javascript; charset=utf-8'), '/i18n.js': ('i18n.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
            if url.path not in files:
                return self.send(404, {'error': 'Nenalezeno'})
            name, mime = files[url.path]
            self.send(200, (ROOT / 'static' / name).read_bytes(), mime)
        except ValueError as error:
            self.send(400, {'error': str(error)})
        except KeyError:
            self.send(400, {'error': 'Zadej datum a čas od–do'})
        except Exception:
            self.send(500, {'error': 'Chyba zpracování lokálních dat'})

    def do_POST(self):
        origin = self.headers.get('Origin', '')
        if not self.trusted() or origin not in [f'http://127.0.0.1:{self.server.server_port}', f'http://localhost:{self.server.server_port}']:
            return self.send(403, {'error': 'Nepovolený původ požadavku'})
        token = self.headers.get('X-CSRF-Token','')
        if not token.isascii() or not secrets.compare_digest(token, CSRF_TOKEN):
            return self.send(403, {'error':'settingsReload'})
        try:
            if self.path in ['/api/access-policy','/api/policy-lookup','/api/rules','/api/settings/window','/api/cache/prune','/api/settings/test','/api/settings','/api/settings/backup','/api/settings/restore']:
                if self.headers.get('Content-Type','').split(';')[0].strip().lower() != 'application/json':
                    return self.send(415, {'error':'settingsInvalid'})
                length = int(self.headers.get('Content-Length','0'))
                if not 0 < length <= (4_000_000 if self.path=='/api/rules' else 16384):
                    return self.send(413, {'error':'settingsInvalid'})
                data = json.loads(self.rfile.read(length))
                if self.path=='/api/access-policy':
                    with SETTINGS_LOCK, settings_runtime():
                        return self.send(200,refresh_access_policy(data))
                if self.path=='/api/policy-lookup':
                    return self.send(200,lookup_policy_rules(data))
                if self.path=='/api/rules':
                    return self.send(200,save_rule_mappings(data))
                if self.path in ['/api/settings/window','/api/cache/prune']:
                    return self.send(200,update_sync_window(data, prune=self.path=='/api/cache/prune'))
                if self.path=='/api/settings/backup':
                    return self.send(200,create_backup())
                if self.path=='/api/settings/restore':
                    return self.send(200,restore_backup(data))
                return self.send(200, update_connection(data, save=self.path=='/api/settings'))
            if self.path == '/api/sync':
                start_sync()
                return self.send(202, {'ok':True})
            self.send(404, {'error':'Nenalezeno'})
        except (ValueError, RuntimeError) as error:
            # RuntimeError messages are restricted to sanitized S3/curl status codes.
            message = str(error)
            self.send(409 if message in ['settingsBusy','setupRequired'] else 400, {'error':message})
        except Exception:
            self.send(500, {'error':'settingsFailed'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=Path(os.environ.get('CSA_CONFIG_FILE', user_directory() / 'config.json')))
    parser.add_argument('--setup', action='store_true', help='Set up your own S3 connection interactively')
    parser.add_argument('--credentials', default=os.environ.get('CSA_CREDENTIALS_FILE'))
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--open-browser', action='store_true', help='Open the local GUI automatically')
    args = parser.parse_args()
    if args.setup:
        try:
            setup_configuration(args.config)
        except (ValueError, OSError) as error:
            parser.error(str(error))
        sys.exit(0)
    CONFIG_PATH = args.config.expanduser().resolve()
    try:
        settings = load_settings(CONFIG_PATH)
        if args.credentials:
            settings['credentials'] = Path(args.credentials).expanduser().resolve()
        if not settings['credentials'].is_file():
            raise FileNotFoundError()
        activate_settings(settings)
        with connect(settings['database']) as db:
            saved = db.execute("SELECT value FROM metadata WHERE key='lastSync'").fetchone()
        activate_settings(settings, saved[0] if saved else None)
    except (ValueError, TypeError, OSError, sqlite3.Error):
        # A fresh installation must reach the GUI without terminal configuration.
        pass
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'CSA Traffic: http://127.0.0.1:{args.port}', flush=True)
    if args.open_browser:
        threading.Timer(0.5, lambda:webbrowser.open(f'http://127.0.0.1:{args.port}')).start()
    server.serve_forever()
