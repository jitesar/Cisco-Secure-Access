import csv
import datetime as dt
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(app, 'utc_now', return_value=dt.datetime(2026,10,22,18,tzinfo=app.UTC))
        self.clock.start()
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = app.DB
        self.old_prefix = app.PREFIX
        app.PREFIX = 'test-organization/'
        app.DB = Path(self.temp.name) / 'cache' / 'test.sqlite'

    def tearDown(self):
        self.clock.stop()
        app.DB = self.old_db
        app.PREFIX = self.old_prefix
        self.temp.cleanup()

    def blob(self, rows):
        out = io.StringIO(newline='')
        writer = csv.writer(out)
        writer.writerows(rows)
        return gzip.compress(out.getvalue().encode())

    def test_schema_and_missing_counters(self):
        blob = self.blob([
            ['Timestamp', 'Source IP', 'Bytes Sent', 'Bytes Received', 'Identities', 'Private Flow'],
            ['2026-10-22 12:30:00', '10.1.2.3', '123', '', '["Tunnel A","User B"]', ''],
        ])
        row = app.parse_log(blob, 'firewall', 'a')[0]
        self.assertEqual(row[6:9], (123, None, 'unknown'))
        self.assertEqual(json.loads(row[5]), ['Tunnel A', 'User B'])
        self.assertEqual(row[4], '10.1.2.3')
        self.assertRaises(ValueError, app.parse_log, self.blob([['no headers'], ['x']]), 'firewall', 'b')
        self.assertRaises(ValueError, app.byte_value, '-1')

    def test_filters_boundaries_and_source_separation(self):
        epoch = app.timestamp('2026-10-22 12:00:00')
        events = [
            ('a', 1, 'firewall', epoch, '10.1.0.1', '["A", "B"]', 10, 20, 'unknown'),
            ('a', 2, 'firewall', epoch+100, '10.2.0.1', '["A"]', 100, 200, 'private'),
            ('a', 3, 'proxy', epoch, '10.1.0.1', '["A"]', 1000, 2000, 'internet'),
            ('a', 4, 'firewall', epoch+3600, '10.1.0.1', '["B"]', 500, 1000, 'internet'),
        ]
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)', events)
        params = {'from': '2026-10-22T12:00:00+00:00', 'to': '2026-10-22T13:00:00+00:00', 'subnet': '10.1.0.8/16', 'identity': 'B'}
        data = app.report(params)
        self.assertEqual(data['totals']['sent'], 10)
        self.assertEqual(data['totals']['records'], 1)
        self.assertEqual(data['subnet'], '10.1.0.8/16')
        self.assertEqual(sum(x['received'] for x in data['series']), 20)
        data = app.report({**params, 'scope': 'internet'})
        self.assertEqual(data['totals']['records'], 0)
        self.assertRaises(ValueError, app.report, {**params, 'subnet': 'bad'})
        self.assertRaises(ValueError, app.report, {**params, 'to': '2026-11-01T13:00:00+00:00'})

    def test_ipv6_and_empty_data(self):
        params = {'from': '2026-10-22T12:00:00+00:00', 'to': '2026-10-22T14:00:00+00:00', 'subnet': '2001:db8::/32'}
        data = app.report(params)
        self.assertEqual(len(data['series']), 2)
        self.assertEqual(data['totals']['records'], 0)

    def test_offsets_are_respected(self):
        self.assertEqual(app.timestamp('2026-10-22T14:00:00+02:00'), app.timestamp('2026-10-22 12:00:00'))

    def test_headerless_v10(self):
        firewall = [''] * 34
        for index, value in {0:'2026-10-22 12:00:00', 2:'Tunnel A', 7:'10.1.1.1', 20:'50', 21:'80', 27:'FALSE'}.items():
            firewall[index] = value
        data = app.parse_log(self.blob([firewall]), 'firewall', 'old')
        self.assertEqual(data[0][6:9], (50,80,'internet'))
        mixed = app.parse_log(self.blob([firewall,firewall+['']*6]), 'firewall', 'mixed')
        self.assertEqual(len(mixed), 2)
        self.assertEqual(mixed[1][6:9], (50,80,'internet'))
        proxy = [''] * 49
        for index, value in {0:'2026-10-22 12:00:00',2:'10.1.1.1',11:'10',12:'20',13:'15',23:'User A'}.items():
            proxy[index] = value
        data = app.parse_log(self.blob([proxy]), 'proxy', 'old-proxy')
        self.assertEqual(data[0][6:8], (10,20))

    def test_transfer_details_fields_and_filter_intersection(self):
        details = []
        rows = app.parse_log(self.blob([
            ['Timestamp','Source IP','Bytes Sent','Bytes Received','Identities','Private Flow','Destination IP','Destination Port','Protocol','Action','Rule ID'],
            ['2026-10-22 12:30:00','10.1.2.3','10','20','["A","B"]','TRUE','192.0.2.1','443','TCP','allow','rule-1'],
            ['2026-10-22 12:31:00','10.1.2.3','500','600','["Other"]','FALSE','192.0.2.2','80','TCP','allow','rule-2'],
            ['2026-10-22 13:00:00','10.1.2.3','1000','2000','["B"]','TRUE','192.0.2.3','443','TCP','allow','rule-3'],
        ]), 'firewall','private-tenant/key',details)
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)', rows)
            db.executemany('INSERT INTO event_details VALUES (?,?,?)', details)
        params = {'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','subnet':'10.1.0.0/16','identity':'B','scope':'private','ip':'10.1.2.3'}
        data = app.transfers(params)
        self.assertEqual(data['totals']['records'],1)
        self.assertEqual(data['totals']['sent'],app.report(params)['totals']['sent'])
        self.assertEqual(data['items'][0]['destination'],'192.0.2.1')
        self.assertEqual(data['items'][0]['port'],'443')
        self.assertNotIn('private-tenant',json.dumps(data))
        item = data['items'][0]
        detail = app.transfers({**params,'event':str(item['id']),'eventRevision':item['eventRevision']})
        self.assertEqual(detail['fields']['ruleid'],'rule-1')
        self.assertEqual(detail['fields']['protocol'],'TCP')
        self.assertEqual(app.transfers({**params,'identity':'Not B'})['totals']['records'],0)
        self.assertEqual(app.transfers({**params,'subnet':'10.8.0.0/16'})['totals']['records'],0)
        self.assertEqual(app.transfers({**params,'source':'proxy'})['totals']['records'],0)
        self.assertRaisesRegex(ValueError,'transferUnavailable',app.transfers,{**params,'ip':'10.9.0.1','event':str(item['id']),'eventRevision':item['eventRevision']})
        self.assertRaisesRegex(ValueError,'transferUnavailable',app.transfers,{**params,'event':str(item['id']),'eventRevision':'bad'})
        with app.connect() as db:
            db.execute("INSERT INTO metadata VALUES ('cacheRevision','2')")
        self.assertRaisesRegex(ValueError,'transfersChanged',app.transfers,{**params,'revision':'0'})

    def test_transfer_pagination_sort_legacy_and_missing_counters(self):
        epoch=app.timestamp('2026-10-22T12:00:00Z')
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',[
                ('old',i,'firewall',epoch+i,'2001:db8::1','["Žluťoučký kůň"]',None if i==0 else i,0,'unknown') for i in range(105)
            ])
            db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('old',105,'firewall',epoch,'','[]',None,None,'unknown'))
        params={'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'2001:0db8::1'}
        first=app.transfers(params)
        second=app.transfers({**params,'page':'2'})
        last=app.transfers({**params,'page':'3'})
        self.assertEqual([len(p['items']) for p in [first,second,last]],[50,50,5])
        self.assertEqual(first['pages'],3)
        self.assertEqual(len({item['id'] for p in [first,second,last] for item in p['items']}),105)
        self.assertEqual(first['totals']['detailed'],0)
        self.assertEqual(first['totals']['missing'],1)
        self.assertEqual(last['items'][-1]['sent'],None)
        record=first['items'][0]
        self.assertFalse(app.transfers({**params,'event':str(record['id']),'eventRevision':record['eventRevision']})['available'])
        self.assertEqual(app.transfers({**params,'sort':'volume'})['items'][0]['sent'],104)
        self.assertEqual(app.transfers({**params,'ip':''})['totals']['records'],1)
        for values in [{'page':'0'},{'page':'-1'},{'sort':'DROP TABLE events'},{'ip':'bad'},{'event':'NaN'}]:
            self.assertRaises(ValueError,app.transfers,{**params,**values})

    def test_proxy_details_and_field_limits(self):
        details=[]
        text='https://example.test/'+('a'*17000)
        rows=app.parse_log(self.blob([
            ['Timestamp','Internal Client IP','Request Size','Response Size','URL','Request Method','Status Code','Destination IP','Authorization'],
            ['2026-10-22 12:30:00','10.1.2.3','10','20',text,'GET','200','192.0.2.4','not-to-be-kept'],
        ]),'proxy','proxy-key',details)
        fields=json.loads(details[0][2])
        self.assertNotIn('authorization',fields['fields'])
        self.assertEqual(fields['fields']['requestmethod'],'GET')
        self.assertEqual(fields['truncated'],['url'])
        self.assertEqual(len(fields['fields']['url']),16384)
        self.assertEqual(rows[0][6:9],(10,20,'internet'))

    def test_legacy_details_fetch_only_matching_source_file(self):
        key=app.PREFIX+'firewalllogs/2026-10-22/legacy.csv.gz'
        def blob(sent='10'):
            return self.blob([
                ['Timestamp','Source IP','Bytes Sent','Bytes Received','Destination IP','Destination Port'],
                ['2026-10-22 12:00:00','10.1.2.3',sent,'20','192.0.2.5','443'],
            ])
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',app.parse_log(blob(),'firewall',key))
            db.execute('INSERT INTO files VALUES (?,?,?)',(key,'old','now'))
        params={'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.2.3'}
        item=app.transfers(params)['items'][0]
        params.update(event=str(item['id']),eventRevision=item['eventRevision'])
        with patch.object(app,'ACTIVE_SETTINGS',{'configured':True}), patch.object(app,'S3') as client:
            client.return_value.get.return_value=blob('11')
            self.assertRaisesRegex(ValueError,'transfersChanged',app.hydrate_transfer,params,app.DB)
            self.assertFalse(app.transfers(params)['available'])
            client.return_value.get.return_value=blob()
            result=app.hydrate_transfer(params,app.DB)
            self.assertEqual(result['fields']['destinationip'],'192.0.2.5')
            self.assertEqual(result['fields']['destinationport'],'443')
            self.assertTrue(app.transfers(params)['available'])
            client.return_value.get.assert_called_with(key)
            count=client.return_value.get.call_count
            app.hydrate_transfer(params,app.DB)
            self.assertEqual(client.return_value.get.call_count,count)
        self.assertEqual(app.report(params)['totals']['sent'],10)

    def test_reimport_is_idempotent_and_changed_file_replaces_rows(self):
        today = app.utc_now().date().isoformat()
        key = app.PREFIX + 'firewalllogs/' + today + '/sample.csv.gz'
        def blob_for(sent):
            return self.blob([
                ['Timestamp','Source IP','Bytes Sent','Bytes Received'],
                [today+' 12:00:00','10.1.0.1',str(sent),'20'],
            ])
        class FakeS3:
            etag = 'one'
            def __init__(self, _): pass
            def list(self, prefix):
                return [(key, self.etag)] if prefix == app.PREFIX+'firewalllogs/'+today+'/' else []
            def get(self, _): return blob_for(10 if self.etag == 'one' else 30)
        original = dict(app.STATE)
        try:
            with patch.object(app, 'S3', FakeS3):
                app.ingest()
                app.ingest()
                self.assertIsNone(app.STATE['error'])
                with app.connect() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
                FakeS3.etag = 'two'
                app.ingest()
                with app.connect() as db:
                    row = db.execute('SELECT COUNT(*), SUM(sent) FROM events').fetchone()
                    self.assertEqual(tuple(row),(1,30))
        finally:
            app.STATE.clear()
            app.STATE.update(original)

    def test_ip_ranges_lists_overlap_and_ipv6(self):
        ranges = app.parse_ip_filter('10.1.0.0/24, 10.1.0.5 - 10.1.0.255; 10.2.0.1\n2001:db8::1–2001:db8::5')
        self.assertEqual(len(ranges),3)
        for address in ['10.1.0.0','10.1.0.255','10.2.0.1','2001:db8::1','2001:db8::5']:
            self.assertTrue(app.matches_ip(address,ranges), address)
        for address in ['10.2.0.2','10.3.0.1','2001:db8::6','']:
            self.assertFalse(app.matches_ip(address,ranges), address)
        for value in ['10.0.0.5-10.0.0.1','10.0.0.1-2001:db8::1','bad','10.0.0.1-','10.0.0.999']:
            self.assertRaises(ValueError,app.parse_ip_filter,value)
        self.assertEqual(len(app.parse_ip_filter('::/0')),1)
        epoch=app.timestamp('2026-10-22 12:00:00')
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',[
                ('x',1,'firewall',epoch,'10.1.0.5','[]',10,20,'unknown'),
                ('x',2,'firewall',epoch,'10.2.0.1','[]',30,40,'unknown'),
                ('x',3,'firewall',epoch,'10.3.0.1','[]',100,200,'unknown'),
            ])
        report=app.report({'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','subnet':'10.1.0.0/24,10.1.0.5-10.1.0.8;10.2.0.1'})
        self.assertEqual(report['totals']['records'],2)
        self.assertEqual(report['totals']['sent'],40)

    def test_last_30_days_and_custom_subinterval(self):
        params={'from':'2026-09-22T18:00:00Z','to':'2026-10-22T18:00:00Z'}
        data=app.report(params)
        self.assertEqual(len(data['series']),720)
        data=app.report({'from':'2026-09-25T12:15:00Z','to':'2026-09-27T14:30:00Z'})
        self.assertEqual(data['totals']['records'],0)
        for changes in [
            {'from':'2026-09-22T17:59:00Z'},
            {'to':'2026-10-22T18:01:00Z'},
            {'from':'2026-10-22T18:00:00Z'},
        ]:
            self.assertRaises(ValueError,app.report,{**params,**changes})

    def test_ingestion_checks_all_31_utc_directories(self):
        prefixes=[]
        class EmptyS3:
            def __init__(self,_): pass
            def list(self,prefix):
                prefixes.append(prefix)
                return []
        original=dict(app.STATE)
        try:
            with patch.object(app,'S3',EmptyS3): app.ingest()
            self.assertEqual(len(prefixes),62)
            self.assertIn(app.PREFIX+'firewalllogs/2026-09-22/',prefixes)
            self.assertIn(app.PREFIX+'proxylogs/2026-10-22/',prefixes)
        finally:
            app.STATE.clear();app.STATE.update(original)

    def test_20_day_history_survives_import_and_expired_cache_is_removed(self):
        day=(app.utc_now()-dt.timedelta(days=20)).date().isoformat()
        key=app.PREFIX+'firewalllogs/'+day+'/sample.csv.gz'
        blob=self.blob([
            ['Timestamp','Source IP','Bytes Sent','Bytes Received'],
            [day+' 12:00:00','10.1.0.1','10','20'],
        ])
        class FakeS3:
            def __init__(self,_): pass
            def list(self,prefix):
                return [(key,'one')] if prefix==app.PREFIX+'firewalllogs/'+day+'/' else []
            def get(self,_): return blob
        with app.connect() as db:
            db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('expired',1,'firewall',(app.utc_now()-dt.timedelta(days=32)).timestamp(),'10.1.0.1','[]',100,200,'unknown'))
            db.execute('INSERT INTO files VALUES (?,?,?)',('expired','old','old'))
        original=dict(app.STATE)
        try:
            with patch.object(app,'S3',FakeS3): app.ingest()
            self.assertIsNone(app.STATE['error'])
            with app.connect() as db:
                self.assertEqual(tuple(db.execute('SELECT COUNT(*), SUM(sent) FROM events').fetchone()),(1,10))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM files WHERE key=?',('expired',)).fetchone()[0],0)
        finally:
            app.STATE.clear();app.STATE.update(original)

    def test_configuration_is_portable_and_cache_is_separated_by_tenant(self):
        root=Path(self.temp.name).resolve()
        config=root/'config.json'
        data={'s3Path':'s3://test-bucket/org-one','region':'eu-central-1','credentialsFile':'credentials.json'}
        app.write_private_json(config,data)
        first=app.load_settings(config)
        self.assertEqual(first['prefix'],'org-one/')
        self.assertEqual(first['credentials'],root/'credentials.json')
        data['s3Path']='s3://test-bucket/org-two/'
        app.write_private_json(config,data)
        second=app.load_settings(config)
        self.assertNotEqual(first['database'],second['database'])
        for updates in [{'s3Path':'https://example.com/'},{'region':'eu-central-1.example.com'},{'s3Path':'s3://test-bucket/prefix?bad=1'}]:
            app.write_private_json(config,{**data,**updates})
            self.assertRaises(ValueError,app.load_settings,config)

    def test_private_json_can_be_read_and_replaced(self):
        path=Path(self.temp.name)/'settings'/'credentials.json'
        app.write_private_json(path,{'accessKeyId':'fake','secretAccessKey':'fake-test-value'})
        with path.open() as f: self.assertEqual(json.load(f)['accessKeyId'],'fake')
        app.write_private_json(path,{'accessKeyId':'replaced'})
        with path.open() as f: self.assertEqual(json.load(f),{'accessKeyId':'replaced'})
        if app.os.name!='nt':
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(path.parent.stat().st_mode&0o777,0o700)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.folder=Path(self.temp.name).resolve()
        self.saved={name:getattr(app,name) for name in ['CONFIG_PATH','ACTIVE_SETTINGS','BUCKET','PREFIX','REGION','CREDENTIALS','DB']}
        self.old_state=dict(app.STATE)
        app.CONFIG_PATH=self.folder/'config.json'
        app.ACTIVE_SETTINGS=None
        app.STATE.update(running=False,error=None,lastSync=None)
        self.payload={'s3Path':'s3://example-bucket/customer/','region':'eu-central-1','accessKeyId':'TEST_ACCESS','secretAccessKey':'TEST_SECRET'}
        self.probe=patch.object(app.S3,'get',return_value=b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><KeyCount>0</KeyCount></ListBucketResult>')
        self.get=self.probe.start()

    def tearDown(self):
        self.probe.stop()
        for name,value in self.saved.items(): setattr(app,name,value)
        app.STATE.clear();app.STATE.update(self.old_state)
        self.temp.cleanup()

    def test_probe_does_not_save_credentials(self):
        self.assertTrue(app.update_connection(self.payload)['ok'])
        self.assertFalse(app.CONFIG_PATH.exists())
        self.assertEqual(list(self.folder.iterdir()),[])
        self.assertIsNone(app.ACTIVE_SETTINGS)

    def test_save_first_connection_and_no_secrets_in_metadata(self):
        result=app.update_connection(self.payload,save=True)
        self.assertTrue(result['configured'])
        self.assertTrue(result['hasCredentials'])
        self.assertNotIn('TEST_ACCESS',json.dumps(result))
        self.assertNotIn('TEST_SECRET',json.dumps(result))
        loaded=app.load_settings(app.CONFIG_PATH)
        with loaded['credentials'].open() as f: self.assertEqual(json.load(f)['secretAccessKey'],'TEST_SECRET')
        self.assertNotIn('TEST_SECRET',app.CONFIG_PATH.read_text())

    def test_reuse_requires_same_connection_and_a_complete_pair(self):
        app.update_connection(self.payload,save=True)
        keys=app.CREDENTIALS
        blank={**self.payload,'accessKeyId':'','secretAccessKey':''}
        app.update_connection(blank,save=True)
        self.assertEqual(app.CREDENTIALS,keys)
        self.assertRaisesRegex(ValueError,'settingsKeysRequired',app.update_connection,{**blank,'s3Path':'s3://example-bucket/another/'})
        self.assertRaisesRegex(ValueError,'settingsKeysRequired',app.update_connection,{**self.payload,'secretAccessKey':''})

    def test_failed_probe_or_persistence_preserves_working_config(self):
        app.update_connection(self.payload,save=True)
        previous=app.CONFIG_PATH.read_bytes()
        old_keys=app.CREDENTIALS
        self.get.side_effect=RuntimeError('S3 HTTP 403: AccessDenied')
        self.assertRaises(RuntimeError,app.update_connection,{**self.payload,'secretAccessKey':'REPLACEMENT'},save=True)
        self.assertEqual(app.CONFIG_PATH.read_bytes(),previous)
        self.assertEqual(app.CREDENTIALS,old_keys)
        self.get.side_effect=None
        original=app.write_private_json
        def fail_config(path,data):
            if Path(path)==app.CONFIG_PATH: raise OSError('simulated disk failure')
            original(path,data)
        with patch.object(app,'write_private_json',side_effect=fail_config):
            self.assertRaises(OSError,app.update_connection,{**self.payload,'secretAccessKey':'REPLACEMENT'},save=True)
        self.assertEqual(app.CONFIG_PATH.read_bytes(),previous)
        self.assertEqual(app.CREDENTIALS,old_keys)
        self.assertEqual(len(list(self.folder.glob('credentials-*.json'))),1)

    def test_replacement_keys_and_tenant_switch(self):
        app.update_connection(self.payload,save=True)
        old_keys,old_db=app.CREDENTIALS,app.DB
        app.update_connection({**self.payload,'s3Path':'s3://example-bucket/another/','secretAccessKey':'REPLACEMENT'},save=True)
        self.assertNotEqual(app.DB,old_db)
        self.assertFalse(old_keys.exists())
        self.assertIsNone(app.STATE['lastSync'])

    def test_reject_changes_during_import(self):
        app.STATE['running']=True
        self.assertRaisesRegex(ValueError,'settingsBusy',app.update_connection,self.payload,save=True)
        self.get.assert_not_called()

    def test_gui_api_origin_token_content_type_and_size_guards(self):
        from types import SimpleNamespace
        origin='http://127.0.0.1:8765'
        base={'Host':'127.0.0.1:8765','Origin':origin,'X-CSRF-Token':app.CSRF_TOKEN,'Content-Type':'application/json'}
        def request(headers,body=b'{}'):
            handler=object.__new__(app.Handler)
            handler.server=SimpleNamespace(server_port=8765)
            handler.path='/api/settings/test'
            handler.headers={**headers,'Content-Length':str(len(body))}
            handler.rfile=io.BytesIO(body)
            result=[]
            handler.send=lambda status,data:result.append((status,data))
            handler.do_POST()
            return result[0]
        with patch.object(app,'update_connection',return_value={'ok':True}) as update:
            self.assertEqual(request({**base,'Origin':'https://example.com'})[0],403)
            self.assertEqual(request({**base,'X-CSRF-Token':''})[0],403)
            self.assertEqual(request({**base,'Host':'example.com:8765'})[0],403)
            self.assertEqual(request({**base,'Content-Type':'text/plain'})[0],415)
            self.assertEqual(request(base,b'x'*16385)[0],413)
            update.assert_not_called()
            self.assertEqual(request(base)[0],200)
            update.assert_called_once_with({},save=False)

    def test_explicit_backup_contains_keys_without_machine_specific_paths(self):
        self.assertRaisesRegex(ValueError,'backupNotConfigured',app.create_backup)
        app.update_connection(self.payload,save=True)
        snapshot=app.create_backup()
        self.assertEqual(snapshot['credentials']['secretAccessKey'],'TEST_SECRET')
        self.assertEqual(snapshot['settings']['s3Path'],self.payload['s3Path'])
        self.assertNotIn(str(self.folder),json.dumps(snapshot))
        self.assertNotIn('TEST_SECRET',json.dumps(app.public_settings()))

    def test_restore_verifies_before_writing_and_requires_backup_credentials(self):
        app.update_connection(self.payload,save=True)
        snapshot=app.create_backup()
        previous=app.CONFIG_PATH.read_bytes()
        self.get.side_effect=RuntimeError('S3 HTTP 403: AccessDenied')
        self.assertRaises(RuntimeError,app.restore_backup,snapshot)
        self.assertEqual(app.CONFIG_PATH.read_bytes(),previous)
        self.get.side_effect=None
        invalid={**snapshot,'credentials':{'accessKeyId':'','secretAccessKey':''}}
        self.assertRaisesRegex(ValueError,'backupInvalid',app.restore_backup,invalid)
        self.assertRaisesRegex(ValueError,'backupInvalid',app.restore_backup,{**snapshot,'version':2})
        self.assertEqual(app.CONFIG_PATH.read_bytes(),previous)
        snapshot['preferences']={'language':'en'}
        snapshot['settings']['s3Path']='s3://example-bucket/restored/'
        restored=app.restore_backup(snapshot)
        self.assertEqual(restored['s3Path'],'s3://example-bucket/restored/')
        self.assertEqual(restored['language'],'en')
        self.assertNotIn('TEST_SECRET',json.dumps(restored))


if __name__ == '__main__':
    unittest.main()
