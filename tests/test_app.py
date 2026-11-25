import csv
import datetime as dt
import gzip
import io
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import threading
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

    def test_rule_mappings_before_scope_filter_and_across_drilldown(self):
        t=app.timestamp('2026-10-22 00:00:00')
        q={'from':'2026-10-21T00:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.0.1','identity':'A','scope':'internet'}
        rule={'id':'77','scope':'internet','from':'2026-10-22','to':'2026-10-22'}
        with patch.object(app,'ACTIVE_SETTINGS',{'database':app.DB}):
            request={'cacheId':app.DB.parent.name,'previous':[],'rules':[rule]}
            app.save_rule_mappings(request)
            with self.assertRaisesRegex(ValueError,'settingsReload'):
                app.save_rule_mappings(request)
            with self.assertRaisesRegex(ValueError,'invalidRules'):
                app.save_rule_mappings({**request,'rules':[rule,rule]})
        with app.connect() as db:
            for n,(stamp,scope,flow,label) in enumerate([(t,'private','TRUE','A'),(t,'unknown','','A'),
                    (t-1,'unknown','','A'),(t,'unknown','unexpected','A'),(t,'unknown','','B')]):
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('f',n,'firewall',stamp,q['ip'],json.dumps([label]),1,2,scope))
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('f',n,json.dumps({'fields':{'privateflow':flow,'ruleid':'77'}})))
        r=app.report(q)
        self.assertEqual(r['classification']['private'],{'records':1,'bytes':3})
        self.assertEqual(r['classification']['mappedInternet'],{'records':1,'bytes':3})
        self.assertEqual(r['classification']['unknown'],{'records':2,'bytes':6})
        self.assertEqual(r['totals']['records'],1)
        item,=app.transfers(q)['items']
        self.assertEqual((item['scope'],item['mapped']),('internet',True))
        self.assertEqual(app.unknown_rules({**q,'revision':r['revision']},app.DB),[{'id':'77','records':2,'bytes':6}])

    def test_report_reuses_hours_and_rechecks_changed_boundaries_and_revision(self):
        base=app.timestamp('2026-10-22T00:00:00Z')
        with app.connect() as db:
            db.execute("INSERT INTO metadata VALUES ('cacheRevision','1')")
            for n,offset in enumerate([0,60,3600,7200,10800]):
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                           ('f',n,'proxy',base+offset,'192.0.2.1','[]',n,None,'internet'))
        query={'source':'proxy','from':'2026-10-22T00:00:00Z','to':'2026-10-22T03:00:00Z'}
        original=app.report_part
        calculated=[]
        def track(key,calculate):
            def miss():
                calculated.append(key)
                return calculate()
            return original(key,miss)
        with patch.object(app,'report_part',side_effect=track):
            first=app.report(query)
            calculated.clear()
            self.assertEqual(first,app.report(query))
            self.assertFalse(calculated)
            shifted={**query,'from':'2026-10-22T00:01:00Z','to':'2026-10-22T03:01:00Z'}
            self.assertEqual(app.report(shifted)['totals']['sent'],10)
            self.assertEqual(len(calculated),2)
            with app.connect() as db:
                db.execute("UPDATE metadata SET value='2' WHERE key='cacheRevision'")
                db.execute('UPDATE events SET sent=10 WHERE rownum=4')
            self.assertEqual(app.report(shifted)['totals']['sent'],16)

    def test_connection_filters_before_ranking_paging_and_totals(self):
        stamp=app.timestamp('2026-10-22T12:20:00Z')
        q={'source':'firewall','from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z'}
        with app.connect() as db:
            db.execute("INSERT INTO metadata VALUES ('cacheRevision','1')")
            for n in range(82):
                match=n>=30
                ip='192.0.2.99' if match or n==0 else '192.0.2.'+str(n)
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('f',n,'firewall',stamp,ip,'[]',1 if match else 200,1,'internet'))
                fields={'protocol':'17' if match else '6','action':'ALLOW','destinationip':'192.0.2.4',
                        'destinationport':'53','servername':'dns.example.test','ruleid':'77'}
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('f',n,json.dumps({'fields':fields})))
        app.report(q)
        filtered={**q,'protocol':'UDP','action':'allow','destinationip':'192.0.2.4',
                  'destinationport':'53','servername':'EXAMPLE','ruleid':'77','scope':'internet'}
        r=app.report(filtered)
        self.assertEqual([(v['label'],v['records']) for v in r['top']],[('192.0.2.99',52)])
        result=app.transfers({**filtered,'ip':'192.0.2.99','page':'2'})
        self.assertEqual((result['pages'],len(result['items']),result['totals']['sent']),(2,2,52))
        self.assertEqual(app.report({**filtered,'action':'block'})['totals']['records'],0)
        q={**filtered,'ip':'192.0.2.99'}
        first=app.transfers({**q,'part':'preview'})
        self.assertTrue(first['hasNext'])
        self.assertEqual(len(first['items']),50)
        self.assertNotIn('totals',first)
        self.assertEqual(app.transfers({**q,'part':'summary'})['totals'],result['totals'])
        empty=app.transfers({**q,'part':'preview','action':'DENY'})
        self.assertFalse(empty['hasNext'])
        self.assertEqual(empty['totals']['records'],0)


    def test_source_ip_ranking_limit(self):
        q={'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z'}
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                           [('f',i,'firewall',app.timestamp(q['from']),f'192.0.2.{i}','[]',i,0,'unknown') for i in range(1,61)])
        default=app.report(q)
        expanded=app.report({**q,'topLimit':'50'})
        self.assertEqual(len(default['top']),20)
        self.assertEqual(len(expanded['top']),50)
        self.assertEqual(default['sourceCount'],60)
        self.assertEqual(len(app.report({**q,'topLimit':'100'})['top']),60)
        self.assertEqual(default['top'],expanded['top'][:20])
        self.assertEqual(expanded['top'][-1]['sent'],11)
        self.assertEqual(default['totals'],expanded['totals'])

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
        fast=app.transfers({**params,'page':'2','part':'items','revision':first['revision']})
        self.assertEqual(fast['items'],second['items'])
        self.assertNotIn('totals',fast)
        self.assertRaisesRegex(ValueError,'transfersChanged',app.transfers,{**params,'part':'items','revision':'stale'})
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

    def test_all_transfer_columns_sort_globally_before_pagination(self):
        epoch=app.timestamp('2026-10-22T12:00:00Z')
        addresses=['192.0.2.2','192.0.2.10','2001:db8::2','2001:db8::10',None]
        protocols=['6','17','1','GET','POST',None]
        records=[]
        with app.connect() as db:
            for i in range(125):
                fields={} if i%10==0 else {'destinationip':addresses[i%5],'destinationport':str([443,80,5][i%3]),'protocol':protocols[i%6],'action':['ALLOW','block','warn'][i%3]}
                fields={k:v for k,v in fields.items() if v is not None}
                if not fields.get('destinationip') and i%10!=0: fields['hostname']='example.test'
                sent=None if i%17==0 else i*7%113
                received=None if i%19==0 else i*3%101
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('sort',i,'firewall',epoch+i,'10.1.2.3','[]',sent,received,'unknown'))
                if fields: db.execute('INSERT INTO event_details VALUES (?,?,?)',('sort',i,json.dumps({'fields':fields,'truncated':[]})))
                records.append({'id':i+1,'ts':epoch+i,'sent':sent,'received':received,'fields':fields})
        def primary(record,column):
            f=record['fields']
            if column=='time': return record['ts']
            if column in ['received','sent']: return record[column]
            if column=='total': return None if record['sent'] is None and record['received'] is None else (record['sent'] or 0)+(record['received'] or 0)
            if column=='action': return f.get('action','').lower() or None
            if column=='protocol': return {'6':'TCP (6)','17':'UDP (17)','1':'ICMP (1)'}.get(f.get('protocol'),f.get('protocol','')).lower() or None
            if not f.get('destinationip'):
                return (7,f['hostname'],int(f['destinationport']),f['hostname']) if f.get('hostname') else None
            address=ipaddress.ip_address(f['destinationip'])
            return (address.version,int(address),int(f['destinationport']),'')
        params={'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.2.3'}
        for column in ['time','destination','protocol','action','received','sent','total']:
            for direction in ['asc','desc']:
                with self.subTest(column=column,direction=direction):
                    base=sorted(records,key=lambda r:(r['ts'],r['id']),reverse=True)
                    present=[r for r in base if primary(r,column) is not None]
                    missing=[r for r in base if primary(r,column) is None]
                    expected=sorted(present,key=lambda r:primary(r,column),reverse=direction=='desc')+missing
                    pages=[app.transfers({**params,'sort':column,'direction':direction,'page':str(page)}) for page in range(1,4)]
                    self.assertEqual([item['id'] for page in pages for item in page['items']],[r['id'] for r in expected])
                    self.assertEqual(pages[0]['totals']['records'],125)
                    self.assertEqual(pages[0]['sort'],column)
                    self.assertEqual(pages[0]['direction'],direction)
        for changes in [{'direction':'DESC; DROP TABLE events'},{'sort':'destination;DELETE'},{'direction':'sideways'}]:
            self.assertRaises(ValueError,app.transfers,{**params,**changes})

    def test_destination_url_view_sorts_before_pagination_and_ignores_proxy_hostname(self):
        epoch=app.timestamp('2026-10-22T12:00:00Z')
        with app.connect() as db:
            for i in range(65):
                fields={'url':f'https://site-{64-i:02d}.example/path','servername':'actual.example',
                        'hostname':f'proxy-{i:02d}.internal','destinationip':'192.0.2.1'}
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('urls',i,'proxy',epoch,'10.1.2.3','[]',1,2,'unknown'))
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('urls',i,json.dumps({'fields':fields,'truncated':[]})))
        params={'source':'proxy','from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.2.3','sort':'destination','destinationView':'url'}
        for direction in ['asc','desc']:
            pages=[app.transfers({**params,'direction':direction,'page':str(page)}) for page in [1,2]]
            items=[item for page in pages for item in page['items']]
            expected=sorted([f'https://site-{i:02d}.example/path' for i in range(65)],reverse=direction=='desc')
            self.assertEqual([item['url'] for item in items],expected)
            self.assertEqual(items[0]['servername'],'actual.example')
            self.assertEqual(pages[0]['destinationView'],'url')
        self.assertRaises(ValueError,app.transfers,{**params,'destinationView':'url; DROP TABLE events'})

    def test_destination_url_fallbacks_and_missing_values(self):
        epoch=app.timestamp('2026-10-22T12:00:00Z')
        fields=[{'hostname':'proxy.internal'}, {'servername':'b.example','hostname':'proxy.internal'},
                {'fqdns':'a.example'}, {'destinationip':'192.0.2.2'}, {'url':'https://c.example','servername':'ignored.example'}]
        with app.connect() as db:
            for i,detail in enumerate(fields):
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('fallback',i,'proxy',epoch,'10.1.2.3','[]',1,2,'unknown'))
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('fallback',i,json.dumps({'fields':detail,'truncated':[]})))
        params={'source':'proxy','from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.2.3','sort':'destination','destinationView':'url'}
        for direction,expected in [('asc',[4,3,2,5,1]),('desc',[5,2,3,4,1])]:
            items=app.transfers({**params,'direction':direction})['items']
            self.assertEqual([item['id'] for item in items],expected)
            self.assertEqual(items[-1]['url'],'')
            self.assertEqual(items[-1]['servername'],'')

    def test_server_name_view_overrides_url_and_proxy_and_sorts_all_pages(self):
        epoch=app.timestamp('2026-10-22T12:00:00Z')
        fields=[{'servername':f'server-{64-i:02d}.example','url':f'https://url-{i:02d}.example/path',
                 'hostname':f'proxy-{i:02d}.internal','destinationip':'192.0.2.1'} for i in range(65)]
        fields += [{'url':'https://ignored.example','hostname':'proxy.internal'},
                   {'fqdns':'fqdn.example','url':'https://ignored.example'},
                   {'destinationip':'192.0.2.2','url':'https://ignored.example'}]
        with app.connect() as db:
            for i,detail in enumerate(fields):
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('servers',i,'proxy',epoch,'10.1.2.3','[]',1,2,'unknown'))
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('servers',i,json.dumps({'fields':detail,'truncated':[]})))
        params={'source':'proxy','from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.2.3','sort':'destination','destinationView':'server'}
        names=[f'server-{i:02d}.example' for i in range(65)]
        for direction in ['asc','desc']:
            pages=[app.transfers({**params,'direction':direction,'page':str(page)}) for page in [1,2]]
            items=[item for page in pages for item in page['items']]
            expected=['192.0.2.2']+['fqdn.example']+names
            if direction=='desc':expected.reverse()
            expected.append('')
            self.assertEqual([item['servername'] or item['fqdns'] or item['destination'] for item in items],expected)
            self.assertEqual(pages[0]['destinationView'],'server')

    def test_destination_ports_are_numeric_and_detail_changes_invalidate_text_sort(self):
        epoch=app.timestamp('2026-10-22T12:00:00Z')
        with app.connect() as db:
            for i,port in enumerate(['443','80','5','']):
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('ports',i,'firewall',epoch,'10.1.2.3','[]',1,1,'unknown'))
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('ports',i,json.dumps({'fields':{'destinationip':'192.0.2.1','destinationport':port},'truncated':[]})))
        params={'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.2.3','sort':'destination'}
        initial=app.transfers({**params,'direction':'asc'})
        self.assertEqual([r['port'] for r in initial['items']],['5','80','443',''])
        self.assertEqual([r['port'] for r in app.transfers({**params,'direction':'desc'})['items']],['443','80','5',''])
        with app.connect() as db: db.execute("INSERT INTO metadata VALUES ('detailRevision','2')")
        self.assertRaisesRegex(ValueError,'transferSortChanged',app.transfers,{**params,'detailsRevision':initial['detailsRevision']})
        self.assertEqual(app.transfers({**params,'sort':'sent','detailsRevision':initial['detailsRevision']})['totals']['records'],4)
        self.assertEqual(app.transfers(params)['detailsRevision'],'2')

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

    def test_proxy_sort_uses_method_and_hostname_when_ip_is_missing(self):
        epoch=app.timestamp('2026-10-22T12:00:00Z')
        with app.connect() as db:
            for i,(method,host) in enumerate([('POST','b.example.test'),('GET','a.example.test'),('HEAD','')]):
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',('proxy-sort',i,'proxy',epoch,'10.1.2.3','[]',1,2,'internet'))
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('proxy-sort',i,json.dumps({'fields':{'requestmethod':method,'hostname':host},'truncated':[]})))
        params={'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z','ip':'10.1.2.3','source':'proxy'}
        self.assertEqual([r['protocol'] for r in app.transfers({**params,'sort':'protocol','direction':'asc'})['items']],['GET','HEAD','POST'])
        self.assertEqual([r['hostname'] for r in app.transfers({**params,'sort':'destination','direction':'asc'})['items']],['a.example.test','b.example.test',''])
        self.assertEqual([r['hostname'] for r in app.transfers({**params,'sort':'destination','direction':'desc'})['items']],['b.example.test','a.example.test',''])

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

    def test_octet_ranges_are_cartesian_and_not_continuous(self):
        ranges = app.parse_ip_filter('10-11.30-33.1-2.3-50')
        count = 0
        for first in range(9,13):
            for second in range(29,35):
                for third in range(4):
                    for fourth in range(2,52):
                        address = f'{first}.{second}.{third}.{fourth}'
                        expected = 10 <= first <= 11 and 30 <= second <= 33 and 1 <= third <= 2 and 3 <= fourth <= 50
                        self.assertEqual(app.matches_ip(address,ranges),expected,address)
                        count += expected
        self.assertEqual(count,768)
        self.assertEqual(len(ranges),1)
        broad = app.parse_ip_filter('0-255.0-255.0-255.0-255')
        self.assertEqual(len(broad),1)
        for address in ['0.0.0.0','255.255.255.255','127.0.0.1']:
            self.assertTrue(app.matches_ip(address,broad))
        self.assertFalse(app.matches_ip('2001:db8::1',broad))
        short = app.parse_ip_filter('10.30.1.3 – 50')
        self.assertTrue(app.matches_ip('10.30.1.50',short))
        self.assertFalse(app.matches_ip('10.30.2.3',short))
        self.assertTrue(app.matches_ip('10.30.1.3',app.parse_ip_filter('10-10.30.1.3-3')))

    def test_octet_ranges_reject_invalid_bounds_and_syntax(self):
        for value in ['11-10.30.1.3','10.30-256.1.3','10.-1.1.3','10.30.1.3-',
                      '10--11.30.1.3','010-11.30.1.3','10-11.30.1.3/24',
                      '10-11.30.1.3.4','10-11.30.1','10-11.30.1.x','2001:db8::1-5']:
            with self.subTest(value=value):
                self.assertRaises(ValueError,app.parse_ip_filter,value)

    def test_octet_ranges_union_report_and_drilldown(self):
        epoch = app.timestamp('2026-10-22 12:00:00')
        addresses = [('10.30.1.3',10,20),('11.33.2.50',30,40),
                     ('10.31.2.51',100,200),('10.30.3.3',100,200),
                     ('192.0.2.2',50,60),('2001:db8::1',70,80),('11.29.1.3',1000,2000)]
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',[
                ('x',index,'firewall',epoch,address,'[]',sent,received,'unknown')
                for index,(address,sent,received) in enumerate(addresses,1)
            ])
        params = {'from':'2026-10-22T12:00:00Z','to':'2026-10-22T13:00:00Z',
                  'subnet':'10-11.30-33.1-2.3-50;10.30.1.0/24,192.0.2.1-192.0.2.3\n2001:db8::/64'}
        totals = app.report(params)['totals']
        self.assertEqual((totals['records'],totals['sent'],totals['received']),(4,160,200))
        self.assertEqual(app.transfers({**params,'ip':'11.33.2.50'})['totals']['records'],1)
        self.assertEqual(app.transfers({**params,'ip':'10.31.2.51'})['totals']['records'],0)

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

    def test_parallel_import_is_bounded_incremental_and_skips_legacy_details(self):
        today=app.utc_now().date().isoformat()
        prefix=app.PREFIX+'firewalllogs/'+today+'/'
        blobs={prefix+str(i).zfill(2)+'.csv.gz':self.blob([
            ['Timestamp','Source IP','Bytes Sent','Bytes Received'],
            [today+' 12:00:00','10.1.2.3',str(i),'20'],
        ]) for i in range(12)}
        lock=threading.Lock()
        listing_barrier=threading.Barrier(app.IMPORT_WORKERS)
        download_barrier=threading.Barrier(app.IMPORT_WORKERS)
        parsed_threads=[]
        parsed=app.parse_log
        class FakeS3:
            listing_calls=0
            downloads=0
            active=0
            peak=0
            max_files=0
            temporary=set()
            changed=False
            def __init__(self,_): pass
            def list(self,path):
                with lock:
                    FakeS3.listing_calls+=1
                    count=FakeS3.listing_calls
                if count<=app.IMPORT_WORKERS: listing_barrier.wait(timeout=5)
                return [(key,'two' if self.changed and key.endswith('00.csv.gz') else 'one') for key in blobs] if path==prefix else []
            def download(self,key,path):
                with lock:
                    FakeS3.downloads+=1
                    count=FakeS3.downloads
                    FakeS3.active+=1
                    FakeS3.peak=max(FakeS3.peak,FakeS3.active)
                    FakeS3.temporary.add(str(Path(path).parent))
                try:
                    if count<=app.IMPORT_WORKERS: download_barrier.wait(timeout=5)
                    Path(path).write_bytes(blobs[key])
                    with lock: FakeS3.max_files=max(FakeS3.max_files,len(list(Path(path).parent.glob('*.csv.gz'))))
                finally:
                    with lock: FakeS3.active-=1
        def parse_file(path,*args):
            self.assertIsInstance(path,str)
            parsed_threads.append(threading.get_ident())
            return parsed(path,*args)
        original=dict(app.STATE)
        try:
            with patch.object(app,'S3',FakeS3),patch.object(app,'parse_log',side_effect=parse_file):
                app.ingest()
                self.assertIsNone(app.STATE['error'])
                self.assertEqual(FakeS3.peak,app.IMPORT_WORKERS)
                self.assertLessEqual(FakeS3.max_files,app.IMPORT_WORKERS)
                self.assertEqual(set(parsed_threads),{threading.get_ident()})
                self.assertTrue(all(not Path(p).exists() for p in FakeS3.temporary))
                self.assertEqual(app.STATE['downloaded'],12)
                with app.connect() as db:
                    db.execute('DELETE FROM event_details')
                    db.execute('DELETE FROM detailed_files')
                app.ingest()
                self.assertIsNone(app.STATE['error'])
                self.assertEqual(FakeS3.downloads,12)
                self.assertEqual((app.STATE['skipped'],app.STATE['total']),(12,0))
                FakeS3.changed=True
                first=prefix+'00.csv.gz'
                blobs[first]=self.blob([['Timestamp','Source IP','Bytes Sent','Bytes Received'],[today+' 12:00:00','10.1.2.3','100','20']])
                app.ingest()
                self.assertIsNone(app.STATE['error'])
                self.assertEqual(FakeS3.downloads,13)
                self.assertEqual((app.STATE['downloaded'],app.STATE['skipped']),(1,11))
                with app.connect() as db:
                    self.assertEqual(tuple(db.execute('SELECT COUNT(*),SUM(sent) FROM events').fetchone()),(12,166))
        finally:
            app.STATE.clear();app.STATE.update(original)

    def test_failed_parallel_import_keeps_working_rows_and_cleans_temporary_files(self):
        today=app.utc_now().date().isoformat()
        prefix=app.PREFIX+'firewalllogs/'+today+'/'
        key=prefix+'a.csv.gz'
        def blob(sent):
            return self.blob([['Timestamp','Source IP','Bytes Sent','Bytes Received'],[today+' 12:00:00','10.1.2.3',str(sent),'20']])
        with app.connect() as db:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',app.parse_log(blob(10),'firewall',key))
            db.execute('INSERT INTO files VALUES (?,?,?)',(key,'old',app.utc_now().isoformat()))
        class FakeS3:
            fail=True
            temporary=set()
            def __init__(self,_): pass
            def list(self,path): return [(key,'new'),(prefix+'b.csv.gz','new')] if path==prefix else []
            def download(self,item,path):
                self.temporary.add(str(Path(path).parent))
                Path(path).write_bytes(blob(100 if item==key else 200))
                if self.fail and item==key: raise RuntimeError('S3 HTTP 503: SlowDown')
        original=dict(app.STATE)
        try:
            with patch.object(app,'S3',FakeS3):
                app.STATE['lastSync']='previous-success'
                app.ingest()
                self.assertEqual(app.STATE['phase'],'failed')
                self.assertEqual(app.STATE['lastSync'],'previous-success')
                self.assertTrue(all(not Path(p).exists() for p in FakeS3.temporary))
                with app.connect() as db:
                    self.assertEqual(db.execute('SELECT sent FROM events WHERE file=?',(key,)).fetchone()[0],10)
                    self.assertEqual(db.execute('SELECT etag FROM files WHERE key=?',(key,)).fetchone()[0],'old')
                FakeS3.fail=False
                app.ingest()
                self.assertIsNone(app.STATE['error'])
                with app.connect() as db:
                    self.assertEqual(tuple(db.execute('SELECT COUNT(*),SUM(sent) FROM events').fetchone()),(2,300))
        finally:
            app.STATE.clear();app.STATE.update(original)

    def test_recent_empty_files_are_not_downloaded_repeatedly(self):
        today=app.utc_now().date().isoformat()
        prefix=app.PREFIX+'firewalllogs/'+today+'/'
        key=prefix+'empty.csv.gz'
        blob=self.blob([['Timestamp','Source IP','Bytes Sent','Bytes Received']])
        class FakeS3:
            calls=0
            def __init__(self,_): pass
            def list(self,path): return [(key,'same')] if path==prefix else []
            def get(self,_):
                FakeS3.calls+=1
                return blob
        original=dict(app.STATE)
        try:
            with patch.object(app,'S3',FakeS3):
                app.ingest();app.ingest()
                self.assertIsNone(app.STATE['error'])
                self.assertEqual(FakeS3.calls,1)
                self.assertEqual(app.STATE['skipped'],1)
        finally:
            app.STATE.clear();app.STATE.update(original)

    def test_s3_download_streams_to_file_and_keeps_auth_out_of_arguments(self):
        output=Path(self.temp.name)/'download.gz'
        client=app.S3(values={'accessKeyId':'TEST_ACCESS','secretAccessKey':'TEST_SECRET'},settings={'region':'eu-central-1','bucket':'example-bucket'})
        def success(args,**kwargs):
            self.assertIn('--output',args)
            self.assertNotIn('TEST_SECRET',' '.join(args))
            self.assertIn(b'TEST_SECRET',kwargs['input'])
            Path(args[args.index('--output')+1]).write_bytes(b'test compressed bytes')
            return type('Result',(),{'returncode':0,'stdout':b'\n200'})()
        with patch.object(app.subprocess,'run',side_effect=success):
            client.download('test.csv.gz',output)
        self.assertEqual(output.read_bytes(),b'test compressed bytes')
        output.write_bytes(b'<Error><Code>AccessDenied</Code></Error>')
        with patch.object(app.subprocess,'run',return_value=type('Result',(),{'returncode':0,'stdout':b'\n403'})()):
            self.assertRaisesRegex(RuntimeError,'S3 HTTP 403: AccessDenied',client.download,'test.csv.gz',output)

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

    def test_lookup_policy_scope(self):
        condition={'attributeName':'umbrella.destination.private_resource_ids','attributeOperator':'INTERSECT','attributeValue':[12]}
        self.assertEqual(app.policy_scope({'ruleConditions':[condition]}),'private')
        self.assertIsNone(app.policy_scope({'ruleConditions':[{**condition,'attributeOperator':'NOT_INTERSECT'}]}))
        self.assertIsNone(app.policy_scope({'ruleAccess':'internet','ruleConditions':[condition]}))
        self.assertIsNone(app.policy_scope({'ruleName':'Internet Allow'}))
        self.assertEqual(app.policy_scope({'ruleSettings':[{'settingName':'umbrella.default.traffic','settingValue':'PUBLIC_INTERNET'}]}),'internet')
        settings={'prefix':'123_test/','bucket':'cisco-managed-region','database':self.folder/'cache'/'sample'/'traffic.sqlite'}
        payload={'ids':['77'],'clientId':'fake','clientSecret':'dummy','cacheId':'sample'}
        rule={'ruleId':77,'organizationId':123,'ruleName':'Example'}
        with patch.object(app,'ACTIVE_SETTINGS',settings):
            with patch.object(app,'policy_request',side_effect=[{'access_token':'sample'},rule.copy(),
                    {'result':[{**rule,'ruleAccess':'internet'}]}]):
                self.assertEqual(app.lookup_policy_rules(payload)['rules'][0]['scope'],'internet')
            with patch.object(app,'policy_request',side_effect=[{'access_token':'sample'},{**rule,'organizationId':999}]):
                self.assertEqual(app.lookup_policy_rules(payload)['rules'][0]['error'],'policyOrg')
            with patch.object(app,'policy_request',side_effect=[{'access_token':'sample'},
                    {'ruleId':77}, {'count':2,'result':[{'ruleId':22}]},
                    {'count':2,'result':[{**rule,'ruleAccess':'private'}]}, {}, {'result':{'ruleId':79}}, {'organizationId':999}]):
                results=app.lookup_policy_rules({**payload,'ids':['77','78','79']})['rules']
                self.assertEqual(results[0]['scope'],'private')
                self.assertEqual(results[1]['error'],'policyNotFound')
                self.assertEqual(results[2]['error'],'policyOrg')

    def test_policy_lookup_shared_failure_preserves_cause_and_independent_rules(self):
        settings={'prefix':'123_test/','bucket':'cisco-managed-region','database':self.folder/'sample'/'traffic.sqlite'}
        payload={'ids':['1','2','3'],'clientId':'test','clientSecret':'dummy','cacheId':'sample'}
        failure=app.PolicyResponseError('list','http',503)
        responses=[{'access_token':'sample'},{'ruleId':1},failure,{'ruleId':2},
                   {'ruleId':3,'organizationId':123,'ruleSettings':[{'settingName':'umbrella.default.traffic','settingValue':'PRIVATE_NETWORK'}]}]
        with patch.object(app,'ACTIVE_SETTINGS',settings),patch.object(app,'policy_request',side_effect=responses) as request:
            results=app.lookup_policy_rules(payload)['rules']
            self.assertEqual([r.get('error') for r in results], [str(failure),str(failure),None])
            self.assertEqual(results[-1]['scope'],'private')
            self.assertEqual(sum('offset=' in c.args[1] for c in request.call_args_list),1)

    def test_saved_access_policy_applies_to_existing_cache(self):
        connection=app.update_connection(self.payload,save=True)
        settings=app.ACTIVE_SETTINGS
        data={'cacheId':connection['cacheId'],'clientId':'sample','clientSecret':'dummy'}
        instant='2026-10-22T12:00:00Z'
        rows=[{'ruleId':i,'ruleAccess':kind,'modifiedAt':instant} for i,kind in [(1,'private'),(2,'internet')]]
        with app.connect() as db:
            for i in (1,2):
                db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)',
                           ('f',i,'firewall',app.timestamp(instant),'192.0.2.1','[]',10,1,'unknown'))
                db.execute('INSERT INTO event_details VALUES (?,?,?)',('f',i,json.dumps({'fields':{'ruleid':str(i)}})))
        responses=[{'access_token':'example'},{'result':rows}]
        with patch.object(app,'policy_request',side_effect=responses*2) as request:
            initial=app.refresh_access_policy(data)
            self.assertEqual((initial['total'],initial['mapped']),(2,2))
            self.assertEqual(app.refresh_access_policy({'cacheId':data['cacheId']}),initial)
            self.assertEqual(request.call_args_list[2],request.call_args_list[0])
        self.assertTrue(app.public_settings()['hasPolicyCredentials'])
        self.assertNotIn('dummy',json.dumps(app.public_settings()))
        if app.os.name!='nt':
            self.assertEqual(app.policy_key_path(settings).stat().st_mode&0o777,0o600)
        with patch.object(app,'policy_request',side_effect=app.PolicyResponseError('token','http',401)):
            self.assertRaises(app.PolicyResponseError,app.refresh_access_policy,data)
        query={'from':instant,'to':'2026-10-22T13:00:00Z'}
        with patch.object(app,'utc_now',return_value=dt.datetime(2026,10,22,13,tzinfo=app.UTC)):
            for kind in ('private','internet'):
                report=app.report({**query,'scope':kind})
                self.assertEqual(report['classification']['mapped'+kind.title()],{'records':1,'bytes':11})
                self.assertEqual(report['totals']['records'],1)

    def test_whole_policy_paginates_and_fetches_only_missing_details(self):
        settings={'prefix':'123_test/','bucket':'cisco-managed-region','database':self.folder/'sample'/'traffic.sqlite'}
        payload={'wholePolicy':True,'clientId':'test','clientSecret':'dummy','cacheId':'sample'}
        rows=[{'ruleId':i,'ruleAccess':'internet','modifiedAt':'2026-11-13T12:00:00Z'} for i in range(1,102)]
        rows[-1].pop('ruleAccess')
        responses=[{'access_token':'test'},{'count':101,'result':rows[:100]},
                   {'count':101,'result':rows[100:]},{'organizationId':123},
                   {'ruleId':101,'ruleAccess':'private'}]
        with patch.object(app,'ACTIVE_SETTINGS',settings),patch.object(app,'policy_request',side_effect=responses) as request:
            result=app.lookup_policy_rules(payload)['rules']
        self.assertEqual([r['scope'] for r in result],['internet']*100+['private'])
        self.assertEqual([c.args[1] for c in request.call_args_list][1:],
                         ['/policies/v2/rules?limit=100&offset=0','/policies/v2/rules?limit=100&offset=100',
                          '/deployments/v2/roamingcomputers/orgInfo','/policies/v2/rules/101'])

    def test_orginfo_fallback_for_batch(self):
        settings={'prefix':'123_test/','bucket':'cisco-managed-region','database':self.folder/'sample'/'traffic.sqlite'}
        payload={'ids':['1','2'],'clientId':'test','clientSecret':'dummy','cacheId':'sample'}
        rules=[{'ruleId':i,'ruleAccess':'internet'} for i in (1,2)]
        for reply,expected in [({'organizationId':123},None),({'organizationId':999},'policyOrg'),
                               (app.PolicyResponseError('org','http',403),'policyResponse/org/http/403')]:
            responses=[{'access_token':'test'},rules[0],{'result':rules},reply,rules[1]]
            with patch.object(app,'ACTIVE_SETTINGS',settings),patch.object(app,'policy_request',side_effect=responses) as request:
                rows=app.lookup_policy_rules(payload)['rules']
                self.assertEqual([row.get('error') for row in rows],[expected]*2)
                self.assertEqual([row['scope'] for row in rows],[None if expected else 'internet']*2)
                self.assertEqual(request.call_args_list[3].args,('GET','/deployments/v2/roamingcomputers/orgInfo','Bearer test'))

    def test_policy_http_diagnostics_and_envelopes(self):
        with patch.object(app.http.client,'HTTPSConnection') as connection:
            response=connection.return_value.getresponse.return_value
            response.status=429
            with self.assertRaisesRegex(app.PolicyResponseError,'policyResponse/detail/http/429'):
                app.policy_request('GET','/policies/v2/rules/77','Bearer dummy')
            response.status=200
            response.read.return_value=b'<html>private diagnostic data</html>'
            with self.assertRaisesRegex(app.PolicyResponseError,'^policyResponse/list/json/200$'):
                app.policy_request('GET','/policies/v2/rules?limit=100','Bearer dummy')
            response.read.return_value=b'{"data":{"result":[{"ruleId":77}],"count":1}}'
            self.assertEqual(app.policy_request('GET','/policies/v2/rules?limit=100','Bearer dummy')['result'],[{'ruleId':77}])

    def test_nested_catalog_and_detail_over_http(self):
        settings={'prefix':'123_test/','bucket':'cisco-managed-region','database':self.folder/'sample'/'traffic.sqlite'}
        payload={'ids':['77','78'],'clientId':'test','clientSecret':'dummy','cacheId':'sample'}
        rule={'ruleId':77,'organizationId':123,'ruleAccess':'internet'}
        replies=[{'access_token':'test'}, {'data':{'rule':{'ruleId':77}}},
                 {'count':2,'result':{'items':[{'ruleId':4}]}},
                 {'count':2,'result':{'items':[rule]}},
                 {'data':{'rule':{**rule,'ruleId':78,'organizationId':90}}}]
        with patch.object(app,'ACTIVE_SETTINGS',settings),patch.object(app.http.client,'HTTPSConnection') as connection:
            response=connection.return_value.getresponse.return_value
            response.status=200
            response.read.side_effect=[json.dumps(reply).encode() for reply in replies]
            first,second=app.lookup_policy_rules(payload)['rules']
            self.assertEqual(first['scope'],'internet')
            self.assertEqual(second['error'],'policyOrg')
        with self.assertRaises(app.PolicyResponseError) as error:
            app.policy_payload({'result':{'message':'confidential','private-field':'secret'}},'list')
        self.assertEqual(error.exception.structure,'$.result (message=str)')

    def test_prune_phase_estimates(self):
        with patch.dict(app.PRUNE_PROGRESS, clear=True), patch.object(app.time,'monotonic',return_value=100) as clock:
            app.prune_phase('deleting',done=0,total=100)
            self.assertNotIn('remaining',app.prune_status())
            app.PRUNE_PROGRESS['done']=25
            clock.return_value=110
            self.assertEqual(app.prune_status()['remaining'],30)
            app.prune_phase('compacting',estimate=None)
            self.assertNotIn('remaining',app.prune_status())
            app.prune_phase('compacting',estimate=20)
            clock.return_value=115
            self.assertEqual(app.prune_status()['remaining'],15)
            clock.return_value=140
            self.assertNotIn('remaining',app.prune_status())

    def test_custom_cache_location_and_return_to_default(self):
        default=app.update_connection(self.payload,save=True)
        original=app.DB
        with app.connect() as db:
            db.execute("INSERT INTO metadata VALUES ('test-marker','original')")
        target=self.folder/'external'
        target.mkdir()
        request={**self.payload,'cacheDirectory':str(target),'accessKeyId':'','secretAccessKey':''}
        selected=app.update_connection(request,save=True)
        self.assertEqual(app.DB,target/original.parent.name/'traffic.sqlite')
        self.assertNotEqual(default['cacheId'],selected['cacheId'])
        self.assertEqual(app.load_settings(app.CONFIG_PATH)['database'],app.DB)
        self.assertEqual(app.CREDENTIALS.parent,self.folder)
        with app.connect() as db:
            self.assertIsNone(db.execute("SELECT value FROM metadata WHERE key='test-marker'").fetchone())
        target.rename(self.folder/'disconnected')
        with self.assertRaisesRegex(ValueError,'cachePathUnavailable'),app.connect():
            pass
        self.assertFalse(target.exists())
        with self.assertRaisesRegex(ValueError,'cachePathInvalid'):
            app.update_connection({**request,'cacheDirectory':'relative'},save=True)
        app.update_connection({**request,'cacheDirectory':''},save=True)
        self.assertEqual(app.DB,original)
        with app.connect() as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='test-marker'").fetchone()[0],'original')

    def test_sync_window_prune_and_widen(self):
        result = app.update_connection(self.payload,save=True)
        options = {'cacheId':result['cacheId'],'syncDays':1}
        now = dt.datetime(2026,10,22,18,tzinfo=app.UTC)
        folder = app.PREFIX+'firewalllogs/2026-10-21/'
        key = folder+'mixed.csv.gz'
        blob = gzip.compress(b'Timestamp,Source IP,Bytes Sent,Bytes Received\n'
                             b'2026-10-21 17:59:59,192.0.2.1,1,2\n'
                             b'2026-10-21 18:00:00,192.0.2.2,3,4\n')
        with patch.object(app,'utc_now',return_value=now), patch.object(app,'S3') as client:
            source = client.return_value
            source.list.side_effect = lambda path: [(key,'etag')] if path==folder else []
            source.download.side_effect = lambda key,path: Path(path).write_bytes(blob)
            app.ingest()
            app.update_sync_window(options)
            self.assertEqual(app.load_settings(app.CONFIG_PATH)['syncDays'],1)
            source.list.reset_mock()
            app.ingest()
            self.assertEqual(source.list.call_count,4)
            self.assertEqual(source.download.call_count,1)
            self.assertEqual(app.update_sync_window(options,prune=True)['removed'],1)
            app.ingest()
            self.assertEqual(source.download.call_count,1)
            with app.connect() as db:
                self.assertEqual(db.execute('SELECT ip FROM events').fetchone()[0],'192.0.2.2')
                self.assertEqual(db.execute('SELECT COUNT(*) FROM event_details').fetchone()[0],1)
            app.update_sync_window({**options,'syncDays':2})
            app.ingest()
            self.assertEqual(source.download.call_count,2)
            with app.connect() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],2)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM event_details').fetchone()[0],2)
            for invalid in (0,31,True,0.5,'1'):
                with self.assertRaisesRegex(ValueError,'invalidSyncDays'):
                    app.update_sync_window({**options,'syncDays':invalid})
            with self.assertRaisesRegex(ValueError,'saveWindowFirst'):
                app.update_sync_window(options,prune=True)

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
