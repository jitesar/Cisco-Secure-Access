'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const context=vm.createContext({TextEncoder,TextDecoder,URLSearchParams,Intl,Date,atob,btoa});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/time.js'),'utf8'),context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/i18n.js'),'utf8'),context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/exports.js'),'utf8'),context);
const query=new URLSearchParams({source:'firewall',from:'2026-10-22T00:30:00Z',to:'2026-10-22T02:30:00Z',subnet:'192.0.2.0/24',identity:' =HYPERLINK("https://example.invalid")\nŽluťoučký kůň',scope:'private'});
const snapshot={query,totals:{received:1000,sent:250,records:7,missing:2,unknown:3},series:[{ts:1792627200,received:1000,sent:50},{ts:1792630800,received:0,sent:200},{ts:1792634400,received:0,sent:0}],top:[{label:'192.0.2.1',received:1000,sent:250,records:7}],coverage:{from:1792627200,to:1792634400,records:7},lastSync:'2026-10-22T03:00:00Z',importWarning:'Synthetic import incomplete'};
const output=process.env.CSA_EXPORT_TEST_OUTPUT;
for(const lang of ['cs','en']){
  vm.runInContext('language='+JSON.stringify(lang),context);
  const doc=context.reportDocument(snapshot,context.t,new Date('2026-10-23T12:00:00Z'));
  assert.equal(doc.series.reduce((n,r)=>n+r[1],0),snapshot.totals.received);
  assert.equal(doc.series.reduce((n,r)=>n+r[2],0),snapshot.totals.sent);
  assert(doc.metadata.some(r=>r[1]===query.get('identity')));
  assert(doc.metadata.some(r=>r[1]===1000));
  assert(doc.rows.some(r=>r[0]==='Synthetic import incomplete'));
  const csv=context.reportCSV(doc.rows);
  assert(csv.startsWith('\ufeff'));
  assert(csv.includes("' =HYPERLINK"));
  assert(csv.includes('Žluťoučký kůň'));
  assert(!csv.includes('secretAccessKey'));
  const xls=context.reportXLS(doc.rows);
  assert.equal(Buffer.from(xls.slice(0,8)).toString('hex'),'d0cf11e0a1b11ae1');
  if(output){fs.mkdirSync(output,{recursive:true});fs.writeFileSync(path.join(output,'report-'+lang+'.xls'),xls);fs.writeFileSync(path.join(output,'report-'+lang+'.csv'),csv)}
  const empty=context.reportDocument({...snapshot,totals:{received:0,sent:0,records:0,missing:0,unknown:0},top:[],series:[],coverage:{records:0}},context.t);
  assert.equal(empty.series.length,0);assert(empty.metadata.some(r=>r[0]===context.t('noHistoryHint')));
}
for(const zone of ['Europe/Prague','America/New_York','Asia/Kathmandu','UTC']){
  const doc=context.reportDocument({...snapshot,timeZone:zone},context.t,new Date('2026-10-23T12:00:00Z'));
  assert(doc.metadata.some(row=>row[1]===zone));
  for(const key of ['reportGenerated','reportSynced','reportCoverage','csvFrom','csvTo']){
    const row=doc.metadata.find(row=>row[0]===context.t(key));assert(row);assert(String(row[1]).includes('GMT'));
  }
  assert.equal(doc.series[0][0],context.displayTimestamp(snapshot.series[0].ts*1000,zone));
  assert.equal(doc.seriesTimes[0],snapshot.series[0].ts*1000);
  assert(doc.rows.some(row=>row[0]===context.t('reportTimeNote',{zone})));
}
assert(context.reportCSV([['\t=1+1','\n@SUM(1)','+5','-1','plain'],[5]]).includes('"\'\t=1+1"'));
const longText='Příliš žluťoučký kůň 🐎 '.repeat(450);
const largeRows=[['Label','Bytes'],[longText,42],...Array.from({length:1800},(_,i)=>['2026-10-22T00:00:00Z',i*1000,i*2000])];
const big=context.reportXLS(largeRows);
assert(big.length>65536);
if(output){fs.writeFileSync(path.join(output,'large.xls'),big);fs.writeFileSync(path.join(output,'long-label.txt'),longText)}
assert.throws(()=>context.reportXLS([['a'.repeat(32768)]]),/exportTooLarge/);
const pdf=context.reportPDFPages(['data:image/jpeg;base64,'+btoa('fakejpeg')],1240,1754);
const pdfText=new TextDecoder().decode(pdf);
assert(pdfText.startsWith('%PDF-1.4'));assert(pdfText.includes('/Count 1'));
const xref=Number(pdfText.match(/startxref\n(\d+)/)[1]);assert.equal(pdfText.slice(xref,xref+4),'xref');
console.log('Report exports: CZ/EN metadata, numeric totals, empty reports, CSV formula protection, Unicode XLS, multi-sector XLS and PDF cross references OK');
