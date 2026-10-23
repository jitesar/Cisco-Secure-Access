'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const context=vm.createContext({Intl,Date});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/time.js'),'utf8'),context);
for(const [zone,instant,wall] of [
 ['Europe/Prague','2026-10-23T12:00:00Z','2026-10-23T14:00'],
 ['America/New_York','2026-10-23T12:00:00Z','2026-10-23T08:00'],
 ['UTC','2026-10-23T12:00:00Z','2026-10-23T12:00'],
 ['Asia/Kathmandu','2026-10-23T12:00:00Z','2026-10-23T17:45'],
 ['Australia/Adelaide','2026-10-23T12:00:00Z','2026-10-23T22:30'],
 ['America/New_York','2026-12-23T00:15:00Z','2026-12-22T19:15'],
]){
 assert.equal(context.wallValue(new Date(instant),zone),wall);
 assert.equal(context.zonedDate(wall,zone).toISOString(),new Date(instant).toISOString());
}
assert.throws(()=>context.zonedDate('2026-03-08T02:30','America/New_York'),/dstError/);
assert.throws(()=>context.zonedDate('2026-11-01T01:30','America/New_York'),/dstAmbiguous/);
assert.throws(()=>context.zonedDate('2026-10-25T02:30','Europe/Prague'),/dstAmbiguous/);
assert.throws(()=>context.zonedDate('2026-03-29T02:30','Europe/Prague'),/dstError/);
assert.throws(()=>context.zonedDate('','UTC'),/rangeError/);
assert.equal(context.zonedFormatter({hour:'numeric'},'America/New_York').resolvedOptions().hour12,true);
assert.equal(context.zonedFormatter({hour:'numeric'},'Europe/Prague').resolvedOptions().hour12,false);
const us=context.displayTimestamp('2026-10-23T20:00:00Z','America/New_York');assert.match(us,/10\/23\/2026/);assert.match(us,/PM/);assert.match(us,/GMT-04:00/);
const before=context.displayTimestamp('2026-11-01T05:30:00Z','America/New_York'),after=context.displayTimestamp('2026-11-01T06:30:00Z','America/New_York');assert.notEqual(before,after);assert.match(before,/GMT-04:00/);assert.match(after,/GMT-05:00/);
for(const zone of Intl.supportedValuesOf('timeZone'))assert.doesNotThrow(()=>context.displayTimestamp('2026-10-23T12:00:00Z',zone));
assert(context.validTimeZone('UTC'));assert(!context.validTimeZone('bad/time-zone'));
// Settings changes preserve the input instants and never replace them with a new preset.
const fields={'#from':{value:'2026-10-23T14:00'},'#to':{value:'2026-10-23T15:00'}};let persisted=null;
context.$=id=>fields[id];context.localStorage={setItem:(key,value)=>{persisted=[key,value]}};context.updateFormatters=()=>{};context.updateDateBounds=()=>{};context.applyLanguage=()=>{};
vm.runInContext("let language='cs';localizeTimeZone=()=>{}",context);
context.applyTimeZone('America/New_York');assert.equal(fields['#from'].value,'2026-10-23T08:00');assert.equal(fields['#to'].value,'2026-10-23T09:00');assert.equal(persisted[1],'America/New_York');
context.localStorage.setItem=()=>{throw Error('quota')};assert.throws(()=>context.applyTimeZone('UTC'),/timeZoneStorage/);assert.equal(fields['#from'].value,'2026-10-23T08:00');
console.log('Time zones: regional 12/24-hour display, fractional offsets, midnight, DST gaps/repeats, instant preservation and persistence failures OK');
