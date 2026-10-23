'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Node {
  constructor(){this.value='';this.options=[];this.handlers={};this.textContent='';this.disabled=false;this.hidden=false;this.classes=new Set();this.classList={toggle:(key,on)=>on?this.classes.add(key):this.classes.delete(key),remove:key=>this.classes.delete(key)};this.dataset={}}
  addEventListener(key,fn){this.handlers[key]=fn}
  replaceChildren(...options){this.options=options;this.value=options[0]?.value||''}
  add(option){this.options.push(option)}
}
const nodes=new Map(),get=id=>{if(!nodes.has(id))nodes.set(id,new Node());return nodes.get(id)};
const quick=new Node();quick.dataset.hours='24';quick.classes.add('selected');
const tabs=['firewall','proxy'].map(source=>{const node=new Node();node.dataset.source=source;return node});
const memory=new Map();let writesFail=false,readFail=false,loads=0,presetHours=null,queryError='';
const context={console,URLSearchParams,Date,Option:class {constructor(text,value){this.text=text;this.value=value}},
  $:get,t:key=>key,
  document:{querySelector:()=>quick.classes.has('selected')?quick:null,querySelectorAll:selector=>selector==='[data-source]'?tabs:[quick]},
  window:{addEventListener(){}},localStorage:{getItem:key=>{if(readFail)throw Error('blocked');return memory.get(key)||null},setItem:(key,value)=>{if(writesFail)throw Error('quota');memory.set(key,value)}},
  params:()=>{if(queryError)throw Error(queryError);return new URLSearchParams({scope:get('#scope').value,subnet:get('#subnet').value,identity:get('#identity').value,from:'2026-10-22T10:00:00Z',to:'2026-10-23T10:00:00Z'})},
  preset:hours=>{presetHours=hours;quick.classes.add('selected')},updateDateBounds(){},localValue:date=>date.toISOString().slice(0,16),load:async()=>{loads++},
};
vm.createContext(context);vm.runInContext("let source='firewall';",context);vm.runInContext(fs.readFileSync('static/filters.js','utf8'),context);
const run=script=>vm.runInContext(script,context),snapshot=()=>JSON.parse(memory.get('csa-saved-filters-v1'));
(async()=>{
  run('initializeSavedFilters()');
  assert(get('#saved-filter-load').disabled);
  get('#mode').value='subnet';get('#scope').value='private';get('#subnet').value='10-11.30-33.1-2.3-50';get('#saved-filter-name').value='Office';
  run('saveSearchFilter()');assert.equal(snapshot()[0].hours,24);assert.equal(snapshot()[0].subnet,get('#subnet').value);
  get('#subnet').value='192.0.2.0/24';run('saveSearchFilter()');assert.equal(snapshot().length,1);assert.equal(snapshot()[0].subnet,'192.0.2.0/24');
  // Recreate state as on a fresh browser page, then apply the persisted selection.
  run('savedFilters=[];initializeSavedFilters()');get('#saved-filter-select').value='Office';
  await run('applySavedFilter()');assert.equal(presetHours,24);assert.equal(loads,1);assert.equal(get('#scope').value,'private');assert.equal(get('#subnet').value,'192.0.2.0/24');
  quick.classes.delete('selected');get('#saved-filter-name').value='Custom identity';get('#mode').value='identity';get('#identity').value='Tunnel A';run('saveSearchFilter()');
  assert.equal(snapshot()[1].hours,null);get('#identity').options=[];get('#identity').value='';
  await run('applySavedFilter()');assert.equal(get('#identity').value,'Tunnel A');assert.equal(get('#from').value,'2026-10-22T10:00');assert(!quick.classes.has('selected'));
  assert(get('#identity').options.some(option=>option.value==='Tunnel A'));
  queryError='windowError';const before=loads;await run('applySavedFilter()');assert.equal(loads,before);assert.equal(get('#saved-filter-message').textContent,'savedFilterExpired');queryError='';
  writesFail=true;get('#saved-filter-name').value='Cannot persist';run('saveSearchFilter()');assert.equal(get('#saved-filter-message').textContent,'savedFiltersStorage');assert.equal(snapshot().length,2);writesFail=false;
  get('#saved-filter-select').value='Custom identity';get('#saved-filter-delete').handlers.click();assert.equal(snapshot().length,1);assert.equal(get('#saved-filter-message').textContent,'savedFilterDeleted');
  get('#saved-filter-name').value='';run('saveSearchFilter()');assert.equal(get('#saved-filter-message').textContent,'savedFilterNameRequired');
  const valid=snapshot()[0];assert.throws(()=>context.validateSavedFilters([valid,valid]));
  for(const changes of [{hours:999},{source:'invalid'},{from:'invalid'},{mode:'invalid'},{scope:'invalid'},{name:''}])assert.throws(()=>context.validateSavedFilters([{...valid,...changes}]));
  readFail=true;run('initializeSavedFilters()');assert.equal(get('#saved-filter-message').textContent,'savedFiltersStorageRead');
  console.log('Saved filters: create, update, persistence, relative/custom time, identities, expiry, deletion, storage failures and validation OK');
})().catch(error=>{console.error(error);process.exitCode=1});
