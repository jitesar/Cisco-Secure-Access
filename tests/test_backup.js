'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const path=require('node:path');
const context=vm.createContext({crypto:webcrypto,TextEncoder,TextDecoder,btoa,atob});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/filters.js'),'utf8'),context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/backup.js'),'utf8'),context);
const snapshot={format:'csa-traffic-settings',version:1,settings:{s3Path:'s3://example-bucket/test/',region:'eu-central-1'},credentials:{accessKeyId:'TEST_ACCESS',secretAccessKey:'TEST_SECRET'},preferences:{language:'en',timeZone:'America/New_York'}};
const filter={name:'Office',source:'firewall',mode:'subnet',scope:'all',subnet:'10-11.30-33.1-2.3-50',identity:'',hours:24,from:'2026-10-22T10:00:00Z',to:'2026-10-23T10:00:00Z'};
snapshot.savedFilters=[filter];
const password='test-only-password-123';
(async()=>{
  const encrypted=await context.encryptBackup(snapshot,password);
  const serialized=JSON.stringify(encrypted);
  for(const value of ['TEST_ACCESS','TEST_SECRET','example-bucket',filter.name,filter.subnet])assert(!serialized.includes(value));
  const restored=await context.decryptBackup(serialized,password);
  assert.equal(JSON.stringify(restored),JSON.stringify(snapshot));
  await assert.rejects(context.decryptBackup(serialized,'wrong-password'),/backupDecryptFailed/);
  const changed=JSON.parse(serialized);changed.ciphertext=(changed.ciphertext[0]==='A'?'B':'A')+changed.ciphertext.slice(1);
  await assert.rejects(context.decryptBackup(JSON.stringify(changed),password),/backupDecryptFailed/);
  for(const changes of [{version:2},{iterations:1},{iterations:999999999},{iv:'abcd'},{cipher:'AES-CBC'},{salt:'invalid'}]){
    await assert.rejects(context.decryptBackup(JSON.stringify({...encrypted,...changes}),password),/backupInvalid/);
  }
  await assert.rejects(context.decryptBackup('invalid json',password),/backupInvalid/);
  await assert.rejects(context.decryptBackup('x'.repeat(vm.runInContext('MAX_BACKUP_BYTES',context)+1),password),/backupInvalid/);
  await assert.rejects(context.encryptBackup(snapshot,'short'),/backupPasswordShort/);
  const second=await context.encryptBackup(snapshot,password);
  assert.notEqual(second.salt,encrypted.salt);assert.notEqual(second.iv,encrypted.iv);
  const legacy={...snapshot};delete legacy.savedFilters;
  const legacyEncrypted=JSON.stringify(await context.encryptBackup(legacy,password));
  assert(!('savedFilters' in await context.decryptBackup(legacyEncrypted,password)));
  const many={...snapshot,savedFilters:Array.from({length:100},(_,i)=>({...filter,name:'Office '+i,subnet:'10.0.0.1,'.repeat(200)}))};
  const largeEncrypted=JSON.stringify(await context.encryptBackup(many,password));
  assert(largeEncrypted.length>131072);
  assert.equal(JSON.stringify((await context.decryptBackup(largeEncrypted,password)).savedFilters),JSON.stringify(many.savedFilters));
  for(const invalid of [null,[filter,filter],[{...filter,hours:999}]]){
    const malformed=JSON.stringify(await context.encryptBackup({...snapshot,savedFilters:invalid},password));
    await assert.rejects(context.decryptBackup(malformed,password),/backupInvalid/);
  }
  await assert.rejects(context.encryptBackup({...snapshot,extra:'x'.repeat(vm.runInContext('MAX_BACKUP_PLAINTEXT',context))},password),/backupTooLarge/);

  // Exercise the actual GUI export/import handlers with real encryption and a
  // synthetic S3 API, without reading or changing any real credentials.
  const nodes=new Map(),node=id=>{if(!nodes.has(id))nodes.set(id,{value:'',textContent:'',options:[],files:[],open:true,reportValidity:()=>true,replaceChildren(...items){this.options=items},addEventListener(){}});return nodes.get(id)};
  const storage=new Map();let failWrite=false,failAPI=false,calls=0,finished=0,downloaded=null,posted=null;
  Object.assign(context,{
    $:node,t:key=>key,translateError:key=>key,
    Option:class {constructor(text,value){this.text=text;this.value=value}},
    localStorage:{getItem:key=>storage.get(key)??null,setItem:(key,value)=>{if(failWrite)throw Error('quota');storage.set(key,value)},removeItem:key=>storage.delete(key)},
    settingsBusy:false,connection:{configured:true},language:'en',timeZone:'America/New_York',
    setSettingsBusy:busy=>{context.settingsBusy=busy},validTimeZone:()=>true,applyTimeZone(){},applyLanguage(){},
    finishConnection:async()=>{finished++},wallValue:date=>date.toISOString().slice(0,16),setTimeout(){},Blob,
    URL:{createObjectURL:blob=>{downloaded=blob;return 'blob:synthetic'},revokeObjectURL(){}},
    document:{createElement:()=>({click(){}})},error:message=>{throw Error(message)},
    api:async(url,options)=>{calls++;if(failAPI)throw Error('syntheticS3Failure');if(url.endsWith('/backup'))return JSON.parse(JSON.stringify(legacy));posted=JSON.parse(options.body);return {language:'en'}},
  });
  const key='csa-saved-filters-v1';
  storage.set(key,JSON.stringify([{...filter,name:'Local only'},{...filter,name:'Office',subnet:'192.0.2.0/24'}]));
  node('#backup-password').value=password;node('#backup-confirm').value=password;
  await context.exportBackup();assert(downloaded);
  const exportSnapshot=await context.decryptBackup(await downloaded.text(),password);
  assert.equal(JSON.stringify(exportSnapshot.savedFilters),storage.get(key));
  const importFile=async text=>{node('#restore-file').files=[{size:text.length,text:async()=>text}];node('#restore-password').value=password;await context.importBackup()};
  await importFile(serialized);let merged=JSON.parse(storage.get(key));
  assert.equal(merged.length,2);assert.equal(merged.find(item=>item.name==='Office').subnet,filter.subnet);assert.equal(finished,1);
  assert(!('savedFilters' in posted));assert(JSON.stringify(posted).length<1000);
  const before=storage.get(key);await importFile(legacyEncrypted);assert.equal(storage.get(key),before);
  failWrite=true;const beforeCalls=calls;await importFile(serialized);assert.equal(calls,beforeCalls);assert.equal(storage.get(key),before);failWrite=false;
  failAPI=true;const incoming=JSON.stringify(await context.encryptBackup({...snapshot,savedFilters:[{...filter,name:'New from backup'}]},password));
  await importFile(incoming);assert.equal(storage.get(key),before);failAPI=false;
  storage.delete(key);failAPI=true;await importFile(incoming);assert(!storage.has(key));failAPI=false;
  await importFile(largeEncrypted);assert.equal(JSON.parse(storage.get(key)).length,100);assert(!('savedFilters' in posted));
  const full=storage.get(key),limitCalls=calls;await importFile(incoming);assert.equal(storage.get(key),full);assert.equal(calls,limitCalls);
  console.log('Backup filters: encrypted round trip, 100-filter large backup, legacy compatibility, GUI export/import, same-name merge, API rollback, storage failure and count limit OK');
  console.log('Backup crypto: round trip, wrong password, tampering, format bounds and fresh randomness OK');
})().catch(error=>{console.error(error);process.exitCode=1});
