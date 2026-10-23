'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const path=require('node:path');
const context=vm.createContext({crypto:webcrypto,TextEncoder,TextDecoder,btoa,atob});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/backup.js'),'utf8'),context);
const snapshot={format:'csa-traffic-settings',version:1,settings:{s3Path:'s3://example-bucket/test/',region:'eu-central-1'},credentials:{accessKeyId:'TEST_ACCESS',secretAccessKey:'TEST_SECRET'},preferences:{language:'en',timeZone:'America/New_York'}};
const password='test-only-password-123';
(async()=>{
  const encrypted=await context.encryptBackup(snapshot,password);
  const serialized=JSON.stringify(encrypted);
  for(const value of ['TEST_ACCESS','TEST_SECRET','example-bucket'])assert(!serialized.includes(value));
  const restored=await context.decryptBackup(serialized,password);
  assert.equal(JSON.stringify(restored),JSON.stringify(snapshot));
  await assert.rejects(context.decryptBackup(serialized,'wrong-password'),/backupDecryptFailed/);
  const changed=JSON.parse(serialized);changed.ciphertext=(changed.ciphertext[0]==='A'?'B':'A')+changed.ciphertext.slice(1);
  await assert.rejects(context.decryptBackup(JSON.stringify(changed),password),/backupDecryptFailed/);
  for(const changes of [{version:2},{iterations:1},{iterations:999999999},{iv:'abcd'},{cipher:'AES-CBC'},{salt:'invalid'}]){
    await assert.rejects(context.decryptBackup(JSON.stringify({...encrypted,...changes}),password),/backupInvalid/);
  }
  await assert.rejects(context.decryptBackup('invalid json',password),/backupInvalid/);
  await assert.rejects(context.decryptBackup('x'.repeat(131073),password),/backupInvalid/);
  await assert.rejects(context.encryptBackup(snapshot,'short'),/backupPasswordShort/);
  const second=await context.encryptBackup(snapshot,password);
  assert.notEqual(second.salt,encrypted.salt);assert.notEqual(second.iv,encrypted.iv);
  console.log('Backup crypto: round trip, wrong password, tampering, format bounds and fresh randomness OK');
})().catch(error=>{console.error(error);process.exitCode=1});
