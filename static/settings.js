'use strict';
let connection={configured:false,csrfToken:''};
let settingsBusy=false,settingsMessage=null;

function connectionChanged(){
  return $('#settings-path').value.trim().replace(/\/+$/,'')!==(connection.s3Path||'').replace(/\/+$/,'') || $('#settings-region').value.trim()!==connection.region;
}

function renderPolicySummary(){
  const node=$('#policy-summary');
  node.textContent=ruleEditor?.policyCount!=null?t('policySummary',{n:fmt.format(ruleEditor.policyCount)}):
    ruleEditor?t('policyAbsent'):'';
}

function localizeSettings(){
  renderPolicySummary();
  const keep=connection.hasCredentials&&!connectionChanged();
  $('#settings-keyhint').textContent=t(keep?'settingsKeepKeys':'settingsNewKeys');
  const replacing=Boolean($('#settings-access').value||$('#settings-secret').value);
  $('#settings-access').required=!keep||replacing;
  $('#settings-secret').required=!keep||replacing;
  localizeBackup();
  if(settingsMessage){
    $('#settings-message').textContent=settingsMessage.raw?translateError(settingsMessage.raw):t(settingsMessage.key);
  }
}

function settingsFeedback(key,kind='success',raw=false){
  settingsMessage={key,raw:raw?key:null};
  const node=$('#settings-message');
  node.hidden=false;
  node.className='settings-message '+kind;
  localizeSettings();
}

function setSettingsBusy(busy){
  settingsBusy=busy;
  $('#settings-fields').disabled=busy;
  updateWindowControls();
  $('#settings-close').disabled=busy;
  localizeBackup();
}

function showSettings(){
  ruleEditor=null;
  $('#policy-credentials').open=!connection.hasPolicyCredentials;
  $('#manual-rules').open=false;
  $('#policy-selected').open=false;
  $('#rules-panel').hidden=!connection.configured;
  $('#rules-panel').open=connection.configured&&!connection.hasPolicyCredentials;
  $('#policy-client').value=$('#policy-secret').value='';
  $('#policy-client').required=$('#policy-secret').required=!connection.hasPolicyCredentials;
  $('#policy-message').textContent='';
  $('#policy-ids').value=(current?.ruleRanking||[]).map(row=>row.id).filter(Boolean).slice(0,10).join(', ');
  ++ruleRequest;
  $('#sync-days').value=connection.syncDays??30;
  $('#window-message').textContent='';
  updateWindowControls();
  $('#cache-directory').value=connection.cacheDirectory||'';
  $('#cache-directory').placeholder=connection.defaultCacheDirectory||'';
  $('#database-path').textContent=connection.databasePath||'';
  $('#settings-path').value=connection.s3Path||'';
  $('#settings-region').value=connection.region||'eu-central-1';
  $('#settings-access').value='';
  $('#settings-secret').value='';
  settingsMessage=null;backupMessage=null;clearBackupPasswords();
  $('#settings-message').hidden=true;$('#backup-message').hidden=true;
  localizeSettings();localizeTimeZone();$('#settings-timezone-message').textContent='';
  if(!$('#settings-dialog').open)$('#settings-dialog').showModal();$('#settings-path').focus();
}

function updateConnectionUI(){
  $('#setupbanner').hidden=connection.configured;
  $('#filtercontrols').disabled=!connection.configured;
  $('#sync').disabled=!connection.configured||Boolean(lastStatus?.running);
  localizeBackup();
}

function updateWindowControls(){
  const input=$('#sync-days');
  input.disabled=settingsBusy;
  $('#window-save').disabled=settingsBusy||!connection.configured;
  $('#window-prune').disabled=settingsBusy||!connection.configured||input.valueAsNumber!==connection.syncDays;
}

function monitorPrune(message){
  const bar=$('#prune-progress');
  let active=true,timer;
  bar.removeAttribute('value');
  bar.hidden=false;
  async function poll(){
    try{
      const state=await api('/api/cache/prune-status');
      if(!active||state.phase==='idle')return;
      let label;
      if(state.phase==='deleting'&&state.total){
        bar.max=state.total;
        bar.value=state.done;
        label=t('pruneDeleting',{done:fmt.format(state.done),total:fmt.format(state.total),
          percent:Math.floor(100*state.done/state.total)});
      }else{
        bar.removeAttribute('value');
        label=t(state.phase==='compacting'?'pruneCompacting':'pruneCounting');
      }
      const duration=seconds=>Math.floor(seconds/3600)+' h '+Math.floor(seconds%3600/60)+' min '+seconds%60+' s';
      message.textContent=label+' · '+t('pruneElapsed',{time:duration(state.elapsed)})+' · '+
        (state.remaining!==undefined?t('pruneETA',{time:duration(state.remaining)}):t('pruneUnknown'));
    }catch{/* Keep polling while the cleanup request is active. */}
    finally{if(active)timer=setTimeout(poll,1000)}
  }
  poll();
  return ()=>{active=false;clearTimeout(timer);bar.hidden=true};
}

async function changeWindow(prune){
  if(settingsBusy||!$('#sync-window-form').reportValidity())return;
  const days=$('#sync-days').valueAsNumber;
  if(prune&&!window.confirm(t('confirmPrune',{days})))return;
  setSettingsBusy(true);
  const message=$('#window-message');
  message.textContent=t(prune?'pruningWindow':'settingsSaving');
  const stopProgress=prune?monitorPrune(message):()=>{};
  try{
    const result=await api(prune?'/api/cache/prune':'/api/settings/window',{
      method:'POST',body:JSON.stringify({syncDays:days,cacheId:connection.cacheId})
    });
    if(prune){
      stopProgress();
      message.textContent=t('prunedWindow',{count:result.removed});
      void load();
    }else{
      connection.syncDays=result.syncDays;
      message.textContent=t('windowSaved');
    }
  }catch(e){message.textContent=translateError(e.message)}
  finally{stopProgress();setSettingsBusy(false)}
}

async function initializeConnection(){
  initializeRuleEditor();
  initializePolicyLookup();
  initializeBackup();
  $('#sync-days').addEventListener('input',()=>{updateWindowControls();$('#window-message').textContent=''});
  $('#window-prune').addEventListener('click',()=>changeWindow(true));
  $('#sync-window-form').addEventListener('submit',event=>{event.preventDefault();changeWindow(false)});
  $('#open-settings').addEventListener('click',showSettings);
  $('#setup-button').addEventListener('click',showSettings);
  $('#settings-close').addEventListener('click',()=>$('#settings-dialog').close());
  $('#settings-dialog').addEventListener('cancel',event=>{if(settingsBusy)event.preventDefault()});
  $('#settings-dialog').addEventListener('close',()=>{
    $('#policy-client').value=$('#policy-secret').value='';
    $('#settings-access').value='';$('#settings-secret').value='';
  });
  for(const field of ['#settings-path','#settings-region','#settings-access','#settings-secret']){
    $(field).addEventListener('input',()=>{
      settingsMessage=null;$('#settings-message').hidden=true;localizeSettings();
    });
  }
  $('#settings-test').addEventListener('click',()=>submitSettings(false));
  $('#settings-form').addEventListener('submit',event=>{event.preventDefault();submitSettings(true)});
  try{
    setActivity('loadSettingsStage');
    connection=await api('/api/settings');
    updateConnectionUI();
    if(connection.configured){await load();await status()}
    else{setActivity(null);showSettings()}
  }catch(e){setActivity(null);error(e.message)}
}

async function submitSettings(save){
  if(settingsBusy)return;
  localizeSettings();
  if(!$('#settings-form').reportValidity()||!$('#sync-days').reportValidity())return;
  const payload={cacheDirectory:$('#cache-directory').value.trim(),syncDays:$('#sync-days').valueAsNumber,s3Path:$('#settings-path').value.trim(),region:$('#settings-region').value.trim(),accessKeyId:$('#settings-access').value.trim(),secretAccessKey:$('#settings-secret').value.trim()};
  setSettingsBusy(true);
  settingsFeedback(save?'settingsSaving':'settingsTesting','pending');
  try{
    const result=await api(save?'/api/settings':'/api/settings/test',{method:'POST',body:JSON.stringify(payload)});
    if(!save){settingsFeedback('settingsTestOK');return}
    await finishConnection(result);
  }catch(e){
    if($('#settings-dialog').open)settingsFeedback(e.message,'failure',true);
    else error(e.message);
  }finally{
    // Never retain the submitted key values in application state or browser storage.
    payload.accessKeyId='';payload.secretAccessKey='';
    setSettingsBusy(false);
  }
}

async function finishConnection(result,toastKey='settingsSaved'){
    connection=result;
    requestNo++;current=null;historyPreview=null;closeTransfers();updateExportButtons();
    $('#total').textContent=$('#received').textContent=$('#sent').textContent=$('#rate').textContent='—';
    $('#recordcount').textContent=t('selectPeriod');$('#top').replaceChildren();$('#export').disabled=true;draw();
    $('#identity').replaceChildren(new Option(t('chooseIdentity'),''));
    $('#mode').value='all';$('#subnetfield').hidden=true;$('#identityfield').hidden=true;
    updateConnectionUI();
    setSettingsBusy(false);
    $('#settings-dialog').close();
    $('#connectiontoast').dataset.i18n=toastKey;$('#connectiontoast').textContent=t(toastKey);$('#connectiontoast').hidden=false;
    error('');
    await load();
    await api('/api/sync',{method:'POST'});
    wasRunning=true;
    await status();
}

let ruleEditor=null,ruleRequest=0;
function editorRules(){
  return [...$('#rule-rows').children].map(row=>Object.fromEntries(
    [...row.querySelectorAll('[name]')].map(field=>[field.name,field.value])));
}
function updateRuleSave(){
  const rules=editorRules(),previous=ruleEditor?.rules;
  const changed=previous&&(rules.length!==previous.length||rules.some((r,i)=>
    ['id','scope','from','to'].some(k=>r[k]!==previous[i][k])));
  $('#rules-form button[type=submit]').disabled=!changed;
}
function appendRule(rule={id:'',scope:'internet',from:'',to:''},update=true){
  const row=document.createElement('div');
  row.className='rule-row';
  for(const [name,key] of [['id','Rule ID'],['scope','trafficType'],['from','validFrom'],['to','validTo']]){
    const label=document.createElement('label'),caption=document.createElement('span');
    caption.dataset.i18n=key;caption.textContent=t(key);
    const field=document.createElement(name==='scope'?'select':'input');
    field.name=name;
    if(name==='scope'){
      for(const value of ['internet','private']){
        const option=new Option(t(value),value);option.dataset.i18n=value;field.add(option);
      }
    }else if(name==='id'){
      field.required=true;field.pattern='[0-9]{1,20}';field.inputMode='numeric';
    }else field.type='date';
    field.value=rule[name];
    label.append(caption,field);row.append(label);
  }
  const remove=document.createElement('button');
  remove.type='button';remove.className='secondary';remove.dataset.i18n='removeRule';remove.textContent=t('removeRule');
  remove.onclick=()=>{row.remove();updateRuleSave()};row.append(remove);$('#rule-rows').append(row);if(update)updateRuleSave();
}
async function openRuleEditor(){
  const seq=++ruleRequest;
  ruleEditor=null;$('#rules-fields').disabled=true;$('#rule-rows').replaceChildren();
  $('#rules-message').textContent=t('loadingRules');
  try{
    const snapshot=await api('/api/rules');
    if(seq!==ruleRequest)return;
    ruleEditor=snapshot;renderPolicySummary();
    snapshot.rules.forEach(rule=>appendRule(rule,false));updateRuleSave();
    $('#rules-fields').disabled=false;$('#rules-message').textContent='';
  }catch(e){if(seq===ruleRequest)$('#policy-summary').textContent=translateError(e.message)}
}
function initializeRuleEditor(){
  $('#rules-form').addEventListener('input',()=>{$('#rules-message').textContent='';updateRuleSave()});

  $('#rules-panel').addEventListener('toggle',()=>{if($('#rules-panel').open)openRuleEditor()});
  $('#add-rule').addEventListener('click',()=>appendRule());
  $('#rules-form').addEventListener('submit',async event=>{
    event.preventDefault();
    if(!ruleEditor||settingsBusy)return;
    const rules=editorRules();
    setSettingsBusy(true);$('#rules-fields').disabled=true;
    try{
      const result=await api('/api/rules',{method:'POST',body:JSON.stringify({cacheId:ruleEditor.cacheId,previous:ruleEditor.rules,rules})});
      ruleEditor.rules=result.rules;updateRuleSave();
      $('#rules-message').textContent=t('rulesSaved');
      void load();
    }catch(e){$('#rules-message').textContent=translateError(e.message)}
    finally{setSettingsBusy(false);$('#rules-fields').disabled=false}
  });
}

let policyActivityTimer,policyOperation=0;
function policyActivity(stage){
  clearInterval(policyActivityTimer);
  $('#policy-activity').hidden=!stage;
  const operation=++policyOperation;
  if(stage){
    $('#policy-stage').dataset.i18n=stage;
    $('#policy-stage').textContent=t(stage);
    const started=performance.now();
    $('#policy-elapsed').textContent='0 s';
    policyActivityTimer=setInterval(()=>{
      $('#policy-elapsed').textContent=fmt.format(Math.floor((performance.now()-started)/1000))+' s';
    },1000);
  }
  return operation;
}

function initializePolicyLookup(){
  $('#settings-dialog').addEventListener('close',()=>policyActivity(null));
  $('#policy-lookup').addEventListener('submit',async event=>{
    event.preventDefault();
    if(!ruleEditor||settingsBusy)return;
    const wholePolicy=event.submitter?.id==='policy-all';
    const ids=[...new Set($('#policy-ids').value.trim().split(/[\s,;]+/))];
    const message=$('#policy-message');
    $('#rules-message').textContent='';
    if(!wholePolicy&&(ids.length>10||ids.some(id=>!/^\d{1,20}$/.test(id)))){message.textContent=t('policyIds');return}
    setSettingsBusy(true);
    const fields=$('#policy-lookup fieldset');
    fields.disabled=true;$('#rules-fields').disabled=true;message.textContent='';
    const operation=policyActivity(wholePolicy?'policyFetchStage':'loadingRules');
    try{
      const result=await api(wholePolicy?'/api/access-policy':'/api/policy-lookup',{method:'POST',body:JSON.stringify({
        ids,wholePolicy,cacheId:ruleEditor.cacheId,clientId:$('#policy-client').value.trim(),clientSecret:$('#policy-secret').value.trim()
      })});
      if(wholePolicy){
        connection.hasPolicyCredentials=true;
        ruleEditor.policyCount=result.mapped;
        renderPolicySummary();
        $('#policy-credentials').open=false;
        $('#policy-client').required=$('#policy-secret').required=false;
        message.textContent=t('policyApplied',result);
        if(source==='firewall'&&(loading||!current||current.revision!==result.revision)){
          const refresh=policyActivity('policyReportStage');
          void load().then(ok=>{
            if(refresh!==policyOperation)return;
            policyActivity(null);
            if(ok===false)message.textContent+=' '+t('policyReportFailed');
          });
        }
        return;
      }
      const lines=[];
      const existing=new Set(editorRules().map(row=>row.id));
      let added=0;
      for(const rule of result.rules){
        lines.push([rule.id,rule.name,rule.error?translateError(rule.error):t(rule.scope||'unknownTraffic'),rule.structure,rule.modified].filter(Boolean).join(' · '));
        if(!rule.scope||existing.has(rule.id))continue;
        const modified=Date.parse(rule.modified && !/(Z|[+-]\d\d:\d\d)$/.test(rule.modified)?rule.modified+'Z':rule.modified);
        if(!Number.isFinite(modified))continue;
        // Day-level mappings may only start on a complete UTC day after an edit.
        const versionStart=Math.ceil(modified/86400000)*86400000;
        const from=new Date(versionStart).toISOString().slice(0,10);
        const to=new Date().toISOString().slice(0,10);
        if(from<=to){appendRule({id:rule.id,scope:rule.scope,from,to},false);added++}
      }
      if(added)$('#manual-rules').open=true;
      updateRuleSave();
      message.textContent=lines.join('\n')+'\n'+t(added?'policyReview':'policyNoDraft');
    }catch(e){message.textContent=translateError(e.message)}
    finally{
      if(operation===policyOperation)policyActivity(null);
      $('#policy-client').value=$('#policy-secret').value='';
      fields.disabled=false;$('#rules-fields').disabled=false;setSettingsBusy(false);
    }
  });
}
