'use strict';
const $=s=>document.querySelector(s);
let source='firewall', current=null, loading=false, wasRunning=false, requestNo=0;
let activeError='',lastStatus=null;
let topSort='total',topDirection='desc';
let historyPreview=null, activityStarted=performance.now(), activityTimer;
function setActivity(key){
  const box=$('#load-activity');
  clearInterval(activityTimer);
  if(!key){box.hidden=true;return}
  if(box.hidden||key==='loadSettingsStage')activityStarted=performance.now();
  box.hidden=false;
  $('#load-stage').dataset.i18n=key;
  $('#load-stage').textContent=t(key);
  function tick(){
    const seconds=Math.floor((performance.now()-activityStarted)/1000);
    $('#load-elapsed').textContent=seconds>=1?fmt.format(seconds)+' s':'';
  }
  tick();
  activityTimer=setInterval(tick,1000);
}

function updatePresetHistory(bounds){
  const end=Math.floor(Date.now()/60000)*60;
  for(const button of document.querySelectorAll('[data-hours]')){
    const span=button.querySelector('.preset-span');
    span.hidden=!bounds;
    if(!bounds)continue;
    const duration=Number(button.dataset.hours)*3600;
    const overlap=bounds.from==null?0:Math.max(0,Math.min(end,bounds.to)-Math.max(end-duration,bounds.from));
    const percent=100*overlap/duration;
    span.querySelector('meter').value=percent;
    span.querySelector('small').textContent=(percent>0&&percent<1?'<1':percent>99&&percent<100?'>99':fmt.format(Math.round(percent)))+' %';
  }
  $('#preset-hint').hidden=!bounds;
}

function updateExportButtons(){document.querySelectorAll('[data-report-format]').forEach(button=>button.disabled=!current||loading)}
function rate(n){return n>=1e6?fmt.format(n/1e6)+' Mb/s':n>=1000?fmt.format(n/1000)+' kb/s':fmt.format(n)+' b/s'}
function bytes(n){if(!n)return '0 B';const units=['B','kB','MB','GB','TB'];const i=Math.min(4,Math.floor(Math.log(n)/Math.log(1000)));return fmt.format(n/1000**i)+' '+units[i]}
function localValue(date){return wallValue(date)}
function updateDateBounds(){const now=new Date();now.setSeconds(0,0);const earliest=new Date(now-30*86400000);for(const field of [$('#from'),$('#to')]){field.min=localValue(earliest);field.max=localValue(now)}}
function preset(hours){updateDateBounds();const end=new Date();end.setSeconds(0,0);$('#to').value=localValue(end);$('#from').value=localValue(new Date(end-hours*3600000));refreshIntervalFields();document.querySelectorAll('[data-hours]').forEach(b=>b.classList.toggle('selected',+b.dataset.hours===hours))}
async function api(url,options){const response=await fetch(url,{...options,headers:{...(options?.body?{'Content-Type':'application/json'}:{}),...(options?.method&&options.method!=='GET'?{'X-CSRF-Token':connection.csrfToken||''}:{}),...options?.headers}});const data=await response.json();if(!response.ok)throw Error(data.error||'requestFailed');return data}
function error(message){activeError=message;const rendered=message&&typeof message==='object'?t(message.key,{...message.vars,error:translateError(message.vars.error)}):translateError(message||'');$('#error').textContent=rendered;$('#error').hidden=!rendered}
function params(){const from=zonedDate($('#from').value),to=zonedDate($('#to').value);if(!(to>from)||to-from>30*86400000)throw Error('rangeError');const now=new Date();now.setSeconds(0,0);if(from<new Date(now-30*86400000)||to>new Date())throw Error('windowError');const mode=$('#mode').value;if(mode==='subnet'&&!$('#subnet').value.trim())throw Error('ipRequired');if(mode==='identity'&&!$('#identity').value)throw Error('identityRequired');return new URLSearchParams({...activeConnectionFilters,topLimit:$('#top-limit').value,source,scope:$('#scope').value,from:from.toISOString(),to:to.toISOString(),subnet:mode==='subnet'?$('#subnet').value.trim():'',identity:mode==='identity'?$('#identity').value:''})}
async function load(){
  setConnectionForm($('#top-connection-filters'),{...activeConnectionFilters,scope:$('#scope').value});
  if(!connection.configured)return;
  closeTransfers();
  const request=++requestNo;
  loading=true;
  $('#classification').hidden=true;
  updateExportButtons();
  $('.apply').disabled=true;
  if(historyPreview?.query.get('source')!==source){
    historyPreview=null;
    $('#historybox').hidden=true;
    updatePresetHistory(null);
  }
  try{
    error('');
    updateDateBounds();
    const query=params();
    if(!historyPreview){
      setActivity('loadHistoryStage');
      try{
        const coverage=await api('/api/history?source='+query.get('source'));
        if(request!==requestNo)return;
        renderHistory({coverage,query});
      }catch{/* The full report also includes authoritative bounds. */}
    }
    if(request!==requestNo)return;
    setActivity('loadReportStage');
    const reportQuery=new URLSearchParams(query);
    reportQuery.set('topLimit',$('#top-limit').options[$('#top-limit').options.length-1].value);
    const data=await api('/api/report?'+reportQuery);
    if(request!==requestNo)return;
    current={...data,query,rankedSources:data.top};
    selectTopLimit();
    render();
    return true;
  }catch(e){
    if(request===requestNo){error(e.message);return false}
  }finally{
    if(request===requestNo){
      loading=false;
      setActivity(null);
      updateExportButtons();
      $('.apply').disabled=false;
    }
  }
}
function render(){const d=current,totals=d.totals,total=totals.sent+totals.received;$('#total').textContent=bytes(total);$('#received').textContent=bytes(totals.received);$('#sent').textContent=bytes(totals.sent);$('#recordcount').textContent=t('recordCount',{n:fmt.format(totals.records)});const seconds=(new Date(d.query.get('to'))-new Date(d.query.get('from')))/1000;$('#rate').textContent=rate(total*8/seconds);$('#rxhint').textContent=source==='proxy'?'Response Size':'Bytes Received';$('#txhint').textContent=source==='proxy'?'Request Size':'Bytes Sent';
const selected=$('#identity').value;$('#identity').replaceChildren(new Option(t('chooseIdentity'),''),...[...new Set([...d.identities,...(selected?[selected]:[])])].map(x=>new Option(x,x)));$('#identity').value=selected;
let note=t('notice');if(totals.unknown)note+=' '+t('unknownNote',{n:fmt.format(totals.unknown)});if(totals.missing)note+=' '+t('missingNote',{n:fmt.format(totals.missing)});$('#notice').textContent=note;
renderClassification(d);renderHistory(d);$('#empty').hidden=totals.records!==0;$('#chartcaption').textContent=timefmt.format(new Date(d.query.get('from')))+' — '+timefmt.format(new Date(d.query.get('to')))+' · '+t('hourly');
renderTop();
$('#coverage').textContent=d.coverage.records?t('cacheRange',{from:timefmt.format(new Date(d.coverage.from*1000)),to:timefmt.format(new Date(d.coverage.to*1000)),n:fmt.format(d.coverage.records)}):t('cacheHint');updateExportButtons();draw()}
function classificationLabel(key){
  return t(({internet:'confirmedInternet',private:'confirmedPrivate',unknown:'unknownTraffic'})[key]||key);
}
function renderClassification(d){
  const section=$('#classification');
  section.hidden=!d.classification||d.query.get('source')!==source;
  if(section.hidden)return;
  const groups=d.classification;
  const {internet,private:privateAccess,mappedInternet,mappedPrivate,unknown}=groups;
  const sum=(a,b)=>({records:a.records+b.records,bytes:a.bytes+b.bytes});
  const totals={internet:sum(internet,mappedInternet),private:sum(privateAccess,mappedPrivate),unknown};
  const classified=totals.internet.records+totals.private.records;
  const total=classified+unknown.records;
  $('#classified-count').textContent=total?t('classifiedCount',{n:fmt.format(classified),total:fmt.format(total)}):t('noClassificationRecords');
  function fillTable(body,entries,label){
    body.replaceChildren();
    for(const [key,group] of Object.entries(entries)){
      const row=body.insertRow();
      for(const text of [label(key),fmt.format(group.records),bytes(group.bytes)])row.insertCell().textContent=text;
    }
  }
  fillTable($('#classification-body'),totals,key=>t(key==='unknown'?'unknownTraffic':key));
  fillTable($('#classification-detail'),groups,classificationLabel);
  $('#unknown-rules').hidden=!unknown.records;
  $('#ranking-activity').hidden=!d.ruleRankingBusy;
  $('#unknown-rules').disabled=Boolean(d.ruleRankingBusy)||!d.classification.unknown.records;
  $('#open-policy-lookup').hidden=!d.ruleRanking?.some(row=>row.id);
  $('#rule-ranking').textContent=d.ruleRankingBusy?t('rankingLocalRules'):d.ruleRankingError?translateError(d.ruleRankingError):
    (d.ruleRanking||[]).map(r=>(r.id?'Rule ID '+r.id:t('missingRule'))+' · '+fmt.format(r.records)+' × · '+bytes(r.bytes)).join('\n');
}
$('#open-policy-lookup').addEventListener('click',()=>{
  showSettings();
  $('#rules-panel').open=true;
  $('#policy-selected').open=true;
  $('#policy-ids').focus();
});
$('#unknown-rules').addEventListener('click',async()=>{
  const report=current;
  if(!report?.classification||report.ruleRankingBusy)return;
  report.ruleRankingBusy=true;report.ruleRankingError='';
  renderClassification(report);
  const started=performance.now();
  function showElapsed(){
    if(current===report)$('#ranking-elapsed').textContent=fmt.format(Math.floor((performance.now()-started)/1000))+' s';
  }
  showElapsed();
  const timer=setInterval(showElapsed,1000);
  try{
    const query=new URLSearchParams(report.query);
    query.set('revision',report.revision);
    report.ruleRanking=await api('/api/unknown-rules?'+query);
  }catch(e){report.ruleRankingError=e.message}
  finally{
    clearInterval(timer);
    report.ruleRankingBusy=false;
    if(current===report&&!loading)renderClassification(report);
  }
});
function selectTopLimit(){
  const limit=$('#top-limit').value;
  current.top=current.rankedSources.slice(0,Number(limit));
  current.query.set('topLimit',limit);
}
$('#top-limit').addEventListener('change',()=>{
  if(!current)return;
  selectTopLimit();
  renderTop();
});
function renderTop(){
const d=current,total=d.totals.sent+d.totals.received;
$('#top-count').textContent=d.sourceCount==null?t('topRestart'):t(d.top.length===d.sourceCount?'topAllShown':'topCount',{shown:fmt.format(d.top.length),total:fmt.format(d.sourceCount)});
for(const button of document.querySelectorAll('[data-top-sort]')){
  const active=button.dataset.topSort===topSort,next=active?(topDirection==='asc'?'desc':'asc'):(button.dataset.topSort==='ip'?'asc':'desc');
  button.classList.toggle('active',active);button.closest('th').setAttribute('aria-sort',active?(topDirection==='asc'?'ascending':'descending'):'none');
  button.querySelector('.sort-indicator').textContent=active?(topDirection==='asc'?'↑':'↓'):'↕';
  button.setAttribute('aria-label',t('transferSortBy',{column:button.querySelector('[data-i18n]').textContent,direction:t(next==='asc'?'transferAscending':'transferDescending')}));
}
const tbody=$('#top');tbody.replaceChildren();for(const item of sortedTop(d.top,topSort,topDirection)){const tr=document.createElement('tr');const sum=item.sent+item.received;for(let i=0;i<5;i++){const td=document.createElement('td');if(i===0){const link=document.createElement('button');link.type='button';link.className='transfer-link';link.textContent=(item.label==='Neznámá IP'?t('unknownIP'):item.label)+' ›';link.setAttribute('aria-label',t('transferOpen',{ip:item.label==='Neznámá IP'?t('unknownIP'):item.label}));link.addEventListener('click',()=>openTransfers(item.label==='Neznámá IP'?'':item.label));td.append(link);tr.className='top-source-row';tr.addEventListener('click',event=>{if(!event.target.closest('button'))link.click()})}else if(i===1){const bar=document.createElement('span');bar.className='share';bar.title=fmt.format(total?sum/total*100:0)+' %';const fill=document.createElement('span');fill.style.width=(total?sum/total*100:0)+'%';bar.append(fill);td.append(bar)}else td.textContent=bytes(i===2?item.received:i===3?item.sent:sum);tr.append(td)}tbody.append(tr)}if(!d.top.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.textContent=t('emptyTable');tr.append(td);tbody.append(tr)}
}
function sourceAddressParts(label){
  if(!label||label==='Neznámá IP')return null;
  if(!label.includes(':'))return [4,...label.split('.').map(Number)];
  let address=label;
  if(address.includes('.')){const index=address.lastIndexOf(':'),v=address.slice(index+1).split('.').map(Number);address=address.slice(0,index+1)+((v[0]<<8)|v[1]).toString(16)+':'+((v[2]<<8)|v[3]).toString(16)}
  const sides=address.split('::'),left=sides[0]?sides[0].split(':'):[],right=sides[1]?sides[1].split(':'):[];
  return [6,...(sides.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left).map(x=>parseInt(x,16))];
}
function compareSourceAddresses(a,b){
  const left=sourceAddressParts(a),right=sourceAddressParts(b);
  if(!left||!right)return left?-1:right?1:0;
  for(let i=0;i<left.length;i++){const diff=left[i]-right[i];if(diff)return diff}
  return 0;
}
function sortedTop(items,key,direction){
  const sign=direction==='asc'?1:-1;
  return [...items].sort((a,b)=>{
    if(key==='ip'){
      if(!sourceAddressParts(a.label)||!sourceAddressParts(b.label))return compareSourceAddresses(a.label,b.label);
      return sign*compareSourceAddresses(a.label,b.label);
    }
    const value=item=>key==='sent'?item.sent:key==='received'?item.received:item.sent+item.received;
    return sign*(value(a)-value(b))||compareSourceAddresses(a.label,b.label);
  });
}
for(const button of document.querySelectorAll('[data-top-sort]'))button.addEventListener('click',()=>{
  const key=button.dataset.topSort;
  topDirection=topSort===key?(topDirection==='asc'?'desc':'asc'):(key==='ip'?'asc':'desc');topSort=key;
  if(current)renderTop();
});
function renderHistory(d){if(d.query.get('source')!==source)return;
historyPreview={coverage:d.coverage,query:d.query};$('#historybox').hidden=false;updatePresetHistory(d.coverage);
const c=d.coverage,box=$('#historybox');if(c.from==null){box.classList.add('partial');$('#historyinfo').textContent=t('noHistory');$('#historydetail').textContent=t('noHistoryHint');return}const partial=new Date(d.query.get('from')).getTime()<c.from*1000;box.classList.toggle('partial',partial);$('#historyinfo').textContent=t('historyRange',{from:rangefmt.format(new Date(c.from*1000)),to:rangefmt.format(new Date(c.to*1000))});$('#historydetail').textContent=t(partial?'partialHistory':'fullHistory')}
function draw(){const canvas=$('#chart'),rect=canvas.getBoundingClientRect(),scale=devicePixelRatio||1;canvas.width=rect.width*scale;canvas.height=rect.height*scale;const ctx=canvas.getContext('2d');ctx.scale(scale,scale);const w=rect.width,h=rect.height,p={left:63,right:12,top:18,bottom:35};const rows=current?.series||[];const max=Math.max(1,...rows.map(x=>x.sent+x.received))*1.15;ctx.font='10px -apple-system, sans-serif';ctx.fillStyle='#95a9bf';ctx.strokeStyle='#27354a';ctx.lineWidth=1;for(let i=0;i<=4;i++){const y=p.top+(h-p.top-p.bottom)*i/4;ctx.beginPath();ctx.moveTo(p.left,y);ctx.lineTo(w-p.right,y);ctx.stroke();ctx.textAlign='right';ctx.fillText(bytes(max*(1-i/4)),p.left-9,y+3)}const dx=(w-p.left-p.right)/Math.max(rows.length,1);for(let i=0;i<rows.length;i++){const x=p.left+i*dx+dx*.12,bw=Math.max(1,dx*.76),base=h-p.bottom,ry=rows[i].received/max*(h-p.top-p.bottom),sy=rows[i].sent/max*(h-p.top-p.bottom);ctx.fillStyle='#36cdb0';ctx.fillRect(x,base-ry,bw,ry);ctx.fillStyle='#9a88ef';ctx.fillRect(x,base-ry-sy,bw,sy);if(i%Math.max(1,Math.ceil(rows.length/(w<500?3:7)))===0){ctx.fillStyle='#95a9bf';ctx.textAlign='center';ctx.fillText(timefmt.format(new Date(rows[i].ts*1000)),x+bw/2,h-10)}}canvas._geometry={p,dx,rows,w,h};canvas.setAttribute('aria-label',current?t('chartSummary',{received:bytes(current.totals.received),sent:bytes(current.totals.sent)}):t('chartAria'))}
$('#chart').addEventListener('mousemove',e=>{const canvas=$('#chart'),g=canvas._geometry,tip=$('#tooltip');if(!g?.rows.length)return;const r=canvas.getBoundingClientRect(),x=e.clientX-r.left,i=Math.floor((x-g.p.left)/g.dx);if(i<0||i>=g.rows.length){tip.hidden=true;return}const row=g.rows[i];tip.textContent=timefmt.format(new Date(row.ts*1000))+'\n'+t('received')+': '+bytes(row.received)+'\n'+t('sent')+': '+bytes(row.sent);tip.hidden=false;tip.style.left=Math.max(0,Math.min(x+10,g.w-195))+'px';tip.style.top='10px'});$('#chart').addEventListener('mouseleave',()=>$('#tooltip').hidden=true);window.addEventListener('resize',draw);
$('#filters').addEventListener('submit',e=>{e.preventDefault();load()});$('#mode').addEventListener('change',()=>{$('#subnetfield').hidden=$('#mode').value!=='subnet';$('#identityfield').hidden=$('#mode').value!=='identity'});document.querySelectorAll('[data-hours]').forEach(b=>b.addEventListener('click',()=>{preset(+b.dataset.hours);load()}));document.querySelectorAll('[data-source]').forEach(b=>b.addEventListener('click',()=>{source=b.dataset.source;activeConnectionFilters={};document.querySelectorAll('[data-source]').forEach(t=>t.classList.toggle('active',t===b));$('#sourcedesc').textContent=t(source==='proxy'?'sourceProxy':'sourceFirewall');$('#scope').value='all';$('#scope').disabled=source==='proxy';if($('#mode').value==='identity'){$('#mode').value='all';$('#identityfield').hidden=true;}$('#identity').value='';load()}));
$('#sync').addEventListener('click',async()=>{try{error('');await api('/api/sync',{method:'POST'});wasRunning=true;await status()}catch(e){error(e.message)}});
function renderStatus(s){
  if(!s)return;
  if(s.unavailable){$('#syncstatus').textContent=t('serverUnavailable');return}
  $('#sync').disabled=s.running||!connection.configured;$('#sync').textContent=t(s.running?'loadingLogs':'loadLogs');
  let text=!connection.configured?t('setupRequired'):s.error?t('importIncomplete'):s.lastSync?t('lastSync',{time:timefmt.format(new Date(s.lastSync))}):t('ready');
  if(s.running){
    if(s.phase==='policy')text=t('loadingPolicy');
    else if(s.phase==='listing')text=t('syncListing',{done:fmt.format(s.directoriesDone||0),total:fmt.format(s.directoriesTotal||62),n:fmt.format(s.listed||0)});
    else if(s.phase==='cleanup')text=t('syncCleaning');
    else if(s.phase==='downloading')text=t('syncDownloading',{done:fmt.format(s.processed||0),total:fmt.format(s.total||0),skipped:fmt.format(s.skipped||0)});
    else text=s.total?t('syncProgress',{done:fmt.format(s.processed),total:fmt.format(s.total)}):t('findingLogs');
  }else if(s.phase==='complete')text+=' · '+t('syncResult',{downloaded:fmt.format(s.downloaded||0),skipped:fmt.format(s.skipped||0),seconds:fmt.format(s.durationSeconds||0)});
  if(s.policyError)text+=' · '+t('policySyncError')+' '+translateError(s.policyError);
  $('#syncstatus').textContent=text;
}
async function status(){try{const s=await api('/api/status');lastStatus=s;renderStatus(s);if(wasRunning&&!s.running){wasRunning=false;await load()}if(s.error)error({key:'importError',vars:{error:s.error}});if(s.running)wasRunning=true}catch(e){lastStatus={unavailable:true};renderStatus(lastStatus)}}
document.querySelectorAll('[data-report-format]').forEach(button=>button.addEventListener('click',()=>downloadReport(button.dataset.reportFormat)));
for(const field of [$('#from'),$('#to')])field.addEventListener('input',()=>document.querySelectorAll('[data-hours]').forEach(b=>b.classList.remove('selected')));
function applyLanguage(next,persist=true){
  language=next==='en'?'en':'cs';updateFormatters();document.documentElement.lang=language;document.title=t('title');
  document.querySelectorAll('[data-i18n]').forEach(node=>node.textContent=t(node.dataset.i18n));
  document.querySelectorAll('[data-i18n-aria]').forEach(node=>node.setAttribute('aria-label',t(node.dataset.i18nAria)));
  document.querySelectorAll('[data-lang]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.lang===language)));
  $('#sourcedesc').textContent=t(source==='proxy'?'sourceProxy':'sourceFirewall');$('#tooltip').hidden=true;
  const preview=historyPreview;
  if(current&&current.query.get('source')===source)render();
  if(preview)renderHistory(preview);
  renderStatus(lastStatus);error(activeError);localizeSettings();renderTransfers();renderSavedFilters();localizeTimeZone();
  if(persist){try{localStorage.setItem('csa-language',language)}catch(_){}}
}
for(const button of document.querySelectorAll('[data-lang]'))button.addEventListener('click',()=>applyLanguage(button.dataset.lang));
window.addEventListener('storage',event=>{if(event.key==='csa-language')applyLanguage(event.newValue,false)});
initializeConnectionFilters();initializeTransfers();initializeTimeZone();initializeSavedFilters();applyLanguage(language,false);preset(24);initializeConnection();setInterval(status,2500);
