'use strict';
let transferState=null;
const TRANSFER_FIELDS={timestamp:'Timestamp',direction:'Direction',protocol:'Protocol',sourceip:'Source IP',sourceport:'Source Port',destinationip:'Destination IP',destinationport:'Destination Port',fqdns:'FQDNs',hostname:'Hostname',servername:'Server Name',action:'Action',ruleid:'Rule ID',rulesetid:'Ruleset ID',firstpackettimestamp:'First Packet Timestamp',lastpackettimestamp:'Last Packet Timestamp',packetssent:'Packets Sent',packetsreceived:'Packets Received',bytessent:'Bytes Sent',bytesreceived:'Bytes Received',destinationcountry:'Destination Country',sourcecountry:'Source Country',awsregion:'AWS Region',datacenter:'Data Center',appid:'App ID',applicationids:'Application IDs',applicationentityname:'Application Entity Name',privateappgroupid:'Private App Group ID',privateflow:'Private Flow',trafficsource:'Traffic Source',internalclientip:'Internal Client IP',externalclientip:'External Client IP',requestmethod:'Request Method',url:'URL',statuscode:'Status Code',contenttype:'Content Type',requestsize:'Request Size',responsesize:'Response Size',responsebodysize:'Response Body Size',identities:'Identities',policyidentitylabel:'Policy Identity Label',identitytypes:'Identity Types',identitytype:'Identity Type',fwblockreason:'FW Block Reason',forwardingmethod:'Forwarding Method',egressip:'Egress IP',egress:'Egress'};

function setConnectionForm(form,values){
  for(const key of ['scope',...connectionFields])form.elements[key].value=values[key]||(key==='scope'?'all':'');
  const proxy=(values.source||source)==='proxy';
  const protocol=form.elements.protocol;
  const label=protocol.parentElement.querySelector('span');
  label.dataset.i18n=proxy?'httpMethod':'networkProtocol';
  label.textContent=t(label.dataset.i18n);
  protocol.setAttribute('list',proxy?'http-methods':'network-protocols');
  protocol.placeholder=proxy?'GET, POST, CONNECT…':'TCP, UDP, ICMP…';
  form.elements.action.setAttribute('list',proxy?'proxy-actions':'firewall-actions');
  form.elements.action.placeholder=proxy?'ALLOWED':'ALLOW';
  for(const [field,hidden] of [[form.elements.scope,proxy],[form.elements.destinationport,proxy&&!values.destinationport]]){
    field.disabled=hidden;
    field.parentElement.hidden=hidden;
  }
}
function initializeConnectionFilters(){
  const top=$('#top-connection-filters');
  const detail=top.cloneNode(true);
  detail.id='transfer-connection-filters';
  $('#connection-filter-slot').append(detail);
  for(const form of [top,detail]){
    form.querySelector('[data-clear]').onclick=()=>{setConnectionForm(form,{});form.requestSubmit()};
    form.onsubmit=event=>{
      event.preventDefault();
      const filters=cleanConnectionFilters(Object.fromEntries([...new FormData(form)].map(([k,v])=>[k,v.trim()])));
      const scope=form.elements.scope.value;
      if(form===top){
        activeConnectionFilters=filters;
        $('#scope').value=scope;
        load();
      }else if(transferState){
        for(const key of connectionFields)transferState.query.delete(key);
        for(const [key,value] of Object.entries(filters))transferState.query.set(key,value);
        transferState.query.set('scope',scope);
        transferState.top=null;
        transferState.summaryJob=null;
        transferState.summaryError='';
        transferState.page=1;
        transferState.data=null;
        fetchTransfers();
      }
    };
  }
}

function closeTransfers(){if($('#transfers-dialog').open)$('#transfers-dialog').close();transferState=null}
function openTransfers(ip){
  if(!current||loading)return;
  const query=new URLSearchParams(current.query);query.set('ip',ip);query.set('revision',current.revision||'0');
  const top=current.top.find(row=>row.label===(ip||'Neznámá IP'));
  transferState={query,ip,top,page:1,sort:'time',direction:'desc',destinationView:query.get('source')==='proxy'?'server':'ip',detailsRevision:null,sortStale:false,data:null,busy:false,failure:'',sequence:0,expanded:new Set(),details:new Map()};
  setConnectionForm($('#transfer-connection-filters'),Object.fromEntries(query));
  $('#transfers-dialog').showModal();fetchTransfers();
}
async function fetchTransfers(){
  const state=transferState;if(!state)return;
  const sequence=++state.sequence;state.busy=true;state.failure='';state.sortStale=false;state.expanded.clear();state.details.clear();renderTransfers();
  const query=new URLSearchParams(state.query);query.set('page',state.page);query.set('sort',state.sort);query.set('direction',state.direction);query.set('destinationView',state.destinationView);if(state.page>1&&state.detailsRevision!==null)query.set('detailsRevision',state.detailsRevision);
  query.set('part',state.top?'items':'preview');
  try{
    const data=await api('/api/transfers?'+query);
    if(transferState!==state||sequence!==state.sequence)return;
    if(!data.totals&&state.top){
      data.totals=state.top;
      data.pages=Math.max(1,Math.ceil(state.top.records/data.pageSize));
    }
    state.data=data;
    state.detailsRevision=data.detailsRevision;
    if(data.totals)state.top=data.totals;
    else if(!state.summaryJob){
      query.set('part','summary');
      query.set('detailsRevision',data.detailsRevision);
      const job=api('/api/transfers?'+query);
      state.summaryJob=job;
      job.then(summary=>{
        if(transferState!==state||state.summaryJob!==job)return;
        state.top=summary.totals;
        if(state.data)Object.assign(state.data,summary);
        renderTransfers();
      }).catch(e=>{
        if(transferState!==state||state.summaryJob!==job)return;
        state.summaryJob=null;state.summaryError=e.message;renderTransfers();
      });
    }
  }
  catch(e){if(transferState!==state||sequence!==state.sequence)return;state.data=null;state.failure=e.message}
  finally{if(transferState===state&&sequence===state.sequence){state.busy=false;renderTransfers()}}
}
function transferBytes(value){return value===null?t('transferMissingValue'):bytes(value)}
function transferTotal(item){return item.sent===null&&item.received===null?t('transferMissingValue'):bytes((item.sent||0)+(item.received||0))+(item.sent===null||item.received===null?' *':'')}
function transferProtocol(value){return ({'6':'TCP (6)','17':'UDP (17)','1':'ICMP (1)','58':'ICMPv6 (58)'})[value]||value||'—'}
function transferTime(ts){return displayTimestamp(ts*1000)}
function transferFieldValue(key,value){
  if(['timestamp','firstpackettimestamp','lastpackettimestamp'].includes(key)){
    const raw=String(value).trim().replace(' ','T'),date=new Date(/(?:Z|[+-]\d\d:?\d\d)$/.test(raw)?raw:raw+'Z');
    if(Number.isFinite(+date))return displayTimestamp(date);
  }return value;
}
function transferDestination(item,view){
  const missing=item.available?t('transferMissingValue'):t('transferNotLoaded');
  const ip=item.destination?(item.destination.includes(':')?'['+item.destination+']':item.destination)+(item.port?':'+item.port:''):'';
  if(view==='server')return item.servername||item.fqdns||ip||missing;
  const address=ip||item.hostname||missing;
  return address+(ip&&item.hostname?'\n'+item.hostname:'');
}
function transferDL(entries){
  const list=document.createElement('dl');list.className='transfer-fields';
  for(const [label,value] of entries){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=String(value);list.append(dt,dd)}return list;
}
async function toggleTransfer(item){
  const state=transferState;if(!state)return;
  if(state.expanded.has(item.id)){state.expanded.delete(item.id);renderTransfers();return}
  state.expanded.add(item.id);renderTransfers();
  if(state.details.has(item.id))return;
  state.details.set(item.id,{busy:true});
  const query=new URLSearchParams(state.query);query.set('event',item.id);query.set('eventRevision',item.eventRevision);query.set('hydrate','1');
  try{const detail=await api('/api/transfers?'+query);if(transferState!==state)return;state.details.set(item.id,{data:detail});if(['destination','protocol','action'].includes(state.sort)&&detail.detailsRevision!==state.detailsRevision)state.sortStale=true;if(detail.available){const f=detail.fields;item.available=true;item.url=f.url||'';item.servername=f.servername||'';item.fqdns=f.fqdns||'';item.destination=f.destinationip||'';item.port=f.destinationport||'';item.hostname=(f.hostname||f.servername||f.fqdns||'').slice(0,500);item.protocol=f.protocol||f.requestmethod||'';item.action=f.action||''}}
  catch(e){if(transferState!==state)return;state.details.set(item.id,{failure:e.message});if(['transfersChanged','transferUnavailable'].includes(e.message))state.failure=e.message}
  if(transferState===state)renderTransfers();
}
function renderTransfers(){
  const state=transferState;if(!state)return;
  const q=state.query, data=state.data;
  $('#transfers-title').textContent=t('transferTitle',{ip:state.ip||t('unknownIP')});
  $('#transfers-context').textContent=t(q.get('source')==='proxy'?'proxy':'firewall')+' · '+transferTime(new Date(q.get('from')).getTime()/1000)+' - '+transferTime(new Date(q.get('to')).getTime()/1000)+' · '+timeZone+'\n'+t('trafficType')+': '+t(({all:'allTraffic',internet:'internet',private:'private',unknown:'unknownTraffic'})[q.get('scope')])+(q.get('subnet')?' · '+t('csvIP')+': '+q.get('subnet'):'')+(q.get('identity')?' · '+t('identity')+': '+q.get('identity'):'');
  $('#transfers-destination-view').value=state.destinationView;$('#transfers-destination-view').disabled=state.busy;
  const destinationLabel=document.querySelector('[data-transfer-sort="destination"] [data-i18n]');
  destinationLabel.dataset.i18n=state.destinationView==='server'?'transferDestinationServer':'transferDestination';destinationLabel.textContent=t(destinationLabel.dataset.i18n);
  for(const button of document.querySelectorAll('[data-transfer-sort]')){
    const active=button.dataset.transferSort===state.sort, next=active?(state.direction==='asc'?'desc':'asc'):defaultTransferDirection(button.dataset.transferSort);
    button.disabled=state.busy;button.classList.toggle('active',active);button.closest('th').setAttribute('aria-sort',active?(state.direction==='asc'?'ascending':'descending'):'none');
    button.querySelector('.sort-indicator').textContent=active?(state.direction==='asc'?'↑':'↓'):'↕';
    button.setAttribute('aria-label',t('transferSortBy',{column:button.querySelector('[data-i18n]').textContent,direction:t(next==='asc'?'transferAscending':'transferDescending')}));
  }
  $('#transfers-sort-note').hidden=!state.sortStale;$('#transfers-refresh-sort').hidden=!state.sortStale&&state.failure!=='transferSortChanged';
  $('#transfers-refresh-sort').disabled=state.busy;
  $('#transfers-status').textContent=state.busy?t('transferLoading'):state.failure?translateError(state.failure):data&&!data.totals?(state.summaryError?translateError(state.summaryError):t('transferCounting')):data?t('transferSummary',{n:fmt.format(data.totals.records),received:bytes(data.totals.received),sent:bytes(data.totals.sent)}):'';
  $('#transfers-status').classList.toggle('failure',Boolean(state.failure));
  $('#transfers-legacy').hidden=!data||(data.totals?.detailed==null?data.items.every(item=>item.available):data.totals?.detailed===data.totals.records);
  $('#transfers-missing').hidden=!data||!(data.totals?.missing??data.items.some(item=>item.sent===null||item.received===null));
  $('#transfers-refresh').hidden=state.failure!=='transfersChanged'&&state.failure!=='transferUnavailable';
  $('#transfers-previous').disabled=state.busy||state.sortStale||!data||state.page<=1;$('#transfers-next').disabled=state.busy||state.sortStale||!data||(data.pages!=null?state.page>=data.pages:!data.hasNext);
  $('#transfers-page').textContent=data?t(data.pages!=null?'transferPage':'transferPageOnly',{page:state.page,pages:data.pages}):'';
  const focused=document.activeElement?.dataset.transferId, scroll=$('#transfers-dialog').scrollTop;
  const tbody=$('#transfers-rows');tbody.replaceChildren();
  if(state.busy||!data)return;
  if(!data.items.length){const row=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=8;cell.textContent=t('emptyTable');row.append(cell);tbody.append(row)}
  for(const item of data.items){
    const tr=document.createElement('tr');tr.className='transfer-row';
    const first=document.createElement('td'),button=document.createElement('button');button.className='transfer-link';button.type='button';button.dataset.transferId=item.id;button.textContent=(state.expanded.has(item.id)?'▾ ':'▸ ')+transferTime(item.ts);button.setAttribute('aria-expanded',String(state.expanded.has(item.id)));if(state.expanded.has(item.id))button.setAttribute('aria-controls','transfer-detail-'+item.id);button.setAttribute('aria-label',t('transferExpand',{time:transferTime(item.ts)}));button.addEventListener('click',()=>toggleTransfer(item));first.append(button);tr.append(first);
    const scope=['internet','private'].includes(item.scope)?item.scope:'unknown';
    const badge=document.createElement('span');
    badge.className='traffic-badge traffic-'+scope;
    badge.textContent=scope==='private'?'Private':scope==='internet'?'Internet':t('unknownTraffic');
    tr.insertCell().append(badge);
    for(const value of [transferDestination(item,state.destinationView),transferProtocol(item.protocol),item.action||'—',transferBytes(item.received),transferBytes(item.sent),transferTotal(item)]){const td=document.createElement('td');td.textContent=value;tr.append(td)}
    tr.addEventListener('click',e=>{if(!e.target.closest('button'))toggleTransfer(item)});tbody.append(tr);
    if(!state.expanded.has(item.id))continue;
    const detailRow=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=8;cell.className='transfer-detail';cell.id='transfer-detail-'+item.id;
    cell.append(transferDL([[t('sourceIP'),item.ip||t('unknownIP')],[t('identity'),item.identities.join(', ')||t('transferMissingValue')],[t('transferUTC'),displayTimestamp(item.ts*1000)],[t('csvReceived'),item.received===null?t('transferMissingValue'):item.received],[t('csvSent'),item.sent===null?t('transferMissingValue'):item.sent]]));
    const detail=state.details.get(item.id),message=document.createElement('p');message.className='transfer-note';
    if(!detail||detail.busy)message.textContent=t('transferLoading');
    else if(detail.failure){message.textContent=translateError(detail.failure);const retry=document.createElement('button');retry.type='button';retry.className='secondary';retry.textContent=t('transferRetry');retry.addEventListener('click',()=>{state.details.delete(item.id);state.expanded.delete(item.id);toggleTransfer(item)});cell.append(retry)}
    else if(!detail.data.available)message.textContent=t('transferLegacy');
    else{message.textContent=t('transferRawFields');cell.append(transferDL(Object.entries(detail.data.fields).map(([key,value])=>[TRANSFER_FIELDS[key]||key,transferFieldValue(key,value)])));if(detail.data.truncated.length){const warning=document.createElement('p');warning.textContent=t('transferTruncated',{fields:detail.data.truncated.map(k=>TRANSFER_FIELDS[k]||k).join(', ')});warning.className='transfer-note';cell.append(warning)}}
    cell.prepend(message);detailRow.append(cell);tbody.append(detailRow);
  }
  if(focused)tbody.querySelector('[data-transfer-id="'+focused+'"]')?.focus({preventScroll:true});
  $('#transfers-dialog').scrollTop=scroll;
}

function defaultTransferDirection(key){return ['time','received','sent','total'].includes(key)?'desc':'asc'}
function changeTransferSort(key){
  const state=transferState;if(!state||state.busy)return;
  state.direction=state.sort===key?(state.direction==='asc'?'desc':'asc'):defaultTransferDirection(key);
  state.sort=key;state.page=1;fetchTransfers();
}
function initializeTransfers(){
$('#transfers-close').addEventListener('click',closeTransfers);
$('#transfers-dialog').addEventListener('close',()=>{transferState=null});
$('#transfers-destination-view').addEventListener('change',()=>{const state=transferState;if(!state||state.busy)return;state.destinationView=$('#transfers-destination-view').value;state.page=1;fetchTransfers()});
for(const button of document.querySelectorAll('[data-transfer-sort]'))button.addEventListener('click',()=>changeTransferSort(button.dataset.transferSort));
$('#transfers-refresh-sort').addEventListener('click',()=>{if(transferState){transferState.page=1;fetchTransfers()}});
$('#transfers-previous').addEventListener('click',()=>{if(transferState){transferState.page--;fetchTransfers()}});
$('#transfers-next').addEventListener('click',()=>{if(transferState){transferState.page++;fetchTransfers()}});
$('#transfers-refresh').addEventListener('click',()=>{closeTransfers();load()});

}
