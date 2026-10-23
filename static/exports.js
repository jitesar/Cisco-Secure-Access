'use strict';
// Export the rendered snapshot. Never read connection settings or unsaved filters.
function reportDocument(snapshot, translate, generated=new Date()) {
  const q=snapshot.query, totals=snapshot.totals;
  const zone=snapshot.timeZone||timeZone,stamp=value=>displayTimestamp(value,zone);
  const total=totals.received+totals.sent;
  const seconds=(new Date(q.get('to'))-new Date(q.get('from')))/1000;
  const rows=[
    ['CSA Traffic',translate('reportTitle')],
    [translate('timeZoneLabel'),zone],
    [translate('reportGenerated'),stamp(generated)],
    [translate('csvSource'),translate(q.get('source')==='proxy'?'proxy':'firewall')],
    [translate('csvIP'),q.get('subnet')||translate('allSources')],
    [translate('csvIdentity'),q.get('identity')||translate('allSources')],
    [translate('csvScope'),translate(({all:'allTraffic',internet:'internet',private:'private',unknown:'unknownTraffic'})[q.get('scope')])],
    [translate('csvFrom'),stamp(q.get('from'))],
    [translate('csvTo'),stamp(q.get('to'))],
    [translate('reportSynced'),snapshot.lastSync?stamp(snapshot.lastSync):translate('reportNotSynced')],
    [translate('reportCoverage'),snapshot.coverage.records ? stamp(snapshot.coverage.from*1000)+' - '+stamp(snapshot.coverage.to*1000) : translate('noHistory')],
    [],[translate('summary')],
    [translate('csvReceived'),totals.received],
    [translate('csvSent'),totals.sent],
    [translate('reportTotalBytes'),total],
    [translate('reportRecords'),totals.records],
    [translate('reportRate'),total*8/seconds],
    [translate('reportMissing'),totals.missing],
    [translate('reportUnknown'),totals.unknown],
    [],[translate('reportNotes')],
    [translate('notice')], [translate('chartNote')],
    [translate('reportTimeNote',{zone})],
    [translate('reportSessionNote')],
    [translate('reportPrecision')],
  ];
  if(!snapshot.coverage.records) rows.push([translate('noHistoryHint')]);
  else rows.push([translate(new Date(q.get('from')).getTime()<snapshot.coverage.from*1000?'partialHistory':'fullHistory')]);
  if(totals.missing)rows.push([translate('missingNote',{n:totals.missing})]);
  if(totals.unknown)rows.push([translate('unknownNote',{n:totals.unknown})]);
  if(snapshot.importWarning)rows.push([snapshot.importWarning]);
  const hourly=[translate('csvHour'),translate('csvReceived'),translate('csvSent'),translate('reportTotalBytes')];
  const top=[translate('sourceIP'),translate('csvReceived'),translate('csvSent'),translate('reportTotalBytes'),translate('reportRecords')];
  const series=snapshot.series.map(x=>[stamp(x.ts*1000),x.received,x.sent,x.received+x.sent]);
  const ips=snapshot.top.map(x=>[x.label==='Neznámá IP'?translate('unknownIP'):x.label,x.received,x.sent,x.received+x.sent,x.records]);
  return {metadata:rows, hourly,top,series,seriesTimes:snapshot.series.map(x=>x.ts*1000),ips, rows:[...rows,[],[translate('chartTitle')],hourly,...series,[],[translate('topTitle')],top,...ips]};
}

function reportCSV(rows) {
  const quote=value=>{
    if(typeof value==='number')return String(value);
    // Treat externally supplied labels as text, including leading whitespace/control characters.
    let text=String(value??'');
    if(/^[\s\u0000-\u001f]*[=+@-]/u.test(text))text="'"+text;
    return '"'+text.replaceAll('"','""')+'"';
  };
  return '\ufeff'+rows.map(row=>row.map(quote).join(';')).join('\r\n')+'\r\n';
}

function exportJoin(parts) {
  const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;
  for(const p of parts){out.set(p,at);at+=p.length}return out;
}
function exportBytes(size,write){const b=new Uint8Array(size);write(new DataView(b.buffer));return b}
function exportUTF16(text){return exportBytes(text.length*2,v=>{for(let i=0;i<text.length;i++)v.setUint16(i*2,text.charCodeAt(i),true)})}

// BIFF8 workbook in a Compound File Binary container, as specified in MS-XLS/MS-CFB.
// Strings are shared text cells, never formulas. No HTML disguised as .xls.
function reportXLS(rows) {
  const record=(id,data=new Uint8Array())=>exportJoin([exportBytes(4,v=>{v.setUint16(0,id,true);v.setUint16(2,data.length,true)}),data]);
  const bof=type=>record(0x0809,exportBytes(16,v=>{v.setUint16(0,0x0600,true);v.setUint16(2,type,true);v.setUint16(4,0x0dbb,true);v.setUint16(6,1997,true);v.setUint32(8,0x41,true);v.setUint32(12,6,true)}));
  const font=bold=>record(0x0031,exportJoin([exportBytes(16,v=>{v.setUint16(0,220,true);v.setUint16(4,0x7fff,true);v.setUint16(6,bold?700:400,true);v.setUint8(14,5);v.setUint8(15,1)}),exportUTF16('Arial')]));
  const xf=(style,fontIndex=0,format=0)=>record(0x00e0,exportBytes(20,v=>{v.setUint16(0,fontIndex,true);v.setUint16(2,format,true);v.setUint16(4,style?0xfff5:1,true);v.setUint8(6,0x28);v.setUint8(9,0xfc)}));
  const strings=[],indices=new Map();let stringCells=0;
  for(const row of rows)for(const value of row)if(typeof value!=='number'){
    const text=String(value??'');if(text.length>32767)throw Error('exportTooLarge');
    stringCells++;if(!indices.has(text)){indices.set(text,strings.length);strings.push(text)}
  }
  const sst=[];let buffer=exportBytes(8,v=>{v.setUint32(0,stringCells,true);v.setUint32(4,strings.length,true)}),sstId=0x00fc;
  const flushSST=()=>{sst.push(record(sstId,buffer));buffer=new Uint8Array();sstId=0x003c};
  for(const text of strings){
    if(buffer.length+3>8224)flushSST();
    buffer=exportJoin([buffer,exportBytes(3,v=>{v.setUint16(0,text.length,true);v.setUint8(2,1)})]);
    let at=0;
    while(at<text.length){
      let count=Math.min(Math.floor((8224-buffer.length)/2),text.length-at);
      if(count&&at+count<text.length&&/[\uD800-\uDBFF]/.test(text[at+count-1]))count--;
      if(!count){flushSST();buffer=new Uint8Array([1]);continue}
      buffer=exportJoin([buffer,exportUTF16(text.slice(at,at+count))]);at+=count;
      if(at<text.length){flushSST();buffer=new Uint8Array([1])}
    }
  }
  flushSST();
  const globals=[bof(5),record(0x0042,exportBytes(2,v=>v.setUint16(0,1200,true))),
    record(0x003d,exportBytes(18,v=>{v.setUint16(4,16000,true);v.setUint16(6,10000,true);v.setUint16(8,0x38,true);v.setUint16(14,1,true);v.setUint16(16,600,true)})),font(false),font(true)];
  for(let i=0;i<15;i++)globals.push(xf(true));
  globals.push(xf(false),xf(false,1),xf(false,0,3),xf(false,0,4));
  globals.push(record(0x0293,exportBytes(4,v=>{v.setUint16(0,0x8000,true)})));
  const bound=offset=>record(0x0085,exportJoin([exportBytes(8,v=>{v.setUint32(0,offset,true);v.setUint8(6,6);v.setUint8(7,1)}),exportUTF16('Report')]));
  globals.push(...sst,bound(0),record(0x000a));
  const sheet=[bof(0x10),record(0x0200,exportBytes(14,v=>{v.setUint32(4,rows.length,true);v.setUint16(10,5,true)}))];
  for(let c=0;c<5;c++)sheet.push(record(0x007d,exportBytes(12,v=>{v.setUint16(0,c,true);v.setUint16(2,c,true);v.setUint16(4,(c===0?64:c===1?46:24)*256,true)})));
  if(rows.length>65536)throw Error('exportTooLarge');
  const merged=[];
  rows.forEach((row,r)=>{
    const widths=row.length===1?[182]:[64,46,24,24,24];
    const count=Math.max(1,...row.map((v,c)=>String(v).split('\n').reduce((n,line)=>n+Math.max(1,Math.ceil(line.length/(widths[c]-2))),0)));
    sheet.push(record(0x0208,exportBytes(16,v=>{v.setUint16(0,r,true);v.setUint16(4,Math.max(1,row.length),true);v.setUint16(6,Math.min(8190,Math.max(360,count*280)),true);v.setUint32(12,0x0040,true)})));
    if(row.length===1)merged.push(exportBytes(8,v=>{v.setUint16(0,r,true);v.setUint16(2,r,true);v.setUint16(6,4,true)}));
  });
  rows.forEach((row,r)=>row.forEach((value,c)=>{
    const numeric=typeof value==='number';
    const cell=exportBytes(6,v=>{v.setUint16(0,r,true);v.setUint16(2,c,true);v.setUint16(4,numeric?(Number.isInteger(value)?17:18):row.length===1||r===0?16:15,true)});
    if(numeric)sheet.push(record(0x0203,exportJoin([cell,exportBytes(8,v=>v.setFloat64(0,value,true))])));
    else sheet.push(record(0x00fd,exportJoin([cell,exportBytes(4,v=>v.setUint32(0,indices.get(String(value??'')),true))])));
  }));
  if(merged.length)sheet.push(record(0x00e5,exportJoin([exportBytes(2,v=>v.setUint16(0,merged.length,true)),...merged])));
  sheet.push(record(0x023e,exportBytes(18,v=>{v.setUint16(0,0x06b6,true);v.setUint16(10,64,true)})),record(0x000a));
  const offset=globals.reduce((n,p)=>n+p.length,0);globals[globals.length-2]=bound(offset);
  const workbook=exportJoin([...globals,...sheet]);
  const n=Math.ceil(Math.max(4096,workbook.length)/512);
  let fats=1;while(fats*128<n+1+fats)fats++;
  if(fats>109)throw Error('exportTooLarge');
  const FREE=0xffffffff,END=0xfffffffe,FAT=0xfffffffd;
  const header=exportBytes(512,v=>{
    [0xe011cfd0,0xe11ab1a1].forEach((x,i)=>v.setUint32(i*4,x,true));
    v.setUint16(24,0x3e,true);v.setUint16(26,3,true);v.setUint16(28,0xfffe,true);v.setUint16(30,9,true);v.setUint16(32,6,true);
    v.setUint32(44,fats,true);v.setUint32(48,n,true);v.setUint32(56,4096,true);v.setUint32(60,END,true);v.setUint32(68,END,true);
    for(let i=0;i<109;i++)v.setUint32(76+i*4,i<fats?n+1+i:FREE,true);
  });
  const directory=exportBytes(512,v=>{
    const entry=(at,name,type,start,size,child)=>{
      const text=exportUTF16(name+'\0');new Uint8Array(v.buffer).set(text,at);
      v.setUint16(at+64,text.length,true);v.setUint8(at+66,type);v.setUint8(at+67,1);
      v.setUint32(at+68,FREE,true);v.setUint32(at+72,FREE,true);v.setUint32(at+76,child,true);v.setUint32(at+116,start,true);v.setUint32(at+120,size,true);
    };
    entry(0,'Root Entry',5,END,0,1);entry(128,'Workbook',2,0,Math.max(4096,workbook.length),FREE);
  });
  const fat=exportBytes(fats*512,v=>{for(let i=0;i<fats*128;i++)v.setUint32(i*4,i<n?(i===n-1?END:i+1):i===n?END:i<n+1+fats?FAT:FREE,true)});
  return exportJoin([header,workbook,new Uint8Array(n*512-workbook.length),directory,fat]);
}

// A4 PDF with browser-rendered Unicode text and charts; no remote fonts or libraries.
// JPEG page images keep Czech glyphs identical to the UI on every PDF viewer.
function reportPDF(documentData, translate, formatTime, formatBytes) {
  const W=1240,H=1754,M=80,pages=[];let canvas,ctx,y;
  const page=()=>{canvas=document.createElement('canvas');canvas.width=W;canvas.height=H;ctx=canvas.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,W,H);ctx.fillStyle='#0a786d';ctx.font='bold 20px sans-serif';ctx.fillText('CISCO SECURE ACCESS / CSA TRAFFIC',M,55);y=110};
  const finish=()=>{ctx.fillStyle='#65758a';ctx.font='18px sans-serif';ctx.fillText('CSA Traffic',M,H-40);ctx.textAlign='right';ctx.fillText(String(pages.length+1),W-M,H-40);ctx.textAlign='left';pages.push(canvas.toDataURL('image/jpeg',0.94));};
  const space=height=>{if(y+height>H-85){finish();page()}};
  const lines=(text,width)=>{
    const result=[];
    for(const sourceLine of String(text).split('\n')){
      let line='';
      for(const word of sourceLine.split(/\s+/)){
        if(line&&ctx.measureText(line+' '+word).width>width){result.push(line);line=''}
        // Fall back to character wrapping only for a single oversized label.
        if(ctx.measureText(word).width>width){
          for(const char of word){if(ctx.measureText(line+char).width>width){result.push(line);line=''}line+=char}
        }else line+=(line?' ':'')+word;
      }result.push(line);
    }return result;
  };
  const paragraph=(text,bold=false)=>{ctx.font=(bold?'bold ':'')+'22px sans-serif';const wrapped=lines(text,W-2*M);for(const line of wrapped){space(32);ctx.font=(bold?'bold ':'')+'22px sans-serif';ctx.fillStyle=bold?'#132e47':'#31455b';ctx.fillText(line,M,y);y+=32}y+=8};
  const table=(heading,rows,widths)=>{
    const header=()=>{space(72);ctx.fillStyle='#e8f2f3';ctx.fillRect(M,y-24,W-2*M,42);ctx.font='bold 17px sans-serif';ctx.fillStyle='#173c50';let x=M+10;heading.forEach((h,i)=>{ctx.fillText(h,x,y,widths[i]-20);x+=widths[i]});y+=48};header();
    for(const row of rows){
      ctx.font='19px sans-serif';const cells=row.map((v,i)=>lines(v,widths[i]-24));const height=Math.max(...cells.map(x=>x.length))*27+18;
      if(y+height>H-85){finish();page();header()}
      let x=M+10;ctx.font='19px sans-serif';ctx.fillStyle='#263c52';cells.forEach((cell,i)=>{cell.forEach((line,j)=>ctx.fillText(line,x,y+j*27));x+=widths[i]});y+=height;
      ctx.strokeStyle='#e0e7ed';ctx.beginPath();ctx.moveTo(M,y-13);ctx.lineTo(W-M,y-13);ctx.stroke();
    }y+=25;
  };
  page();paragraph(translate('reportTitle'),true);
  const headings=new Set([translate('summary'),translate('reportNotes')]);
  const numberFormat=new Intl.NumberFormat(language==='en'?'en-GB':'cs-CZ',{maximumFractionDigits:2});
  for(const row of documentData.metadata.slice(1)){if(!row.length){y+=12;continue}const heading=headings.has(row[0]);if(heading)space(100);paragraph(row.map(v=>typeof v==='number'?numberFormat.format(v):v).join(': '),heading)}
  space(440);paragraph(translate('chartTitle'),true);
  const series=documentData.series, max=Math.max(1,...series.map(r=>r[3]));
  const left=M+110,top=y+20,bottom=top+245,right=W-M,dx=(right-left)/Math.max(1,series.length);
  ctx.font='17px sans-serif';
  for(let i=0;i<=4;i++){const yy=bottom-i*245/4;ctx.strokeStyle='#dce5ed';ctx.beginPath();ctx.moveTo(left,yy);ctx.lineTo(right,yy);ctx.stroke();ctx.fillStyle='#53677a';ctx.fillText(formatBytes(max*i/4),M,yy+5)}
  series.forEach((r,i)=>{const x=left+i*dx,rx=r[1]/max*245,tx=r[2]/max*245;ctx.fillStyle='#24b99c';ctx.fillRect(x,bottom-rx,Math.max(.5,dx*.8),rx);ctx.fillStyle='#8875df';ctx.fillRect(x,bottom-rx-tx,Math.max(.5,dx*.8),tx)});
  for(let i=0;i<series.length;i+=Math.max(1,Math.ceil(series.length/4))){ctx.fillStyle='#53677a';ctx.fillText(formatTime(documentData.seriesTimes[i]),Math.min(left+i*dx,W-M-185),bottom+30)}
  y=bottom+75;paragraph(translate('received')+' = '+translate('reportGreen')+' / '+translate('sent')+' = '+translate('reportPurple'));
  space(150);paragraph(translate('topTitle'),true);table(documentData.top,documentData.ips.map(r=>r.map(String)),[360,180,180,180,180]);
  space(150);paragraph(translate('hourlyVolume'),true);table(documentData.hourly,series.map(r=>r.map(String)),[420,220,220,220]);
  finish();return reportPDFPages(pages,W,H);
}

function reportPDFPages(pages,width,height) {
  const encode=text=>new TextEncoder().encode(text),objects=[];
  const stream=(dictionary,bytes)=>exportJoin([encode('<< '+dictionary+' /Length '+bytes.length+' >>\nstream\n'),bytes,encode('\nendstream')]);
  objects.push(encode('<< /Type /Catalog /Pages 2 0 R >>'));
  objects.push(encode('<< /Type /Pages /Count '+pages.length+' /Kids ['+pages.map((_,i)=>(3+i*3)+' 0 R').join(' ')+'] >>'));
  pages.forEach((url,i)=>{
    const id=3+i*3,base64=url.split(',')[1],raw=atob(base64),bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
    objects.push(encode('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] /Resources << /XObject << /Image '+(id+1)+' 0 R >> >> /Contents '+(id+2)+' 0 R >>'));
    objects.push(stream('/Type /XObject /Subtype /Image /Width '+width+' /Height '+height+' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode',bytes));
    objects.push(stream('',encode('q 595.28 0 0 841.89 0 0 cm /Image Do Q')));
  });
  const parts=[encode('%PDF-1.4\n%CSA\n')],offsets=[0];let length=parts[0].length;
  objects.forEach((object,i)=>{offsets.push(length);const bytes=exportJoin([encode((i+1)+' 0 obj\n'),object,encode('\nendobj\n')]);parts.push(bytes);length+=bytes.length});
  parts.push(encode('xref\n0 '+offsets.length+'\n0000000000 65535 f \n'+offsets.slice(1).map(n=>String(n).padStart(10,'0')+' 00000 n \n').join('')+'trailer\n<< /Size '+offsets.length+' /Root 1 0 R >>\nstartxref\n'+length+'\n%%EOF\n'));
  return exportJoin(parts);
}

function downloadReport(format) {
  if(!current||loading)return;
  const snapshot={...current,timeZone,query:new URLSearchParams(current.query),importWarning:lastStatus?.error?t('importError',{error:translateError(lastStatus.error)}):lastStatus?.running?t('reportImportRunning'):''};
  const translate=(key,vars)=>t(key,vars),data=reportDocument(snapshot,translate);
  try {
    const content=format==='csv'?reportCSV(data.rows):format==='xls'?reportXLS(data.rows):reportPDF(data,translate,value=>timefmt.format(new Date(value)),bytes);
    const mime={csv:'text/csv;charset=utf-8',xls:'application/vnd.ms-excel',pdf:'application/pdf'}[format];
    const url=URL.createObjectURL(new Blob([content],{type:mime})),a=document.createElement('a');
    a.href=url;a.download='csa-traffic-'+wallValue(new Date(snapshot.query.get('from')),snapshot.timeZone).slice(0,10)+'.'+format;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }catch(_){error('exportFailed')}
}
