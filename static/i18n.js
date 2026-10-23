'use strict';
// Shared keys keep static UI, live reports, chart and errors in the same locale.
const MESSAGES = {
  cs: {
    timeZoneTitle:'Zobrazení data a času', timeZoneLabel:'Časová zóna', timeZoneSave:'Uložit časovou zónu', timeZoneHint:'Zóna platí pro filtry, grafy, detaily i reporty. Formát data a 12/24hodinový čas se řídí regionem zóny. Volba se ukládá v tomto prohlížeči.', timeZoneExample:'Ukázka: {example}', timeZoneSaved:'Časová zóna byla uložena.', timeZoneInvalid:'Neplatná časová zóna.', timeZoneStorage:'Časovou zónu nelze uložit do úložiště prohlížeče.', dstAmbiguous:'Tento místní čas se při změně letního času opakuje. Vyber hranici intervalu mimo opakovanou hodinu.',
    savedFiltersTitle:'Uložené filtry', savedFilterChoose:'Vyber uložený filtr', savedFilterName:'Název filtru', savedFilterSave:'Uložit / aktualizovat', savedFilterLoad:'Použít filtr', savedFilterDelete:'Smazat',
    savedFilterHint:'Filtry se ukládají v tomto prohlížeči. Stejný název přepíše filtr. Rychlá období se počítají od aktuálního času, vlastní interval zůstává pevný.', savedFilterSaved:'Filtr byl uložen.', savedFilterLoaded:'Filtr byl použit.', savedFilterDeleted:'Filtr byl smazán.', savedFilterNameRequired:'Zadej název filtru (nejvýše 80 znaků).', savedFiltersLimit:'Lze uložit nejvýše 100 filtrů.', savedFiltersInvalid:'Neplatný formát uložených filtrů.', savedFiltersStorage:'Filtr nelze uložit. Zkontroluj, zda je povolené místní úložiště prohlížeče.', savedFiltersStorageRead:'Uložené filtry se nepodařilo načíst z tohoto prohlížeče.', savedFilterExpired:'Uložený časový interval už není v posledních 30 dnech. Uprav Od / Do nebo vyber rychlé období a zobraz přenosy.',
    transferAscending:'Vzestupně', transferDescending:'Sestupně', transferSortBy:'{column}: seřadit {direction}', transferSortChanged:'Doplnění detailů změnilo údaje pro řazení. Obnov pořadí před přechodem na další stránku.', transferRefreshSort:'Obnovit pořadí',
    syncListing:'Kontroluji S3 složky {done}/{total} · nalezeno {n} souborů', syncDownloading:'Importováno {done}/{total} nových či změněných · {skipped} beze změny', syncCleaning:'Dokončuji import a čistím starou cache…', syncResult:'Importováno {downloaded}, beze změny {skipped} · {seconds} s',
    transferTitle:'Přenosy pro {ip}', transferClose:'Zavřít přenosy', transferOpen:'Zobrazit přenosy pro {ip}', transferExpand:'Rozbalit nebo sbalit přenos z {time}', transferLatest:'Nejnovější', transferVolume:'Největší objem', transferListHint:'Klikni na hlavičku pro řazení, znovu pro opačný směr. Kliknutím na řádek zobrazíš detail.',
    transferLoading:'Načítám přenosy…', transferSummary:'{n} záznamů · Přijato {received} · Odesláno {sent}', transferNotLoaded:'Detaily nenačteny', transferMissingValue:'Není v logu', transferPage:'Strana {page} z {pages}', transferPrevious:'Předchozí', transferNext:'Další', transferUTC:'Čas záznamu', transferTime:'Čas ({zone})', transferDestination:'Cíl', transferProtocol:'Protokol / metoda', transferAction:'Akce', transferRefresh:'Obnovit report', transferRetry:'Zkusit znovu',
    transferLegacy:'Starší cache obsahuje pouze souhrnné údaje. Rozbalením záznamu se jeho detaily načtou ze S3. Běžná synchronizace nezměněné soubory znovu nestahuje.', transferMissingNote:'U některých přenosů chybí počítadlo. Hvězdička označuje neúplný součet; souhrn zahrnuje jen dostupné hodnoty.', transferRawFields:'Dostupná pole původního logového záznamu', transferTruncated:'Hodnota je zkrácená na 16 384 znaků: {fields}.', transferRecordNote:'Jeden řádek odpovídá jednomu logovému záznamu, nikoliv jednotlivému paketu. Součty se řídí Timestamp v logu.',
    transferIPRequired:'Vyber platnou zdrojovou IP.', transferInvalidPage:'Neplatná stránka nebo řazení přenosů.', transfersChanged:'Cache se od načtení reportu změnila. Obnov report a znovu otevři přenosy.', transferUnavailable:'Záznam už není v tomto výběru dostupný. Obnov report a otevři jej znovu.',
    reportExport:'Export reportu', reportExportHint:'Stáhne zobrazený report: filtry, souhrn, hodinové hodnoty a nejaktivnější IP. PDF obsahuje i graf.',
    reportTitle:'Report datových přenosů', reportGenerated:'Vytvořeno', reportSynced:'Poslední úplná synchronizace', reportNotSynced:'Dosud neproběhla', reportCoverage:'Rozsah záznamů zdroje v cache',
    reportTotalBytes:'Celkem bajtů', reportRecords:'Počet záznamů', reportRate:'Průměrná rychlost (b/s)', reportMissing:'Záznamy s chybějícím počítadlem', reportUnknown:'Záznamy s nerozlišeným provozem', reportNotes:'Poznámky k měření',
    reportTimeNote:'Všechny časy používají zónu {zone}; UTC posun rozlišuje opakované hodiny při změně letního času. Interval zahrnuje počátek a nezahrnuje konec.', reportSessionNote:'Bajty relací jsou přiřazené podle Timestamp v logu, nejsou rozdělené podle průběhu relace.', reportPrecision:'Tabulky uvádějí bajty a b/s v desetinných jednotkách. Seznam IP obsahuje nejvýše 20 nejaktivnějších adres.',
    reportGreen:'zelená', reportPurple:'fialová', reportImportRunning:'Probíhá import. Report vychází z aktuálně zobrazeného snímku dat a nemusí být úplný.', exportFailed:'Report se nepodařilo exportovat. Zkus kratší interval nebo menší filtr.',
    backupTitle:'Záloha a obnova konfigurace', backupIntro:'Zálohuj uloženou S3 cestu, region, přístupové klíče, jazyk a časovou zónu do souboru šifrovaného heslem. Logy se nezálohují.',
    backupSetupHint:'Nemáš ještě připojení? Existující zálohu můžeš obnovit níže.', backupExportTitle:'Vytvořit zálohu', backupPassword:'Heslo zálohy (alespoň 12 znaků)', backupConfirm:'Heslo znovu',
    backupPasswordHint:'Heslo ulož odděleně od souboru. Bez něj zálohu nelze obnovit.', backupDownload:'Stáhnout šifrovanou zálohu', backupRestoreTitle:'Obnovit zálohu', backupFile:'Soubor zálohy (.csabackup)', backupRestorePassword:'Heslo zálohy',
    backupRestoreHint:'Obnova ověří S3 přístup a nahradí současné připojení. Při chybě zůstane současné nastavení zachované.', backupRestore:'Obnovit a připojit',
    backupEncrypting:'Připravuji a šifruji zálohu…', backupDownloaded:'Šifrovaný soubor byl předán ke stažení. Uchovej jej spolu s odděleně uloženým heslem.', backupRestoring:'Dešifruji zálohu a ověřuji S3 připojení…', backupRestored:'Konfigurace byla obnovena. Načítám logy.',
    backupNotConfigured:'Nejprve ulož funkční S3 připojení, potom vytvoř zálohu.', backupInvalid:'Soubor není platná nebo podporovaná záloha CSA Traffic.', backupPasswordMismatch:'Zadaná hesla se neshodují.', backupPasswordShort:'Heslo musí mít alespoň 12 znaků.', backupDecryptFailed:'Zálohu nelze dešifrovat. Zkontroluj heslo; soubor může být také poškozený.', backupCryptoUnavailable:'Prohlížeč nepodporuje potřebné šifrování. Otevři aplikaci na localhostu v aktuálním prohlížeči.',
    settingsButton:'Nastavení S3', settingsTitle:'Připojení k S3', settingsClose:'Zavřít nastavení',
    settingsIntro:'Připoj úložiště s logy Cisco Secure Access. S3 cestu a klíče najdeš v Log Managementu.',
    settingsFirst:'Zadej S3 cestu a klíče v nastavení. Konfigurace v terminálu není potřeba.',
    settingsPath:'S3 Data Path', settingsRegion:'AWS region', settingsAccess:'Access Key ID', settingsSecret:'Secret Access Key',
    settingsKeepKeys:'Klíče jsou uložené. Pro jejich zachování ponech obě pole prázdná. Nové klíče zadávej vždy jako dvojici.',
    settingsNewKeys:'Pro nové nebo změněné S3 připojení zadej oba přístupové klíče.',
    settingsStorage:'Klíče se ukládají lokálně mimo aplikaci a export. Uložené hodnoty se v prohlížeči nezobrazují.',
    settingsTest:'Otestovat spojení', settingsSave:'Uložit a připojit', settingsTesting:'Ověřuji přístup k S3…', settingsSaving:'Ověřuji spojení a ukládám nastavení…',
    settingsTestOK:'Spojení funguje. Ověřeno čtení seznamu souborů v zadané S3 cestě. Nastavení zatím nebylo změněno.',
    settingsSaved:'Připojení bylo uloženo. Načítám logy.', setupRequired:'Nejprve připoj S3 úložiště.',
    settingsInvalid:'Zkontroluj S3 cestu (s3://bucket/prefix/) a AWS region.', settingsKeysRequired:'Zadej platnou dvojici Access Key ID a Secret Access Key. Při změně připojení jsou nové klíče povinné.',
    settingsBusy:'Probíhá import nebo jiná operace. Počkej na dokončení a zkus to znovu.', settingsProbeFailed:'S3 nevrátilo očekávaný seznam souborů.',
    settingsFailed:'Nastavení se nepodařilo uložit. Původní připojení zůstává k dispozici.', settingsReload:'Obnov stránku a zkus to znovu.',
    title:'CSA · Přenosy dat', local:'Lokální aplikace · S3', heading:'Přenosy přes CSA. V detailu.', subtitle:'Objem dat podle sítě, identity a času.',
    loadLogs:'↻ Načíst nové logy', loadingLogs:'↻ Načítám logy…', ready:'Připraveno k načtení', sourceGroup:'Zdroj měření', firewall:'Cloud Firewall', proxy:'Web proxy',
    sourceFirewall:'Přenosy síťových relací', sourceProxy:'Velikosti webových požadavků a odpovědí', filterBy:'Filtrovat podle', allSources:'Všechny zdroje', ipNetworks:'IP adresy / sítě', identity:'Identita', chooseIdentity:'Vyber identitu',
    ipHelp:'IP, CIDR, rozsah adres či oktetů (např. 10-11.30-33.1-2.3-50). Položky odděl čárkou, středníkem, mezerou nebo novým řádkem.', trafficType:'Druh provozu', allTraffic:'Veškerý zaznamenaný', internet:'Internet · potvrzený', private:'Private Access · potvrzený', unknownTraffic:'Nerozlišený provoz',
    from:'Od', to:'Do', showTraffic:'Zobrazit přenosy →', quickSelect:'Rychlý výběr', hour1:'1 hodina', hours24:'24 hodin', days3:'3 dny', days7:'7 dní', days30:'30 dní', timezone:'Časy: {zone}',
    intervalHint:'Vlastní interval nastav v polích Od a Do, kdekoliv v posledních 30 dnech.', checkingHistory:'Ověřuji dostupnou historii…',
    notice:'Firewall a web proxy jsou samostatná měření. Jejich objemy nesčítáme, protože se provoz může překrývat.', unknownNote:'{n} záznamů nemá rozlišení Internet / Private Access.', missingNote:'U {n} záznamů chybí některé počítadlo; součet zahrnuje jen dostupné hodnoty.',
    summary:'Souhrn přenosů', total:'Celkový přenos', receivedData:'Přijatá data', sentData:'Odeslaná data', selectPeriod:'Vyber období', recordCount:'{n} záznamů', averageRate:'Průměrná rychlost', averageHint:'Průměr za celý vybraný interval',
    chartTitle:'Průběh přenosů', hourlyVolume:'Objem dat za hodinu', hourly:'po hodinách', received:'Přijato', sent:'Odesláno', chartAria:'Hodinový graf přijatých a odeslaných dat', chartSummary:'Přijatá data {received}, odeslaná {sent}. Hodinové hodnoty jsou dostupné také v exportu CSV.',
    emptyTitle:'Pro tento výběr nemáme záznamy.', emptyHint:'Zkus širší období, jiný filtr nebo načti nové logy.', chartNote:'Hodiny bez záznamů zobrazujeme jako 0 zaznamenaných bajtů. Nejde o potvrzení úplnosti logování.',
    topTitle:'Nejaktivnější zdrojové IP', topHint:'Nejvýše 20 adres podle objemu dat. Kliknutím otevřeš jednotlivé přenosy.', exportCSV:'↓ Export CSV', sourceIP:'Zdrojová IP', share:'Podíl', totalColumn:'Celkem', emptyTable:'Žádné záznamy pro tento výběr', unknownIP:'Neznámá IP',
    emptyCache:'Lokální cache zatím neobsahuje data.', cacheHint:'Cache je prázdná. Načti logy ze S3.', cacheRange:'Rozsah záznamů v cache: {from} – {to} · {n} záznamů',
    noHistory:'Pro tento zdroj zatím nejsou načtené žádné logy.', noHistoryHint:'Načti nové logy ze S3. Prázdná historie neznamená nulový provoz.', historyRange:'Dostupné záznamy: {from} — {to}',
    partialHistory:'Vybraný interval začíná před prvním dostupným záznamem. Starší část není doložena logy; proto mohou mít 3, 7 i 30 dní stejný součet.', fullHistory:'Součet zahrnuje záznamy ve vybraném intervalu. Rozsah první–poslední záznam neprokazuje úplnost logování.',
    syncProgress:'Zpracováno {done} / {total} souborů', findingLogs:'Hledám soubory za posledních 30 dní…', importIncomplete:'Import nebyl dokončen', lastSync:'Poslední úplná aktualizace: {time}', serverUnavailable:'Lokální server není dostupný', importError:'Import: {error}. Zobrazená cache může být neúplná.',
    rangeError:'Vyber období delší než 0 a nejvýše 30 dní.', windowError:'Celý interval musí ležet v posledních 30 dnech, bez budoucích časů.', ipRequired:'Zadej IP adresu, CIDR, rozsah nebo jejich výčet.', identityRequired:'Vyber identitu.', dstError:'Tento místní čas neexistuje kvůli změně letního času.', requestFailed:'Požadavek selhal',
    methodTitle:'Co přesně měříme?',
    method1:'Cloud Firewall: součet Bytes Sent a Bytes Received. Web proxy: Request Size a Response Size, bez opětovného přičtení Response Body Size. Tyto zdroje nesčítáme. Směr je z pohledu klienta.',
    method2:'IP adresy, CIDR a rozsahy se porovnávají se zdrojovou IP uloženou v logu; NAT může původní IP skrýt. Identity vycházejí z pole Identities; textový kombinovaný štítek zůstává zachovaný jako celek. Internet a Private Access ve firewallu rozlišujeme jen při vyplněném Private Flow. Prázdné pole znamená neurčený provoz.',
    method3:'Záznam je přiřazen podle Timestamp v logu, nikoli rozdělen podle skutečného průběhu dlouhé relace. Import čte posledních 31 UTC datových adresářů a opakuje jejich kontrolu kvůli opožděným souborům. Starší chybně zařazené soubory nemusí být zachyceny. Rozsah prvního a posledního záznamu neprokazuje úplnost dat. Aktualizace probíhá ručně tlačítkem.',
    csvHour:'Hodina', csvReceived:'Přijaté bajty', csvSent:'Odeslané bajty', csvSource:'Zdroj', csvIP:'IP filtr', csvIdentity:'Identita', csvScope:'Druh provozu', csvFrom:'Filtr od', csvTo:'Filtr do', csvFilename:'csa-prenosy.csv',
  },
  en: {
    timeZoneTitle:'Date and time display', timeZoneLabel:'Time zone', timeZoneSave:'Save time zone', timeZoneHint:'Applies to filters, charts, details and reports. Date order and 12/24-hour time follow the zone’s region. The choice is stored in this browser.', timeZoneExample:'Example: {example}', timeZoneSaved:'Time zone saved.', timeZoneInvalid:'Invalid time zone.', timeZoneStorage:'Could not save the time zone in browser storage.', dstAmbiguous:'This local time repeats during a daylight-saving transition. Choose an interval boundary outside the repeated hour.',
    savedFiltersTitle:'Saved filters', savedFilterChoose:'Choose a saved filter', savedFilterName:'Filter name', savedFilterSave:'Save / update', savedFilterLoad:'Apply filter', savedFilterDelete:'Delete',
    savedFilterHint:'Filters are stored in this browser. The same name replaces a filter. Quick periods are relative to the current time; custom intervals keep their original dates.', savedFilterSaved:'Filter saved.', savedFilterLoaded:'Filter applied.', savedFilterDeleted:'Filter deleted.', savedFilterNameRequired:'Enter a filter name (up to 80 characters).', savedFiltersLimit:'You can save up to 100 filters.', savedFiltersInvalid:'Invalid saved filter format.', savedFiltersStorage:'Could not save the filter. Check that browser local storage is enabled.', savedFiltersStorageRead:'Could not read saved filters from this browser.', savedFilterExpired:'The saved interval is no longer within the last 30 days. Adjust From / To or choose a quick period, then show traffic.',
    transferAscending:'Ascending', transferDescending:'Descending', transferSortBy:'{column}: sort {direction}', transferSortChanged:'Newly loaded details changed the sort values. Refresh the order before moving to another page.', transferRefreshSort:'Refresh order',
    syncListing:'Checking S3 folders {done}/{total} · {n} files found', syncDownloading:'Imported {done}/{total} new or changed · {skipped} unchanged', syncCleaning:'Finishing import and cleaning old cache…', syncResult:'Imported {downloaded}, unchanged {skipped} · {seconds} s',
    transferTitle:'Transfers for {ip}', transferClose:'Close transfers', transferOpen:'Show transfers for {ip}', transferExpand:'Expand or collapse transfer at {time}', transferLatest:'Newest first', transferVolume:'Largest volume', transferListHint:'Select a header to sort; select it again to reverse direction. Select a row to view details.',
    transferLoading:'Loading transfers…', transferSummary:'{n} records · Received {received} · Sent {sent}', transferNotLoaded:'Details not loaded', transferMissingValue:'Not in log', transferPage:'Page {page} of {pages}', transferPrevious:'Previous', transferNext:'Next', transferUTC:'Record timestamp', transferTime:'Time ({zone})', transferDestination:'Destination', transferProtocol:'Protocol / method', transferAction:'Action', transferRefresh:'Refresh report', transferRetry:'Try again',
    transferLegacy:'Older cached records contain only summary fields. Expand a record to fetch its details from S3; unchanged files are not downloaded again during a normal sync.', transferMissingNote:'Some transfers have missing counters. An asterisk marks a partial total; the summary includes only available values.', transferRawFields:'Available fields from the original log record', transferTruncated:'Value limited to 16,384 characters: {fields}.', transferRecordNote:'Each row represents a log record, not an individual packet. Totals are assigned using the log Timestamp.',
    transferIPRequired:'Select a valid source IP.', transferInvalidPage:'Invalid transfers page or sort order.', transfersChanged:'The cache has changed since this report was loaded. Refresh the report and open the transfers again.', transferUnavailable:'This record is no longer available in this selection. Refresh the report and open it again.',
    reportExport:'Export report', reportExportHint:'Download the displayed report: filters, summary, hourly values and top IPs. PDF also includes the chart.',
    reportTitle:'Data transfer report', reportGenerated:'Generated', reportSynced:'Last complete synchronization', reportNotSynced:'Not yet completed', reportCoverage:'Source records in cache',
    reportTotalBytes:'Total bytes', reportRecords:'Record count', reportRate:'Average throughput (b/s)', reportMissing:'Records with missing counters', reportUnknown:'Unclassified traffic records', reportNotes:'Measurement notes',
    reportTimeNote:'All times use {zone}; UTC offsets distinguish repeated hours during daylight-saving transitions. The interval includes its start and excludes its end.', reportSessionNote:'Session bytes are assigned using the log Timestamp, without distributing them over the session duration.', reportPrecision:'Tables show bytes and b/s in decimal units. The IP list contains up to 20 of the most active addresses.',
    reportGreen:'green', reportPurple:'purple', reportImportRunning:'An import is running. The report uses the displayed data snapshot and may be incomplete.', exportFailed:'Could not export the report. Try a shorter interval or a smaller filter.',
    backupTitle:'Back up and restore configuration', backupIntro:'Back up the saved S3 path, region, access keys, language and time zone in a password-encrypted file. Logs are not included.',
    backupSetupHint:'Not connected yet? You can restore an existing backup below.', backupExportTitle:'Create a backup', backupPassword:'Backup password (at least 12 characters)', backupConfirm:'Repeat password',
    backupPasswordHint:'Keep the password separate from the file. The backup cannot be recovered without it.', backupDownload:'Download encrypted backup', backupRestoreTitle:'Restore a backup', backupFile:'Backup file (.csabackup)', backupRestorePassword:'Backup password',
    backupRestoreHint:'Restoring verifies S3 access and replaces the current connection. A failure leaves your current settings unchanged.', backupRestore:'Restore and connect',
    backupEncrypting:'Preparing and encrypting the backup…', backupDownloaded:'The encrypted file has been sent to your downloads. Keep the password separately.', backupRestoring:'Decrypting the backup and verifying the S3 connection…', backupRestored:'Configuration restored. Loading logs.',
    backupNotConfigured:'Save a working S3 connection before creating a backup.', backupInvalid:'This is not a valid or supported CSA Traffic backup.', backupPasswordMismatch:'The passwords do not match.', backupPasswordShort:'Use a password with at least 12 characters.', backupDecryptFailed:'The backup could not be decrypted. Check the password; the file may also be damaged.', backupCryptoUnavailable:'This browser does not support the required encryption. Open the application on localhost in a current browser.',
    settingsButton:'S3 settings', settingsTitle:'Connect to S3', settingsClose:'Close settings',
    settingsIntro:'Connect your Cisco Secure Access log storage. Find the S3 path and keys in Log Management.',
    settingsFirst:'Enter your S3 path and keys in settings. No terminal configuration is needed.',
    settingsPath:'S3 Data Path', settingsRegion:'AWS region', settingsAccess:'Access Key ID', settingsSecret:'Secret Access Key',
    settingsKeepKeys:'Keys are saved. Leave both fields blank to keep them. Always enter replacement keys as a pair.',
    settingsNewKeys:'Enter both access keys for a new or changed S3 connection.',
    settingsStorage:'Keys are saved locally, outside the application and export. Saved values are never displayed in the browser.',
    settingsTest:'Test connection', settingsSave:'Save and connect', settingsTesting:'Checking S3 access…', settingsSaving:'Testing the connection and saving settings…',
    settingsTestOK:'Connection successful. Listing files at the specified S3 path was verified. Your settings have not been changed yet.',
    settingsSaved:'Connection saved. Loading logs.', setupRequired:'Connect your S3 storage first.',
    settingsInvalid:'Check the S3 path (s3://bucket/prefix/) and AWS region.', settingsKeysRequired:'Enter a valid Access Key ID and Secret Access Key pair. New keys are required when changing the connection.',
    settingsBusy:'An import or another operation is running. Wait for it to finish and try again.', settingsProbeFailed:'S3 did not return the expected file listing.',
    settingsFailed:'Settings could not be saved. The previous connection is still available.', settingsReload:'Reload the page and try again.',
    title:'CSA · Data traffic', local:'Local application · S3', heading:'Your traffic. In focus.', subtitle:'Explore data usage by network, identity and time.',
    loadLogs:'↻ Load new logs', loadingLogs:'↻ Loading logs…', ready:'Ready to load', sourceGroup:'Measurement source', firewall:'Cloud Firewall', proxy:'Web proxy',
    sourceFirewall:'Network session transfers', sourceProxy:'Web request and response sizes', filterBy:'Filter by', allSources:'All sources', ipNetworks:'IP addresses / networks', identity:'Identity', chooseIdentity:'Select an identity',
    ipHelp:'IP, CIDR, address range or IPv4 octet ranges (e.g. 10-11.30-33.1-2.3-50). Separate entries with commas, semicolons, spaces or new lines.', trafficType:'Traffic type', allTraffic:'All recorded traffic', internet:'Internet · confirmed', private:'Private Access · confirmed', unknownTraffic:'Unclassified traffic',
    from:'From', to:'To', showTraffic:'Show traffic →', quickSelect:'Quick select', hour1:'1 hour', hours24:'24 hours', days3:'3 days', days7:'7 days', days30:'30 days', timezone:'Time zone: {zone}',
    intervalHint:'Set any custom From–To interval within the last 30 days.', checkingHistory:'Checking available history…',
    notice:'Firewall and web proxy are separate measurements. Their volumes are not added together because the same traffic may appear in both.', unknownNote:'{n} records do not distinguish Internet from Private Access.', missingNote:'{n} records are missing a byte counter; totals include only available values.',
    summary:'Traffic summary', total:'Total transferred', receivedData:'Data received', sentData:'Data sent', selectPeriod:'Select a time range', recordCount:'{n} records', averageRate:'Average throughput', averageHint:'Average over the entire selected interval',
    chartTitle:'Traffic over time', hourlyVolume:'Data volume per hour', hourly:'hourly', received:'Received', sent:'Sent', chartAria:'Hourly chart of received and sent data', chartSummary:'Data received {received}, data sent {sent}. Hourly values are also available in the CSV export.',
    emptyTitle:'No records for this selection.', emptyHint:'Try a wider time range, another filter or load new logs.', chartNote:'Hours without records show 0 recorded bytes. This does not confirm complete logging coverage.',
    topTitle:'Top source IP addresses', topHint:'Up to 20 addresses ranked by data volume. Select a row to view individual transfers.', exportCSV:'↓ Export CSV', sourceIP:'Source IP', share:'Share', totalColumn:'Total', emptyTable:'No records for this selection', unknownIP:'Unknown IP',
    emptyCache:'The local cache does not contain data yet.', cacheHint:'The cache is empty. Load logs from S3.', cacheRange:'Cached records: {from} – {to} · {n} records',
    noHistory:'No logs have been loaded for this source yet.', noHistoryHint:'Load new logs from S3. An empty history does not mean zero traffic.', historyRange:'Available records: {from} — {to}',
    partialHistory:'The selected interval starts before the first available record. There are no logs for the earlier part, so 3, 7 and 30 days may show the same total.', fullHistory:'Totals include records within the selected interval. The first and last record do not prove complete logging coverage.',
    syncProgress:'Processed {done} / {total} files', findingLogs:'Finding files from the last 30 days…', importIncomplete:'Import did not complete', lastSync:'Last complete update: {time}', serverUnavailable:'The local server is unavailable', importError:'Import: {error}. The displayed cache may be incomplete.',
    rangeError:'Select a time range greater than 0 and no longer than 30 days.', windowError:'The entire interval must be within the last 30 days, with no future times.', ipRequired:'Enter an IP address, CIDR, range or a list of these.', identityRequired:'Select an identity.', dstError:'This local time does not exist because of a daylight saving time change.', requestFailed:'The request failed',
    methodTitle:'What exactly is measured?',
    method1:'Cloud Firewall: Bytes Sent plus Bytes Received. Web proxy: Request Size plus Response Size, without adding Response Body Size a second time. These sources are not added together. Direction is from the client’s perspective.',
    method2:'IP addresses, CIDRs and ranges are matched against the source IP in the log; NAT may hide the original IP. Identities come from the Identities field; combined text labels are preserved as a whole. Firewall Internet and Private Access traffic are classified only when Private Flow is populated. An empty field means unclassified traffic.',
    method3:'Records are assigned by their log Timestamp; long-session bytes are not distributed over the actual session duration. Import checks the last 31 UTC date folders and rechecks them for late files. Older files stored in the wrong folder may be missed. The first and last record do not prove complete coverage. Use the button to update manually.',
    csvHour:'Hour', csvReceived:'Received bytes', csvSent:'Sent bytes', csvSource:'Source', csvIP:'IP filter', csvIdentity:'Identity', csvScope:'Traffic type', csvFrom:'Filter from', csvTo:'Filter to', csvFilename:'csa-traffic.csv',
  },
};

let language='cs';
try { if(localStorage.getItem('csa-language')==='en') language='en'; } catch (_) {}
let locale,fmt,rangefmt,timefmt;
function updateFormatters(){
  locale=language==='en'?'en-GB':'cs-CZ';
  fmt=new Intl.NumberFormat(locale,{maximumFractionDigits:2});
  rangefmt=zonedFormatter({year:'numeric',day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',timeZoneName:'shortOffset'});
  timefmt=zonedFormatter({day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',timeZoneName:'shortOffset'});
}
function t(key,vars={}){
  const template=MESSAGES[language][key]||key;
  return template.replace(/\{(\w+)\}/g,(_,name)=>String(vars[name]??(name==='zone'?timeZone:'')));
}
function translateError(message){
  if(MESSAGES.cs[message]) return t(message);
  if(language==='cs') return message;
  const exact={
    'Použij nejvýše 1000 položek v IP filtru':'Use at most 1,000 items in the IP filter',
    'Neplatný čas záznamu':'Invalid record timestamp',
    'Neplatné počítadlo bajtů':'Invalid byte counter',
    'Záporné počítadlo bajtů':'Negative byte counter',
    'Soubor s přístupovými údaji není vyplněný':'The credentials file is incomplete',
    'S3 nevrátilo pokračovací token':'S3 did not return a continuation token',
    'Neplatný zdroj':'Invalid source',
    'Čas musí obsahovat časové pásmo':'The time must include a time zone',
    'Vyber interval delší než 0 a nejvýše 30 dní':MESSAGES.en.rangeError,
    'Celý interval musí ležet v posledních 30 dnech a nesmí sahat do budoucnosti':MESSAGES.en.windowError,
    'Neplatný druh provozu':'Invalid traffic type',
    'Nepovolený host':'Host not allowed',
    'Nenalezeno':'Not found',
    'Zadej datum a čas od–do':'Enter a start and end date and time',
    'Chyba zpracování lokálních dat':'Failed to process local data',
    'Nepovolený původ požadavku':'Request origin not allowed',
  };
  if(exact[message]) return exact[message];
  const invalid=message.match(/^Neplatná položka IP filtru: (.*?)\. Použij IP, CIDR[^\n]*\.$/s);
  if(invalid) return 'Invalid IP filter item: '+invalid[1]+'. Use an IP, CIDR, a full address range or IPv4 octet ranges (e.g. 10-11.30-33.1-2.3-50).';
  return message.replace(/^Chybí povinné sloupce v (.+) logu$/, 'Required columns are missing in the $1 log')
    .replace(/^Nepodporovaný počet CSV sloupců: /,'Unsupported CSV column count: ')
    .replace(/^Připojení k S3 selhalo \(curl /,'S3 connection failed (curl ');
}
updateFormatters();
