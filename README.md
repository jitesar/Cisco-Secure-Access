# CSA Traffic — lokální verze 0.6

Dashboard pro čtení Cisco Secure Access S3 logů. Python 3.10+ a curl s podporou `--aws-sigv4` (7.75+). Žádné externí Python ani JavaScript závislosti.

## První spuštění na jiném počítači

1. Stáhni repository přes **Code → Download ZIP**, rozbal ho a otevři složku se souborem `app.py`; případně použij `git clone https://github.com/jitesar/Cisco-Secure-Access.git`. Distribuční ZIP lze rozbalit do složky `csa-traffic`. Je potřeba Python 3.10+ a curl 7.75+ s podporou AWS SigV4.
2. Na macOS otevři `Start.command`, ve Windows `start.cmd`. Spouštěč otevře lokální GUI v prohlížeči. Na Linuxu lze spustit `python3 app.py --open-browser`.
3. Při prvním spuštění se automaticky otevře **Nastavení S3 / S3 settings**. Zadej S3 Data Path, AWS region, Access Key ID a Secret Access Key.
4. Volitelně použij **Otestovat spojení**; tlačítko **Uložit a připojit** spojení znovu ověří, uloží nastavení a zahájí načtení logů.

Konfigurace v terminálu není potřeba. Formulář je kdykoliv dostupný v záhlaví a podporuje češtinu i angličtinu. Při zachování stejné S3 cesty a regionu lze ponechat obě pole klíčů prázdná a použít uloženou dvojici. Při změně cesty/regionu aplikace vyžaduje oba nové klíče. Běžné nastavení nevrací uložené hodnoty klíčů do prohlížeče; výjimkou je uživatelem vyžádaná záloha, při které se načtou do paměti prohlížeče a zašifrují.

Test ověřuje oprávnění vypsat obsah zadaného prefixu; samotné čtení logů se ověří při importu. Neúspěšný test nepřepíše fungující konfiguraci. Během importu se nastavení nemění. Pro jiný bucket, prefix nebo region je oddělená cache. Aplikace běží na http://127.0.0.1:8765 a poslouchá pouze lokálně; nejde o hostovanou víceuživatelskou službu.

Volitelně lze dál použít terminál: `python3 app.py --setup` pro nastavení a `python3 app.py` pro běžné spuštění (ve Windows `python`). Pokud chybí curl nebo je příliš starý, test/import ohlásí chybu; existující cache zůstane čitelná.

## Trvalé nastavení a přístupové údaje

Aplikace automaticky čte `config.json` a jím odkazovaný soubor klíčů z uživatelské složky mimo distribuovaný projekt:

- macOS: `~/Library/Application Support/CSA Traffic/`
- Windows: `%LOCALAPPDATA%\CSA Traffic\`
- Linux: `$XDG_CONFIG_HOME/csa-traffic/`, jinak `~/.config/csa-traffic/`

`config.json` obsahuje `s3Path`, `region` a `credentialsFile`. Relativní cesta k přístupovým údajům se vyhodnocuje vůči umístění konfigurace. Soubor klíčů (`credentials.json` z původního nastavení nebo `credentials-<id>.json` vytvořený GUI) obsahuje `accessKeyId` a `secretAccessKey`. Klíče se zadávají skrytě a zapisují mimo projekt; na macOS/Linuxu mají soubory práva 600 a nadřazená složka 700. Jde o lokální soubory, nikoli šifrovaný trezor. Zálohuj je ve vlastním zabezpečeném zálohování.

Jiné umístění konfigurace lze určit přes `--config /cesta/config.json` nebo `CSA_CONFIG_FILE`. Samostatný soubor klíčů lze přepsat přepínačem `--credentials` nebo `CSA_CREDENTIALS_FILE`. Port mění `--port`. Žádná S3 organizace není v kódu napevno. Klíče nevstupují do prohlížeče ani cache, curl je dostává přes stdin. Vzory `config.example.json` a `credentials.example.json` obsahují pouze zástupné hodnoty.

## Export aplikace

```sh
python3 export_app.py --output csa-traffic.zip
```

Export používá pevný seznam zdrojových souborů. Přibalí aplikaci, statické soubory, testy, průvodce nastavením, spouštěče a vzory konfigurace. Nezahrnuje skutečnou konfiguraci, klíče, databázi, screenshoty ani historii logů. ZIP můžeš předat dalšímu uživateli; vlastní S3 připojí v GUI bez terminálové konfigurace.

## Ovládání a měření

- Výběr Cloud Firewall nebo Web proxy, všech zdrojů / IP/CIDR/rozsahu nebo výčtu IPv4 či IPv6 / identity a intervalu v rámci posledních 30 dní.
- Součty přijatých a odeslaných bajtů, průměrná rychlost za celý interval, hodinový graf, 20 nejaktivnějších IP a CSV hodinových hodnot. Jednotky jsou desetinné (GB = 10^9 B).
- Internet / Private Access / nerozlišený provoz podle `Private Flow`. Prázdná hodnota není považována za Internet. Web proxy je samostatná internetová statistika.
- Firewall a proxy se **nesčítají**. Mají rozdílnou úroveň měření a mohou zachytit stejný provoz.
- Firewall: `Bytes Sent` / `Bytes Received`. Proxy: `Request Size` / `Response Size`; `Response Body Size` se podruhé nepřičítá. Chybějící počítadla se hlásí, nejde o ověřené nulové přenosy.
- Filtr subnetu pracuje s IP v logu; NAT může skutečný subnet skrýt. Textové identity se zachovávají jako celek, JSON pole identit se rozloží na jednotlivé položky. Skupinové členství AD/Entra zatím aplikace nezískává.
- Timestamp určuje přiřazení do intervalu `[od, do)` a hodinového koše. Bajty dlouhé relace se nerozdělují podle průběhu relace. Graf nemusí odpovídat skutečnému okamžitému vytížení linky.
- Formulář a popisky používají Europe/Prague, interní filtry UTC. Při podzimní změně času jsou místní hodiny opakované; pro tuto první verzi je vhodné vybrat hranice intervalu mimo opakovanou hodinu.

Podporované formáty: CSV s pojmenovanými hlavičkami a v10/v17 bez hlavičky s přesně 34/40 firewall nebo 49/57 proxy sloupci, včetně smíšených souborů při upgradu. Jiné formáty bez hlavičky import odmítne, aby neposunul počítadla na nesprávné sloupce.

## Import a omezení

Ručně spouštěný import seznamuje posledních 31 UTC adresářů v `firewalllogs` a `proxylogs`, stránkuje S3 výsledky a importuje celé soubory. Opakované načtení nezduplikuje řádky: soubor je evidován podle klíče a ETag. Změněný soubor atomicky nahrazuje staré řádky. Při chybě zůstávají úspěšně načtené soubory v cache a dashboard hlásí neúplný import. Záznamy starší než 31 dní se po úspěšném importu mažou.

Cache je v uživatelské složce `cache/<otisk-pripojeni>/traffic.sqlite` mimo projekt a obsahuje skutečné IP a identity. Pro každý bucket, prefix a region je oddělená. Nevkládej ji do sdílených podkladů. Při smazání cache se data znovu stáhnou. S3 obsah se nemění. Jednotlivý soubor může mít nejvýše 150 MB komprimovaně; velké instalace vyžadují streamování a škálovatelnější úložiště. Tato verze drží parsovaný soubor a vybraný report v paměti. Rozsah záznamů není důkazem kompletního pokrytí. Export zapnutý dnes neposkytuje automaticky týden zpětné historie; pozdní události v adresářích mimo importované období nejsou zachyceny.

## Ověření

```sh
python3 -m unittest discover -s tests -v
node --check static/app.js
```

## IP filtr a historie

Podporované příklady: `10.20.0.0/16`, `10.20.1.5`, `10.20.1.10-10.20.1.50`, nebo jejich kombinace oddělená čárkami, středníky, mezerami či novými řádky. Oba konce rozsahu jsou zahrnuté a musí patřit stejné rodině IP. Rozsahy se nepřevádějí na seznam jednotlivých adres; překryvy filtrů nezduplikují provoz.

Interval Od–Do musí celý ležet v posledních 30 dnech, maximálně do aktuálního času. Přesnost hranic formuláře je na minuty. Presety 3/7/30 dní mění období, nevytvářejí starší logy. Zvýrazněný panel ukazuje skutečný první a poslední záznam v cache vybraného zdroje a upozorní, pokud zvolený interval začíná před dostupnou historií. Data se doplňují ruční synchronizací.

## Jazyk a vzhled

Tmavé GUI obsahuje v záhlaví přepínač Čeština / English. Volba se ukládá do localStorage prohlížeče a synchronizuje mezi otevřenými kartami aplikace. Přepnutí zachová aktuální filtry a interval. Překládají se popisky, graf, dynamické statistiky, známé chybové zprávy, prázdné stavy, popis měření a hlavičky CSV. Čísla a aplikační datumové popisky odpovídají zvolenému jazyku; časové pásmo zůstává Europe/Prague. Nativní datumový ovladač může používat lokalizaci prohlížeče či operačního systému. Názvy skutečných identit, technických polí logů a kódy chyb S3 se nemění.

GUI API chrání zápisy kontrolou localhost Host, přesného Origin a tokenem CSRF pro daný běh serveru. JSON požadavky nastavení mají omezenou velikost. Test nezapisuje klíče; uložení používá nový soubor klíčů a atomické přepnutí konfigurace. Při chybě zápisu zůstává původní konfigurace platná. Nahrazené soubory klíčů spravované aplikací se po úspěšném přepnutí odstraňují; při zálohování zahrň celou uživatelskou složku, ne jen pevný název credentials.json.

## Šifrovaná záloha a přenos na jiný počítač

V **Nastavení S3 → Záloha a obnova konfigurace** zadej heslo dlouhé alespoň 12 znaků, zopakuj jej a stáhni soubor `.csabackup`. Obsahuje S3 cestu, region, oba aktuální přístupové klíče a zvolený jazyk. Neobsahuje logy, cache, absolutní cesty ani databázi. Zálohuje se uložená konfigurace, nikoliv rozepsaný formulář.

Na jiném počítači spusť aplikaci a v témže panelu vyber soubor, zadej heslo a použij **Obnovit a připojit**. Funguje to i při prvním spuštění bez nastavení. Před zápisem aplikace ověří přístup k S3; neplatné heslo, poškozený soubor nebo neúspěšné ověření zachová původní nastavení. Po obnově se logy znovu načtou. Záloha neprodlužuje platnost S3 klíčů: pokud mezitím expirovaly nebo byly zneplatněny rotací, použij aktuální klíče.

Šifrování probíhá v prohlížeči pomocí Web Crypto: AES-256-GCM, náhodná 16bajtová sůl, 12bajtový IV, 128bitový autentizační tag a PBKDF2-SHA256 s 600 000 iteracemi. Formát v1 přijímá pouze tyto parametry. Heslo se neposílá serveru ani neukládá. Klíče se při explicitním exportu načtou přes chráněný POST do paměti prohlížeče; neukládají se do localStorage a do staženého souboru vstupují pouze šifrovaně. Bez hesla nelze zálohu obnovit; heslo uchovej odděleně v bezpečném úložišti.

Kryptografické a formátové kontroly lze spustit příkazem `node tests/test_backup.js` (Node 18+ je potřeba jen pro tyto vývojářské testy, nikoliv pro běh aplikace).
