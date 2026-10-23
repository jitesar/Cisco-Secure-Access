# CSA Traffic — Cisco Secure Access Traffic Dashboard

[![Download latest release ZIP](https://img.shields.io/badge/Download-latest%20release%20ZIP-2ec4a6?style=for-the-badge&logo=github)](https://github.com/jitesar/Cisco-Secure-Access/releases/latest/download/csa-traffic-v0.8.zip)

**[Download ZIP (v0.8)](https://github.com/jitesar/Cisco-Secure-Access/releases/latest/download/csa-traffic-v0.8.zip)** · [Latest release and installation notes](https://github.com/jitesar/Cisco-Secure-Access/releases/latest)

Local application, version 0.8, for analyzing traffic volumes from Cisco Secure Access logs exported to Amazon S3. Filter by subnet, IP range, address list or identity, select a time period within the last 30 days, and view upload/download totals and an hourly chart.

![CSA Traffic dashboard showing subnet filters, traffic totals and an hourly chart](https://github.com/jitesar/Cisco-Secure-Access/releases/download/v0.6/csa-traffic-dashboard.png)

The application runs on your computer and reads your S3 logs. It requires Python 3.10+ and curl 7.75+ with `--aws-sigv4` support. There are no third-party Python or JavaScript dependencies. A current browser with Web Crypto support is required for encrypted configuration backups.

## Quick start

1. Download the repository using **Code → Download ZIP**, extract it, and open the folder containing `app.py`. Alternatively, clone it:

   ```sh
   git clone https://github.com/jitesar/Cisco-Secure-Access.git
   cd Cisco-Secure-Access
   ```

2. Start the application:

   | Platform | Start command |
   | --- | --- |
   | macOS | Open `Start.command`, or run `python3 app.py --open-browser` |
   | Windows | Open `start.cmd`, or run `python app.py --open-browser` |
   | Linux | Run `python3 app.py --open-browser` |

3. Open [http://127.0.0.1:8765](http://127.0.0.1:8765) if the browser does not open automatically. Use the **Čeština / English** selector in the header to choose your language.
4. On first launch, **S3 settings** opens automatically. Enter your S3 Data Path (`s3://bucket/customer-prefix/`), AWS region, Access Key ID and Secret Access Key. Use the credentials for your log storage.
5. Optionally select **Test connection**, then **Save and connect**. Saving verifies access, stores the configuration locally and starts importing logs.
6. Select a log source, traffic type, subnet or identity, and time interval to display the report.

No terminal configuration is required. S3 settings remains available from the header. The server listens on `127.0.0.1` only and is intended for local use.

The connection test checks permission to list the configured S3 prefix. Reading individual log files is verified during import. A failed connection test leaves the working configuration unchanged. Settings cannot be changed during an import.

If you keep the same S3 path and region, leave both key fields blank to reuse the saved credentials. Changing the path or region requires both keys to be entered again. Regular settings responses do not return saved key values to the browser; explicitly requested backups do, so the browser can encrypt them.

## Reports and filters

- Choose **Cloud Firewall** or **Web proxy** as the source.
- Filter by all sources, IP addresses/subnets/ranges, or identity.
- View received and sent bytes, average throughput over the entire interval, an hourly chart, the 20 most active IP addresses, and CSV, XLS and PDF report exports.
- Select Internet, Private Access or unclassified firewall traffic, based on the `Private Flow` field. An empty value is unclassified. Web proxy provides a separate Internet traffic view.
- Use a preset or a custom From–To interval within the last 30 days, ending no later than the current time. The GUI accepts minute-level boundaries.

### IP filter examples

| Input | Matches |
| --- | --- |
| `10.20.0.0/16` | An IPv4 subnet in CIDR notation |
| `10.20.1.5` | One address |
| `10.20.1.10-10.20.1.50` | An inclusive address range |
| `10-11.30-33.1-2.3-50` | All IPv4 combinations of the four octet ranges (768 addresses) |
| `10.30.1.3-50` | Last-octet range with the other octets fixed |
| `10.20.1.5, 10.30.0.0/16` | A combination of addresses and subnets |
| `2001:db8::/64` | An IPv6 subnet |

Separate entries with commas, semicolons, spaces or newlines. Full address range endpoints must use the same IP version. Ranges are compared without expanding them into individual addresses, and overlapping entries do not double-count traffic.

IPv4 octet ranges use either a single value or an inclusive `low-high` range in each of the four positions. Each bound must be between 0 and 255, with the lower bound first. For example, `10-11.30-33.1-2.3-50` includes `10.30.1.3` and `11.33.2.50`, but excludes `10.34.1.3` and `10.30.1.51`. It is a combination of independent octet ranges, not one continuous interval between two addresses. You can mix it with IPs, CIDRs and full IPv4/IPv6 ranges in the same filter. Octet-range syntax is IPv4-only; IPv6 continues to use full addresses, CIDRs or full address ranges.

Subnet filters match source IP addresses recorded in the logs. NAT may hide the original subnet. Text identity labels are preserved as a whole; JSON identity arrays are split into individual entries. The application does not currently retrieve AD/Entra group membership.

### Explore individual transfers

Select a row or source IP in **Top source IP addresses** to open its individual log records. The detail panel preserves the displayed report's source, time interval, subnet/address filter, identity and traffic type. It shows 50 records per page. Select any column header to sort by time, destination, protocol/method, action, received bytes, sent bytes or total bytes. Select the same header again to reverse direction. The active column shows an arrow indicating the sort direction. Sorting applies to the full filtered result before pagination. IP addresses and destination ports use numeric ordering; missing values remain last in both directions.

Select a record's timestamp or row to expand it. The panel shows identities, exact counters and the available original fields, including destination IP/port, protocol or HTTP method, action, rule IDs and session timestamps. Proxy records can also include hostname, URL and HTTP status. Missing fields are explicitly marked; each row is a log record rather than an individual packet.

Older caches remain readable. Expanding an older record downloads only its source file from your configured S3 storage to backfill the available details. The application checks that the file still matches the cached records before attaching details. Normal synchronization skips unchanged files even if their details have not been cached yet. New or changed files include their details on import. S3 data is never changed.

Sorting uses the fields currently available in the local cache and does not download missing details just to sort. If loading details changes a destination/protocol/action sort, select **Refresh order** in the panel before moving to another page.

If the cache changes during browsing, refresh the main report before reopening the transfers. This prevents combining pages from different cache versions. Source-file paths and customer S3 prefixes are not included in detail responses. Fields longer than 16,384 characters are explicitly marked as truncated. Detailed fields, including URLs and identities, are stored in the local cache and should be treated as private report data.

### Measurement details

Firewall and proxy totals are **kept separate** because they measure different layers and may represent the same traffic.

| Log source | Counters |
| --- | --- |
| Cloud Firewall | `Bytes Sent` and `Bytes Received` |
| Web proxy | `Request Size` and `Response Size` |

`Response Body Size` is not added again. Missing counters are reported rather than treated as verified zero traffic. Units are decimal: 1 GB = 10^9 bytes.

Each record is assigned to the half-open interval `[from, to)` and an hourly bucket using its log timestamp. Bytes from a long-running session are not distributed across the duration of that session, so the chart does not necessarily represent instantaneous link utilization.

The form and displayed times use `Europe/Prague`; internal filters use UTC. During the autumn daylight-saving transition, local hours repeat. For this version, choose interval boundaries outside the repeated hour.

## Export reports

Use **Export report** above the summary cards to download the currently displayed report as **CSV**, **Excel (.xls)** or **PDF**. Exports use the displayed snapshot and its applied filters, even if you have edited the form without selecting **Show traffic**. Downloads are temporarily disabled while a new report is loading. Reports with no matching records can also be exported.

All three formats include:

- Source, IP/identity filter, traffic type and the exact selected UTC interval.
- Generation time, last complete synchronization and the source's available record range.
- Received, sent and total bytes, record count, average throughput, and missing/unclassified counter counts.
- Hourly byte values, up to 20 top source IPs and measurement/coverage notes. An ongoing or failed import is identified when known.

**CSV** is UTF-8 with a byte-order mark and semicolon separators. It contains labeled sections for metadata, summary, hourly data and top IPs, replacing the earlier hourly-only export. Text that could be interpreted as a spreadsheet formula is escaped.

**XLS** is a native Excel 97–2003 binary workbook, with numeric cells and Unicode text. It contains one formatted `Report` worksheet; external identity labels are stored as text, never formulas. No additional spreadsheet libraries are needed to run the application.

**PDF** downloads directly as a paginated A4 report, including the hourly chart and tables. Pages are rendered as images to preserve Czech characters and consistent layout across PDF viewers; text is not searchable or selectable. The chart uses `Europe/Prague`, while table timestamps are UTC. Tables include exact byte values; the displayed average rate is rounded to two decimal places.

Exports follow the current GUI language. They contain report data such as IP addresses and identities, but do not include S3 credentials or connection configuration. Report generation runs locally in the browser, without uploading data to an external service.

## History, import and limitations

The available-history panel shows the first and last cached record for the selected source and warns if the selected interval starts before the available history. Selecting 3, 7 or 30 days changes the reporting interval; it does not create older logs. Enabling S3 export today does not automatically provide a week of historical data.

After the initial connection or configuration restore, refresh data manually using the synchronization button. The importer:

- Checks all 62 date/source directories within the last 31 UTC days, including paginated S3 results. Up to four listing requests run concurrently, so late-arriving logs in older directories remain discoverable.
- Compares the S3 listing with the local key/ETag manifest and downloads only new or changed files. Missing detail fields in an otherwise unchanged cached file do not trigger a full re-download; they are fetched on demand when a transfer is expanded.
- Downloads up to four files concurrently into a private temporary directory. A single database writer parses one file at a time and commits each complete file atomically. The number of queued downloads is bounded. Newer date directories are prioritized.
- Displays separate progress for checking S3 folders, importing new/changed files and cleanup, followed by imported/unchanged file counts and elapsed time.
- Atomically replaces a file's old rows if its ETag changes.
- Keeps successfully imported files if another file fails, and reports an incomplete import.
- Deletes records and their details older than 31 days after a successful import. Recent empty-file manifests are retained to avoid downloading empty logs repeatedly; old manifests without cached records expire.

Supported formats include CSV with named headers and headerless v10/v17 files with exactly 34/40 firewall columns or 49/57 proxy columns. Mixed versions during a schema upgrade are supported. Other headerless layouts are rejected to avoid interpreting the wrong columns as byte counters.

A file may be up to 150 MB compressed. At most four compressed downloads are held in temporary storage (up to approximately 600 MB at the file-size limit). Compressed files are read from disk during parsing and temporary files are removed on completion or failure. This version keeps one parsed file and the selected report in memory; very large deployments still require streaming parsed rows and more scalable storage. Late events placed in directories outside the imported date window may be missed. The first and last record timestamps do not prove complete coverage. S3 contents are never modified.

## Configuration and credential storage

The application reads `config.json` and its referenced credentials file from a user-specific directory outside the project:

| Platform | Default directory |
| --- | --- |
| macOS | `~/Library/Application Support/CSA Traffic/` |
| Windows | `%LOCALAPPDATA%\CSA Traffic\` |
| Linux | `$XDG_CONFIG_HOME/csa-traffic/`, or `~/.config/csa-traffic/` |

`config.json` contains `s3Path`, `region` and `credentialsFile`. Relative credential paths are resolved against the configuration file's directory. The credentials file contains `accessKeyId` and `secretAccessKey`; it may be named `credentials.json` by the original setup or `credentials-<id>.json` by the GUI.

Key fields mask entered values. Files are stored outside the project, with mode `600` for files and `700` for the containing directory on macOS/Linux. These local JSON files are not an encrypted vault. Use encrypted configuration backups for portable copies, or your own secure backup system.

The SQLite cache is stored at `cache/<connection-fingerprint>/traffic.sqlite` within the configuration directory. It is separate for each bucket, prefix and region, and contains actual IP addresses and identities. Keep it out of shared packages. Removing it causes logs to be downloaded again on the next import.

No customer S3 organization or credentials are hardcoded. The files [config.example.json](config.example.json) and [credentials.example.json](credentials.example.json) contain placeholders only. Credentials are passed to curl through standard input and are not stored in the traffic cache.

### Optional command-line configuration

```sh
python3 app.py --setup
python3 app.py
```

On Windows, use `python` instead of `python3`.

| Option / environment variable | Purpose |
| --- | --- |
| `--config /path/config.json` / `CSA_CONFIG_FILE` | Override the configuration file location |
| `--credentials /path/credentials.json` / `CSA_CREDENTIALS_FILE` | Override the credentials file location |
| `--port` | Change the local HTTP port |
| `--open-browser` | Open the GUI when the server starts |

If curl is missing or too old, connection testing/import reports an error; existing cached data remains readable.

### Local API protections

Settings writes require a localhost Host header, an exact matching Origin and a CSRF token generated for the current server run. Settings JSON requests have a size limit. Testing does not persist credentials. Saving writes a new credentials file and atomically switches the configuration; a write failure preserves the previous configuration.

Replaced credentials files managed by the application are removed after a successful switch. If you back up local files directly, include the entire configuration directory rather than assuming the active file is always named `credentials.json`.

## Encrypted configuration backup and restore

### Create a backup

1. Open **S3 settings → Back up and restore configuration**.
2. Enter a password of at least 12 characters and repeat it.
3. Select **Download encrypted backup** to download a `.csabackup` file.

The backup contains the saved S3 path, region, both current access keys and the selected language. It excludes logs, cache, database contents and machine-specific absolute paths. Unsaved settings form edits are not included. Keep the password separately; the backup cannot be recovered without it.

### Restore on another computer

1. Download and start the application on the other computer.
2. Open the same backup panel, select the `.csabackup` file and enter its password.
3. Select **Restore and connect**.

Restore also works on a fresh installation without a saved connection. The application verifies S3 access before replacing the current configuration. An incorrect password, damaged file or failed connection check leaves the existing settings unchanged. Logs are imported again after a successful restore.

Restoring a backup does not renew or reactivate S3 keys. If they have expired or been rotated, supply the current credentials.

### Backup format

Encryption runs in the browser using Web Crypto: AES-256-GCM, a random 16-byte salt, a 12-byte IV, a 128-bit authentication tag and PBKDF2-SHA256 with 600,000 iterations. Format v1 accepts only these parameters.

The password is neither sent to the server nor stored. During an explicit backup request, credentials are retrieved into browser memory through a protected POST request and encrypted before download. Credentials are not saved to localStorage; the downloaded backup contains them only in encrypted form.

## Language and appearance

The dark GUI supports Czech and English through the header selector. The choice is saved in browser localStorage and synchronized between open application tabs. Switching languages preserves the current filters and interval.

Labels, charts, dynamic statistics, known error messages, empty states, measurement notes and CSV headers are localized. Numbers and application date labels follow the selected language; the time zone remains `Europe/Prague`. Native date controls may follow the browser or operating system language. Identity names, technical log field names and S3 error codes remain unchanged.

## Create a distributable ZIP

```sh
python3 export_app.py --output csa-traffic.zip
```

The export uses an explicit source-file allowlist. It includes the application, static assets, tests, launchers, documentation and example configuration. Actual configuration, credentials, databases, screenshots and log history are excluded. Share the ZIP with another user, who can configure their own S3 connection in the GUI.

To move your own connection to another computer, transfer a separate encrypted `.csabackup` file and keep its password separate.

## Development checks

Run from the repository root:

```sh
python3 -m unittest discover -s tests -v
node --check static/app.js
node tests/test_backup.js
node tests/test_exports.js
```

Node.js 18+ is needed only for the developer checks, not to run the application. The backup tests cover encryption/decryption, incorrect passwords, tampering, format validation and fresh randomness.
