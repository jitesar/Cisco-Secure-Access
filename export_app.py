#!/usr/bin/env python3
"""Create a distributable from an explicit allowlist, never a directory snapshot."""
import argparse
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parent
EXPORT_FILES=(
    'app.py','README.md','.gitignore','config.example.json','credentials.example.json',
    'Start.command','start.cmd','export_app.py',
    'static/time.js','static/filters.js','static/transfers.js','static/exports.js','static/backup.js','static/settings.js','static/index.html','static/app.js','static/i18n.js','static/style.css',
    'tests/test_time.js','tests/test_filters.js','tests/test_exports.js','tests/test_backup.js','tests/test_app.py',
)


def export(destination):
    destination=Path(destination).expanduser().resolve()
    destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name in EXPORT_FILES:
            source=ROOT/name
            if source.is_symlink() or not source.is_file():
                raise ValueError('Missing file or symlink in export allowlist: '+name)
            archive.write(source,'csa-traffic/'+name)
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError('Archive integrity verification failed')
    return destination


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,default=ROOT.parent/'output'/'csa-traffic-v0.11.zip')
    print(export(parser.parse_args().output))
