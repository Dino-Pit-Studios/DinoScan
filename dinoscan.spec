# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for DinoScan standalone executable

a = Analysis(
    ['dinoscan_cli.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.json', '.'),
        ('README.md', '.'),
        ('core', 'core'),
        ('analyzers', 'analyzers'),
    ],
    hiddenimports=[
        'dinoscan.core.ast_analyzer',
        'dinoscan.core.base_analyzer', 
        'dinoscan.core.config_manager',
        'dinoscan.core.file_scanner',
        'dinoscan.core.reporter',
        'dinoscan.analyzers.advanced_security_analyzer',
        'dinoscan.analyzers.circular_import_analyzer',
        'dinoscan.analyzers.dead_code_analyzer',
        'dinoscan.analyzers.doc_quality_analyzer',
        'dinoscan.analyzers.duplicate_code_analyzer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='dinoscan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)