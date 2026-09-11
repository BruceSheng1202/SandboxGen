"""Synthetic data only: verify diagnostic offsets before interpreting a dump."""
import importlib.util
from pathlib import Path
import struct

import pytest

spec = importlib.util.spec_from_file_location('crash_parse', Path(__file__).with_name('crash_parse.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_amd64_exception_and_module(tmp_path):
    data = bytearray(2048)
    data[:4] = b'MDMP'
    struct.pack_into('<II', data, 8, 2, 32)
    struct.pack_into('<III', data, 32, 4, 112, 64)
    struct.pack_into('<III', data, 44, 6, 168, 256)
    struct.pack_into('<I', data, 64, 1)
    struct.pack_into('<QIIII', data, 68, 0x180000000, 0x10000, 0, 0, 180)
    name = 'C:\\task\\benign.dll'.encode('utf-16-le')
    struct.pack_into('<I', data, 180, len(name))
    data[184:184 + len(name)] = name
    struct.pack_into('<II', data, 264, 0xc0000005, 0)
    struct.pack_into('<Q', data, 280, 0x180001234)
    struct.pack_into('<I', data, 288, 2)
    struct.pack_into('<QQ', data, 296, 0, 0)
    struct.pack_into('<II', data, 416, 1232, 512)
    values = list(range(16)) + [0x180001234]
    struct.pack_into('<17Q', data, 632, *values)
    path = tmp_path / 'test.dmp'
    path.write_bytes(data)
    result = module.minidump(path)
    assert result['code'] == '0xc0000005'
    assert result['fault_location'] == {'module': 'C:\\task\\benign.dll', 'rva': '0x1234'}
    assert result['registers']['rip'] == '0x180001234'
    assert result['registers']['rsp'] == '0x4'
    assert result['parameters'] == ['0x0', '0x0']


def test_invalid_dump(tmp_path):
    path = tmp_path / 'test.dmp'
    path.write_bytes(b'not a minidump')
    with pytest.raises(ValueError, match='signature'):
        module.minidump(path)


@pytest.mark.parametrize('windows_names', [False, True])
def test_windows_and_posix_archive_paths(tmp_path, monkeypatch, windows_names):
    import json
    root = tmp_path / 'task'
    root.mkdir()
    if windows_names:
        event_path = root / 'diagnostics\\events.json'
    else:
        (root / 'diagnostics').mkdir()
        event_path = root / 'diagnostics' / 'events.json'
    event_path.write_text(json.dumps({'events': [], 'dumps': [], 'wer': {}}))
    monkeypatch.setattr(module, 'pe_summary', lambda _: {})
    result = module.parse(tmp_path)
    assert result['diagnostic_files'] == ['diagnostics/events.json']
    assert result['collection'] == {'dumps': [], 'wer': {}}


def test_duplicate_event_values_and_timestamp_are_preserved(tmp_path, monkeypatch):
    import json
    diag = tmp_path / 'task' / 'diagnostics'
    diag.mkdir(parents=True)
    raw = '<Event><TimeCreated SystemTime="2026-09-09T00:00:00Z"/><Data>first</Data><Data>second</Data></Event>'
    (diag / 'events.json').write_text(json.dumps({'events': [raw]}))
    monkeypatch.setattr(module, 'pe_summary', lambda _: {})
    fields = module.parse(tmp_path)['events'][0]['fields']
    assert fields[0]['attributes'] == {'SystemTime': '2026-09-09T00:00:00Z'}
    assert [f['text'] for f in fields if f['tag'] == 'Data'] == ['first', 'second']


def test_unloaded_module_list(tmp_path):
    data = bytearray(256)
    data[:4] = b'MDMP'
    struct.pack_into('<II', data, 8, 1, 32)
    struct.pack_into('<III', data, 32, 14, 36, 64)
    struct.pack_into('<III', data, 64, 12, 24, 1)
    struct.pack_into('<QIIII', data, 76, 0x180000000, 0x10000, 0, 0, 128)
    name = 'benign.dll'.encode('utf-16-le')
    struct.pack_into('<I', data, 128, len(name))
    data[132:132 + len(name)] = name
    path = tmp_path / 'unloaded.dmp'
    path.write_bytes(data)
    result = module.minidump(path)
    assert result['unloaded_modules'] == [{'name': 'benign.dll', 'base': 0x180000000, 'size': 0x10000}]
