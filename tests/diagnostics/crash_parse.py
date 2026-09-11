"""Parse untrusted PE/dumps ONLY inside the isolated analysis container."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import xml.etree.ElementTree as ET


def pe_summary(path, focus=None):
    import pefile
    pe = pefile.PE(str(path))
    base = pe.OPTIONAL_HEADER.ImageBase
    exports = [{'name': (e.name or b'').decode(errors='replace'), 'rva': hex(e.address),
                'forwarder': (e.forwarder or b'').decode(errors='replace')}
               for e in getattr(pe, 'DIRECTORY_ENTRY_EXPORT', type('Empty', (), {'symbols': []})) .symbols]
    targets = [e for e in exports if e['name'] == 'WinHttpOpen']
    targets.append({'name': 'PE entry', 'rva': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)})
    targets.append({'name': 'text start', 'rva': hex(pe.OPTIONAL_HEADER.BaseOfCode)})
    if hashlib.sha256(path.read_bytes()).hexdigest() == 'a4c6bcde72216f0168d6356410960d9cb0f648e31fd9ead093f32119e4157cbb':
        for name, rva in [('attach setup', 0x3530), ('attach tail', 0x3580),
                          ('work callback', 0x3b90), ('thread callback', 0x3da0)]:
            targets.append({'name': name, 'rva': hex(rva)})
    if focus is not None:
        targets.append({'name': 'fault', 'rva': hex(focus)})
    asm = {}
    for t in targets:
        address = base + int(t['rva'], 16)
        result = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
                                 f'--start-address={address}', f'--stop-address={address + 320}', str(path)],
                                capture_output=True, text=True, timeout=20, check=True)
        asm[t['name']] = result.stdout
    return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'base': hex(base),
            'exports': exports, 'disassembly': asm,
            'imports': [{'dll': entry.dll.decode(errors='replace'),
                         'symbols': [{'name': (item.name or b'').decode(errors='replace'),
                                      'iat_rva': hex(item.address - base)} for item in entry.imports]}
                        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])]}


def minidump(path):
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('dump exceeds diagnostic size bound')
    data = path.read_bytes()

    def unpack(fmt, offset):
        return struct.unpack_from('<' + fmt, data, offset)

    if data[:4] != b'MDMP':
        raise ValueError('invalid dump signature')
    count, directory = unpack('II', 8)
    if count > 256:
        raise ValueError('too many streams')
    streams = {}
    for i in range(count):
        kind, size, rva = unpack('III', directory + i * 12)
        if rva + size > len(data):
            raise ValueError('invalid stream range')
        streams[kind] = (rva, size)
    modules = []

    def module_name(name_rva):
        length, = unpack('I', name_rva)
        if length > 8192 or name_rva + 4 + length > len(data):
            raise ValueError('invalid module name')
        return data[name_rva + 4:name_rva + 4 + length].decode('utf-16-le', errors='replace')

    if 4 in streams:
        rva, _ = streams[4]
        n, = unpack('I', rva)
        if n > 4096:
            raise ValueError('too many modules')
        for i in range(n):
            address, size, checksum, stamp, name_rva = unpack('QIIII', rva + 4 + i * 108)
            modules.append({'name': module_name(name_rva), 'base': address, 'size': size})
    unloaded = []
    if 14 in streams:
        rva, stream_size = streams[14]
        header, entry_size, n = unpack('III', rva)
        if header < 12 or entry_size < 24 or n > 4096 or header + entry_size * n > stream_size:
            raise ValueError('invalid unloaded modules')
        for i in range(n):
            address, size, checksum, stamp, name_rva = unpack('QIIII', rva + header + i * entry_size)
            unloaded.append({'name': module_name(name_rva), 'base': address, 'size': size})

    def location(address):
        for module in modules:
            if module['base'] <= address < module['base'] + module['size']:
                return {'module': module['name'], 'rva': hex(address - module['base'])}
        for module in unloaded:
            if module['base'] <= address < module['base'] + module['size']:
                return {'module': module['name'], 'rva': hex(address - module['base']), 'unloaded': True}
        return None

    result = {'name': path.name, 'size': len(data), 'modules': modules, 'unloaded_modules': unloaded,
              'stream_types': sorted(streams)}
    if 6 not in streams:
        return result
    offset, _ = streams[6]
    code, flags = unpack('II', offset + 8)
    address, = unpack('Q', offset + 24)
    params, = unpack('I', offset + 32)
    info = list(unpack('Q' * min(params, 15), offset + 40))
    context_size, context_rva = unpack('II', offset + 160)
    if context_size < 256:
        raise ValueError('not an AMD64 context')
    names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9',
             'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip']
    registers = dict(zip(names, unpack('Q' * 17, context_rva + 120)))
    result.update(code=hex(code), address=hex(address), fault_location=location(address),
                  parameters=[hex(v) for v in info], registers={k: hex(v) for k, v in registers.items()})
    # Stack values annotated against module ranges, NOT a claimed unwind.
    ranges = []
    if 5 in streams:
        rva, _ = streams[5]
        n, = unpack('I', rva)
        if n > 65536:
            raise ValueError('too many memory ranges')
        for i in range(n):
            start, size, pos = unpack('QII', rva + 4 + i * 16)
            ranges.append((start, size, pos))
    if 9 in streams:
        rva, _ = streams[9]
        n, pos = unpack('QQ', rva)
        if n > 65536:
            raise ValueError('too many memory ranges')
        for i in range(n):
            start, size = unpack('QQ', rva + 16 + i * 16)
            ranges.append((start, size, pos))
            pos += size
    stack = []
    rsp = registers['rsp']
    for start, size, pos in ranges:
        if start <= rsp < start + size:
            for delta in range(0, min(512, start + size - rsp) - 7, 8):
                value, = unpack('Q', pos + rsp - start + delta)
                stack.append({'offset': hex(delta), 'value': hex(value), 'location': location(value)})
            break
    result['stack_words_not_unwind'] = stack
    return result


def parse(task):
    result = {'sample': pe_summary(task / 'sample'), 'events': [], 'dumps': [],
              'parser_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    root = task / 'task'
    # Windows .NET's archive may use backslashes, which POSIX zipfile keeps as
    # literal filename characters. Accept either archive convention read-only.
    files = {str(p.relative_to(root)).replace('\\', '/'): p for p in root.rglob('*') if p.is_file()}
    result['diagnostic_files'] = sorted(k for k in files if k.startswith('diagnostics/'))
    if 'diagnostics/events.json' in files:
        events = json.loads(files['diagnostics/events.json'].read_text(encoding='utf-8-sig'))
        for raw in events.pop('events', []):
            root = ET.fromstring(raw)
            # Preserve duplicate unnamed <Data> values (WER 1001 uses them).
            fields = [{'tag': node.tag.rsplit('}', 1)[-1], 'attributes': dict(node.attrib), 'text': node.text}
                      for node in root.iter() if node.attrib or (node.text and node.text.strip())]
            result['events'].append({'fields': fields})
        result['collection'] = events
    for name, path in sorted(files.items()):
        if not name.startswith('diagnostics/') or not name.lower().endswith('.dmp'):
            continue
        dump = minidump(path)
        result['dumps'].append(dump)
        fault = dump.get('fault_location') or {}
        sample_name = json.loads((task / 'meta.json').read_text())['name']
        if fault.get('module', '').lower() == ('c:\\task\\' + sample_name).lower():
            result['sample_fault'] = pe_summary(task / 'sample', int(fault['rva'], 16))
        if fault.get('module', '').lower() == 'c:\\windows\\system32\\winhttp.dll':
            result['system_fault'] = pe_summary(files['diagnostics/system-winhttp.dll'], int(fault['rva'], 16))
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--task', type=Path, default=Path('/task'))
    args = p.parse_args()
    print(json.dumps(parse(args.task), indent=2))
