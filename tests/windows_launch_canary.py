"""Benign native PE canaries for the real isolated Windows backend.

Run on a Slurm compute node only. No malware, compiler, model API, network
traffic or guest configuration changes outside the disposable COW overlay.
The tiny EXE returns immediately; the DLL has a TRUE DllMain and a no-op
rundll32-compatible export. x86/x64 DLLs exercise both system loaders.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from core.qemu_backend import QemuCapeClient, QemuConfig


def benign_pe(*, dll=False, x86=False):
    data = bytearray(0x600 if dll else 0x400)
    def put(offset, fmt, *values):
        struct.pack_into('<' + fmt, data, offset, *values)
    data[:2] = b'MZ'; put(0x3c, 'I', 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 224 if x86 else 240
    put(0x84, 'HHIIIHH', 0x14c if x86 else 0x8664, 2 if dll else 1,
        0, 0, 0, optional_size, (0x2102 if x86 else 0x2022) if dll else 0x22)
    opt = 0x98
    put(opt, 'H', 0x10b if x86 else 0x20b)
    put(opt+4, 'III', 0x200, 0x200 if dll else 0, 0)
    put(opt+16, 'II', 0x1000, 0x1000)
    if x86:
        put(opt+24, 'II', 0x2000, 0x10000000 if dll else 0x400000)
    else:
        put(opt+24, 'Q', 0x180000000 if dll else 0x140000000)
    put(opt+32, 'II', 0x1000, 0x200)
    put(opt+40, 'HHHHHH', 6, 0, 0, 0, 6, 0)
    put(opt+56, 'II', 0x3000 if dll else 0x2000, 0x200)
    put(opt+68, 'HH', 3, 0)
    if x86:
        put(opt+72, 'IIIIII', 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        directory = opt+96
    else:
        put(opt+72, 'QQQQII', 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        directory = opt+112
    sec = opt+optional_size
    data[sec:sec+8] = b'.text\0\0\0'
    put(sec+8, 'IIIIIIHHI', 0x20, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    if dll:
        # DllMain returns TRUE; stdcall on x86 pops its three arguments.
        code = b'\xb8\x01\x00\x00\x00' + (b'\xc2\x0c\x00' if x86 else b'\xc3')
        data[0x200:0x200+len(code)] = code
        code = b'\xc2\x10\x00' if x86 else b'\xc3'  # void CALLBACK CanaryEntry(...)
        data[0x210:0x210+len(code)] = code
        sec += 40; data[sec:sec+8] = b'.edata\0\0'
        put(sec+8, 'IIIIIIHHI', 0x80, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040)
        put(directory, 'II', 0x2000, 0x80)
        put(0x400, 'IIHHIIIIIII', 0, 0, 0, 0, 0x2040, 1, 1, 1, 0x2028, 0x202c, 0x2030)
        put(0x428, 'IIH', 0x1010, 0x2060, 0)
        data[0x440:0x44b] = b'canary.dll\0'
        data[0x460:0x46c] = b'CanaryEntry\0'
    else:
        data[0x200:0x203] = b'\x31\xc0\xc3'  # xor eax,eax; ret
    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vm-dir', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    cfg = QemuConfig(qemu_vm_dir=str(args.vm_dir), qemu_task_dir=str(args.work / 'tasks'), timeout=20)
    client = QemuCapeClient(cfg, connect=False)
    # No Linux guest needed for this Windows-only canary. All submission,
    # container launch, collection, attribution and cleanup use production code.
    client._connected = True; client.podman = ['podman']
    client.win_golden = args.vm_dir / 'win-golden.qcow2'
    client.win_state = args.vm_dir / 'win-state.gz'
    client.task_root = args.work / 'tasks'; client.task_root.mkdir(exist_ok=True)
    results = []
    for name, dll, x86 in [('canary.47428979', False, False),
                            ('canary x64.dll', True, False), ('canary x86.dll', True, True)]:
        path = args.work / name; path.write_bytes(benign_pe(dll=dll, x86=x86))
        options = {'package': 'dll' if dll else 'exe', 'timeout': 20, 'route': 'drop'}
        if dll:
            options['options'] = 'function=CanaryEntry'
        print('CANARY_START', name, flush=True)
        task = client.submit_file(str(path), options)
        report = client.get_report(task)
        quality = client.report_has_signal(report)
        (args.output / (name + '.report.json')).write_text(json.dumps(report, indent=2))
        passed = quality['execution_valid'] is True and report['sandboxgen'].get('launcher_version') == 1
        if dll:
            expected = 'syswow64' if x86 else 'system32'
            passed = passed and expected in report['sandboxgen'].get('launch_executable', '').lower()
        task_dir = client.task_root / str(task)
        cleaned = not any((task_dir / junk).exists() for junk in ('sample', 'overlay.qcow2', 'result.zip', 'task'))
        result = {'name': name, 'passed': passed, 'quality': quality, 'cleanup_ok': cleaned,
                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        results.append(result)
        print('CANARY_RESULT', json.dumps(result), flush=True)
    (args.output / 'summary.json').write_text(json.dumps(results, indent=2))
    return 0 if all(r['passed'] and r['cleanup_ok'] for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
