"""Offline tests for Windows report shaping helpers (no QEMU required)."""

from __future__ import annotations

import importlib.util
import struct
import json
from unittest.mock import mock_open, patch

import pytest
from pathlib import Path


MODULE_PATH = (Path(__file__).resolve().parents[1] / "src" / "sandbox_infra" /
               "qemu" / "win_detonate.py")
SPEC = importlib.util.spec_from_file_location("win_detonate_test_module", MODULE_PATH)
win = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(win)


def _pcap(packet: bytes, linktype: int = 1) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    record = struct.pack("<IIII", 0, 0, len(packet), len(packet))
    return header + record + packet


def test_parse_pcap_extracts_ipv4_syn(tmp_path):
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ipv4 = (b"\x45\x00" + struct.pack("!H", 40) + b"\x00\x00\x00\x00" +
            b"\x40\x06\x00\x00" + bytes([10, 0, 2, 15]) + bytes([1, 2, 3, 4]))
    tcp = struct.pack("!HHII", 50000, 443, 0, 0) + b"\x50\x02" + b"\x00" * 6
    path = tmp_path / "net.pcap"
    path.write_bytes(_pcap(ethernet + ipv4 + tcp))

    dns, syns = win._parse_pcap(path)

    assert dns == []
    assert syns == ["1.2.3.4:443"]


def test_parse_pcap_rejects_unknown_magic_and_linktype(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not-pcap" + b"\x00" * 40)
    assert win._parse_pcap(path) == ([], [])

    path.write_bytes(_pcap(b"\x00" * 64, linktype=113))
    assert win._parse_pcap(path) == ([], [])


def test_endpoint_host_preserves_ipv6_address():
    assert win._endpoint_host("1.2.3.4:443") == "1.2.3.4"
    assert win._endpoint_host("[2001:db8::1]:443") == "2001:db8::1"
    assert win._endpoint_host("2001:db8::1:443") == "2001:db8::1"


def test_sandbox_metadata_merge_preserves_health_error():
    report = {"sandboxgen": {"error": "guest timeout was too short"}}

    win._update_sandboxgen(report, {"timed_out": True, "guest_waited_s": 28})

    assert report["sandboxgen"]["error"] == "guest timeout was too short"
    assert report["sandboxgen"]["guest_waited_s"] == 28


def test_background_noise_is_not_returned_as_sample_behavior():
    procs = {
        "10": {"pid": "10", "image": r"C:\task\sample.exe"},
        "11": {"pid": "11", "image": r"C:\Windows\System32\msiexec.exe"},
        "99": {"pid": "99", "image": r"C:\Windows\System32\schtasks.exe"},
    }
    tree = {"10", "11"}

    tree_procs, summary, background = win._shape_attributed_behavior(
        procs, tree, [r"C:\Users\analyst\drop.bin"], [r"HKU\sample"],
        {("10", "own"), ("99", "noise")},
        {("10", "own"), ("99", "noise")},
    )

    assert [p["pid"] for p in tree_procs] == ["10", "11"]
    assert "background_processes" not in summary
    assert background == {
        "processes": [r"C:\Windows\System32\schtasks.exe"],
        "file_written_count": 1,
        "regkey_written_count": 1,
    }


@pytest.mark.parametrize("image", ["OpenWith.exe", "schtasks.exe", "cmd.exe", "smartscreen.exe"])
def test_path_mention_is_not_sample_root(image):
    procs = {"1": {"pid": "1", "image": "C:\\Windows\\System32\\" + image,
                    "cmdline": r'helper "C:\task\sample.exe"'}}
    assert win._sample_tree(procs, "sample.exe") == set()


def test_exact_exe_image_and_descendants_are_attributed():
    procs = {"1": {"pid": "1", "image": r"C:\task\Order no. 1.exe", "cmdline": ""},
             "2": {"pid": "2", "ppid": "1", "image": r"C:\Windows\System32\cmd.exe"},
             "3": {"pid": "3", "image": r"C:\task\Order no. 1.exe.bak"}}
    assert win._sample_tree(procs, "Order no. 1.exe") == {"1", "2"}


def test_dll_requires_expected_loader_entry_and_image_load():
    p = {"pid": "1", "image": r"C:\Windows\System32\rundll32.exe",
         "cmdline": r'rundll32.exe "C:\task\test dll.dll",TestEntry'}
    launch = {"package": "dll", "function": "TestEntry", "architecture": "x64"}
    assert win._sample_tree({"1": p}, "test dll.dll", launch) == set()
    p["loaded_images"] = [r"C:\task\test dll.dll"]
    assert win._sample_tree({"1": p}, "test dll.dll", launch) == {"1"}
    assert win._sample_tree({"1": p}, "test dll.dll", {**launch, "function": "Other"}) == set()
    assert win._sample_tree({"1": p}, "test dll.dll", {**launch, "architecture": "x86"}) == set()


def test_parse_sysmon_image_load(tmp_path):
    path = tmp_path / "sysmon.xml"
    path.write_text('''<Event><System><EventID>1</EventID></System><EventData>
<Data Name="ProcessId">1</Data><Data Name="Image">C:\\Windows\\System32\\rundll32.exe</Data>
</EventData></Event><Event><System><EventID>7</EventID></System><EventData>
<Data Name="ProcessId">1</Data><Data Name="ImageLoaded">C:\\task\\test.dll</Data>
</EventData></Event>''')
    procs = win._parse_sysmon_xml(path)[0]
    assert procs["1"]["loaded_images"] == [r"C:\task\test.dll"]


def test_launch_parameters_are_json_not_command_text(monkeypatch):
    calls = []
    monkeypatch.setattr(win, "_http", lambda method, path, **kw: calls.append((path, kw)) or {"exit_code": 0})
    launch = {"version": 1, "package": "dll", "architecture": "x86", "function": "TestEntry"}
    with patch("builtins.open", mock_open(read_data=b"trusted runner")):
        digest = win._start_sample({"name": "test dll.dll", "launch": launch})
    request = json.loads(calls[1][1]["data"])
    assert request["launch"] == launch
    assert request["path"] == r"C:\task\test dll.dll"
    command = json.loads(calls[2][1]["data"])["cmd"]
    assert "test dll.dll" not in command and "TestEntry" not in command
    assert calls[2][0] == "/run" and len(digest) == 64


def test_legacy_launch_metadata_refused():
    with pytest.raises(ValueError, match="validated launch"):
        win._start_sample({"name": "sample.exe"})


@pytest.mark.parametrize("change", [{"launcher_version": None}, {"launch_error": "error"},
    {"waited_s": 0}, {"export_error": "error"}, {"wait_error": "error"}])
def test_health_rejects_launch_and_collection_failure(change):
    run = {"launcher_version": 1, "waited_s": win.TIMEOUT, **change}
    assert win._execution_health(run, {"1"})["execution_valid"] is False


def test_health_requires_real_sample_and_accepts_short_lived_root():
    run = {"launcher_version": 1, "waited_s": win.TIMEOUT, "root_exited_s": 0.2}
    assert win._execution_health(run, set())["execution_valid"] is False
    assert win._execution_health(run, {"1"})["execution_valid"] is True
