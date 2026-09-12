"""Regression inputs from the Linux/Windows consistency audit; no guests/APIs."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace
from unittest.mock import Mock, mock_open, patch

import pytest

from test_qemu_backend import _client, _elf, _elf_header, _pe_header, _win_client, vm_dir
from test_pipeline_smoke import _build, _call, FakeCAPE, sample
from core.agent_loop import AgentLoop
from core.backend_contract import publish_backend_facts, submission_problems
from core.env_spec import EnvironmentSpec
from core.qemu_backend import QemuCapeClient
from core.run_context import RunContext
from core.spec_policy import SpecPermissionError
from core.workflow_log import WorkflowLog
from agents.executor import ExecutorAgent, AGENT_IP_LINUX


SRC = Path(__file__).resolve().parents[1] / "src"
loader = importlib.util.spec_from_file_location("linux_collector_consistency", SRC / "sandbox_infra/qemu/detonate.py")
linux = importlib.util.module_from_spec(loader)
with patch("builtins.open", mock_open(read_data='{"name":"sample.elf","sha256":"fixture"}')):
    loader.loader.exec_module(linux)


def trace_at(tmp_path, text):
    path = tmp_path / "strace.log"
    path.write_text(text)
    return linux._parse_strace(str(path))


@pytest.mark.parametrize("payload", [b"\x7fE", b"\x7fELF", _elf_header(machine=183), _elf_header(machine=3)])
def test_linux_rejects_invalid_or_incompatible_headers_before_staging(vm_dir, payload):
    path = vm_dir / "invalid.elf"
    path.write_bytes(payload)
    client = _client(vm_dir, {})
    with pytest.raises(ValueError):
        client.submit_file(str(path), {"package": "elf"})
    assert not client._tasks


@pytest.mark.parametrize("machine,elf_class", [(62, 2), (3, 1)])
def test_linux_supports_both_deployed_x86_abis(vm_dir, machine, elf_class):
    path = vm_dir / "sample.elf"
    path.write_bytes(_elf_header(machine=machine, elf_class=elf_class))
    assert _client(vm_dir, {}).validate_submission(str(path), {"package": "elf"})["guest_os"] == "linux"


@pytest.mark.parametrize("platform", ["linux", "windows"])
@pytest.mark.parametrize("field,value", [("platform", "wrong-os"), ("machine", "wrong-vm"), ("package", "wrong-package")])
def test_both_platforms_reject_incompatible_requests(vm_dir, platform, field, value):
    client = _win_client(vm_dir, {})
    path = Path(_elf(vm_dir)) if platform == "linux" else vm_dir / "sample.exe"
    if platform == "windows":
        path.write_bytes(_pe_header())
    options = {"platform": platform, "machine": "qemu-" + platform,
               "package": "elf" if platform == "linux" else "exe", field: value}
    with pytest.raises(ValueError):
        client.submit_file(str(path), options)
    assert not client._tasks


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_unimplemented_options_are_visible_on_both_platforms(vm_dir, platform):
    client = _win_client(vm_dir, {})
    path = Path(_elf(vm_dir)) if platform == "linux" else vm_dir / "sample.exe"
    if platform == "windows":
        path.write_bytes(_pe_header())
    tid = client.submit_file(str(path), {"memory": True, "options": "human=1,force-sleepskip=1"})
    details = client.submission_details(tid)
    assert set(client.submission_warnings(tid)) >= {"memory=True", "human=1", "force-sleepskip=1"}
    assert details["effective"]["memory_dump"] is False
    assert details["effective"]["platform"] == platform


def test_failed_syscalls_never_become_successful_behavior(tmp_path):
    trace = trace_at(tmp_path,
        '123 10.0 openat(AT_FDCWD, "/etc/example", O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission denied)\n'
        '123 10.1 execve("/tmp/task/sample.elf", ["sample.elf"], 0x0) = -1 ENOEXEC (Exec format error)\n'
        '123 10.2 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ECONNREFUSED (Connection refused)\n')
    assert trace["summary"]["file_written"] == []
    assert trace["summary"]["executed"] == []
    assert trace["summary"]["file_write_attempted"] == ["/etc/example"]
    assert [event["errno"] for event in trace["events"]] == ["EACCES", "ENOEXEC", "ECONNREFUSED"]
    assert trace["connections"][0]["established"] is False
    health = linux._execution_health(trace, {"exit_code": 1}, "/tmp/task/sample.elf")
    assert health["execution_valid"] is False


def test_open_for_write_is_distinct_from_positive_byte_write(tmp_path):
    trace = trace_at(tmp_path,
        '123 10.0 openat(AT_FDCWD, "/etc/open-only", O_WRONLY|O_CREAT, 0644) = 3</etc/open-only>\n'
        '123 10.1 write(4</etc/written>, "ok", 2) = 2\n'
        '123 10.2 write(5</etc/failed>, "no", 2) = -1 EACCES (Permission denied)\n')
    assert trace["summary"]["file_written"] == ["/etc/written"]
    assert trace["summary"]["file_opened_for_write"] == ["/etc/open-only"]


@pytest.mark.parametrize("descriptor,path,device", [
    ("/dev/null<char 1:3>", "/dev/null", "char"),
    ("/dev/loop0<block 7:0>", "/dev/loop0", "block"),
    ("/tmp/name<literal>", "/tmp/name<literal>", None),
])
@pytest.mark.parametrize("returned", ["2", "0", "-1 EBADF (Bad file descriptor)"])
def test_fd_device_annotations_do_not_pollute_paths(tmp_path, descriptor, path, device, returned):
    trace = trace_at(tmp_path, f'123 10.1 write(4<{descriptor}>, "ok", 2) = {returned}\n')
    assert trace["events"][0]["path"] == path
    assert trace["events"][0].get("device_type") == device
    assert trace["summary"]["file_write_attempted"] == [path]
    assert trace["summary"]["file_written"] == ([path] if returned == "2" else [])


def test_resumed_exec_and_nonzero_sample_exit_still_prove_startup(tmp_path):
    trace = trace_at(tmp_path,
        '123 10.0 execve("/tmp/task/sample.elf", ["sample.elf"], 0x0 <unfinished ...>\n'
        '124 10.1 getpid() = 124\n'
        '123 10.2 <... execve resumed>) = 0\n')
    health = linux._execution_health(trace, {"exit_code": 7}, "/tmp/task/sample.elf")
    assert health["execution_valid"] is True
    assert health["sample_process_root_pids"] == [123]


def test_script_startup_requires_the_selected_interpreter_and_sample(tmp_path):
    trace = trace_at(tmp_path,
        '123 10.0 execve("/bin/sh", ["/bin/sh", "/tmp/task/sample.sh"], 0x0) = 0\n')
    assert linux._execution_health(trace, {"exit_code": 0}, "/tmp/task/sample.sh", "/bin/sh")["execution_valid"]
    assert not linux._execution_health(trace, {"exit_code": 0}, "/tmp/task/other.sh", "/bin/sh")["execution_valid"]


def test_udp_and_unknown_socket_connect_are_not_declared_tcp(tmp_path):
    trace = trace_at(tmp_path,
        '123 10.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 3\n'
        '123 10.1 connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.1")}, 16) = 0\n'
        '123 10.2 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.2")}, 16) = 0\n')
    assert [c["protocol"] for c in trace["connections"]] == ["udp", "unknown"]
    assert all(c["established"] is None for c in trace["connections"])


def test_socket_reuse_and_non_tcp_streams_do_not_inherit_tcp_labels(tmp_path):
    trace = trace_at(tmp_path,
        '123 10.0 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3\n'
        '123 10.1 close(3) = 0\n'
        '123 10.2 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.1")}, 16) = 0\n'
        '123 10.3 socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) = 4\n'
        '123 10.4 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.2")}, 16) = 0\n')
    assert [c["protocol"] for c in trace["connections"]] == ["unknown", "unknown"]


@pytest.mark.parametrize("exec_result,valid", [("0", True), ("-1 ENOEXEC (Exec format error)", False)])
def test_linux_collector_to_backend_execution_gate(tmp_path, monkeypatch, exec_result, valid):
    task = tmp_path / "collection"
    task.mkdir()
    (task / "sample").write_bytes(b"inert")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tf:
        for name, body in {
            "task/run.json": json.dumps({"exit_code": 1, "timed_out": False}).encode(),
            "task/strace.log": f'123 10.0 execve("/tmp/task/sample.elf", ["sample.elf"], 0x0) = {exec_result}\n'.encode(),
        }.items():
            item = tarfile.TarInfo(name)
            item.size = len(body)
            tf.addfile(item, io.BytesIO(body))
    monkeypatch.setattr(linux, "TASK", str(task))
    monkeypatch.setattr(linux, "meta", {"name": "sample.elf", "sha256": "fixture", "package": "elf"})
    monkeypatch.setattr(linux, "subprocess", SimpleNamespace(run=Mock(), Popen=lambda *a, **k: Mock()))
    monkeypatch.setattr(linux, "socket", SimpleNamespace(AF_UNIX=1, socket=lambda *a: Mock()))
    monkeypatch.setattr(linux, "_wait_ready", lambda *a: True)
    monkeypatch.setattr(linux, "_parse_pcap", lambda *a: ([], []))
    monkeypatch.setattr(linux, "_http", lambda method, path, **kw: archive.getvalue() if path == "/result" else {"state": "done"})
    assert linux.main() == 0
    report = json.loads((task / "report.json").read_text())
    quality = QemuCapeClient.report_has_signal(None, report)
    assert quality["execution_valid"] is valid
    assert quality["has_signal"] is valid


def test_old_linux_report_does_not_certify_execution_from_a_pid_or_timeout():
    report = {"backend": "qemu-tcg", "behavior": {"processes": [{"pid": 123}]},
              "signatures": [{"name": "long_running_or_timeout"}], "sandboxgen": {"exit_code": 1}}
    assert QemuCapeClient.report_has_signal(None, report)["execution_valid"] is False


def test_capabilities_describe_only_configured_platforms(vm_dir):
    client = _client(vm_dir, {})
    caps = client.capabilities()
    assert caps["platforms"] == ["linux"]
    assert caps["windows_packages"] == []
    assert "elf" in caps["linux_packages"]
    assert caps["linux_scripts"][".py"] == "/usr/bin/python3"
    assert "windows" in _win_client(vm_dir, {}).capabilities()["platforms"]


def executor_for(tmp_path, client):
    spec = EnvironmentSpec(tmp_path, "platform")
    ctx = RunContext(run_id="platform", workspace=tmp_path)
    log = WorkflowLog(tmp_path, "platform")
    return ExecutorAgent(spec, log, None, tmp_path, architect=Mock(), cape_client=client, ctx=ctx, host_ops=Mock())


def test_qemu_health_and_recovery_never_call_docker_or_legacy_host_ops(vm_dir, monkeypatch):
    client = _client(vm_dir, {})
    ex = executor_for(vm_dir, client)
    publish_backend_facts(ex.spec, client)
    ex.spec.set("sample.os_target", "linux", actor="controller")
    ex.spec.set("cape_submission.platform", None, actor="controller")
    assert ex._vm_for_platform() == "qemu-linux"
    assert ex._agent_ip_for_platform() == AGENT_IP_LINUX
    loop = AgentLoop(None, "x", ex.spec, ex.log, "Executor", cape_client=client, ctx=ex.ctx)
    monkeypatch.setattr("core.agent_loop.subprocess.run", lambda *a, **k: pytest.fail("legacy process invoked"))
    assert json.loads(loop._tool_cape_service_check())["ready"] is True
    assert "per submission" in loop._tool_cape_vm_start("qemu-linux")
    ex._diagnose_failure()
    assert ex.host_ops.mock_calls == []
    monkeypatch.setattr(ex, "_run", lambda: {"passes_completed": 0})
    monkeypatch.setattr(ex.ctx, "acquire_vm_lease", lambda *a: pytest.fail("legacy VM lease used"))
    assert ex.run() == {"passes_completed": 0}


def test_unknown_platform_is_not_silently_windows(tmp_path):
    ex = executor_for(tmp_path, FakeCAPE())
    with pytest.raises(ValueError, match="platform"):
        ex._vm_for_platform()


def test_qemu_timeout_recovery_handles_null_without_inventing_features(vm_dir):
    client = _client(vm_dir, {})
    ex = executor_for(vm_dir, client)
    publish_backend_facts(ex.spec, client)
    ex.spec.set("cape_submission.timeout", None, actor="controller")
    ex.spec.set("cape_submission.options", None, actor="controller")
    assert ex._fix_timeout_no_data()
    assert ex.spec.get("cape_submission.timeout") == 180
    assert ex.spec.get("cape_submission.options") == ""
    assert ex.spec.get("cape_submission.memory") is False


def test_qemu_missing_report_does_not_wait_for_legacy_processing(vm_dir, monkeypatch):
    ex = executor_for(vm_dir, _client(vm_dir, {}))
    monkeypatch.setattr("agents.executor.time.sleep", lambda *a: pytest.fail("waiting for nonexistent CAPE processor"))
    assert ex._fix_report_missing() is False
    assert ex.host_ops.mock_calls == []


@pytest.mark.parametrize("fixed", [False, True])
def test_submission_recovery_requires_a_valid_corrected_plan(vm_dir, fixed):
    client = _client(vm_dir, {})
    ex = executor_for(vm_dir, client)
    ex.ctx.bind_sample(Path(_elf(vm_dir)))
    publish_backend_facts(ex.spec, client)
    for key, value in {"package": "elf", "platform": "linux", "machine": "qemu-linux", "timeout": 60}.items():
        ex.spec.set("cape_submission." + key, value, actor="Architect")
    ex.spec.set("cape_submission.error", "unsupported dependency", actor="Architect")

    def adjust(reason):
        if fixed:
            ex.spec.set("cape_submission.error", None, actor="Architect")
        return {"finished": True}

    ex.architect.adjust.side_effect = adjust
    assert ex._fix_submission_error() is fixed
    assert bool(ex.spec.get("cape_submission.validation_errors")) is not fixed


def test_pass_one_adjustment_cannot_bypass_configuration_validation(vm_dir):
    ex = executor_for(vm_dir, _client(vm_dir, {}))
    ex.ctx.bind_sample(Path(_elf(vm_dir)))
    ex.spec.set("pass1.adjustment_needed", "WRONG_PACKAGE", actor="Executor")
    ex.architect.adjust.return_value = {"finished": True}
    ex._run_agent_loop = Mock(return_value={"finished": True})
    assert ex.run() == {"passes_completed": 0}
    assert ex._run_agent_loop.call_count == 1
    assert ex.spec.get("executor.validation_failed") is True
    assert ex.spec.get("cape_submission.validation_errors")


def test_actual_settings_and_ignored_proposals_are_controller_owned(vm_dir):
    client = _client(vm_dir, {})
    path = Path(_elf(vm_dir))
    ex = executor_for(vm_dir, client)
    ex.ctx.bind_sample(path)
    ex.ctx.set_route_policy("drop")
    ex.spec.set("sandbox.ram_mb", 8192, actor="Scout")
    ex.spec.set("monitors.procmon", {"reasoning": "proposal"}, actor="Scout")
    loop = AgentLoop(None, "x", ex.spec, ex.log, "Executor", cape_client=client, ctx=ex.ctx)
    result = loop._tool_cape_submit({"package": "elf", "options": "human=1"})
    assert "backend did NOT apply: human=1" in result
    assert ex.spec.get("sandbox.actual.ram_mb") == client.cfg.mem_mb
    assert ex.spec.get("sandbox.actual.proposed_sandbox.ram_mb") == 8192
    assert "procmon" in ex.spec.get("sandbox.actual.proposed_monitors")
    assert ex.ctx.latest_task() is not None
    for key in ("sandbox.actual", "sandbox.actual.ram_mb", "cape_submission.actual"):
        with pytest.raises(SpecPermissionError):
            ex.spec.set(key, {}, actor="Architect")


@pytest.mark.parametrize("field,value", [("error", "Unsupported Linux"), ("platform", None), ("package", None), ("timeout", None)])
def test_architect_finish_with_invalid_plan_never_reaches_executor(tmp_path, sample, field, value):
    orch, llm = _build(tmp_path, sample)
    original = llm._architect
    llm._architect = lambda n: (_call(tool="update_spec", key="cape_submission." + field, value=value)
                               + _call(tool="finish", summary="incomplete plan")) if n == 3 else original(n)
    assert orch.run() is False
    assert orch.cape.submits == []
    assert orch.spec.get("cape_submission.validation_errors")


def test_backend_contract_reaches_scout_before_it_proposes_an_environment(tmp_path, sample):
    class QemuFixture(FakeCAPE):
        def __init__(self):
            super().__init__()
            self.cfg.mode = "qemu"
            self.health_checks = 0

        def capabilities(self):
            return {"backend": "qemu-tcg", "platforms": ["windows"], "windows_packages": ["exe", "dll"], "vm_provisioning": False}

        def list_machines(self):
            return [{"name": "qemu-windows", "platform": "windows", "arch": "x86_64"}]

        def health_check(self):
            self.health_checks += 1
            return {"backend": "qemu-tcg", "ready": True}

    orch, llm = _build(tmp_path, sample, cape=QemuFixture())
    original = llm._architect
    llm._architect = lambda n: original(n) + (_call(tool="update_spec", key="cape_submission.machine", value="qemu-windows")
                                            + _call(tool="cape_service_check") if n == 1 else "")
    assert orch.run() is True
    scout_system = next(s for s in llm.systems if "You are the Scout Agent" in s)
    assert '"backend": "qemu-tcg"' in scout_system
    assert "qemu-windows" in scout_system
    assert orch.cape.health_checks == 1
    assert "network=" not in orch.spec.get("cape_submission.options")


def test_fixed_dll_instruction_requires_an_actual_export(vm_dir):
    client = _win_client(vm_dir, {})
    dll = vm_dir / "sample.dll"
    dll.write_bytes(_pe_header(dll=True))
    with pytest.raises(ValueError, match="DllMain"):
        client.validate_submission(str(dll), {"package": "dll", "options": "function=DllMain"})
    assert client.validate_submission(str(dll), {"package": "dll", "options": "function=Test"})["launch"]["function"] == "Test"


def test_submitted_plan_must_match_the_actual_available_linux_machine(vm_dir):
    client = _client(vm_dir, {})
    path = _elf(vm_dir)
    ex = executor_for(vm_dir, client)
    publish_backend_facts(ex.spec, client)
    for k, v in {"package": "elf", "platform": "linux", "machine": "qemu-linux", "timeout": 60}.items():
        ex.spec.set("cape_submission." + k, v, actor="Architect")
    ex.spec.set("sample.os_target", "linux", actor="Scout")
    assert submission_problems(ex.spec, client, path) == []
    ex.spec.set("cape_submission.machine", "qemu-windows", actor="Architect")
    assert submission_problems(ex.spec, client, path)
