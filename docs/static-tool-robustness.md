# Static tool robustness update

Historical GLM and DeepSeek traces showed binary searches returning only a match notification, repeated strings calls returning the same prefix despite changed options, and sidecar truncation removing continuation information. This update repairs those tool contracts and a Linux descriptor-path parsing error.

## Tool behavior

- `strings` and `strings_utf16` accept `min_length` (default 6, range 1–4096), `offset` and `limit`. Offsets count characters in command output, not bytes in the input file. Each page returns at most 4000 content characters plus a marker with `next_offset` or `EOF`. Each request reruns the command; there is no persisted output cache.
- `grep` performs a case-insensitive extended-regex search, including binary data, and returns matching text fragments. It accepts `pattern`, `offset` and `limit`. Patterns beginning with a dash remain patterns. No matches and command errors have distinct responses.
- Analysis operations reject unknown options and invalid parameter types before starting the tool. Unsupported options such as `output_file` do not silently succeed or create an output file. Other operations retain their existing supported options.
- The container wrapper and model feedback preserve page and truncation markers. Limits remain bounded; a truncated result is not presented as complete.
- The authoritative tool contract excludes network-tool examples in offline runs and explicitly identifies the disabled tools. It distinguishes workspace-only `read_file` from `analyze_sample`, which can also inspect the pinned input. Missing tools/rules and repeated searches without new evidence should be recorded as limitations.
- YARA execution errors returned by the command helper are propagated instead of being converted into “no matches.” This update does not install missing rules or binaries.

For example, after a strings page reports `next_offset=4000`:

```json
{"tool":"analyze_sample","operation":"strings","path":"/actual/sample/path","options":{"min_length":6,"offset":4000,"limit":4000}}
```

The same options must be retained across pages other than `offset`/`limit` to paginate the same output.

## Parsing and diagnostics

Unsupported XML `invoke` calls receive an explicit format error. Their parameter values and JSON-looking contents are not executed as independent calls; path indices such as `[300]` are not mislabeled as array tool calls. Valid JSON calls and XML text stored inside JSON string values remain supported.

Linux descriptor paths now separate nested `char`/`block` annotations from the actual path. For example, `4</dev/null<char 1:3>>` records `/dev/null` and `device_type=char`. Normal angle brackets in filenames are retained. Positive-byte writes remain distinct from failed and zero-byte writes; device I/O does not prove that a regular file was dropped.

## Role-specific state-writing examples

The shared `update_spec` example previously wrote `cape_submission.package`, which Scout and Executor cannot change. The shared `append_spec` example used `classification.basis`, which Architect, Executor, and Analyst cannot change. These five role/tool combinations produced instructions that the dispatcher would reject.

Both write tools now show examples using fields permitted for the current role. Scout writes classification evidence, Architect writes submission settings and its observations, Executor writes its current pass and observations, and Analyst writes the report and its observations. The prompt also states that controller-owned facts are read-only. The role permissions and the existing Analyst report example structure are preserved.

## Validation and limits

Offline regressions use inert ELF/PE prefixes, generated binary strings, synthetic strace records, and mocked container/API boundaries. They verify tail-content retrieval, ASCII/UTF-16 paging, binary matching, option rejection, end-to-end feedback markers, runtime tool descriptions, protocol recovery and descriptor parsing.

The release checkout passed 530 tests plus 6 subtests, including the wrapper test using a fake container engine and local Unix socket. Separately, the actual generated write examples were checked through the tool dispatcher for all four roles with both download settings: all 16 writes succeeded, and unauthorized package writes remained rejected. This publish validation did not run model APIs or malware samples.

Model evidence interpretation, stage-to-stage configuration propagation, complete raw-sensor retention, and delivery of all collection-limit metadata are not established by these tests. Existing experiment snapshots and their original results retain their meaning; use a new frozen candidate for subsequent experiments.
