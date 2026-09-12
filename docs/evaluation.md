# Reference experiment results

This is a summary of internal reference experiments. The original samples, traces, results, and base images are not published. It describes the validation scope and does not replace a publicly reproducible accuracy benchmark.

| Batch | Sample tasks | Final standalone reports | Notes |
|---|---:|---:|---|
| R1 | 40 | 15 | Initial baseline. The original status recorded 16 completed tasks, but only 15 had standalone reports. |
| R2 | 13 | 12 | Targeted reruns after the first framework fixes. |
| R3 | 1 | 1 | Targeted rerun after changes to request timeout handling. |
| R4 | 10 | 10 | Regression runs on the R4/R5/R6 version for previously recovered samples. |
| R5 | 10 | 10 | New supplementary samples, using the same source as R4. |
| R6 | 12 | 11 | Reruns of the remaining failed samples, using the same source as R4/R5. |

There were 6 formal batches, 86 sample tasks, and 4 frozen source versions. The latest historical results provide reports for 39 of the original 40 samples and all 10 supplementary samples: 49/50 in total. One older report differs from its embedded counterpart in punctuation, so 48/50 pass the historical exact delivery checks.

The R4/R5/R6 source version covers only 32 distinct samples, of which 31 completed. The latest results for the other 18 samples come from earlier versions. Current source includes later framework and prompt changes. These ratios are neither malware analysis accuracy scores nor completion rates for the current source.

Each of the 12 R6 samples received one complete pipeline run. Of 916 API attempts, 9 were extra attempts caused by 6 empty responses, 2 read timeouts, and 1 HTTP 500 response; all of those requests recovered. A separate sample failed after tool protocol correction attempts. The 11 delivered R6 reports passed standalone/embedded report consistency, sample identity, and dynamic task provenance checks. All 274 archived file hashes matched.

Initial release preparation added no real-sample runs. Later framework changes are described in the [platform consistency](platform-consistency.md) and [static tool robustness](static-tool-robustness.md) notes; they do not turn these historical results into a benchmark of the updated source. See [testing](testing.md) for offline regression and release-file checks. Internal job IDs, machine names, personal paths, credentials, and real model traces are excluded from the repository.
