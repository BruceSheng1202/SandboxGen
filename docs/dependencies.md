# Dependencies and build baseline

The release validation environment uses Linux x86_64 and Python 3.12. `src/requirements.txt` lists direct runtime dependencies; `requirements-dev.txt` adds pytest. `requirements/locks/runtime.txt` and `dev.txt` pin all resolved versions and official PyPI artifact SHA256 hashes. The harness container also installs from the runtime lock. `.containerignore` limits build contexts to the required lock file and build definitions so local credentials, configuration, and run data are not sent to builders. `src/sandbox_infra/requirements.txt` is a compatibility entry point referencing the main list, not a separately maintained dependency list.

The reference versions remain OpenAI 3.8.0, Anthropic 1.4.0, requests 2.34.2, and PyYAML 6.0.3. Other static-analysis dependencies were resolved and tested in the separate release environment. The locks are not package-for-package reproductions of the old reference containers or guests. Other platforms and interpreters require their own resolution and validation.

The runtime lock contains 68 packages and the development lock contains 72. Public PyPI vulnerability queries for both locks reported no known vulnerabilities and skipped no packages. These are results at the time of the queries; they do not cover unknown vulnerabilities, the base OS, containers, guests, Windows media, or external services. To audit or regenerate locks later:

```bash
python -m pip install pip-audit pip-tools
python -m pip_audit --disable-pip --no-deps -r requirements/locks/runtime.txt
python -m piptools compile --generate-hashes --strip-extras \
  src/requirements.txt -o requirements/locks/runtime.txt
python -m piptools compile --generate-hashes --strip-extras \
  requirements-dev.txt -o requirements/locks/dev.txt
```

After dependency updates, run the full offline regression suite, package consistency checks, and benign checks in the actual deployment. Updating a lock file does not preserve the exact conditions of earlier experiments.

## Container and guest limitations

QEMU builds retain the reference `alpine:3.20` baseline to preserve the QEMU version and compatibility with saved Windows RAM state during release preparation. **Alpine lists 2026-04-01 as the end of regular support for 3.20; its current support level is on request.** Treat this as a reference baseline, not a production image with newly validated security updates. See [Alpine release branches](https://alpinelinux.org/releases/).

A maintained deployment baseline requires a separate image update, Windows state rebuild, and Linux/Windows benign integration checks. The reference image was not replaced during this release preparation. Image tags, apt/apk repositories, and Ubuntu release download URLs change over time. Record container digests, guest SHA256 hashes, tool versions, and build settings for reproducibility. Python dependency locks do not pin system packages.

GitHub CI uses fixed commit SHAs for third-party actions, read-only permissions, and checkout without persisted credentials. Pinning SHAs reduces exposure to moved tags but still requires maintenance. See [GitHub's security guidance](https://docs.github.com/en/actions/reference/security/secure-use).
