# jenkinsfile-audit

jenkinsfile-audit reads Jenkins pipeline files as text, with comments removed and Groovy strings tracked, and reports the patterns that turn a CI pipeline into an attack path: secrets interpolated into shell commands (visible in logs and process lists), build parameters and branch names pasted into `sh`, containers started as root or with the Docker socket, shared libraries that follow a moving branch and downloads piped into a shell.

**Live demo:** https://jvch0512.github.io/jenkinsfile-audit/ (Synthetic Jenkinsfiles.)

Groovy 2 (JVM), standard library only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
./bin/jenkinsfile-audit examples
./bin/jenkinsfile-audit Jenkinsfile --tsv
./bin/jenkinsfile-audit ./ci --fail-on high       # exit 1 on any high finding
```

Pass a file or a directory (files named `Jenkinsfile`, `Jenkinsfile.*` or `*.jenkinsfile`, searched recursively).

| Rule | Severity | What it catches |
|---|---|---|
| JKS001 | high | `curl` or `wget` piped into a shell |
| JKS002 | high | a secret assigned as a literal (`PASSWORD = 'x'`, `AWS_SECRET_ACCESS_KEY = '...'`) |
| JKS003 | high | a credential variable interpolated in a double-quoted `sh` string (leaks to logs and `ps`) |
| JKS004 | medium | `--privileged` or the Docker socket mounted into a build container |
| JKS005 | medium | container args `-u root` or `-u 0` |
| JKS006 | medium | TLS checks disabled (`curl -k`, `--insecure`, `http.sslVerify=false`, `strict-ssl false`) |
| JKS007 | high | `params.*`, `env.BRANCH_NAME`, `CHANGE_TITLE` or `CHANGE_BRANCH` interpolated in a double-quoted `sh` string (command injection) |
| JKS008 | low | no `timeout` in `options` |
| JKS009 | medium | `@Library` without a version, or pinned to a branch name such as `main` or `master` |
| JKS010 | medium | dynamic code: `evaluate(`, `Eval.me(` or `GroovyShell` |
| JKS011 | low | `agent any` |
| JKS000 | info | the file has no `pipeline` or `node` block |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It is a line-oriented text scanner, not a Groovy parser. Code assembled at run time is not followed.
- Shared libraries are not fetched, so what they do inside `sh` steps is not seen.
- Jenkins credential masking hides secrets in console logs, but not in `ps`, in files that the build writes or in processes started by the step. JKS003 is about the process list and about masking gaps.
- Jenkins plugin configuration and job settings made in the UI are outside the file.

## Where it fits

CI/CD security review: a pre-merge gate for pipeline changes and a quick sweep of a Jenkins estate.

## Tests

```bash
make test    # 51 checks, incl. 3000-case fuzzing and CLI exit codes
```

MIT.
