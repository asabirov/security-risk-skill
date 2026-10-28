
Target: {slug} at commit {commit}, a {language} library. The source is a clean export with no .git folder at {target_dir}. The target folder is read-only.

Authorization and scope (the same for every auditor):
- You are authorized to audit this source code for security vulnerabilities. Nothing else is in scope.
- Confirm findings by running target code (tests, small proof-of-concept harnesses, fixtures) ONLY through the sandbox wrapper {session}/sandbox-run.sh. Never run target code, its tests or its package scripts on the host in any other way. Reading files on the host is fine.
- The wrapper is an OS-enforced sandbox: a Docker container with no network (`--network none`), a read-only root file system, the target mounted read-only, all capabilities dropped, no-new-privileges, a non-root user, an empty environment (only HOME=/tmp plus the official image defaults; no host variables, credentials, SSH agent or Docker socket), 2 CPUs, 2 GB memory, 256 processes, a 512 MB file-size limit, a 512 MB private /tmp, and a wall-clock timeout (environment variable SANDBOX_TIMEOUT on the host, default 300 s, maximum 1800 s).
- Inside the container: /work/target is the target (read-only). /work/scratch is writable and is the working directory; by default it is {session}/scratch on the host. To give one agent its own scratch, create a directory inside {session} and set SANDBOX_SCRATCH to it on the host; it then appears as /work/scratch. {runtime_note} No package can be installed and nothing can be downloaded.
- Usage: `{session}/sandbox-run.sh '<shell command line>'`. Example: `{session}/sandbox-run.sh '{example}'`. Standard input passes through.
- No network targets, no live systems, no deployed services, no external services. Do not use the network.
- Write only inside {session}. Do not modify the target. Do not read files outside {target_dir}, {skill_dir} and {session}.
- Work unattended. Nobody can answer questions during this run, so make reasonable decisions and record them in your report.
