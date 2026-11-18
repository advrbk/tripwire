# How Tripwire works

This is a walk through the code, written so you can explain any part of it out loud. It goes in the order a release travels: feed, download, quarantine, loader, analysers, score, database, dashboard. After that come the safety reasoning and a list of interview questions with short answers.

## The one-sentence version

Tripwire downloads each new PyPI or npm release into a throwaway folder, unpacks it without trusting anything in the archive, reads the files as text, runs six rule-based analysers over that text, turns their findings into a 0-100 score with a plain-English reason, and stores it for a small web page. It never installs, imports or runs the package.

## Module map

| File | Job |
|---|---|
| `models.py` | Plain dataclasses: `Evidence` (one finding), `PackageFile`, `Package`, `ScanResult`, `ReleaseRef`. No logic beyond small helpers. |
| `feeds/http.py` | `PoliteClient`: one `httpx` client with a fixed User-Agent, a minimum gap per host, retries with backoff for 429/5xx, `Retry-After`, and streaming downloads with a byte cap. Also the download host allow-list. |
| `feeds/pypi.py` | Reads PyPI's two RSS feeds (recent updates, brand-new projects) and the JSON API to find the file to download and its sha256. |
| `feeds/npm.py` | Reads npm's replication `_changes` feed (a real cursor) and each package's `latest` document for the tarball URL and SRI hash. |
| `quarantine.py` | Safe extraction of `.tar.*`, `.tgz`, `.zip`, `.whl`. Every member is checked and copied by hand. Digest checks. |
| `loader.py` | Turns extracted files into a `Package`: strips the archive's root folder, decodes text, reads `package.json` with `json` and `setup.py` with `ast`, and works out which files run at install time. |
| `analyzers/*.py` | The six analysers plus shared helpers in `base.py`. |
| `scanner.py` | `scan_archive` / `scan_directory` / `analyze_package`: runs the analysers, adds archive-level findings, calls the scorer. |
| `scoring.py` | Combines evidence into a score, a level and an explanation. |
| `pipeline.py` | The watch loop: poll feeds, resolve, download, verify, scan, store; timing stats. |
| `db.py` | SQLite (WAL mode) for results, findings and feed cursors. Parameterised queries only. |
| `web/app.py` + `static/` | FastAPI JSON API and a no-framework page. Strict CSP. |
| `cli.py` | `scan`, `watch`, `serve`, `bench`. |
| `bench/` | The self-made labelled corpus and the code that scores the rules against it. |

## The life of one release

Take a made-up npm package `left-pad-ng@1.0.1` published a few seconds ago.

1. **Feed.** `NpmFeed.poll()` asks `replicate.npmjs.com/registry/_changes?since=<cursor>` for the next 100 changes. Deletions and design documents are dropped. If a name changed several times in the batch, only its last change is kept. The result is a list of `NpmCandidate(name, seq)`.

2. **Resolve.** `NpmFeed.resolve()` fetches `registry.npmjs.org/left-pad-ng/latest` and builds a `ReleaseRef` with the tarball URL and the `sha512-...` integrity string the registry published. (For PyPI the JSON API gives the sdist or wheel URL and its sha256. The sdist is preferred because it carries `setup.py`, which is where install-time code lives.)

3. **Duplicate check.** `Database.has_release()` skips anything already stored, so a restarted watcher does not redo work.

4. **Download.** `PoliteClient.download()` refuses anything that is not HTTPS on `files.pythonhosted.org` or `registry.npmjs.org`. It does not follow redirects, rejects a too-large `Content-Length`, and stops streaming the moment the byte cap (25 MB) is passed. The local file name is fixed (`download.tgz`), never taken from the remote side.

5. **Verify.** `verify_digest()` hashes the file and compares it with the registry's sha256 or SRI value. A mismatch is stored as an error and the file is not scanned.

6. **Extract.** `safe_extract()` detects the format from the first bytes, not the file name, then walks the members one at a time (details in the safety section). It returns the list of files written and a list of `(name, reason)` for everything it refused.

7. **Load.** `load_package()` finds the common root folder (`package/` for npm, `name-1.0/` for sdists) and strips it. Each text-like file is read (up to 2 MB) and decoded as UTF-8 with replacement. Files with NUL bytes count as binary. `package.json` gives the lifecycle scripts. Any file those scripts point at (`node install.js`, `sh ./setup.sh`) is marked as an install file.

8. **Analyse.** `analyze_package()` runs each analyser in turn. If one throws, its error becomes a zero-weight finding and the rest still run. Archive-level findings are added (blocked path escapes, links, files the OS would not let us read back).

9. **Score.** `score()` returns, for example, `(93, "critical", "Risk 93/100 (critical). index.js (run by an install script) uses the network. ...")`.

10. **Store and clean up.** The result and up to 200 findings go into SQLite. The `finally:` block deletes the whole quarantine folder: archive, extracted files, everything.

11. **Commit the cursor.** `feed.commit(cand)` saves the position, even if the release failed. A restart resumes after it instead of looping on a broken release.

12. **Show.** The dashboard polls `/api/releases` every 5 seconds and renders rows with `textContent`.

## How each analyser decides

All six take a `Package` and return a list of `Evidence(analyzer, rule, weight, message, file, line, snippet)`. A weight is "how much this points at malware on its own", from 0 to 1. A finding of 0.30 or more means the analyser "fired". Weaker findings are kept as context.

### install_hooks: code that runs during install

Most real supply-chain attacks run at install time, because nobody has to import the package for that to happen. Install-time code in this tool means `setup.py` (and local modules it imports), `.pth` files, npm `preinstall`/`install`/`postinstall` scripts, and files those scripts run.

For Python it parses the file with `ast` and resolves imports with `ImportMap`, so `import subprocess as sp; sp.Popen(...)` and `__import__("os").system(...)` both resolve to the real function name. Then it grades what the code does:

- Running a known build tool (`cmake`, `make`, `git`, `sys.executable`) scores 0.1. Native extensions need this.
- Starting any other program scores 0.35.
- Network calls score 0.6.
- A downloader or shell launcher in the command (`curl`, `wget`, `powershell`, `certutil`, `bash -c`, `/dev/tcp/`) scores 0.75.
- `exec(open("pkg/version.py").read())` is skipped on purpose. It is a common way to read a version number.

For npm it looks at the script string first. Known build tools (`node-gyp rebuild`, `husky install`, `prebuild-install`) are 0.05. Shell droppers are 0.8. `node -e "..."` is 0.45 and the inline code is checked too. `node file.js` is 0.2, and then the file itself gets the JavaScript checks: `child_process`, shell commands, network modules. A download from GitHub, the npm registry or nodejs.org (how esbuild or sharp fetch binaries) scores 0.25 instead of 0.55. The host check matches the exact host or a real subdomain, so `evilgithub.com` does not pass for `github.com`.

A `.pth` line that starts with `import` runs on every Python start-up. With `exec`/`eval`/`b64decode`/`urlopen` in it, it scores 0.8.

### obfuscation: hidden code

Legitimate packages minify code and embed base64 images, but they almost never decode a blob and execute it straight away. So the strong rules are about decode-then-execute:

- Python: an `exec`/`eval`/`compile` call with a decoder call inside it (`b64decode`, `decompress`, `unhexlify`, `fromhex`, `.decode()`...) scores 0.85. A reversed string passed to exec scores 0.7.
- `getattr(builtins, "ex" + "ec")`, an attribute name assembled from constant pieces, scores 0.45. Names built from a variable, like `getattr(self, "visit_" + kind)`, are the normal dispatch idiom and do not count.
- JavaScript: `eval(atob(...))`, `new Function(Buffer.from(x, "base64"))` and `Function(String.fromCharCode(...))` score 0.75 (0.85 in install code). Eight or more distinct `_0x1a2b`-style names are the fingerprint of a common obfuscator and score 0.6.
- Blob shapes (base64 over 300 characters with high entropy, hex blobs, long runs of `\x` escapes, random-looking long strings) are context in normal code and moderate in install code. `data:` URIs are skipped.
- A line over 1000 characters in install-time code scores 0.5. Minified bundles are fine at runtime but odd in a postinstall script.

### network: where data goes

Ordinary URLs are ignored, since every library has docs and API links. What this analyser flags:

- Known exfiltration services: Discord webhooks, the Telegram bot API, request catchers (webhook.site, interactsh, Burp Collaborator, canarytokens), tunnels (ngrok, trycloudflare), paste and anonymous file hosts. These score 0.5 to 0.65.
- Hard-coded public IP addresses in URLs or socket calls score 0.45. Private ranges score 0.1, and loopback is ignored.
- DNS exfiltration: a hostname built from data and passed to `gethostbyname`, `dns.lookup` and the like (`f"{secret}.attacker.example"`) scores 0.6.
- Whole-environment sends. This rule follows data instead of matching strings. It marks variables assigned from `os.environ` used as a whole (`dict(os.environ)`, `os.environ.copy()`, `json.dumps(os.environ)`) and follows them through a few assignments. It fires at 0.65 if one reaches a network call (`requests.*`, `httpx.*`, `urlopen`, or `.post` / `.sendall` on any object). Taint is tracked per function, and a parameter shadows a module-level name. Reading one value, `os.environ["API_TOKEN"]` or `env.get("X")` through an alias, does not count, because API clients do that all the time. JavaScript gets a simpler version: bare `process.env` plus a send in the same file, ignoring `env: process.env` and `...process.env`, which hand the environment to a child process.

  The first version of this rule tracked names across the whole file, counted any `.put()` as a send, and treated every `process.env` in JavaScript the same. The first live run showed what that costs. Four of its six flags (all false positives) involved this rule: a local artifact store's `.put()`, a webhook notifier that read single settings through an `environ` alias, and two CLIs passing `process.env` to `spawn`. The scoping and the exceptions above came out of that run.

Install-time code adds 0.1 to any of these.

### credentials: reading secrets

The analyser looks for paths to secret stores and gives a moderate weight: SSH keys, `~/.aws/credentials`, kube config, `.npmrc`/`.pypirc`/`.git-credentials`, browser profile databases ("Login Data", cookies), crypto wallets, Discord/Telegram session folders, shell history. A path is a capability, not proof (the AWS SDK mentions `~/.aws/credentials` for good reasons), so these sit at 0.4 to 0.65. The scorer adds a bonus when the same package also has somewhere to send them.

Environment harvesting: `json.dumps(os.environ)` or `JSON.stringify(process.env)` scores 0.55. Walking every variable scores 0.25. Reading three or more well-known secret-token names (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`...) in one file scores 0.35. Reading `HOME` scores nothing.

### typosquat: look-alike names

The name is normalised (PEP 503 for PyPI: lower case, runs of `-_.` become `-`) and compared with a bundled list of about 300 popular names per ecosystem. Checks, strongest first:

- Look-alike characters (`0` for `o`, `rn` for `m`): 0.7.
- The same letters with separators removed (`crossenv` for `cross-env`): 0.6.
- One edit by optimal string alignment distance, with the kind of typo named: swapped letters or a keyboard neighbour 0.65, doubled or dropped letter 0.6, other 0.55. Only for targets of 5 characters or more, because short names collide by accident.
- Two edits, only for targets of 9 or more characters: 0.4.
- A popular name with a stock affix (`-py`, `-js`, `node-`, `-dev`...): 0.35.

### depconfusion: dependency confusion

The classic attack publishes a public package with the same name as a company's private one and an absurd version like `99.0.0`, so a build that checks both registries picks the public copy. Tripwire cannot know private names, so the rule is: major version 99 or higher on a name that is not in the popular list scores 0.45 (0.55 at 1000+). Calendar versions (`2024.11.5`) and date stamps (`20241105`) are exempt. An internal-sounding name (`internal`, `corp`, `platform`...) and empty metadata add small context findings.

## How scoring works

`scoring.py` is about 100 lines. The steps:

1. **Keep the strongest hit per rule.** Fifty files with the same weak pattern count as one finding, so big packages are not punished for being big.
2. **Drop context.** Findings under 0.2 are shown but add nothing.
3. **Noisy-OR inside each analyser.** Strength = `1 - (1-a)(1-b)...` over its rules. Two independent 0.5 signals give 0.75. It never passes 1, and each weight is capped at 0.97 so nothing is certain on its own.
4. **Noisy-OR across analysers** gives the base score.
5. **Combination bonuses.** Some pairs are much worse together than apart. Reading secrets plus a place to send them adds 0.20. A dependency-confusion version plus install-time code adds 0.20. A look-alike name plus install-time code adds 0.15. There are eight pairs in total, and they count only when both analysers fired (0.30 or more).
6. **Scale to 0-100 and grade:** 85+ critical, 70+ high, 50+ medium (the flag line), 20+ low.
7. **Explain.** The explanation names the top three analysers' strongest findings and the first combo that applied, e.g. "Risk 92/100 (critical). index.js reads or references SSH keys. index.js talks to a hard-coded IP address (198.51.100.23) instead of a domain. It reads secrets and also contains a place to send them."

Why noisy-OR instead of a plain sum? A sum makes ten weak findings look like one strong one. Noisy-OR treats each finding as an independent chance that the package is bad. It rewards agreement between different signals and saturates smoothly.

## Why the quarantine guards exist

An archive is a set of instructions for writing files, and those instructions can be hostile even when there is no "code" in them at all. Each guard answers a specific attack:

| Guard | Attack it stops |
|---|---|
| Never call `extractall`; check and copy each member by hand | Python's tarfile historically trusted member names (CVE-2007-4559). The extractor, not the archive, decides what reaches the disk. |
| Refuse `..` segments, absolute paths, drive letters (`C:`), UNC paths | Path traversal ("zip slip"): writing `../../.bashrc` or into a startup folder. |
| Refuse symlinks and hard links in tar and zip | A link to `/etc` or `..`, followed by a second member written "through" the link, escapes the folder even though each name looks innocent. |
| Refuse devices and FIFOs | Opening a FIFO blocks forever; a device node is never a legitimate package file. |
| Refuse `:` in names, Windows reserved names (`CON`, `NUL`, `LPT1`), trailing dots and spaces | Alternate data streams and names Windows maps to devices or silently renames. |
| Resolve every target and check it is inside the quarantine folder | Belt and braces in case a name check is ever wrong. |
| Exact duplicate entries: the later copy replaces the earlier one | tar, npm and pip all let the last copy win. Keeping the first would let a decoy `install.js` or `package.json` hide the real one that runs. |
| Names that only collide on Windows or macOS go to a side folder, and both copies are analysed | `Setup.py` and `setup.py` are two files on Linux, where pip runs `setup.py`, but one file on Windows. With 8.3 short names on (usual for a Windows system drive, and on for this machine's), `INSTAL~1.JS` *is* `install_script.js`. Writing either would overwrite a file before it is read. Each case adds an `archive/name_collision` finding. |
| File/directory collisions refused | `a` as a file and `a/b.py` cannot both exist. |
| Archive size cap (25 MB) before opening | Wasting bandwidth and disk on huge uploads. |
| Member count cap (5,000) | Millions of empty entries exhaust memory or inodes. |
| Per-file (20 MB) and total (150 MB) caps, counted while copying | Decompression bombs: 20 KB of gzip can expand to 20 MB of zeros, and zip headers can lie about sizes. Bytes are counted as they are written, never trusted from headers. |
| For tar, also check the sizes the headers declare, including for refused members | Skipping a refused member still means decompressing it, so a bomb hidden in a `../` entry would still burn CPU. |
| Cap the whole decompressed tar stream, and refuse any single read over 1 MB | Python's `tarfile` reads a GNU long-name or pax header into memory in one call, sized by the header, before the member reaches any of the checks above. A 300 KB `.tar.gz` with a 300 MB long-name header made it allocate over 600 MB. |
| `scan <folder>` skips symlinks and NTFS junctions | `os.walk(followlinks=False)` still walks into junctions, which any user can create and which can point anywhere on the disk or back at a parent. |
| Detect the format from magic bytes | A zip named `.tar.gz` goes to the zip reader, not the wrong one. |
| Quarantine folder must not be on `sys.path` or `PYTHONPATH` | A planted `json.py` would run the moment anything imported `json`. |
| Delete the whole folder in `finally:` | Nothing from a scan survives it. |

What runs on the package's content: `bytes.decode`, `json.loads`, `ast.parse`, `re` and string methods. None of these can execute code. `ast.parse` calls `compile()` with the AST-only flag, which builds a syntax tree and never produces bytecode. The test suite checks this two ways. `tests/test_no_execution.py` replaces `subprocess.*`, `os.system`, `os.exec*`, `os.spawn*`, `exec`, `eval`, `importlib.import_module`, the `importlib.util` loaders, `runpy` and `pickle.load(s)` with traps, allows `compile()` only in AST-only mode, blocks imports of any fixture module name, and then scans the whole malicious corpus. A trap on `subprocess.run` cannot catch a function bound earlier with `from subprocess import run`, so a second test parses the tool's own source with `ast` and fails if any module imports `subprocess`, `runpy`, `pickle`, `marshal`, `ctypes`, `yaml` and the like, or calls `exec`, `eval`, `compile`, `__import__` or a process or loader function.

Other places untrusted data goes, and how each is handled:

- **SQLite:** parameters only, never string formatting. `LIKE` wildcards in searches are escaped.
- **RSS XML:** parsed with `defusedxml`, which refuses entity-expansion bombs.
- **Dashboard:** the API returns JSON, and the page writes every value with `textContent`, never `innerHTML`. A Content-Security-Policy without `unsafe-inline` blocks injected script even if that ever slipped.
- **Terminal:** `cli.safe_text()` escapes control and format characters, so a file named with ANSI escapes or a right-to-left override cannot rewrite the report.
- **Download URLs:** they come from registry metadata, so they are checked against an allow-list and redirects are not followed. Otherwise a crafted record could make the watcher fetch from anywhere, including internal addresses.

On Windows, antivirus can delete or lock an extracted file between the write and the read, which shows up as `OSError` on open. The loader records such files and the scanner turns them into an `archive/unreadable_files` finding (weight 0.4), instead of quietly skipping them. During development, Microsoft Defender removed one of the inert benchmark fixtures this way. Its heuristic for npm stealers matched a `preinstall` script that pipes `wget` into `sh`. That fixture was dropped from the on-disk corpus, and the pattern is still tested in memory.

## Performance notes

Most analyser rules are regular expressions over every text file, and the slow part was running about 25 of them over large bundled JavaScript files. Each rule now lists the literal strings its pattern cannot match without, for example `api.telegram.org` for the Telegram rule. A substring check on the lower-cased file (done in C) skips the regex when none are present. Results are identical, and a test runs the whole corpus with and without the prefilter. "Lower-cased" needs care: a case-insensitive regex treats the long s `ſ` as `s` (and the Kelvin sign as `k`, dotless `ı` as `i`), but `str.lower()` leaves `ſ` alone, and IDNA maps `webhook.ſite` to `webhook.site`. The prefilter first used plain `lower()` and skipped such a file; it now folds those four characters too, and a test checks every character that `re.IGNORECASE` maps to an ASCII letter. On a real 1.9 MB npm package, analysis went from 2.8 s to 0.6 s. What remains is mostly disk I/O, and on Windows that includes antivirus scanning every file as it is written and opened.

## The benchmark, briefly

`src/tripwire/bench/corpus.py` defines 113 tiny packages in code (59 with a malicious signal, 54 benign). They are built into real archives at run time. Each malicious fixture is labelled with the categories of behaviour it was written to show. Labels were assigned from what the snippet does, not from whether a rule catches it, so an analyser can and does miss its own category. Benign fixtures include deliberately awkward cases: a CMake build step, a setuptools-style `.pth` shim, an env-dump CLI, an SSH config helper, a version number that tracks a browser.

The honest reading: the same person wrote the rules and the corpus, so high numbers mean the rules do what they were designed to do on cases their author imagined. The misses and false positives are the more useful output, because they show what the design cannot see. See the README for the table.

## Likely interview questions

**Why static analysis only? Running it in a sandbox would catch more.**
It would, and dynamic analysis is what the larger research systems do. It also needs a hardened VM per package, takes minutes per release and has its own escape risks. Static triage is cheap enough to run on every release in milliseconds and to point a human or a sandbox at the few worth a closer look. The two are layers, not rivals.

**How do you know it never runs the code?**
By construction, nothing calls `exec`, `subprocess` or `import` on package content; the only operations are decode, `json.loads`, `ast.parse` and regex. And by test: `test_no_execution.py` turns the execution paths into traps that raise, allows `compile` only in AST-only mode, then scans the full malicious corpus and asserts no trap fired. Traps only catch calls made through the module attribute, so a second test reads the tool's own source as syntax trees and fails on any import of `subprocess`, `runpy`, `pickle` and similar, or any call to `exec`, `eval` or a process function.

**What is the zip-slip / tar path traversal problem?**
Archive member names are just strings. A name like `../../etc/cron.d/x` makes a naive extractor write outside the target folder. The fix is to never let the archive pick the path: normalise each name, reject `..` and absolute paths, refuse links, and check that the resolved target is still inside the destination.

**How do you stop a zip bomb?**
Count bytes while copying, against a per-file and a total budget, and abort the whole archive the moment either is passed. Never trust the sizes in the headers, because they can lie. For tar the header sizes are honest (the reader uses them to find the next header), so they are also checked up front, which catches bombs hidden in members that would be skipped anyway.

**Why noisy-OR for scoring?**
It treats findings as independent pieces of evidence, so two medium signals from different analysers add up to more than either, but nothing passes 100 and repeating one weak pattern does not inflate the score. Combination bonuses then encode the pairs that matter far more together, like "reads secrets" plus "has an exfil channel".

**What are the false positives?**
In the benchmark: native build steps are mostly fine, but a setuptools-style `.pth` import shim, a plugin loader that runs `exec(path.read_bytes().decode())`, region-based DNS names (`"%s.storage..." % region`), and tools that legitimately touch `~/.ssh` all cross the flag line. In the live run, see the README. The pattern is that path and string rules cannot tell capability from intent.

**How would an attacker evade it?**
Many ways. Put the payload in a runtime module instead of an install hook. Fetch the second stage from an ordinary-looking domain. Split strings across files. Use a less common decoder, or `importlib` tricks the rules do not model. Ship a compiled extension. The benchmark has some of these on purpose (a Node `connect(port, host)` call, a beacon to a plain domain), and they are missed. Static rules raise the cost of being lazy. They do not stop a determined attacker.

**Why the sdist and not the wheel?**
The sdist carries `setup.py`, which runs on `pip install` for anyone building from source. That is where install-time attacks live. A pure wheel never runs setup code; the only install-time code it can carry is a `.pth` file, and that is checked either way.

**How does the watcher avoid hammering the registries?**
One thread, a minimum gap between requests per host (0.5-2 s), backoff on 429 and 5xx that honours `Retry-After`, a fixed generic User-Agent, and resume cursors so a restart does not refetch. The PyPI RSS feed is polled once a minute.

**What happens if the process dies halfway?**
Each release is committed to SQLite before the feed cursor moves past it, and the cursor is saved after every candidate. On restart the npm cursor resumes exactly. PyPI has no real cursor, so it resumes from the newest publish time seen, plus a list of recent keys to skip.

**What would you do next?**
Measure on real labelled data: public malware datasets such as the Backstabber's Knife Collection or the OpenSSF malicious-packages list, with real benign baselines. Replace hand-picked weights with ones fitted on that data. Add an allow-list of known-good install scripts to cut repeat false positives. Compare each release with its previous version, since a long-trusted package suddenly gaining a postinstall is a strong signal. Hand high scorers to a sandbox.

**What did the live run teach you?**
That my own new rule was the noisiest one. All six flags in the first ten minutes were false positives. Four involved the whole-environment rule's file-wide, name-based taint. Four involved SSH-path matching, including `before.ssh === undefined` read as a `~/.ssh` path. Several had both. Synthetic fixtures had not shown either problem. I fixed both, added a regression test for each pattern, checked that the benchmark did not move, and ran a second live pass to measure again.

**What was the hardest bug?**
Two stand out. A regex alternative meant to catch `"{}.attacker".format(data)` DNS exfiltration only matched `name.format(...)`, so the literal form slipped through; the benchmark found it. And on Windows, antivirus deleting freshly extracted files looked exactly like "binary file, skip it", so a detected file vanished from the analysis silently. It is now reported as evidence.
