# Ioznizer

**LLM-driven reverse engineering for ELF binaries.**

Ioznizer decompiles a Linux binary with Ghidra, then hands a language model the
same tools a reverse engineer would reach for — function listings, pseudo-C,
disassembly, symbol tables, string search — and lets it drive its own
investigation. The output is an analyst-grade report with evidence-linked
findings, IOCs, MITRE ATT&CK mapping and draft YARA rules.

---

## Why tool-driven analysis

The obvious way to point a model at a binary is to dump `strings`, `readelf -a`
and `objdump -d` into a prompt. A 110 KB stripped ELF produces well over a
megabyte of text — far past any context window — so you truncate, and the model
reasons about an arbitrary first slice of the disassembly.

Ioznizer inverts that. The model gets a compact overview and then **asks for what
it needs**, one question at a time:

```
search_strings("syn_flood")             → "[syn_flood] started: ('%d')"
find_references("[syn_flood] started")  → FUN_0804a330 @ 0x0804a330
decompile_function("FUN_0804a330")

    uVar3 = FUN_08059d98();
    FUN_0805a35d("[syn_flood] started: ('%d')\n", uVar3);
    iVar4 = FUN_0805bdbe(2, 3, 6);        // socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    if (iVar4 == -1) {
      FUN_0805a2e1("[syn_flood] socket() failed");
```

The middle step is what makes this work. A string tells you a literal exists;
the cross-reference tells you which function *uses* it. Without that bridge an
agent can only keep searching strings, and every finding it reports is a guess
about code it never read.

A raw TCP socket built for SYN flooding — read directly from decompiled code, in
a stripped binary with no symbols. This is hypothesis-driven investigation, and
it stays within context regardless of binary size.

Every report records which tools the model chose and why, so its reasoning is
auditable rather than opaque.

---

## Pipeline

```mermaid
flowchart LR
    A[ELF sample] --> B[Static extraction<br/>readelf · objdump · strings]
    A --> C[Decompilation<br/>Ghidra headless]
    B --> D[(analysis/)]
    C --> D
    D --> E{Agent loop}
    E -->|tool call| F[Tool dispatcher<br/>10 tools]
    F -->|evidence| E
    E -->|final JSON| G[Report generator]
    G --> H[report.json + report.md]
```

**1 — Static extraction.** Validates the ELF magic, reads the machine type from
the header and passes the matching `-m` flag to `objdump`; without it,
disassembly silently fails on ARM, MIPS, PowerPC and SPARC samples. Symbols are
read with `readelf -s -W`, where `-W` prevents the truncation that otherwise
turns `__libc_start_main` into `_[...]`.

**2 — Decompilation.** Ghidra headless runs a `GhidraScript` that exports
pseudo-C for every recovered function. radare2 is supported as a fallback.

**3 — Agent loop.** The model calls tools, the dispatcher executes them against
the extracted artifacts, results feed back. The loop reserves its final
iterations for the verdict itself, and accepts a response as final only when it
parses as a schema-valid report.

**4 — Report generation.** Structured JSON plus a readable Markdown report.

### Tools available to the model

| Tool | Purpose |
|---|---|
| `search_strings` | Case-insensitive pattern search across extracted strings |
| `find_references` | Which functions reference a string or address — the lead-to-code bridge |
| `decompile_function` | Pseudo-C for one function, by name or address |
| `search_decompiled` | Search the reconstructed code itself, e.g. `socket`, `kill`, `/proc/` |
| `list_functions` | Every function recovered by the decompiler, with entry points |
| `disassemble_address` | Raw disassembly at an address, range or symbol |
| `read_section` | Paged reads of metadata / strings / symbols / disasm / decomp |
| `analyze_symbol` | Full symbol-table detail for one symbol |
| `get_imports` | Undefined symbols plus `DT_NEEDED` shared libraries |
| `get_exports` | Symbols the binary itself defines |

---

## Results

Two binaries, identical pipeline, no tuning between runs, using the default
model (`nvidia/nemotron-3-ultra-550b-a55b:free`) — see
[Choosing a model](#choosing-a-model) to run the same pipeline against a
different one.

### Sample A — stripped 32-bit ELF, unknown provenance

Ghidra recovered **267 functions with zero decompilation failures**.

```
classification : DDoS bot
risk           : Critical  (95/100)
binary         : i386, statically linked, imports: []
sha256         : 7fe9b559e58af2bc4b453a5bcdbdfef0b2d527bdc3416ee801613ac1734baa03
```

The agent worked through six flood routines, each one located by
cross-reference and confirmed by reading its decompiled body:

```
Network Denial of Service - SYN flood      @ FUN_0804a330 @ 0x0804a330
Network Denial of Service - UDP flood      @ FUN_08049ad0 @ 0x08049ad0
Network Denial of Service - ICMP flood     @ FUN_08055fd0 @ 0x08055fd0
Network Denial of Service - TCP bypass     @ FUN_08049ff0 @ 0x08049ff0
Network Denial of Service - PSH-ACK flood  @ FUN_08056210 @ 0x08056210
Network Denial of Service - ACK flood      @ FUN_08056520 @ 0x08056520
```

Each finding points at a function and address, so any of them can be checked
against the binary directly.

What else it recovered from a binary with no symbols:

- **Hardcoded C2 — `154.6.197.37`** — plus a custom control protocol,
  `SNQUERY: <ip>:<password>:<identifier>`.
- **Reconnaissance** — SSDP `M-SEARCH` to `255.255.255.255:1900` and DIAL
  service enumeration, behind a spoofed Chrome User-Agent.
- **Host enumeration** — reads `/proc/net/tcp` to enumerate live connections;
  SOCKS5 proxy support.
- **Process manipulation** — a `watch_time` routine that calls `kill()` on
  tracked PIDs.
- **Packing indicators** — no dynamic section, no GOT, no relocations, and a
  large `.text` (`0x17f86`) against a small `.data`/`.bss`.

Mapped to ATT&CK: `T1498` / `T1498.001` (Network Denial of Service, Direct
Network Flood), `T1046` (Network Service Discovery), `T1071.001` (Application
Layer Protocol), `T1090.001` (Internal Proxy), `T1027` (Obfuscated Files).

Independently checkable: `file` reports *ELF 32-bit LSB, Intel i386, statically
linked, stripped*, and `readelf` confirms the empty dynamic symbol table.

### Sample B — benign control

The control matters as much as the detection. Run against an ordinary local
utility, `decompile_function("read_msg")` returns essentially the original
source:

```c
void * read_msg(void)
{
  __stream = fopen("msg.txt","rb");
  if (__stream == (FILE *)0x0) {
    puts("msg.txt is missing");
    exit(1);
  }
  fseek(__stream,0,2);
  local_10 = ftell(__stream);
  __ptr = malloc(local_10 + 1);
  fread(__ptr,1,local_10,__stream);
  fclose(__stream);
  ...
```

The model classified it as a benign utility with an **empty**
`malicious_behaviors` array — no inflated risk score, no invented C2. A tool
that flags everything is worthless; this is the run that shows it doesn't.

### Report schema

```
executive_summary        classification · risk_level · risk_score · evasion techniques
technical_analysis       binary properties · malicious_behaviors[] with evidence_location
                         and confidence_level · network capabilities · persistence
indicators_of_compromise network IOCs · host IOCs · behavioral IOCs · YARA rules
threat_intelligence      MITRE ATT&CK techniques · actor / campaign attribution
tool_usage_analysis      tools used · investigation strategy · key findings
recommendations          detection · mitigation · further analysis
```

Every entry in `malicious_behaviors` carries an `evidence_location` and a
`confidence_level`, so a reviewer can go straight to the address or function and
check the claim.

---

## Install

```bash
git clone https://github.com/nizaryart/Ioznizer.git
cd Ioznizer
./setup.sh
```

`setup.sh` checks your system tools, creates the virtual environment, installs
the Python dependencies, finds any existing Ghidra or radare2 install, and
prompts for your OpenRouter API key (input hidden, verified against the API,
written to `.env` with mode `600`). It is idempotent — safe to re-run.

```
./setup.sh --check         report what is present, change nothing
./setup.sh --with-ghidra   also download Ghidra (~1 GB, checksum verified)
```

**Requirements:** Python 3.9+ and GNU binutils (`readelf`, `objdump`,
`strings`). `setup.sh` prints the right install command for your package
manager if anything is missing.

### Decompiler

Ghidra is strongly recommended; radare2 is used automatically as a fallback,
and without either the pipeline still runs on disassembly alone.

If you already have Ghidra, `setup.sh` finds it via `GHIDRA_HOME`, `PATH`, or
the usual locations. Otherwise `./setup.sh --with-ghidra` downloads the pinned
release, verifies its SHA-256 against the checksum published by the NSA, and
refuses to extract on a mismatch.

Ghidra targets JDK 21. On a newer JDK, pin it:

```bash
echo 'JAVA_HOME_OVERRIDE=/usr/lib/jvm/java-21-openjdk-amd64' \
  >> "$GHIDRA_HOME/support/launch.properties"
```

### API key

`setup.sh` prompts for one. To set it later, or to change it, edit `.env`:

```bash
OPENROUTER_API_KEY=sk-or-v1-...
```

Free keys: [openrouter.ai/keys](https://openrouter.ai/keys). The key is read
from the environment or `.env` only — never hardcoded, never committed
(`.env` is gitignored), and redacted in logs.

## Usage

```bash
./run.sh samples/time                # benign control sample
./run.sh samples/your_sample.elf     # your own binary
```

Output:

```
analysis/*.txt                  static extraction + decompilation
reports/<name>_<timestamp>.json structured verdict
reports/<name>_<timestamp>.md   readable report
```

If the decompiler is unavailable or the API call fails, extraction still
completes and the report says exactly what was missing — the pipeline degrades
rather than guessing.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | — | Required for LLM analysis |
| `OPENROUTER_MODEL` | `nvidia/nemotron-3-ultra-550b-a55b:free` | Any tool-calling model |
| `GHIDRA_HOME` | auto-detected | Ghidra installation root |
| `DECOMPILER_BACKEND` | auto | Force `ghidra`, `radare2` or `none` |
| `DECOMPILER_TIMEOUT` | `900` | Seconds before decompilation is abandoned |
| `IOZNIZER_SANDBOX` | `1` | Run the decompiler under `bwrap` |
| `MAX_ANALYSIS_ITERATIONS` | `20` | Agent loop ceiling |
| `LLM_MAX_TOKENS` | `16000` | Response ceiling; the final report is a large JSON document |
| `LLM_TEMPERATURE` | `0.7` | Sampling temperature |

### Choosing a model

The model is entirely your choice — anything on OpenRouter that supports tool
calling will drive the pipeline:

```bash
export OPENROUTER_MODEL="nvidia/nemotron-3-ultra-550b-a55b:free"  # free, 1M context
export OPENROUTER_MODEL="anthropic/claude-sonnet-4.5" # or any paid model
```

The default is a free tool-calling model, so a full analysis costs nothing to
run. Depth of analysis scales with the model: larger models follow longer chains
of reasoning through the decompiled code, cite more precise evidence and produce
richer ATT&CK mappings. The tool layer is identical either way — the same eight
tools, the same extracted artifacts — so you can start free and move to a
stronger model when a sample warrants it.

To list the free tool-calling models currently available:

```bash
curl -s https://openrouter.ai/api/v1/models \
  | jq -r '.data[] | select(.id|endswith(":free"))
           | select(.supported_parameters|index("tools"))
           | "\(.id)  ctx=\(.context_length)"'
```

---

## Handling untrusted binaries

Ioznizer performs **static analysis only**. Nothing in the pipeline executes the
sample — the decompiler parses and lifts it, and that is the extent of the
interaction.

As defence in depth against a malformed binary targeting the analyser's own
parsers, decompilation runs under `bwrap` when available: no network
(`--unshare-net`), a scratch home, and the sample staged in read-only at mode
`0400`. Live samples are never committed to this repository; see
[`samples/README.md`](samples/README.md).

Findings are model-generated and evidence-linked by design — each one names the
function or address it came from, so it can be verified against the binary
before it informs a decision.

## Project layout

```
setup.sh                    one-command environment setup and dependency check
run.sh                      entry point; runs main.py inside the virtualenv
main.py                     orchestrates extraction, analysis, reporting
config.py                   environment-driven configuration
backend/extractor.py        ELF validation, arch detection, static extraction
backend/decompiler.py       Ghidra / radare2 backends, sandboxing
backend/ghidra_scripts/     GhidraScript that exports pseudo-C
agent/analyze.py            iterative agent loop and convergence control
agent/openrouter_client.py  API client, retries, backoff
agent/tool_dispatcher.py    executes model tool calls
agent/tools_schema.py       tool definitions
agent/report_generator.py   JSON extraction, validation, rendering
samples/                    benign control sample + sourcing notes
```

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Nizar](https://github.com/nizaryart) — cybersecurity engineer working
on malware analysis, detection engineering and applied AI for security
operations.
