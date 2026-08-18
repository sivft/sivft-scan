# sivft-scan

A CLI that tells you which of your logs are wasting money.

**sivft-scan runs entirely on your machine. It makes no network calls, sends no data anywhere, and only writes the report file you ask for.**

## Install

```sh
go build -o sivft-scan .
```

Or cross-compile binaries for macOS (arm64/amd64) and Linux (arm64/amd64):

```sh
./scripts/build.sh   # outputs to dist/
```

## Try it

```sh
sivft-scan analyze --input examples/sample.jsonl --monthly-gb 120
```

## Usage

```sh
sivft-scan analyze --input sample.jsonl [--output report.html] [--rate-per-gb 0.10] [--monthly-gb 120]
```

It reads a log file line by line (JSONL or plaintext), evaluates ~22 built-in
rules in shadow mode, and generates a standalone HTML report showing total
volume, which rules match how much of it, and a conservative dollar estimate.

The reduction percentage is valid for any sample size. The monthly dollar
estimate needs your actual ingest volume — pass `--monthly-gb`. Without it,
the estimate stays hidden instead of showing a misleading $0.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--input` | — | Path to a log file (JSONL or plaintext). Required. |
| `--format` | `auto` | Hint: `auto`, `jsonl`, `datadog`, `otlp`, `syslog`, `plaintext`. |
| `--rate-per-gb` | `0.10` | Assumed vendor ingest cost per GB. |
| `--monthly-gb` | `0` | Assumed monthly ingest volume in GB; enables the dollar estimate. |
| `--output` | `report.html` | Where to write the HTML report. |

## Example

```sh
sivft-scan analyze --input /path/to/sample.jsonl --monthly-gb 120 --output /tmp/report.html
open /tmp/report.html
```

## What it estimates

The report shows, per rule, how many events and bytes would be dropped or
sampled, plus an overall potential reduction percentage. Reductions are
estimates from static analysis — nothing is actually removed. Sample rules
keep a fraction of matching volume for debuggability.

Assumptions are explicit and conservative. Adjust `--rate-per-gb` to match
your vendor price; actual savings depend on your pricing and retention. Pass
`--monthly-gb` with your real ingest volume to convert the reduction percentage
into a monthly dollar figure.