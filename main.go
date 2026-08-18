package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		if len(os.Args) < 2 {
			os.Exit(2)
		}
		return
	}
	if os.Args[1] != "analyze" {
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	input := fs.String("input", "", "path to a log file (JSONL or plaintext)")
	format := fs.String("format", "auto", "hint for parsing: auto, jsonl, datadog, otlp, syslog, plaintext")
	ratePerGB := fs.Float64("rate-per-gb", 0.10, "assumed vendor ingest cost per GB")
	monthlyGB := fs.Float64("monthly-gb", 0, "assumed monthly ingest volume in GB; enables the dollar estimate")
	output := fs.String("output", "report.html", "path for the generated HTML report")
	fs.Parse(os.Args[2:])

	if *input == "" {
		fmt.Fprintln(os.Stderr, "error: --input is required")
		usage()
		os.Exit(2)
	}

	report, err := analyzeFile(*input, *format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := writeReport(*output, report, *ratePerGB, *monthlyGB); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("analyzed %s: %d %s, %s, potential reduction %s\n",
		*input, report.TotalEvents, plural(report.TotalEvents, "event", "events"), humanBytes(report.TotalBytes), humanBytes(int64(report.SavedBytes)))
	if *monthlyGB > 0 {
		month := *monthlyGB * report.ReductionPct / 100 * *ratePerGB
		fmt.Printf("at %.0f GB/mo ingest this is ~$%.2f/mo in ingest savings\n", *monthlyGB, month)
	}
	fmt.Printf("report written to %s\n", *output)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func usage() {
	fmt.Fprintln(os.Stderr, `sivft-scan - estimate how much of a log file is low-value

Usage:
  sivft-scan analyze --input <file> [flags]

Flags:
  --input <file>     path to a log file (JSONL or plaintext) [required]
  --format <fmt>     hint: auto, jsonl, datadog, otlp, syslog, plaintext
  --rate-per-gb <n>  assumed vendor ingest cost per GB (default 0.10)
  --monthly-gb <n>   assumed monthly ingest volume in GB; enables the
                     monthly dollar estimate (default 0 = estimate hidden)
  --output <file>    path for the HTML report (default report.html)

The tool runs fully locally. It makes no network calls and sends nothing anywhere.`)
}

func analyzeFile(path, format string) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rep := &Report{}
	for _, r := range builtinRules {
		rep.RuleStats = append(rep.RuleStats, &RuleStat{Rule: r})
	}

	rd := bufio.NewReader(f)
	for {
		raw, err := rd.ReadString('\n')
		if len(raw) > 0 {
			line := strings.TrimRight(raw, "\r\n")
			if strings.TrimSpace(line) != "" {
				rep.process(line)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	rep.ReductionPct = pctOf(rep.SavedBytes, float64(rep.TotalBytes))
	return rep, nil
}

func (rep *Report) process(line string) {
	ev := parseEvent(line)
	rep.TotalEvents++
	rep.TotalBytes += int64(ev.SizeBytes)
	for _, st := range rep.RuleStats {
		if st.Match(ev) {
			st.Matches++
			st.Bytes += int64(ev.SizeBytes)
			var saved float64
			if st.Action == "sample" {
				saved = float64(ev.SizeBytes) * st.Rate
			} else {
				saved = float64(ev.SizeBytes)
			}
			st.SavedBytes += saved
			rep.SavedBytes += saved
			if len(st.Samples) < 5 {
				st.Samples = append(st.Samples, ev.Line)
			}
			break
		}
	}
}
