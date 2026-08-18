package main

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Seg struct {
	Name  string
	Pct   float64
	Red   bool
	Other bool
}

func buildSegments(sorted []*RuleStat, totalBytes int64) []Seg {
	if totalBytes <= 0 {
		return nil
	}
	const maxSegs = 6
	var segs []Seg
	kept := float64(totalBytes)
	var tail float64
	for _, st := range sorted {
		if st.SavedBytes <= 0 {
			continue
		}
		if len(segs) < maxSegs {
			segs = append(segs, Seg{Name: st.Name, Pct: st.SavedBytes / float64(totalBytes) * 100, Red: true})
			kept -= st.SavedBytes
		} else {
			tail += st.SavedBytes
		}
	}
	if tail > 0 {
		segs = append(segs, Seg{Name: "other rules", Pct: tail / float64(totalBytes) * 100, Red: true, Other: true})
		kept -= tail
	}
	if kept > 0 {
		segs = append(segs, Seg{Name: "kept", Pct: kept / float64(totalBytes) * 100})
	}
	return segs
}

func writeReport(path string, rep *Report, ratePerGB, monthlyGB float64) error {
	sorted := make([]*RuleStat, len(rep.RuleStats))
	copy(sorted, rep.RuleStats)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].SavedBytes > sorted[j].SavedBytes
	})

	data := struct {
		TotalEvents   int
		TotalBytes    int64
		SavedBytes    float64
		ReductionPct  float64
		EstSavingsUSD float64
		MonthlyGB     float64
		RatePerGB     float64
		Segs          []Seg
		Rules         []*RuleStat
	}{
		TotalEvents:   rep.TotalEvents,
		TotalBytes:    rep.TotalBytes,
		SavedBytes:    rep.SavedBytes,
		ReductionPct:  rep.ReductionPct,
		EstSavingsUSD: monthlyGB * rep.ReductionPct / 100 * ratePerGB,
		MonthlyGB:     monthlyGB,
		RatePerGB:     ratePerGB,
		Segs:          buildSegments(sorted, rep.TotalBytes),
		Rules:         sorted,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"comma":      comma,
		"bytes":      humanBytes,
		"bytesSaved": func(n float64) string { return humanBytes(int64(n)) },
		"pct":        func(n float64) string { return fmt.Sprintf("%.1f%%", n) },
		"money":      func(n float64) string { return fmt.Sprintf("$%.2f", n) },
		"ratePct":    func(r float64) string { return fmt.Sprintf("%.0f%%", r*100) },
	}).Parse(reportTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

func comma(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	return strings.Join(parts, ",")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func pctOf(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return a / b * 100
}

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sivft — Log reduction report</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0b0b0d;
    --panel: #101014;
    --fg: #f5f4f2;
    --muted: #8f8d8a;
    --line: #23221f;
    --rowline: #171615;
    --code: #cfcbc4;
    --red: #ff5d57;
    --amber: #d9a441;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; overflow-x: hidden; }
  body {
    background: var(--bg);
    color: var(--fg);
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  .page { max-width: 44rem; margin: 0 auto; padding: 3.5rem 1.5rem 6rem; }

  header { margin-bottom: 3rem; }
  .top { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; border-bottom: 1px solid var(--line); padding-bottom: 1rem; }
  .wordmark { font-size: .8125rem; letter-spacing: .16em; text-transform: uppercase; color: var(--fg); font-weight: 650; }
  .top .local { font-size: .75rem; color: var(--muted); }
  h1 { font-size: clamp(1.75rem, 5vw, 2.75rem); line-height: 1.1; letter-spacing: -0.02em; font-weight: 650; margin: 2rem 0 .75rem; }
  .lede { color: var(--muted); margin: 0; max-width: 60ch; font-size: .9375rem; }

  .figure { border-bottom: 1px solid var(--line); padding: 0 0 2.5rem; margin-bottom: 2rem; }
  .hero { display: flex; align-items: baseline; gap: .875rem; }
  .hero .num { font-size: clamp(3.5rem, 11vw, 6rem); line-height: .95; font-weight: 650; letter-spacing: -0.04em; color: var(--red); font-variant-numeric: tabular-nums; }
  .hero .unit { font-size: 1.75rem; color: var(--red); }
  .hero .meta { color: var(--muted); font-size: .9375rem; }
  .bar { display: flex; width: 100%; height: 6px; margin: 2rem 0 .75rem; border-radius: 3px; overflow: hidden; background: #19181a; }
  .bar .seg { height: 100%; flex: 0 0 auto; }
  .bar .seg.red { background: var(--red); }
  .bar .seg.red.other { background: #7a2f2c; }
  .bar .seg.kept { background: #2a2926; }
  .legend { display: flex; gap: 1.5rem; font-size: .75rem; color: var(--muted); }
  .legend span::before { content: ""; display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: .5rem; vertical-align: baseline; background: #2a2926; }
  .legend span.red::before { background: var(--red); }

  .stats { display: flex; flex-wrap: wrap; gap: 2.25rem 3rem; padding: 0 0 2.5rem; margin: 0 0 3.5rem; }
  .stats dt { color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .1em; margin: 0 0 .375rem; }
  .stats dd { margin: 0; font-family: var(--mono); font-variant-numeric: tabular-nums; font-size: 1rem; }
  .stats dd.save { color: var(--red); }

  h2 { font-size: 1rem; font-weight: 600; letter-spacing: .02em; margin: 0 0 1.25rem; }
  h2.spaced { margin-top: 3.5rem; }

  table { width: 100%; border-collapse: collapse; font-size: .9375rem; }
  .tablewrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  th { text-align: left; font-weight: 500; font-size: .75rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); padding: .5rem 0; border-bottom: 1px solid var(--line); }
  th.num, td.num { text-align: right; }
  td { padding: .875rem 0; border-bottom: 1px solid var(--rowline); vertical-align: top; }
  th:not(:last-child), td:not(:last-child) { padding-right: 1.5rem; }
  tr:last-child td { border-bottom: 0; }
  td.num { font-family: var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
  tr:hover td { background: var(--panel); }
  .rname { font-weight: 550; }
  .rdesc { color: var(--muted); font-size: .8125rem; margin-top: .125rem; max-width: 42ch; }
  .tag { font-family: var(--mono); font-size: .75rem; letter-spacing: .04em; white-space: nowrap; }
  .tag.drop { color: var(--red); }
  .tag.sample { color: var(--amber); }
  .save { color: var(--red); }

  details { border-top: 1px solid var(--rowline); padding: 1.25rem 0; }
  details:last-of-type { border-bottom: 1px solid var(--line); }
  summary { cursor: pointer; list-style: none; display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; font-weight: 550; border-radius: 2px; }
  summary::-webkit-details-marker { display: none; }
  summary:focus-visible { outline: 1px solid var(--red); outline-offset: 2px; }
  summary .count { font-family: var(--mono); font-size: .8125rem; color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
  pre { margin: 1rem 0 0; padding: 1rem; background: var(--panel); border: 1px solid var(--rowline); border-radius: 4px; overflow-x: auto; color: var(--code); font-family: var(--mono); font-size: .8125rem; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }

  .assumptions { color: var(--muted); font-size: .8125rem; max-width: 60ch; margin-top: 4rem; }
  .assumptions code { font-family: var(--mono); font-size: .75rem; color: var(--fg); }
</style>
</head>
<body>
<div class="page">
  <header>
    <div class="top">
      <span class="wordmark">Sivft</span>
      <span class="local">generated locally · no data sent</span>
    </div>
    <h1>Log reduction report</h1>
    <p class="lede">{{comma .TotalEvents}} events analyzed from {{bytes .TotalBytes}} of logs. Everything below is estimated from this sample — nothing has been dropped.</p>
  </header>

  <section class="figure">
    <div class="hero">
      <span class="num">{{printf "%.1f" .ReductionPct}}</span><span class="unit">%</span>
      <span class="meta">of ingest volume is droppable or sampleable</span>
    </div>
    {{if .Segs}}
    <div class="bar">
      {{range .Segs}}<span class="seg {{if .Red}}red{{end}}{{if .Other}} other{{end}}{{if not .Red}} kept{{end}}" style="width:{{printf "%.2f" .Pct}}%" title="{{.Name}} — {{printf "%.1f" .Pct}}%"></span>{{end}}
    </div>
    <div class="legend">
      <span class="red">droppable</span>
      <span>kept</span>
    </div>
    {{end}}
  </section>

  <dl class="stats">
    <div>
      <dt>Events analyzed</dt>
      <dd>{{comma .TotalEvents}}</dd>
    </div>
    <div>
      <dt>Total volume</dt>
      <dd>{{bytes .TotalBytes}}</dd>
    </div>
    <div>
      <dt>Est. savings / month</dt>
      {{if .MonthlyGB}}<dd class="save">{{money .EstSavingsUSD}}</dd>{{else}}<dd>&mdash;</dd>{{end}}
    </div>
    <div>
      <dt>Assumed ingest</dt>
      <dd>${{printf "%.2f" .RatePerGB}}/GB</dd>
    </div>
  </dl>

  <h2>Where the volume goes</h2>
  <div class="tablewrap">
  <table>
    <thead>
      <tr>
        <th>Rule</th>
        <th>Action</th>
        <th class="num">Matches</th>
        <th class="num">Volume</th>
        <th class="num">Est. saved</th>
      </tr>
    </thead>
    <tbody>
    {{range .Rules}}
      <tr>
        <td>
          <div class="rname">{{.Name}}</div>
          <div class="rdesc">{{.Desc}}</div>
        </td>
        <td><span class="tag {{.Action}}">{{.Action}}{{if eq .Action "sample"}} {{ratePct .Rate}}{{end}}</span></td>
        <td class="num">{{comma .Matches}}</td>
        <td class="num">{{bytes .Bytes}}</td>
        <td class="num save">{{bytesSaved .SavedBytes}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>

  <h2 class="spaced">Affected sample lines</h2>
  {{range .Rules}}
    {{if .Samples}}
    <details>
      <summary>
        <span>{{.Name}}</span>
        <span class="count">{{comma .Matches}} match{{if ne .Matches 1}}es{{end}} · {{len .Samples}} shown</span>
      </summary>
      {{range .Samples}}<pre>{{.}}</pre>{{end}}
    </details>
    {{end}}
  {{end}}

  <p class="assumptions">Assumptions are explicit: ingest cost assumed at <code>${{printf "%.2f" .RatePerGB}}/GB</code>; adjust with <code>--rate-per-gb</code> to match your vendor. {{if .MonthlyGB}}Monthly savings assume <code>{{printf "%.0f" .MonthlyGB}} GB/mo</code> ingest.{{else}}The dollar figure is hidden until you provide your monthly ingest volume with <code>--monthly-gb</code>.{{end}} These are static-analysis estimates from a sample — nothing was dropped. Actual savings depend on your pricing and retention.</p>
</div>
</body>
</html>`
