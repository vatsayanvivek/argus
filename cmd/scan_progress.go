package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/term"

	"github.com/vatsayanvivek/argus/internal/collector/azure"
)

// scanProgressRenderer draws a live multi-line status table during
// the long parallel collection phase of a scan. Each sub-collector
// (resources, identity, rbac, defender, activitylog, policy) gets a
// line that updates in place as it transitions running → completed
// / failed.
//
// Key behaviours:
//
//   * A background ticker re-renders every 250 ms so elapsed-time
//     counters keep advancing visibly even when no ProgressEvent has
//     fired. Previously the UI would freeze at "running 1m10s" for
//     20 minutes if the underlying API call hung.
//   * A Braille-cell spinner animates next to every `running` row so
//     the user always has visual evidence that something is
//     happening, not just a stale elapsed counter.
//   * Done sub-collectors render with their final elapsed time (not
//     the ever-growing clock) so the table tells the truth.
//
// Terminal handling:
//
//   - If stdout is a TTY that supports ANSI, we redraw the block in
//     place using cursor-up and clear-line escape codes.
//   - If stdout isn't a TTY (piped to a file, CI runner without PTY),
//     the ticker loop is suppressed and we only render on event, so
//     piped output stays compact.
type scanProgressRenderer struct {
	mu         sync.Mutex
	started    time.Time
	states     map[string]*collectorState
	order      []string
	ttyMode    bool
	out        io.Writer
	linesDrawn int
	done       bool

	// Ticker machinery.
	tickDone  chan struct{}
	tickWG    sync.WaitGroup
	spinFrame int
}

// collectorState is the per-sub-collector status the renderer tracks.
type collectorState struct {
	name     string
	label    string
	phase    string // pending | running | done | failed
	detail   string
	started  time.Time
	finished time.Time
	err      error
}

// Braille-cell spinner frames. These render cleanly in every modern
// terminal (Windows Terminal, iTerm2, GNOME Terminal, PowerShell 5+,
// VS Code integrated) and don't reserve disproportionate width.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// newScanProgressRenderer builds a renderer preconfigured with the 6
// sub-collectors ARGUS runs in parallel during CollectAll.
func newScanProgressRenderer(out io.Writer) *scanProgressRenderer {
	r := &scanProgressRenderer{
		started:  time.Now(),
		states:   map[string]*collectorState{},
		out:      out,
		tickDone: make(chan struct{}),
	}
	if f, ok := out.(*os.File); ok {
		r.ttyMode = term.IsTerminal(int(f.Fd()))
	}

	defs := []struct {
		name, label string
	}{
		{"resources", "Azure resources (Resource Graph)"},
		{"identity", "Entra ID (users, groups, SPs, CAPs)"},
		{"rbac", "Azure RBAC (ARM authorization)"},
		{"defender", "Microsoft Defender for Cloud"},
		{"activitylog", "Activity Log (30-day window)"},
		{"policy", "Azure Policy compliance"},
	}
	for _, d := range defs {
		r.states[d.name] = &collectorState{name: d.name, label: d.label, phase: "pending"}
		r.order = append(r.order, d.name)
	}
	return r
}

// OnEvent is the ProgressCallback passed to CollectAllWithProgress.
// Safe to call from multiple goroutines — internally serialised by mu.
func (r *scanProgressRenderer) OnEvent(e azure.ProgressEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, ok := r.states[e.Name]
	if !ok {
		return
	}
	switch e.Phase {
	case "started":
		st.phase = "running"
		st.started = time.Now().Add(-e.Elapsed)
		st.detail = e.Detail
	case "completed":
		st.phase = "done"
		st.finished = time.Now()
		st.detail = e.Detail
	case "failed":
		st.phase = "failed"
		st.finished = time.Now()
		st.detail = e.Detail
		st.err = e.Err
	}
	r.render()
}

// Start draws the initial table and, on a TTY, launches the animation
// ticker so elapsed times + spinner frames update at 4 Hz.
func (r *scanProgressRenderer) Start() {
	r.mu.Lock()
	r.render()
	r.mu.Unlock()

	if !r.ttyMode {
		return
	}
	r.tickWG.Add(1)
	go func() {
		defer r.tickWG.Done()
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-r.tickDone:
				return
			case <-t.C:
				r.mu.Lock()
				if !r.done && r.hasRunningLocked() {
					r.spinFrame++
					r.render()
				}
				r.mu.Unlock()
			}
		}
	}()
}

// hasRunningLocked reports whether any sub-collector is still
// running. When everything has either completed or failed, the ticker
// stops redrawing to avoid burning CPU for no reason. Caller must
// hold r.mu.
func (r *scanProgressRenderer) hasRunningLocked() bool {
	for _, st := range r.states {
		if st.phase == "running" || st.phase == "pending" {
			return true
		}
	}
	return false
}

// Done stops the ticker, re-renders one last time with final elapsed
// times, and drops a trailing newline so subsequent output doesn't
// clobber the last row.
func (r *scanProgressRenderer) Done() {
	r.mu.Lock()
	r.done = true
	r.render()
	r.mu.Unlock()

	if r.ttyMode {
		close(r.tickDone)
		r.tickWG.Wait()
	}
	fmt.Fprintln(r.out)
}

// render draws the table in place. TTY mode uses ANSI cursor-up +
// clear-to-end-of-screen to redraw at the same position; non-TTY
// appends a fresh block (noisier, but stays legible in CI logs).
func (r *scanProgressRenderer) render() {
	green := color.New(color.FgHiGreen, color.Bold).SprintFunc()
	red := color.New(color.FgHiRed, color.Bold).SprintFunc()
	cyan := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	magenta := color.New(color.FgHiMagenta, color.Bold).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()
	white := color.New(color.FgHiWhite, color.Bold).SprintFunc()

	if r.ttyMode && r.linesDrawn > 0 {
		// Cursor-up N lines + clear from cursor to end of screen.
		fmt.Fprintf(r.out, "\033[%dA\033[0J", r.linesDrawn)
	}

	lines := 0
	totalElapsed := time.Since(r.started).Round(time.Second)

	// Count done / failed / running for the header summary.
	doneCount, failedCount, runningCount, pendingCount := 0, 0, 0, 0
	for _, st := range r.states {
		switch st.phase {
		case "done":
			doneCount++
		case "failed":
			failedCount++
		case "running":
			runningCount++
		case "pending":
			pendingCount++
		}
	}
	totalCount := len(r.states)

	// Box-top header. Double-line characters for the outer frame.
	boxWidth := 68
	fmt.Fprintln(r.out, cyan("╔"+strings.Repeat("═", boxWidth-2)+"╗"))
	lines++

	// Title row: ARGUS wordmark + elapsed time.
	leftSide := fmt.Sprintf("  %s collecting Azure tenant state", cyan("▶"))
	rightSide := dim(fmt.Sprintf("elapsed %s  ", totalElapsed))
	// Need to account for ANSI escape width when padding. Strip colour
	// codes before measuring, then pad manually.
	leftPlain := stripANSI(leftSide)
	rightPlain := stripANSI(rightSide)
	pad := boxWidth - 2 - len(leftPlain) - len(rightPlain)
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(r.out, "%s%s%s%s%s\n", cyan("║"), leftSide, strings.Repeat(" ", pad), rightSide, cyan("║"))
	lines++

	// Counter row: X done, Y running, Z pending
	statusLine := fmt.Sprintf("  %s %d/%d done",
		statusGlyph(doneCount, totalCount, failedCount), doneCount, totalCount)
	if runningCount > 0 {
		statusLine += dim("  ·  ") + magenta(fmt.Sprintf("%d running", runningCount))
	}
	if pendingCount > 0 {
		statusLine += dim("  ·  ") + dim(fmt.Sprintf("%d queued", pendingCount))
	}
	if failedCount > 0 {
		statusLine += dim("  ·  ") + red(fmt.Sprintf("%d failed", failedCount))
	}
	statusPlain := stripANSI(statusLine)
	pad = boxWidth - 2 - len(statusPlain)
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(r.out, "%s%s%s%s\n", cyan("║"), statusLine, strings.Repeat(" ", pad), cyan("║"))
	lines++

	// Separator between header and per-collector rows.
	fmt.Fprintf(r.out, "%s%s%s\n", cyan("╠"), strings.Repeat("═", boxWidth-2), cyan("╣"))
	lines++

	// Per-collector rows.
	for _, name := range r.order {
		st := r.states[name]
		var icon, phaseText string
		switch st.phase {
		case "pending":
			icon = dim("◌")
			phaseText = dim("queued")
		case "running":
			frame := spinnerFrames[r.spinFrame%len(spinnerFrames)]
			icon = magenta(frame)
			phaseText = magenta(fmt.Sprintf("running %s", time.Since(st.started).Round(time.Second)))
		case "done":
			icon = green("✓")
			phaseText = green(fmt.Sprintf("%s", st.finished.Sub(st.started).Round(time.Second)))
		case "failed":
			icon = red("✗")
			phaseText = red(fmt.Sprintf("failed %s", st.finished.Sub(st.started).Round(time.Second)))
		}

		detail := st.detail
		if len(detail) > boxWidth-30 {
			detail = detail[:boxWidth-33] + "..."
		}
		rowContent := fmt.Sprintf(" %s  %-38s  %-14s %s", icon, truncateLabel(st.label, 38), phaseText, dim(detail))
		rowPlain := stripANSI(rowContent)
		pad := boxWidth - 2 - len(rowPlain)
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintf(r.out, "%s%s%s%s\n", cyan("║"), rowContent, strings.Repeat(" ", pad), cyan("║"))
		lines++
	}

	// Box-bottom.
	fmt.Fprintln(r.out, cyan("╚"+strings.Repeat("═", boxWidth-2)+"╝"))
	lines++

	// Inline hint when things are running that the user knows what's
	// expected. Only shown on the first few ticks to avoid clutter.
	if runningCount > 0 && !r.done && totalElapsed < 10*time.Second {
		hint := dim("  Typical scan: 30s–2min per subscription. Longer means a large tenant or slow API.")
		fmt.Fprintln(r.out, hint)
		lines++
	}

	r.linesDrawn = lines
	_ = white // keep reference
}

// statusGlyph returns a coloured symbol for the overall scan state:
// ✓ if all done cleanly, ✗ if anything failed, ⚙ while work is in
// progress.
func statusGlyph(doneCount, totalCount, failedCount int) string {
	green := color.New(color.FgHiGreen, color.Bold).SprintFunc()
	red := color.New(color.FgHiRed, color.Bold).SprintFunc()
	magenta := color.New(color.FgHiMagenta, color.Bold).SprintFunc()
	if failedCount > 0 {
		return red("⚠")
	}
	if doneCount == totalCount {
		return green("✓")
	}
	return magenta("⚙")
}

// truncateLabel keeps the label within maxWidth characters, adding an
// ellipsis if it had to be cut.
func truncateLabel(s string, maxWidth int) string {
	if len(s) <= maxWidth {
		return s
	}
	return s[:maxWidth-1] + "…"
}

// stripANSI removes ANSI escape sequences so we can measure the
// display width of a coloured string. Handles CSI sequences (ESC[
// ... letter) — good enough for fatih/color output, which is all we
// use.
func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// Skip until we find the final byte (a letter in 0x40..0x7E).
			j := i + 2
			for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7E) {
				j++
			}
			if j < len(s) {
				i = j + 1
			} else {
				i = j
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
