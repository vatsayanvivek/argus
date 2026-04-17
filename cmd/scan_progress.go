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
// / failed. An elapsed timer for the overall scan keeps the user
// confident the tool isn't stuck.
//
// Terminal handling:
//
//   - If stdout is a TTY that supports ANSI, we redraw the block in
//     place using cursor-up and clear-line escape codes.
//   - If stdout isn't a TTY (piped to a file, CI runner without PTY,
//     Windows legacy cmd.exe without VT processing), we fall back to
//     simple append-only event lines so nothing is lost.
//
// This renderer directly replaces the v1.8.x 7-step progress bar
// that froze at 14% during CollectAll.
type scanProgressRenderer struct {
	mu        sync.Mutex
	started   time.Time
	states    map[string]*collectorState
	order     []string // render order, deterministic
	ttyMode   bool
	out       io.Writer
	linesDrawn int
	done      bool
}

// collectorState is the per-sub-collector status the renderer tracks.
type collectorState struct {
	name      string
	label     string
	phase     string // pending | running | done | failed
	detail    string
	started   time.Time
	finished  time.Time
	err       error
}

// newScanProgressRenderer builds a renderer preconfigured with the 6
// sub-collectors ARGUS runs in parallel during CollectAll. The caller
// invokes OnEvent as a ProgressCallback and Done when collection
// finishes.
func newScanProgressRenderer(out io.Writer) *scanProgressRenderer {
	r := &scanProgressRenderer{
		started: time.Now(),
		states:  map[string]*collectorState{},
		out:     out,
	}

	// Detect TTY. If stdout isn't attached to a terminal (piped,
	// redirected), we can't do in-place updates — degrade gracefully.
	if f, ok := out.(*os.File); ok {
		r.ttyMode = term.IsTerminal(int(f.Fd()))
	}

	// The 6 sub-collectors, in display order. Labels are human-
	// readable; the internal names must match what
	// CollectAllWithProgress emits.
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
// Safe to call from multiple goroutines — internally serialised by
// mu.
func (r *scanProgressRenderer) OnEvent(e azure.ProgressEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, ok := r.states[e.Name]
	if !ok {
		return // unknown sub-collector — ignore silently
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

// Start emits the initial table before any events fire, so the user
// sees the plan immediately rather than a blank terminal while the
// first collector starts up.
func (r *scanProgressRenderer) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.render()
}

// Done finalises the renderer, re-rendering one last time so the
// "elapsed" column reflects total scan duration. After Done, OnEvent
// becomes a no-op.
func (r *scanProgressRenderer) Done() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	r.render()
	// Drop a final newline so subsequent stdout writes don't clobber
	// the last table row.
	fmt.Fprintln(r.out)
}

// render draws the table. In TTY mode it moves the cursor up by the
// number of lines previously drawn, then emits fresh rows. In non-TTY
// mode it just appends a new block — noisier but works everywhere.
func (r *scanProgressRenderer) render() {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	if r.ttyMode && r.linesDrawn > 0 {
		// Cursor-up N lines + clear to end of screen. ANSI escapes:
		//   ESC[nA  — up n lines
		//   ESC[0J  — clear from cursor to end of screen
		fmt.Fprintf(r.out, "\033[%dA\033[0J", r.linesDrawn)
	}

	lines := 0
	// Header — overall elapsed time.
	fmt.Fprintf(r.out, "%s %s %s\n",
		bold("ARGUS scan"),
		dim("│"),
		dim(fmt.Sprintf("elapsed %s", time.Since(r.started).Round(time.Second))))
	lines++
	// Divider — matches the header width visually.
	fmt.Fprintln(r.out, dim(strings.Repeat("─", 60)))
	lines++

	// Per-collector rows, rendered in the order declared at
	// construction — deterministic regardless of which goroutine
	// wins the race to finish first.
	for _, name := range r.order {
		st := r.states[name]
		var icon, phaseText string
		switch st.phase {
		case "pending":
			icon = dim("·")
			phaseText = dim("queued")
		case "running":
			icon = yellow("↻")
			phaseText = yellow(fmt.Sprintf("running %s", time.Since(st.started).Round(time.Second)))
		case "done":
			icon = green("✓")
			phaseText = green(fmt.Sprintf("done    %s", st.finished.Sub(st.started).Round(time.Second)))
		case "failed":
			icon = red("✗")
			phaseText = red(fmt.Sprintf("failed  %s", st.finished.Sub(st.started).Round(time.Second)))
		}
		detailCol := ""
		if st.detail != "" {
			detailCol = dim("— " + st.detail)
		}
		// Fixed-width columns so in-place update doesn't shimmy.
		fmt.Fprintf(r.out, " %s %-38s %-20s %s\n", icon, st.label, phaseText, detailCol)
		lines++
	}

	r.linesDrawn = lines
}
