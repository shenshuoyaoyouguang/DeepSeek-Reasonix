package agent

import (
	"context"
	"encoding/json"
	"reasonix/internal/diff"
	"reasonix/internal/event"
	"strings"
	"testing"

	"reasonix/internal/provider"
	"reasonix/internal/tool"
)

// stubGate denies any call whose tool name is in deny; everything else allows.
type stubGate struct {
	deny    map[string]bool
	checked []string
}

func (g *stubGate) Check(ctx context.Context, toolName string, args json.RawMessage, readOnly bool) (bool, string, error) {
	g.checked = append(g.checked, toolName)
	if g.deny[toolName] {
		return false, "denied by test policy", nil
	}
	return true, "", nil
}

// TestGateBlocksDeniedCall proves executeOne consults the gate after the
// plan-mode check: a denied tool returns a "blocked:" result plus a notice and
// never runs, while an allowed tool runs normally.
func TestGateBlocksDeniedCall(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Add(fakeTool{name: "bash", readOnly: false})
	reg.Add(fakeTool{name: "read_file", readOnly: true})

	g := &stubGate{deny: map[string]bool{"bash": true}}
	a := New(nil, reg, NewSession(""), Options{Gate: g}, event.Discard)

	blocked := a.executeOne(context.Background(), provider.ToolCall{Name: "bash", Arguments: `{"command":"rm -rf /"}`})
	if !strings.HasPrefix(blocked.output, "blocked:") {
		t.Errorf("denied call result = %q, want a 'blocked:' result", blocked.output)
	}
	if !blocked.blocked || blocked.errMsg == "" {
		t.Errorf("denied call should surface a user-facing block notice, got %+v", blocked)
	}

	ok := a.executeOne(context.Background(), provider.ToolCall{Name: "read_file", Arguments: `{"path":"/a"}`})
	if !strings.Contains(ok.output, "done") {
		t.Errorf("allowed call should run, got %q", ok.output)
	}

	if len(g.checked) != 2 {
		t.Errorf("gate consulted %d times, want 2 (%v)", len(g.checked), g.checked)
	}
}

// TestNilGateRunsEverything confirms gating is opt-in: with no gate wired, a
// writer call runs unimpeded (backward-compatible default).
func TestNilGateRunsEverything(t *testing.T) {
	reg := tool.NewRegistry()
	reg.Add(fakeTool{name: "write_file", readOnly: false})

	a := New(nil, reg, NewSession(""), Options{}, event.Discard) // no Gate
	out := a.executeOne(context.Background(), provider.ToolCall{Name: "write_file", Arguments: `{"path":"/a"}`})
	if strings.HasPrefix(out.output, "blocked:") {
		t.Errorf("nil gate should not block: %q", out.output)
	}
}

// approvalPreviewTool exposes mutable pre-edit state so the test can model an
// external file change while a human approval prompt is open.
type approvalPreviewTool struct {
	state    string
	previews int
}

func (*approvalPreviewTool) Name() string            { return "write_file" }
func (*approvalPreviewTool) Description() string     { return "stub" }
func (*approvalPreviewTool) Schema() json.RawMessage { return json.RawMessage(`{}`) }
func (*approvalPreviewTool) ReadOnly() bool          { return false }
func (*approvalPreviewTool) Execute(context.Context, json.RawMessage) (string, error) {
	return "done", nil
}
func (t *approvalPreviewTool) Preview(json.RawMessage) (diff.Change, error) {
	t.previews++
	return diff.Change{Path: "file.txt", OldText: t.state, Kind: diff.Modify}, nil
}

type previewingApprovalGate struct{ tool *approvalPreviewTool }

func (g previewingApprovalGate) Check(ctx context.Context, _ string, args json.RawMessage, _ bool) (bool, string, error) {
	// This mirrors Controller.approvalWithPreview: render the approval preview,
	// then wait while the workspace may change before the user approves.
	_, _, _ = tool.PreviewMemoized(ctx, g.tool, args)
	g.tool.state = "after approval"
	return true, "", nil
}

func TestCheckpointPreviewRefreshesAfterApproval(t *testing.T) {
	previewTool := &approvalPreviewTool{state: "before approval"}
	reg := tool.NewRegistry()
	reg.Add(previewTool)
	a := New(nil, reg, NewSession(""), Options{Gate: previewingApprovalGate{tool: previewTool}}, event.Discard)

	var snap diff.Change
	a.SetPreEditHook(func(ch diff.Change) { snap = ch })
	out := a.executeOne(context.Background(), provider.ToolCall{Name: "write_file", Arguments: `{"path":"file.txt"}`})

	if out.errMsg != "" {
		t.Fatalf("executeOne error = %q", out.errMsg)
	}
	if snap.OldText != "after approval" {
		t.Fatalf("checkpoint OldText = %q, want fresh post-approval state", snap.OldText)
	}
	if previewTool.previews != 2 {
		t.Fatalf("Preview calls = %d, want approval preview plus fresh checkpoint preview", previewTool.previews)
	}
}
