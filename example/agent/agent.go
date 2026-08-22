package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

const maxTurns = 6

// Run drives the model until it stops calling tools. It knows nothing about
// which surface it is on -- that is entirely Transport's business, and it is
// why one agent demonstrates three enforcement points.
func Run(ctx context.Context, l *LLM, t Transport, task string, want []Expectation, out io.Writer) *Report {
	rep := NewReport(want)
	msgs := []Message{
		{Role: "system", Content: "You are an agent with tools. Use them to complete the task. " +
			"If a tool call is refused, say so plainly and do not retry it."},
		{Role: "user", Content: task},
	}

	for turn := 0; turn < maxTurns; turn++ {
		reply, err := l.Chat(ctx, msgs, t.Tools())
		if err != nil {
			fmt.Fprintf(out, "  model unreachable: %v\n", err)
			return rep
		}
		if reply.Content != "" {
			fmt.Fprintf(out, "  model> %s\n", reply.Content)
		}
		if len(reply.ToolCalls) == 0 {
			rep.NoToolCall()
			return rep
		}
		msgs = append(msgs, reply)

		for i, call := range reply.ToolCalls {
			res, err := t.Call(ctx, call)
			if err != nil {
				// A transport error is the example being broken, not policy
				// answering. Never record it as a decision.
				fmt.Fprintf(out, "  ERROR  %s: %v\n", call.Name, err)
				return rep
			}
			rep.Record(call, res)

			args, _ := json.Marshal(call.Args)
			if res.Allowed {
				fmt.Fprintf(out, "  ALLOW  %-18s %s\n", call.Name, args)
			} else {
				fmt.Fprintf(out, "  DENY   %-18s %s\n         %s\n", call.Name, args, res.Reason)
			}

			content := res.Output
			if !res.Allowed {
				content = "DENIED by policy: " + res.Reason
			}
			id := ""
			if i < len(reply.RawToolCalls) {
				id = reply.RawToolCalls[i].ID
			}
			msgs = append(msgs, Message{Role: "tool", ToolCallID: id, Content: content})
		}
	}
	return rep
}
