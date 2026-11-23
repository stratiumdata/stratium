"""An OpenAI-compatible model for the litellm-guarded service.

Every reply proposes the same two tool calls, guarded_read and
guarded_write. The integration suite grants the first and not the second, so
what LiteLLM passes on shows what the guardrail did.

Chat completions are answered streamed or whole. The Responses API, which
LiteLLM also uses upstream to serve Anthropic Messages, is answered whole.
"""
import http.server
import json

CALLS = [
    {"id": f"call_{i}", "type": "function",
     "function": {"name": name, "arguments": json.dumps({"path": "/tmp/notes.txt"})}}
    for i, name in enumerate(("guarded_read", "guarded_write"))
]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, reply):
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        print(self.path, "stream" if body.get("stream") else "whole", flush=True)
        if self.path.endswith("/responses"):
            return self.send_json({
                "id": "resp_1", "object": "response", "created_at": 1, "status": "completed",
                "model": body.get("model", "mock"), "parallel_tool_calls": True,
                "tool_choice": "auto", "tools": [],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                "output": [{"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                            "content": [{"type": "output_text", "text": "I will do that.", "annotations": []}]}] + [
                    {"type": "function_call", "id": f"fc_{i}", "call_id": call["id"], "status": "completed",
                     "name": call["function"]["name"], "arguments": call["function"]["arguments"]}
                    for i, call in enumerate(CALLS)],
            })
        base = {"id": "cmpl-1", "created": 1, "model": body.get("model", "mock")}
        if not body.get("stream"):
            return self.send_json(dict(
                base, object="chat.completion",
                usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                choices=[{"index": 0, "finish_reason": "tool_calls", "message": {
                    "role": "assistant", "content": "I will do that.", "tool_calls": CALLS}}],
            ))

        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()

        def event(delta, finish=None):
            chunk = dict(base, object="chat.completion.chunk",
                         choices=[{"index": 0, "delta": delta, "finish_reason": finish}])
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()

        event({"role": "assistant", "content": "I will do that."})
        for i, call in enumerate(CALLS):
            fn = call["function"]
            event({"tool_calls": [{"index": i, "id": call["id"], "type": "function",
                                   "function": {"name": fn["name"], "arguments": ""}}]})
            # The arguments arrive in two pieces, as a real model sends them.
            half = len(fn["arguments"]) // 2
            for part in (fn["arguments"][:half], fn["arguments"][half:]):
                event({"tool_calls": [{"index": i, "function": {"arguments": part}}]})
        event({}, "tool_calls")
        self.wfile.write(b"data: [DONE]\n\n")


http.server.ThreadingHTTPServer(("0.0.0.0", 9001), Handler).serve_forever()
