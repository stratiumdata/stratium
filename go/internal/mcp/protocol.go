package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Transport handles reading and writing JSON-RPC messages over stdio.
type Transport struct {
	reader *bufio.Reader
	writer io.Writer
	mu     sync.Mutex
}

// NewStdioTransport creates a transport that reads from stdin and writes to stdout.
func NewStdioTransport() *Transport {
	return &Transport{
		reader: bufio.NewReader(os.Stdin),
		writer: os.Stdout,
	}
}

// ReadMessage reads a single JSON-RPC message (one line) from the transport.
func (t *Transport) ReadMessage() (*Request, error) {
	line, err := t.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC message: %w", err)
	}

	return &req, nil
}

// WriteResponse writes a JSON-RPC response to the transport.
func (t *Transport) WriteResponse(resp Response) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	data = append(data, '\n')
	_, err = t.writer.Write(data)
	return err
}

// SendResult sends a successful JSON-RPC response.
func (t *Transport) SendResult(id json.RawMessage, result any) error {
	return t.WriteResponse(Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

// SendError sends a JSON-RPC error response.
func (t *Transport) SendError(id json.RawMessage, code int, message string) error {
	return t.WriteResponse(Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	})
}
