package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
)

const (
	ProtocolVersion = "2024-11-05"
	ServerName      = "stratium-mcp"
	ServerVersion   = "1.0.0"
)

// ToolHandler is a function that handles a tool call.
type ToolHandler func(args json.RawMessage) (*ToolCallResult, error)

// Server is the MCP server that dispatches tool calls.
type Server struct {
	transport *Transport
	tools     []Tool
	handlers  map[string]ToolHandler
	logger    *log.Logger
}

// NewServer creates a new MCP server.
func NewServer(logger *log.Logger) *Server {
	return &Server{
		transport: NewStdioTransport(),
		handlers:  make(map[string]ToolHandler),
		logger:    logger,
	}
}

// RegisterTool adds a tool to the server.
func (s *Server) RegisterTool(tool Tool, handler ToolHandler) {
	s.tools = append(s.tools, tool)
	s.handlers[tool.Name] = handler
}

// Run starts the MCP server loop.
func (s *Server) Run() error {
	s.logger.Println("stratium-mcp server starting")

	for {
		req, err := s.transport.ReadMessage()
		if err != nil {
			if err == io.EOF {
				s.logger.Println("client disconnected")
				return nil
			}
			s.logger.Printf("read error: %v", err)
			continue
		}

		if err := s.handleRequest(req); err != nil {
			s.logger.Printf("handler error for %s: %v", req.Method, err)
		}
	}
}

func (s *Server) handleRequest(req *Request) error {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "notifications/initialized":
		s.logger.Println("client initialized")
		return nil
	case "notifications/cancelled":
		return nil
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	case "ping":
		return s.transport.SendResult(req.ID, map[string]string{})
	default:
		if req.ID != nil {
			return s.transport.SendError(req.ID, ErrCodeMethodNotFound,
				fmt.Sprintf("unknown method: %s", req.Method))
		}
		return nil
	}
}

func (s *Server) handleInitialize(req *Request) error {
	return s.transport.SendResult(req.ID, InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: Capabilities{
			Tools: &ToolsCapability{},
		},
		ServerInfo: ServerInfo{
			Name:    ServerName,
			Version: ServerVersion,
		},
	})
}

func (s *Server) handleToolsList(req *Request) error {
	return s.transport.SendResult(req.ID, ToolsListResult{
		Tools: s.tools,
	})
}

func (s *Server) handleToolsCall(req *Request) error {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.transport.SendError(req.ID, ErrCodeInvalidParams, "invalid tool call params")
	}

	handler, ok := s.handlers[params.Name]
	if !ok {
		return s.transport.SendError(req.ID, ErrCodeMethodNotFound,
			fmt.Sprintf("unknown tool: %s", params.Name))
	}

	result, err := handler(params.Arguments)
	if err != nil {
		return s.transport.SendResult(req.ID, &ToolCallResult{
			Content: []ContentBlock{TextContent(fmt.Sprintf("Error: %v", err))},
			IsError: true,
		})
	}

	return s.transport.SendResult(req.ID, result)
}

// SuccessResult creates a successful tool result with a JSON-formatted text block.
func SuccessResult(data any) (*ToolCallResult, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}
	return &ToolCallResult{
		Content: []ContentBlock{TextContent(string(b))},
	}, nil
}

// ErrorResult creates an error tool result.
func ErrorResult(msg string) *ToolCallResult {
	return &ToolCallResult{
		Content: []ContentBlock{TextContent(msg)},
		IsError: true,
	}
}
