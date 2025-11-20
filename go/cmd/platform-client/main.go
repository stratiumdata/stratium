package main

import (
	"context"
	"flag"
	"log"
	"stratium/services/platform"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	addr = flag.String("addr", "localhost:50051", "the address to connect to")
)

func main() {
	flag.Parse()

	// Set up a connection to the server
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Create client
	client := platform.NewPlatformServiceClient(conn)

	// Set up context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Example 1: Test GetDecision for a regular user
	log.Println("=== Testing GetDecision ===")

	decisionReq := &platform.GetDecisionRequest{
		SubjectAttributes: map[string]*structpb.Value{
			"sub":        structpb.NewStringValue("user123"),
			"email":      structpb.NewStringValue("user123@example.com"),
			"department": structpb.NewStringValue("engineering"),
		},
		ResourceAttributes: map[string]string{
			"name": "document-service",
			"type": "service",
		},
		Action:  "read",
		Context: map[string]string{},
	}

	decisionResp, err := client.GetDecision(ctx, decisionReq)
	if err != nil {
		log.Fatalf("GetDecision failed: %v", err)
	}

	log.Printf("Decision: %s", decisionResp.Decision.String())
	log.Printf("Reason: %s", decisionResp.Reason)
	log.Printf("Evaluated Policy: %s", decisionResp.EvaluatedPolicy)
	log.Printf("Timestamp: %s", decisionResp.Timestamp.AsTime().Format(time.RFC3339))

	// Example 2: Test GetDecision for an admin user
	log.Println("\n=== Testing GetDecision for Admin ===")

	adminDecisionReq := &platform.GetDecisionRequest{
		SubjectAttributes: map[string]*structpb.Value{
			"sub":   structpb.NewStringValue("admin456"),
			"email": structpb.NewStringValue("admin456@example.com"),
			"role":  structpb.NewStringValue("admin"),
		},
		ResourceAttributes: map[string]string{
			"name": "any-service",
			"type": "service",
		},
		Action:  "delete",
		Context: map[string]string{},
	}

	adminDecisionResp, err := client.GetDecision(ctx, adminDecisionReq)
	if err != nil {
		log.Fatalf("GetDecision for admin failed: %v", err)
	}

	log.Printf("Admin Decision: %s", adminDecisionResp.Decision.String())
	log.Printf("Admin Reason: %s", adminDecisionResp.Reason)

	// Example 3: Test GetEntitlements
	log.Println("\n=== Testing GetEntitlements ===")

	entitlementsReq := &platform.GetEntitlementsRequest{
		Subject: map[string]*structpb.Value{
			"sub":   structpb.NewStringValue("user123"),
			"email": structpb.NewStringValue("user123@example.com"),
		},
		PageSize: 10,
	}

	entitlementsResp, err := client.GetEntitlements(ctx, entitlementsReq)
	if err != nil {
		log.Fatalf("GetEntitlements failed: %v", err)
	}

	log.Printf("Total entitlements: %d", entitlementsResp.TotalCount)
	log.Printf("Returned entitlements: %d", len(entitlementsResp.Entitlements))

	for i, entitlement := range entitlementsResp.Entitlements {
		log.Printf("Entitlement %d:", i+1)
		log.Printf("  ID: %s", entitlement.Id)
		log.Printf("  Resource: %s", entitlement.Resource)
		log.Printf("  Actions: %v", entitlement.Actions)
		log.Printf("  Active: %t", entitlement.Active)

		if len(entitlement.Conditions) > 0 {
			log.Printf("  Conditions:")
			for j, condition := range entitlement.Conditions {
				log.Printf("    %d. Type: %s, Operator: %s, Value: %s",
					j+1, condition.Type, condition.Operator, condition.Value)
			}
		}
	}

	// Example 4: Test GetEntitlements with filtering
	log.Println("\n=== Testing GetEntitlements with Resource Filter ===")

	filteredEntitlementsReq := &platform.GetEntitlementsRequest{
		Subject: map[string]*structpb.Value{
			"sub":   structpb.NewStringValue("user123"),
			"email": structpb.NewStringValue("user123@example.com"),
		},
		ResourceFilter: "document-service",
		PageSize:       10,
	}

	filteredEntitlementsResp, err := client.GetEntitlements(ctx, filteredEntitlementsReq)
	if err != nil {
		log.Fatalf("GetEntitlements with filter failed: %v", err)
	}

	log.Printf("Filtered entitlements count: %d", len(filteredEntitlementsResp.Entitlements))
	for _, entitlement := range filteredEntitlementsResp.Entitlements {
		log.Printf("  Resource: %s, Actions: %v", entitlement.Resource, entitlement.Actions)
	}

	// Example 5: Test denied access
	log.Println("\n=== Testing Denied Access ===")

	deniedReq := &platform.GetDecisionRequest{
		SubjectAttributes: map[string]*structpb.Value{
			"sub":   structpb.NewStringValue("user123"),
			"email": structpb.NewStringValue("user123@example.com"),
		},
		ResourceAttributes: map[string]string{
			"name": "restricted-service",
			"type": "service",
		},
		Action:  "admin",
		Context: map[string]string{},
	}

	deniedResp, err := client.GetDecision(ctx, deniedReq)
	if err != nil {
		log.Fatalf("GetDecision for denied access failed: %v", err)
	}

	log.Printf("Denied Decision: %s", deniedResp.Decision.String())
	log.Printf("Denied Reason: %s", deniedResp.Reason)

	log.Println("\n=== Client Example Completed Successfully ===")
}
