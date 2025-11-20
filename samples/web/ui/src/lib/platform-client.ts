// Platform gRPC-Web client using ConnectRPC
import { createClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import {
  PlatformService,
  type Entitlement
} from "@/generated/platform_pb.js";

// Create the gRPC-Web transport
const transport = createGrpcWebTransport({
  baseUrl: "http://localhost:8081",
});

// Create the client
const client = createClient(PlatformService, transport);

export interface EntitlementData {
  id: string;
  resource: string;
  actions: string[];
  metadata: Record<string, string>;
  active: boolean;
}

export class PlatformClient {
  async getUserEntitlements(
    userId: string,
    email: string,
    department: string,
    role: string
  ): Promise<EntitlementData[]> {
    try {
      console.log('[PlatformClient] Calling GetEntitlements with:', { userId, email, department, role });

      // Call the GetEntitlements RPC
      // Note: google.protobuf.Value uses "kind" as the oneof field name in protobuf v2
      const response = await client.getEntitlements({
        subject: {
          user_id: { kind: { case: "stringValue", value: userId } },
          email: { kind: { case: "stringValue", value: email } },
          department: { kind: { case: "stringValue", value: department } },
          role: { kind: { case: "stringValue", value: role } },
        },
        pageSize: 100,
      });

      console.log('[PlatformClient] GetEntitlements response:', response);

      // Convert proto entitlements to plain objects
      const entitlements: EntitlementData[] = (response.entitlements || []).map((ent: Entitlement) => ({
        id: ent.id,
        resource: ent.resource,
        actions: ent.actions,
        metadata: ent.metadata,
        active: ent.active,
      }));

      console.log('[PlatformClient] Parsed entitlements:', entitlements);
      return entitlements;
    } catch (error) {
      console.error("[PlatformClient] Failed to get entitlements:", error);
      console.error("[PlatformClient] Error details:", {
        name: error instanceof Error ? error.name : 'Unknown',
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
      throw error;
    }
  }
}

export const platformClient = new PlatformClient();