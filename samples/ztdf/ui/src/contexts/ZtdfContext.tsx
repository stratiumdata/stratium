/**
 * ZTDF React Context
 * Provides ZTDF client instance to the application
 */

import React, { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from "react";
import { ZtdfClient } from "@stratiumdata/sdk";
import type KeyMetadata from "@stratiumdata/sdk";
import { useAuth } from "./AuthContext";
import { ztdfConfig } from "../config/ztdf";

// Type definitions for ZtdfClient config and responses
interface ZtdfClientConfig {
  keyAccessUrl: string;
  keyManagerUrl: string;
  clientId: string;
  clientKeyExpirationMs?: number;
  getToken?: () => Promise<string | null>;
  debug?: boolean;
}

export interface DecryptedFile {
  content: Uint8Array;
  filename?: string;
  contentType?: string;
  accessGranted: boolean;
  accessReason: string;
  appliedRules: string[];
  timestamp: Date;
}

interface ZtdfContextValue {
  client: ZtdfClient | null;
  isInitialized: boolean;
  isInitializing: boolean;
  error: string | null;
  keyMetadata: KeyMetadata | null;
  initialize: () => Promise<void>;
  decryptFile: (file: File) => Promise<DecryptedFile>;
}

const ZtdfContext = createContext<ZtdfContextValue | undefined>(undefined);

export interface ZtdfProviderProps {
  children: ReactNode;
  config?: ZtdfClientConfig;
}

export function ZtdfProvider({ children, config }: ZtdfProviderProps) {
  const { token } = useAuth();
  const [client, setClient] = useState<ZtdfClient | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyMetadata, setKeyMetadata] = useState<KeyMetadata | null>(null);

  // Use ref to always have current client value (avoids closure issues)
  const clientRef = useRef<ZtdfClient | null>(null);

  const initialize = async () => {
    if (isInitialized || isInitializing) {
      return;
    }

    setIsInitializing(true);
    setError(null);

    try {
      // Create getToken function that returns the current JWT token
      const getToken = async () => token;

      // Create client with token getter and config
      const clientConfig: ZtdfClientConfig = {
        keyAccessUrl: ztdfConfig.keyAccessUrl,
        keyManagerUrl: ztdfConfig.keyManagerUrl,
        clientId: ztdfConfig.clientId,
        clientKeyExpirationMs: ztdfConfig.clientKeyExpirationMs,
        ...config,
        getToken,
      };

      const ztdfClient = new ZtdfClient(clientConfig);
      await ztdfClient.initialize();

      // Update both state and ref (ref is used in decryptFile to avoid closure issues)
      clientRef.current = ztdfClient;
      setClient(ztdfClient);
      setKeyMetadata(ztdfClient.getKeyMetadata());
      setIsInitialized(true);

      console.log("ZTDF client initialized successfully");
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Failed to initialize ZTDF client";
      console.error("ZTDF initialization error:", err);
      setError(errorMsg);
    } finally {
      setIsInitializing(false);
    }
  };

  const decryptFile = useCallback(async (file: File): Promise<DecryptedFile> => {
    // Use ref to get current client value (avoids closure issues)
    const currentClient = clientRef.current;

    if (!currentClient) {
      throw new Error("ZTDF client not initialized");
    }

    try {
      return await currentClient.unwrap(file);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Failed to decrypt file";
      throw new Error(errorMsg);
    }
  }, []); // Empty deps since we use ref

  const value: ZtdfContextValue = {
    client,
    isInitialized,
    isInitializing,
    error,
    keyMetadata,
    initialize,
    decryptFile,
  };

  return <ZtdfContext.Provider value={value}>{children}</ZtdfContext.Provider>;
}

export function useZtdf(): ZtdfContextValue {
  const context = useContext(ZtdfContext);
  if (!context) {
    throw new Error("useZtdf must be used within a ZtdfProvider");
  }
  return context;
}
