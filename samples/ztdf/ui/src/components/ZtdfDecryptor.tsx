/**
 * ZTDF Decryptor Component
 * Display component showing the results of ZTDF file decryption
 */

import React, { useState, useCallback, useEffect } from "react";
import { useZtdf } from "../contexts/ZtdfContext";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Alert, AlertDescription } from "./ui/alert";
import { Download, FileCheck, Loader2 } from "lucide-react";

interface ZtdfDecryptorProps {
  lastDecrypted?: { file: any; originalName: string } | null;
}

export function ZtdfDecryptor({ lastDecrypted }: ZtdfDecryptorProps = {}) {
  const { isInitializing } = useZtdf();
  const [decrypted, setDecrypted] = useState<any | null>(null);

  // Update displayed decrypted file when lastDecrypted changes
  useEffect(() => {
    if (lastDecrypted) {
      setDecrypted(lastDecrypted.file);
    }
  }, [lastDecrypted]);

  const handleDownload = useCallback(() => {
    if (!decrypted) return;

    const blob = new Blob([decrypted.content], {
      type: decrypted.contentType || 'application/octet-stream'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = decrypted.filename || 'decrypted-file';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [decrypted]);

  // Don't render anything if there's no decrypted file and not initializing
  if (!decrypted && !isInitializing) {
    return null;
  }

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileCheck className="h-6 w-6" />
          {decrypted?.filename || "Filename Unknown"}
        </CardTitle>
        <CardDescription>
          {decrypted?.accessReason || "Description Unknown"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Initialization Status */}
        {isInitializing && (
          <Alert>
            <Loader2 className="h-4 w-4 animate-spin" />
            <AlertDescription>Initializing ZTDF client...</AlertDescription>
          </Alert>
        )}

        {/* Success Display */}
        {decrypted && (
          <div className="space-y-4">
            <Alert className="bg-green-50 border-green-200">
              <FileCheck className="h-4 w-4 text-green-600" />
              <AlertDescription className="text-green-800">
                File decrypted successfully!
              </AlertDescription>
            </Alert>

            <Button onClick={handleDownload} className="w-full" variant="secondary">
              <Download className="mr-2 h-4 w-4" />
              Download Decrypted File
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
