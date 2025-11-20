import { useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { LogOut, Upload, File, X } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { FileDropzone } from '@/components/FileDropzone';
import { FilePreview } from '@/components/FilePreview';
import { ZtdfDecryptor } from '@/components/ZtdfDecryptor';
import { useZtdf, type DecryptedFile } from '@/contexts/ZtdfContext';

export interface UploadedFile {
  id: string;
  name: string;
  type: string;
  size: number;
  url: string;
  content?: string;
}

const Viewer = () => {
  const { user, logout } = useAuth();
  const { toast } = useToast();
  const { isInitialized, initialize, decryptFile } = useZtdf();
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [selectedFile, setSelectedFile] = useState<UploadedFile | null>(null);
  const [lastDecrypted, setLastDecrypted] = useState<{ file: DecryptedFile; originalName: string } | null>(null);

  const handleFileDrop = async (droppedFiles: File[]) => {
    // Separate ZTDF files from regular files
    const ztdfFiles = droppedFiles.filter(f => f.name.endsWith('.ztdf'));
    const regularFiles = droppedFiles.filter(f => !f.name.endsWith('.ztdf'));

    const newFiles: UploadedFile[] = [];

    // Handle regular files
    for (const file of regularFiles) {
      const url = URL.createObjectURL(file);
      let content: string | undefined;

      // Read text content for text files
      if (file.type.startsWith('text/') || file.name.endsWith('.txt')) {
        content = await file.text();
      }

      newFiles.push({
        id: crypto.randomUUID(),
        name: file.name,
        type: file.type,
        size: file.size,
        url,
        content,
      });
    }

    // Handle ZTDF files - decrypt them automatically
    for (const ztdfFile of ztdfFiles) {
      try {
        // Ensure ZTDF client is initialized
        if (!isInitialized) {
          await initialize();
        }

        // Decrypt the ZTDF file
        const decryptedFile = await decryptFile(ztdfFile);

        // Update last decrypted file info for display
        setLastDecrypted({
          file: decryptedFile,
          originalName: ztdfFile.name,
        });

        // Convert to UploadedFile format
        const blob = new Blob([decryptedFile.content.slice()], {
          type: decryptedFile.contentType || 'application/octet-stream',
        });
        const url = URL.createObjectURL(blob);

        let content: string | undefined;
        const contentType = decryptedFile.contentType || '';
        if (contentType.startsWith('text/') || decryptedFile.filename?.endsWith('.txt')) {
          const textDecoder = new TextDecoder();
          content = textDecoder.decode(decryptedFile.content);
        }

        newFiles.push({
          id: crypto.randomUUID(),
          name: decryptedFile.filename || ztdfFile.name.replace('.ztdf', ''),
          type: contentType,
          size: decryptedFile.content.length,
          url,
          content,
        });

        toast({
          title: 'ZTDF file decrypted',
          description: `${decryptedFile.filename || ztdfFile.name} has been decrypted`,
        });
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Failed to decrypt file';
        toast({
          title: 'Decryption failed',
          description: `${ztdfFile.name}: ${errorMsg}`,
          variant: 'destructive',
        });
      }
    }

    if (newFiles.length > 0) {
      setFiles((prev) => [...prev, ...newFiles]);

      if (regularFiles.length > 0) {
        toast({
          title: 'Files uploaded',
          description: `${regularFiles.length} file(s) uploaded successfully`,
        });
      }

      if (!selectedFile) {
        setSelectedFile(newFiles[0]);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/30 to-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-gradient-to-br from-primary to-primary-glow">
              <File className="w-5 h-5 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-xl font-bold">File Viewer</h1>
              <p className="text-sm text-muted-foreground">{user?.email}</p>
            </div>
          </div>
          <Button variant="outline" onClick={logout} className="gap-2">
            <LogOut className="w-4 h-4" />
            Sign out
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-8 space-y-8">
        {/* ZTDF Decryptor Section */}
        <div>
          <ZtdfDecryptor lastDecrypted={lastDecrypted} />
        </div>

        {/* Regular File Viewer Section */}
        <div>
          {files.length === 0 ? (
            <FileDropzone onFileDrop={handleFileDrop} />
          ) : (
            <div>
              {/* File Preview */}
              {selectedFile && <FilePreview file={selectedFile} />}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Viewer;
