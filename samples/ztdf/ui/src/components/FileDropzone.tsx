import React, { useCallback } from 'react';
import { Upload } from 'lucide-react';
import { cn } from '@/lib/utils';

interface FileDropzoneProps {
  onFileDrop: (files: File[]) => void;
}

export const FileDropzone = ({ onFileDrop }: FileDropzoneProps) => {
  const [isDragging, setIsDragging] = React.useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);

      const droppedFiles = Array.from(e.dataTransfer.files);
      if (droppedFiles.length > 0) {
        onFileDrop(droppedFiles);
      }
    },
    [onFileDrop]
  );

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selectedFiles = e.target.files;
      if (selectedFiles && selectedFiles.length > 0) {
        onFileDrop(Array.from(selectedFiles));
      }
    },
    [onFileDrop]
  );

  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-200px)]">
      <div
        className={cn(
          'relative w-full max-w-2xl p-12 rounded-2xl border-2 border-dashed transition-smooth',
          isDragging
            ? 'border-primary bg-primary/5 shadow-glow'
            : 'border-border bg-card hover:border-primary/50 hover:bg-primary/5'
        )}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <label className="flex flex-col items-center justify-center cursor-pointer">
          <div className="p-4 rounded-full bg-gradient-to-br from-primary to-primary-glow mb-6 shadow-glow">
            <Upload className="w-12 h-12 text-primary-foreground" />
          </div>
          <h3 className="text-2xl font-bold mb-2">Drop your files here</h3>
          <p className="text-muted-foreground mb-4 text-center">
            or click to browse from your computer
          </p>
          <p className="text-sm text-muted-foreground">
            Supports PDF, images, DOCX, text files, and ZTDF encrypted files
          </p>
          <input
            type="file"
            multiple
            className="hidden"
            onChange={handleFileInput}
            accept=".pdf,.png,.jpg,.jpeg,.gif,.webp,.docx,.txt,.md,.ztdf"
          />
        </label>
      </div>
    </div>
  );
};
