import { UploadedFile } from '@/pages/Viewer';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { FileText, Image as ImageIcon, FileCode } from 'lucide-react';

interface FilePreviewProps {
  file: UploadedFile;
}

export const FilePreview = ({ file }: FilePreviewProps) => {
  const renderPreview = () => {
    // Image files
    if (file.type.startsWith('image/')) {
      return (
        <div className="flex items-center justify-center p-8 bg-muted/30 rounded-lg">
          <img
            src={file.url}
            alt={file.name}
            className="max-w-full max-h-[70vh] object-contain rounded-lg shadow-elegant"
          />
        </div>
      );
    }

    // PDF files
    if (file.type === 'application/pdf') {
      return (
        <div className="h-[70vh] rounded-lg overflow-hidden shadow-elegant">
          <iframe src={file.url} className="w-full h-full border-0" title={file.name} />
        </div>
      );
    }

    // Text files
    if (file.type.startsWith('text/') || file.content) {
      return (
        <div className="p-6 bg-muted/30 rounded-lg shadow-elegant">
          <pre className="text-sm overflow-auto max-h-[70vh] whitespace-pre-wrap font-mono">
            {file.content}
          </pre>
        </div>
      );
    }

    // DOCX files (browser can't render directly)
    if (
      file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ) {
      return (
        <div className="flex flex-col items-center justify-center p-12 bg-muted/30 rounded-lg">
          <FileText className="w-16 h-16 text-muted-foreground mb-4" />
          <p className="text-lg font-medium mb-2">DOCX Preview</p>
          <p className="text-sm text-muted-foreground text-center mb-4">
            Browser preview not available for Word documents
          </p>
          <a
            href={file.url}
            download={file.name}
            className="text-primary hover:underline"
          >
            Download to view
          </a>
        </div>
      );
    }

    // Fallback for unsupported types
    return (
      <div className="flex flex-col items-center justify-center p-12 bg-muted/30 rounded-lg">
        <FileCode className="w-16 h-16 text-muted-foreground mb-4" />
        <p className="text-lg font-medium mb-2">Preview not available</p>
        <p className="text-sm text-muted-foreground mb-4">
          This file type cannot be previewed in the browser
        </p>
        <a
          href={file.url}
          download={file.name}
          className="text-primary hover:underline"
        >
          Download file
        </a>
      </div>
    );
  };

  const getFileIcon = () => {
    if (file.type.startsWith('image/')) return ImageIcon;
    if (file.type.startsWith('text/')) return FileCode;
    return FileText;
  };

  const Icon = getFileIcon();

  return (
    <Card className="shadow-elegant">
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          <Icon className="w-5 h-5 text-primary" />
          {file.name}
        </CardTitle>
      </CardHeader>
      <CardContent>{renderPreview()}</CardContent>
    </Card>
  );
};
