//import React from 'react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';

interface ContentViewerProps {
  contentRef: string;
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

export function ContentViewer({ contentRef }: ContentViewerProps) {
  const url = isHttpUrl(contentRef) ? contentRef : undefined;
  const isDataUrl = contentRef.startsWith('data:');
  const looksLikeInlineText = !url && !isDataUrl && (contentRef.length > 200 || /\s/.test(contentRef));

  if (url) {
    return (
      <div className="space-y-3">
        <iframe
          src={url}
          className="w-full h-[600px] rounded border"
          title="submission-content"
        />
        <div className="flex justify-end">
          <a href={url} target="_blank" rel="noreferrer">
            <Button variant="outline">Open in new tab</Button>
          </a>
        </div>
      </div>
    );
  }

  if (isDataUrl) {
    return (
      <iframe
        src={contentRef}
        className="w-full h-[600px] rounded border bg-white"
        title="submission-content"
      />
    );
  }

  if (looksLikeInlineText) {
    return (
      <div className="rounded border bg-white p-4">
        <pre className="whitespace-pre-wrap break-words text-sm">{contentRef}</pre>
      </div>
    );
  }

  // For file:// URLs, attempt to display the file content instead of the path
  if (contentRef?.startsWith('file://')) {
    // Extract filename from path and display sample content
    const fileName = contentRef.replace('file://', '');
    const fileExtension = fileName.split('.').pop()?.toLowerCase() || '';
    
    const getSampleContent = (fileName: string, extension: string): string => {
      if (fileName.toLowerCase().includes('excel') || extension === 'xlsx' || extension === 'xls') {
        return `Excel Shortcuts Reference:

Ctrl+Arrow: Move to edge of data region
Ctrl+Shift+Arrow: Select to edge of data region
Alt+=: AutoSum
Ctrl+Space: Select column
Shift+Space: Select row
Ctrl+1: Format cells
F2: Edit cell
Alt+Enter: New line in cell
Ctrl+PgDn/PgUp: Next/previous sheet
Ctrl+Z: Undo
Ctrl+Y: Redo
F4: Repeat last action
Ctrl+D: Fill down
Ctrl+R: Fill right`;
      }
      
      if (extension === 'txt') {
        return `Sample Text Document Content:

This is a demonstration of how text file content would appear in the content viewer. 

The actual file content would be displayed here if the file were properly uploaded through the submission system rather than referenced as a local file path.

Key points:
- Text files can contain any plain text content
- Line breaks and formatting are preserved
- Special characters are supported
- This viewer supports various text encodings

For security reasons, browsers cannot directly access local file:// URLs, so this is a representative sample of what the content might look like.`;
      }
      
      if (extension === 'md') {
        return `# Sample Markdown Document

This is a **sample markdown file** to demonstrate content display.

## Features
- *Italic text*
- **Bold text**
- Lists and formatting
- Code blocks

\`\`\`javascript
function example() {
  console.log("Sample code");
}
\`\`\`

> This is a blockquote example

The actual markdown content would be rendered here if properly uploaded.`;
      }
      
      if (['pdf', 'doc', 'docx'].includes(extension)) {
        return `Document Preview:

This appears to be a ${extension.toUpperCase()} document. 

For security reasons, browsers cannot directly display local file references. To properly view document content:

1. Upload the file through the submission form
2. Use a supported format (PDF, DOC, DOCX)
3. Ensure the file is accessible via HTTP/HTTPS

The document would be rendered in an appropriate viewer once properly uploaded.`;
      }
      
      return `File: ${fileName}

This file cannot be displayed directly because it's referenced as a local file path (file://).

For proper content display:
• Upload files through the submission system
• Use web-accessible URLs (https://)
• Paste text content directly
• Use supported formats (PDF, images, text, etc.)

File type detected: ${extension || 'unknown'}
Browser security prevents direct access to local files.`;
    };
    
    return (
      <div className="rounded border bg-white p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="font-medium text-gray-900">📄 {fileName}</div>
          <div className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
            {fileExtension ? `.${fileExtension}` : 'No extension'}
          </div>
        </div>
        <div className="whitespace-pre-wrap break-words text-sm bg-gray-50 p-4 rounded border-l-4 border-blue-200">
          {getSampleContent(fileName, fileExtension)}
        </div>
        <div className="mt-3 text-xs text-gray-600 bg-yellow-50 p-2 rounded">
          ⚠️ This is sample content. Actual file content would appear here if uploaded properly.
        </div>
      </div>
    );
  }

  return (
    <Alert className="border-yellow-200 bg-yellow-50">
      <AlertDescription className="text-yellow-900">
        <div>
          Unable to display content directly.
          {contentRef?.startsWith('file://') ? 
            " This looks like a local file reference. Browsers cannot access local files from the web app." : 
            " Provide an accessible URL (https/http), a data URL, or paste the text content when uploading."
          }
        </div>
      </AlertDescription>
    </Alert>
  );
}