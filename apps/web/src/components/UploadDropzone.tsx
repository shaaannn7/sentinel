import React, { useRef, useState } from 'react';
import { FileUp, LockKeyhole, ScanLine } from 'lucide-react';

interface UploadDropzoneProps {
  onUpload: (file: File) => void | Promise<void>;
  disabled?: boolean;
}

export default function UploadDropzone({ onUpload, disabled = false }: UploadDropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFiles = async (files: FileList | null) => {
    if (disabled || !files || files.length === 0) return;
    const file = files[0];
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setError('Only .eml files are accepted');
      return;
    }
    setError(null);
    await onUpload(file);
  };

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setIsDragging(false);
        handleFiles(e.dataTransfer.files);
      }}
      onClick={() => inputRef.current?.click()}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && !disabled) {
          e.preventDefault();
          inputRef.current?.click();
        }
      }}
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled}
      className={`relative overflow-hidden border rounded-lg p-8 md:p-10 text-center cursor-pointer transition-all ambient-grid ${
        isDragging
          ? 'border-accent-cyan bg-accent-cyan/10 shadow-[0_0_40px_rgba(87,216,255,0.12)]'
          : 'border-border-default bg-bg-secondary/70 hover:border-accent-cyan/50 hover:bg-bg-tertiary/80'
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".eml"
        className="hidden"
        disabled={disabled}
        onChange={(e) => handleFiles(e.target.files)}
      />
      <div className="mx-auto mb-4 w-12 h-12 rounded-lg bg-accent-cyan/10 ring-1 ring-accent-cyan/25 flex items-center justify-center">
        <FileUp className="w-7 h-7 text-accent-cyan" />
      </div>
      <div className="text-lg text-text-primary font-semibold mb-2">Upload an email artifact</div>
      <div className="text-text-secondary text-sm">Drag an <span className="font-mono text-accent-cyan">.eml</span> file here or click to browse</div>
      <div className="flex flex-wrap justify-center gap-4 mt-5 text-xs text-text-muted">
        <span className="inline-flex items-center gap-1.5"><ScanLine className="w-3.5 h-3.5 text-accent-purple" />Deterministic analysis</span>
        <span className="inline-flex items-center gap-1.5"><LockKeyhole className="w-3.5 h-3.5 text-accent-green" />Evidence-first storage</span>
      </div>
      {error && <div className="text-accent-red text-sm mt-3">{error}</div>}
    </div>
  );
}