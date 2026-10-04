import React, { useState } from 'react';
import { useRouter } from 'next/router';
import AppShell from '../../src/components/AppShell';
import UploadDropzone from '../../src/components/UploadDropzone';
import PageHeader from '../../src/components/PageHeader';
import { useUploadInvestigation } from '../../src/lib/hooks/useInvestigation';

export default function NewInvestigationPage() {
  const router = useRouter();
  const { mutate: uploadInvestigation, isPending: isLoading, isError, error } = useUploadInvestigation();
  const [fileError, setFileError] = useState<string | null>(null);

  const handleUpload = async (file: File) => {
    setFileError(null);
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setFileError('Only .eml files are accepted');
      return;
    }
    uploadInvestigation(file, {
      onSuccess: (result) => {
        router.push(`/investigations/${result.investigationId}/overview`);
      },
    });
  };

  return (
    <AppShell>
      <div className="mx-auto max-w-5xl px-4 md:px-6 py-6">
        <PageHeader
          title="New Investigation"
          description="Upload a suspicious email to begin analysis"
        />

        <div className="space-y-6">
          <div className="rounded-lg border border-border-default bg-bg-secondary p-6">
            <UploadDropzone
              onUpload={handleUpload}
              disabled={isLoading}
            />
          </div>

          {fileError && (
            <div className="rounded-lg border border-accent-red/20 bg-accent-red/10 p-4">
              <p className="text-accent-red text-sm">{fileError}</p>
            </div>
          )}

          {isError && (
            <div className="rounded-lg border border-accent-red/20 bg-accent-red/10 p-4">
              <p className="text-accent-red text-sm">
                {error?.message || 'Upload failed'}
              </p>
            </div>
          )}

          {isLoading && (
            <div className="flex items-center gap-3">
              <div className="w-5 h-5 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
              <p className="text-text-secondary">Uploading and analyzing email...</p>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}