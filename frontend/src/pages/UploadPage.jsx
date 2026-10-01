import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileCheck,
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  Hash,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import apkService from '../services/apkService';
import { formatFileSize } from '../utils/formatters';

const MAX_FILE_SIZE_BYTES = 200 * 1024 * 1024; // 200 MB

export default function UploadPage() {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileError, setFileError] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);

  const fileInputRef = useRef(null);
  const navigate = useNavigate();

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndSetFile = (file) => {
    setFileError('');
    setUploadResult(null);

    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.apk')) {
      setFileError('Invalid file type. Only Android package files (.apk) are accepted.');
      setSelectedFile(null);
      return;
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      setFileError(`File size (${formatFileSize(file.size)}) exceeds the maximum allowed limit of 200 MB.`);
      setSelectedFile(null);
      return;
    }

    if (file.size === 0) {
      setFileError('The selected file is empty (0 bytes).');
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploading(true);
    setFileError('');
    setUploadProgress(0);

    const formData = new FormData();
    formData.append('apk', selectedFile);

    try {
      const response = await apkService.uploadApk(formData, (percent) => {
        setUploadProgress(percent);
      });

      setUploadResult(response);
      setUploading(false);

      // Redirect after showing upload success
      setTimeout(() => {
        if (response.scan?.id) {
          navigate(`/scans/${response.scan.id}`);
        }
      }, 1500);
    } catch (err) {
      setUploading(false);
      setFileError(err.response?.data?.message || 'APK upload failed. Please verify the archive and try again.');
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Upload Android APK"
        description="Ingest Android application binaries for sandboxed static security analysis, SHA-256 integrity calculation, and automated component inspection."
        badge={<Badge label="Max 200 MB" variant="primary" />}
      />

      {/* Upload Zone Card */}
      <Card className="border-slate-800">
        <form onDragEnter={handleDrag} onSubmit={(e) => e.preventDefault()}>
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk"
            onChange={handleFileChange}
            className="hidden"
            id="apk-upload-input"
          />

          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-2xl p-10 sm:p-14 text-center transition-all cursor-pointer ${
              dragActive
                ? 'border-cyan-400 bg-cyan-950/20 shadow-cyber-glow'
                : 'border-slate-800 hover:border-slate-700 bg-slate-900/30'
            }`}
            onClick={() => fileInputRef.current && fileInputRef.current.click()}
          >
            <div className="h-16 w-16 mx-auto rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mb-4">
              <UploadCloud className="h-8 w-8" />
            </div>

            <h3 className="text-lg font-semibold text-slate-100">Drop your Android APK here</h3>
            <p className="mt-1.5 text-xs text-slate-400">
              or <span className="text-cyan-400 font-medium hover:underline">browse files</span> on your computer
            </p>

            <div className="mt-4 flex items-center justify-center gap-3 text-[11px] font-mono text-slate-400">
              <span className="px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">Supported: .apk</span>
              <span className="px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700">Max size: 200 MB</span>
            </div>
          </div>
        </form>

        {/* Local Validation Error Display */}
        {fileError && (
          <div className="mt-4 p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-xs text-red-300 flex items-start gap-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
            <div>
              <p className="font-semibold text-red-200">Validation Notice</p>
              <p className="mt-0.5">{fileError}</p>
            </div>
          </div>
        )}

        {/* Selected File Details */}
        {selectedFile && !uploadResult && (
          <div className="mt-6 p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3 overflow-hidden">
              <div className="h-10 w-10 rounded-lg bg-cyan-950 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
                <FileCheck className="h-5 w-5" />
              </div>
              <div className="truncate">
                <p className="text-sm font-semibold text-slate-100 truncate">{selectedFile.name}</p>
                <div className="flex items-center gap-3 text-xs text-slate-400 font-mono mt-0.5">
                  <span className="flex items-center gap-1">
                    <HardDrive className="h-3 w-3" />
                    {formatFileSize(selectedFile.size)}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <Button
                variant="ghost"
                size="sm"
                disabled={uploading}
                onClick={() => {
                  setSelectedFile(null);
                  if (fileInputRef.current) fileInputRef.current.value = '';
                }}
              >
                Clear
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={uploading}
                onClick={handleUpload}
              >
                {uploading ? `Uploading (${uploadProgress}%)` : 'Upload & Register APK'}
              </Button>
            </div>
          </div>
        )}

        {/* Upload Progress Bar */}
        {uploading && (
          <div className="mt-4 space-y-1.5">
            <div className="flex justify-between text-xs font-mono text-slate-400">
              <span>Streaming APK to Secure Sandbox...</span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-500 transition-all duration-200"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}

        {/* Upload Success Banner */}
        {uploadResult && (
          <div className="mt-6 p-5 rounded-xl bg-emerald-950/30 border border-emerald-500/40 space-y-3">
            <div className="flex items-center gap-2.5 text-emerald-300 font-semibold text-sm">
              <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              <span>{uploadResult.message || 'APK uploaded successfully. Security analysis has not started yet.'}</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono pt-2 border-t border-emerald-500/20">
              <div>
                <span className="text-slate-400 block">Original Filename:</span>
                <span className="text-slate-200 font-semibold">{uploadResult.apk?.filename}</span>
              </div>
              <div>
                <span className="text-slate-400 block">File Size:</span>
                <span className="text-slate-200 font-semibold">{formatFileSize(uploadResult.apk?.size)}</span>
              </div>
              <div>
                <span className="text-slate-400 block">Scan Job ID:</span>
                <span className="text-cyan-400 font-semibold">#{uploadResult.scan?.id}</span>
              </div>
            </div>

            <div className="text-xs font-mono pt-1">
              <span className="text-slate-400 block">SHA-256 Fingerprint:</span>
              <span className="text-cyan-300 break-all select-all">{uploadResult.apk?.sha256}</span>
            </div>

            <div className="pt-2 flex items-center justify-between text-xs text-slate-400">
              <span>Redirecting to Scan Overview...</span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/scans/${uploadResult.scan?.id}`)}
              >
                Go to Scan Details <ArrowRight className="h-3 w-3 ml-1" />
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
