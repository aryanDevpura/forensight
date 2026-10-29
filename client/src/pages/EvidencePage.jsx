import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { fetchEvidence, uploadEvidence, verifyEvidence, getEvidenceDownloadUrl, fetchServerPublicKey } from '../api/client';
import {
  computeSha256,
  encryptEvidencePayload,
  wrapAesKeyWithServerPublicKey,
  buildCanonicalSigningData,
  signCanonicalDataWithRsaPss,
} from '../utils/crypto';
import {
  Upload,
  Inbox,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  RefreshCw,
  X,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Download,
  KeyRound,
  FileSignature,
} from 'lucide-react';

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function EvidencePage({ onEvidenceUploaded }) {
  const [evidenceList, setEvidenceList] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgressText, setUploadProgressText] = useState('');
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [sourceDevice, setSourceDevice] = useState('local-workstation');
  const [collectorId, setCollectorId] = useState('collector-node-01');
  const [description, setDescription] = useState('');
  const [signerKeyId, setSignerKeyId] = useState('client-demo-01');
  const [signingKeyPem, setSigningKeyPem] = useState(null);
  const [keySource, setKeySource] = useState('demo');
  const [customKeyFileName, setCustomKeyFileName] = useState(null);
  const [serverKeyData, setServerKeyData] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [verifyingMap, setVerifyingMap] = useState({});
  const [verificationResults, setVerificationResults] = useState({});
  const [verificationNotification, setVerificationNotification] = useState(null);
  const fileInputRef = useRef(null);
  const keyInputRef = useRef(null);

  const loadServerKeys = useCallback(async () => {
    try {
      const keys = await fetchServerPublicKey();
      setServerKeyData(keys);
      if (keys.demo_client_private_key && !signingKeyPem) {
        setSigningKeyPem(keys.demo_client_private_key);
        setKeySource('demo');
      }
      if (keys.trusted_signer_id) {
        setSignerKeyId(keys.trusted_signer_id);
      }
    } catch {
      // Ignored: keys can also be loaded manually
    }
  }, [signingKeyPem]);

  useEffect(() => {
    loadServerKeys();
  }, [loadServerKeys]);

  const loadEvidence = useCallback(async () => {
    setIsLoading(true);
    try {
      const records = await fetchEvidence();
      setEvidenceList(records);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to load evidence records');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEvidence();
  }, [loadEvidence]);

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleKeyFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setSigningKeyPem(event.target.result);
        setKeySource('custom');
        setCustomKeyFileName(file.name);
        setErrorMessage(null);
      };
      reader.readAsText(file);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMessage('Please select a forensic artifact file to upload.');
      return;
    }

    if (!signingKeyPem) {
      setErrorMessage('Uploader RSA private key is required to sign the evidence upload. Please select or load a signing key.');
      return;
    }

    setIsUploading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      // 1. Calculate SHA-256 of original bytes
      setUploadProgressText('Calculating SHA-256 of original evidence...');
      const fileBuffer = await selectedFile.arrayBuffer();
      const originalSha256 = await computeSha256(fileBuffer);

      // 2. Encrypt evidence with AES-256-GCM
      setUploadProgressText('Encrypting evidence with AES-256-GCM...');
      const t0Enc = performance.now();
      const {
        rawAesKey,
        nonceHex,
        tagHex,
        packagedBytes,
        payloadSha256,
      } = await encryptEvidencePayload(fileBuffer);
      const encryptionDurationMs = Math.max(0.0001, performance.now() - t0Enc);

      // 3. Wrap AES key with server RSA-OAEP public key
      setUploadProgressText('Wrapping AES key with Server RSA-OAEP public key...');
      let serverPubKey = serverKeyData?.server_public_key;
      if (!serverPubKey) {
        const freshKeys = await fetchServerPublicKey();
        setServerKeyData(freshKeys);
        serverPubKey = freshKeys.server_public_key;
      }
      const wrappedAesKeyHex = await wrapAesKeyWithServerPublicKey(serverPubKey, rawAesKey);

      // 4. Construct canonical message & sign with RSA-PSS
      setUploadProgressText('Generating RSA-PSS digital signature...');
      const timestamp = Math.floor(Date.now() / 1000);
      const uploadId = `UPLOAD-${Date.now().toString(36).toUpperCase()}`;
      const canonicalBytes = buildCanonicalSigningData({
        upload_id: uploadId,
        original_sha256: originalSha256,
        filename: selectedFile.name,
        source_device: sourceDevice,
        collector_id: collectorId,
        timestamp,
        encryption_algorithm: 'AES-256-GCM',
        nonce_hex: nonceHex,
        tag_hex: tagHex,
        encrypted_payload_sha256: payloadSha256,
      });

      const t0Sign = performance.now();
      const signatureHex = await signCanonicalDataWithRsaPss(signingKeyPem, canonicalBytes);
      const signingDurationMs = Math.max(0.0001, performance.now() - t0Sign);

      // 5. Send upload to FastAPI
      setUploadProgressText('Uploading encrypted payload to Investigation Server...');
      const formData = new FormData();
      formData.append('file', new Blob([packagedBytes], { type: 'application/octet-stream' }), selectedFile.name);
      formData.append('source_device', sourceDevice);
      if (collectorId) formData.append('collector_id', collectorId);
      if (description) formData.append('description', description);
      formData.append('original_sha256', originalSha256);
      formData.append('encrypted_aes_key', wrappedAesKeyHex);
      formData.append('rsa_signature', signatureHex);
      formData.append('signer_key_id', signerKeyId || 'client-demo-01');
      formData.append('nonce', nonceHex);
      formData.append('tag', tagHex);
      formData.append('timestamp', timestamp.toString());
      formData.append('upload_id', uploadId);
      formData.append('encryption_duration_ms', encryptionDurationMs.toFixed(4));
      formData.append('signing_duration_ms', signingDurationMs.toFixed(4));

      setUploadProgressText('Verifying RSA signature & decrypting AES-GCM on server...');
      const result = await uploadEvidence(formData);

      setSuccessMessage(
        `Upload successful! Artifact verified & stored at rest (AES-256-GCM). ID: ${result.evidence_id} • SHA-256: ${result.sha256_hash.slice(0, 16)}... • RSA-PSS Signature: Verified`
      );

      // Reset form
      setSelectedFile(null);
      setDescription('');
      if (fileInputRef.current) fileInputRef.current.value = '';
      setShowUploadForm(false);

      // Refresh evidence table and app-level dashboard stats
      await loadEvidence();
      if (onEvidenceUploaded) {
        onEvidenceUploaded();
      }
    } catch (err) {
      const msg = err.message || '';
      let failureTitle = 'Upload rejected';
      if (msg.toLowerCase().includes('signature verification failed') || msg.toLowerCase().includes('signature does not match')) {
        failureTitle = 'Signature verification failed';
      } else if (msg.toLowerCase().includes('tag mismatch') || msg.toLowerCase().includes('decryption or authentication failed') || msg.toLowerCase().includes('aes-gcm')) {
        failureTitle = 'Decryption or authentication failed';
      } else if (msg.toLowerCase().includes('integrity verification failed') || msg.toLowerCase().includes('digest')) {
        failureTitle = 'Integrity verification failed';
      } else if (msg.toLowerCase().includes('untrusted')) {
        failureTitle = 'Untrusted signing key rejected';
      }
      setErrorMessage(`${failureTitle}: ${msg}`);
    } finally {
      setIsUploading(false);
      setUploadProgressText('');
    }
  };

  const handleVerify = async (evidenceId) => {
    setVerifyingMap((prev) => ({ ...prev, [evidenceId]: true }));
    setVerificationNotification(null);

    try {
      const result = await verifyEvidence(evidenceId);
      setVerificationResults((prev) => ({
        ...prev,
        [evidenceId]: result,
      }));

      if (result.status === 'INTACT') {
        setVerificationNotification({
          type: 'success',
          evidenceId: result.evidence_id,
          title: 'Integrity Verified — INTACT',
          message: result.message,
          storedHash: result.stored_hash,
          currentHash: result.current_hash,
        });
      } else if (result.status === 'TAMPERED') {
        setVerificationNotification({
          type: 'error',
          evidenceId: result.evidence_id,
          title: 'Integrity Violation Detected — TAMPERED',
          message: result.message,
          storedHash: result.stored_hash,
          currentHash: result.current_hash,
        });
      } else {
        setVerificationNotification({
          type: 'warning',
          evidenceId: result.evidence_id,
          title: `Integrity Check Alert — ${result.status}`,
          message: result.message,
          storedHash: result.stored_hash,
          currentHash: result.current_hash,
        });
      }

      if (onEvidenceUploaded) {
        onEvidenceUploaded();
      }
    } catch (err) {
      setVerificationNotification({
        type: 'error',
        evidenceId,
        title: 'Integrity Verification Failed',
        message: err.message || 'Unable to complete verification check against Investigation Server.',
      });
    } finally {
      setVerifyingMap((prev) => ({ ...prev, [evidenceId]: false }));
    }
  };

  return (
    <div className="space-y-5">
      {/* Verification Notification Banner */}
      {verificationNotification && (
        <div
          className={`p-3.5 rounded-sm text-xs flex items-start justify-between gap-3 border ${
            verificationNotification.type === 'success'
              ? 'bg-[#f0f9f3] border-[#227244]/40 text-[#144629]'
              : verificationNotification.type === 'warning'
              ? 'bg-[#fef3c7] border-[#f59e0b]/50 text-[#92400e]'
              : 'bg-[#fee2e2] border-[#ef4444] text-[#991b1b]'
          }`}
        >
          <div className="flex items-start gap-2.5">
            {verificationNotification.type === 'success' ? (
              <ShieldCheck className="w-4 h-4 shrink-0 text-[#1a5935] mt-0.5" />
            ) : (
              <ShieldAlert className="w-4 h-4 shrink-0 text-[#991b1b] mt-0.5" />
            )}
            <div className="space-y-1">
              <div className="font-bold flex items-center gap-2">
                <span>{verificationNotification.title}</span>
                <span className="font-mono text-[11px] font-semibold px-1.5 py-0.5 rounded-sm bg-black/5">
                  {verificationNotification.evidenceId}
                </span>
              </div>
              <div className="text-[11px] leading-relaxed">
                {verificationNotification.message}
              </div>
              {verificationNotification.storedHash && verificationNotification.currentHash && (
                <div className="mt-1.5 font-mono text-[10px] space-y-0.5 bg-white/60 p-2 rounded-sm border border-black/10">
                  <div>Stored Acquisition Hash: <span className="font-semibold">{verificationNotification.storedHash}</span></div>
                  <div>Current On-Disk Hash:    <span className="font-semibold">{verificationNotification.currentHash}</span></div>
                </div>
              )}
            </div>
          </div>
          <button
            onClick={() => setVerificationNotification(null)}
            className="text-current opacity-70 hover:opacity-100 text-xs shrink-0 p-0.5"
            title="Dismiss notification"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Success Notification */}
      {successMessage && (
        <div className="p-3.5 bg-[#f0f9f3] border border-[#227244]/40 rounded-sm text-[#144629] text-xs flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-[#1a5935] mt-0.5" />
            <div>
              <div className="font-bold text-[#144629]">Acquisition Hashing Complete</div>
              <div className="text-[11px] text-[#227244] mt-0.5 font-mono break-all">{successMessage}</div>
            </div>
          </div>
          <button
            onClick={() => setSuccessMessage(null)}
            className="text-[#227244] hover:text-[#144629] text-xs"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Error Notification */}
      {errorMessage && (
        <div className="p-3.5 bg-[#fee2e2] border border-[#ef4444] rounded-sm text-[#991b1b] text-xs flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b] mt-0.5" />
            <div>
              <div className="font-bold text-[#7f1d1d]">Ingestion Error</div>
              <div className="text-[11px] text-[#991b1b] mt-0.5">{errorMessage}</div>
            </div>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-[#991b1b] hover:text-[#7f1d1d] text-xs"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Upload Panel (Collapsible / Modal section) */}
      {showUploadForm && (
        <Card
          title="Secure Evidence Ingestion"
          subtitle="Client-side AES-256-GCM encryption, RSA-OAEP key wrapping, and RSA-PSS digital signing"
          action={
            <button
              onClick={() => {
                setShowUploadForm(false);
                setErrorMessage(null);
              }}
              className="text-[#536050] hover:text-[#111813] text-xs font-mono"
            >
              [Close]
            </button>
          }
        >
          <form onSubmit={handleUploadSubmit} className="space-y-4 text-xs">
            {/* Cryptographic Security Notice */}
            <div className="p-2.5 bg-[#f0fdf4] border border-[#86efac] rounded-sm text-[#166534] text-[11px] flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#16a34a] shrink-0" />
                <span>
                  <strong>Zero-Knowledge Transfer:</strong> Artifacts are hashed (SHA-256), encrypted client-side with AES-256-GCM, and signed with RSA-PSS before network transmission.
                </span>
              </div>
              <span className="font-mono text-[10px] bg-white px-2 py-0.5 border border-[#86efac] rounded-sm text-[#15803d]">
                RSA-PSS + AES-256-GCM
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Forensic Artifact File <span className="text-[#991b1b]">*</span>
                </label>
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileChange}
                  disabled={isUploading}
                  className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2 file:mr-3 file:py-1 file:px-2.5 file:rounded-sm file:border-0 file:text-xs file:font-semibold file:bg-[#1b5e34] file:text-white hover:file:bg-[#144629] cursor-pointer"
                />
                <p className="text-[10px] text-[#536050] mt-1 font-sans">
                  Supported: PCAP, PCAPNG, log, txt, csv, evtx, images, audio, video, PDF, DOC, DOCX, archives
                </p>
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Uploader RSA Signing Key (.pem) <span className="text-[#991b1b]">*</span>
                </label>
                <div className="flex items-center gap-2">
                  <input
                    ref={keyInputRef}
                    type="file"
                    accept=".pem,.key"
                    onChange={handleKeyFileChange}
                    disabled={isUploading}
                    className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2 file:mr-2 file:py-0.5 file:px-2 file:rounded-sm file:border-0 file:text-[11px] file:font-semibold file:bg-[#334155] file:text-white hover:file:bg-[#1e293b] cursor-pointer"
                  />
                  {serverKeyData?.demo_client_private_key && (
                    <button
                      type="button"
                      onClick={() => {
                        setSigningKeyPem(serverKeyData.demo_client_private_key);
                        setKeySource('demo');
                        setCustomKeyFileName(null);
                        setSignerKeyId(serverKeyData.trusted_signer_id || 'client-demo-01');
                        if (keyInputRef.current) keyInputRef.current.value = '';
                      }}
                      disabled={isUploading}
                      className="shrink-0 px-2.5 py-2 bg-[#f4f1ea] hover:bg-[#eaede8] text-[#1b5e34] border border-[#bdc7ba] rounded-sm text-[11px] font-mono whitespace-nowrap"
                      title="Load default trusted workstation signing key"
                    >
                      Use Demo Key
                    </button>
                  )}
                </div>
                <p className="text-[10px] text-[#536050] mt-1 font-sans flex items-center gap-1">
                  <KeyRound className="w-3 h-3 text-[#16a34a]" />
                  <span>
                    Status: {signingKeyPem ? (
                      <span className="text-[#16a34a] font-semibold">
                        {keySource === 'demo' ? 'Workstation Key Loaded (client-demo-01)' : `Custom Key Loaded (${customKeyFileName})`}
                      </span>
                    ) : (
                      <span className="text-[#b91c1c] font-semibold">No signing key selected</span>
                    )}
                  </span>
                </p>
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Signer Key ID
                </label>
                <input
                  type="text"
                  value={signerKeyId}
                  onChange={(e) => setSignerKeyId(e.target.value)}
                  disabled={isUploading}
                  placeholder="e.g. client-demo-01"
                  className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2"
                />
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Source Device / Workstation
                </label>
                <input
                  type="text"
                  value={sourceDevice}
                  onChange={(e) => setSourceDevice(e.target.value)}
                  disabled={isUploading}
                  placeholder="e.g. sensor-alpha-01, endpoint-192.168.1.10"
                  className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2"
                />
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Collector / Investigator Node ID
                </label>
                <input
                  type="text"
                  value={collectorId}
                  onChange={(e) => setCollectorId(e.target.value)}
                  disabled={isUploading}
                  placeholder="e.g. collector-node-01"
                  className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2"
                />
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Case Description / Notes (Optional)
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  disabled={isUploading}
                  placeholder="e.g. Perimeter gateway packet capture during incident window"
                  className="w-full text-xs text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2 font-sans"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[#eaede8]">
              <div className="text-[11px] font-mono text-[#536050]">
                {isUploading && (
                  <span className="flex items-center gap-1.5 text-[#1b5e34] font-semibold">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>{uploadProgressText}</span>
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setShowUploadForm(false);
                    setSelectedFile(null);
                    if (fileInputRef.current) fileInputRef.current.value = '';
                  }}
                  disabled={isUploading}
                  className="px-3 py-1.5 bg-[#f4f1ea] hover:bg-[#eaede8] text-[#111813] text-xs font-medium rounded-sm border border-[#bdc7ba] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isUploading || !selectedFile || !signingKeyPem}
                  className="inline-flex items-center gap-1.5 px-4 py-1.5 bg-[#1b5e34] hover:bg-[#144629] disabled:opacity-50 text-white text-xs font-medium rounded-sm border border-[#144629] transition-colors"
                >
                  {isUploading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Processing Secure Ingestion...</span>
                    </>
                  ) : (
                    <>
                      <Upload className="w-3.5 h-3.5" />
                      <span>Sign, Encrypt & Ingest Evidence</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        </Card>
      )}

      {/* Main Evidence Registry Table */}
      <Card
        title="Evidence Registry"
        subtitle={`Catalog of forensic artifacts stored in ./storage/evidence (${evidenceList.length} items registered)`}
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={loadEvidence}
              disabled={isLoading}
              title="Refresh evidence table"
              className="p-1.5 bg-[#f4f1ea] hover:bg-[#eaede8] text-[#536050] hover:text-[#111813] rounded-sm border border-[#bdc7ba] transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => {
                setShowUploadForm(!showUploadForm);
                setErrorMessage(null);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#1b5e34] hover:bg-[#144629] text-white text-xs font-medium rounded-sm border border-[#144629] transition-colors"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{showUploadForm ? 'Hide Upload Panel' : 'Upload Evidence'}</span>
            </button>
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-x-auto bg-white">
          <table className="w-full text-left text-xs min-w-[900px]">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">File Name</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Type</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Source / Collector</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Collected At</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Size</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">SHA-256 Digest</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Integrity Status</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              {isLoading && evidenceList.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-10 text-center text-[#536050]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#1b5e34]" />
                      <span>Loading evidence catalog...</span>
                    </div>
                  </td>
                </tr>
              ) : evidenceList.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-14 text-center text-[#536050]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Inbox className="w-7 h-7 text-[#94a190]" />
                      <p className="text-sm font-semibold text-[#111813]">No Evidence Registered</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        The evidence storage directory is currently empty. Click <strong className="text-[#111813]">Upload Evidence</strong> above to ingest PCAP network captures, system logs, memory dumps, or forensic disk images.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                evidenceList.map((item) => {
                  const isVerifying = !!verifyingMap[item.evidence_id];
                  const vResult = verificationResults[item.evidence_id];

                  return (
                    <tr key={item.id || item.evidence_id} className="hover:bg-[#faf8f3] transition-colors">
                      <td className="py-2.5 px-3 font-mono text-[11px] font-semibold text-[#111813] whitespace-nowrap">
                        {item.evidence_id}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs text-[#111813] font-medium whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <FileCode className="w-3.5 h-3.5 text-[#536050] shrink-0" />
                          <span title={item.file_name}>{item.file_name}</span>
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded-sm bg-[#eaede8] text-[#3e483c] font-mono text-[10px] font-semibold">
                          {item.evidence_type}
                        </span>
                        {item.is_encrypted && (
                          <span
                            className="ml-1.5 inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-sm bg-[#e8f5e9] text-[#1b5e34] border border-[#c8e6c9] font-mono text-[10px] font-semibold"
                            title="Encrypted at rest with AES-256-GCM"
                          >
                            <Lock className="w-2.5 h-2.5" />
                            <span>AES-256</span>
                          </span>
                        )}
                        {item.rsa_signature && (
                          <span
                            className="ml-1.5 inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-sm bg-[#e0f2fe] text-[#0369a1] border border-[#bae6fd] font-mono text-[10px] font-semibold"
                            title={`Digitally signed with RSA-PSS by ${item.signer_key_id || 'trusted signer'}`}
                          >
                            <FileSignature className="w-2.5 h-2.5" />
                            <span>RSA-PSS</span>
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs whitespace-nowrap">
                        <div className="text-[#111813] font-medium">{item.source_device || 'local-workstation'}</div>
                        <div className="text-[10px] text-[#536050] flex items-center gap-1 mt-0.5">
                          <span className="font-sans">Node:</span>
                          <span className="text-[#1b5e34]">{item.collector_id || 'collector-node-01'}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-[#536050] whitespace-nowrap">
                        {item.collected_at
                          ? new Date(item.collected_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
                          : 'N/A'}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs text-[#111813] whitespace-nowrap">
                        {formatBytes(item.file_size_bytes)}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-[#111813] whitespace-nowrap">
                        <span
                          className="bg-[#faf8f3] px-1.5 py-0.5 rounded-sm border border-[#d7ded4] select-all cursor-text"
                          title={`Full Acquisition SHA-256 Digest:\n${item.sha256_hash}`}
                        >
                          {item.sha256_hash.slice(0, 12)}...{item.sha256_hash.slice(-8)}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {vResult ? (
                          <div>
                            <StatusBadge
                              status={vResult.status.toLowerCase()}
                              label={vResult.status}
                              size="xs"
                            />
                            <span
                              className={`block text-[10px] font-mono mt-0.5 ${
                                vResult.is_intact ? 'text-[#1a5935]' : 'text-[#991b1b] font-semibold'
                              }`}
                            >
                              {vResult.is_intact ? 'SHA-256 Intact' : 'Tampered / Mismatch'}
                            </span>
                          </div>
                        ) : (
                          <StatusBadge
                            status="standby"
                            label={item.status || 'ACQUIRED'}
                            size="xs"
                          />
                        )}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleVerify(item.evidence_id)}
                            disabled={isVerifying}
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-sm border transition-colors ${
                              isVerifying
                                ? 'bg-[#eaede8] text-[#536050] border-[#bdc7ba] cursor-wait'
                                : 'bg-[#f4f1ea] hover:bg-[#eaede8] text-[#1b5e34] hover:text-[#144629] border-[#bdc7ba] hover:border-[#1b5e34]'
                            }`}
                            title={`Recalculate SHA-256 on disk and compare with stored acquisition hash for ${item.evidence_id}`}
                          >
                            {isVerifying ? (
                              <>
                                <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#1b5e34]" />
                                <span>Verifying...</span>
                              </>
                            ) : (
                              <>
                                <ShieldCheck className="w-3.5 h-3.5 text-[#1b5e34]" />
                                <span>Verify Integrity</span>
                              </>
                            )}
                          </button>
                          <a
                            href={getEvidenceDownloadUrl(item.evidence_id)}
                            download={item.file_name}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-sm border border-[#bdc7ba] bg-[#f4f1ea] hover:bg-[#eaede8] text-[#3e483c] hover:text-[#111813] transition-colors"
                            title={`Download evidence artifact (${item.is_encrypted ? 'decrypted on the fly with AES-256-GCM' : 'original'})`}
                          >
                            <Download className="w-3.5 h-3.5 text-[#536050]" />
                            <span>Download</span>
                          </a>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
        <Card title="Artifact Intake Pipeline">
          <ul className="space-y-2 text-[#3e483c]">
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Storage Path:</strong> Stored locally under <code className="bg-[#faf8f3] border border-[#d7ded4] px-1 py-0.5 rounded-sm font-mono text-[11px] text-[#111813]">server/storage/evidence</code></span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Supported Formats:</strong> PCAP, PCAPNG, log, txt, json, csv, xml, evtx, images, audio, video, PDF, DOC, DOCX, archives</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Integrity Guarantee:</strong> Streaming SHA-256 acquisition hashes calculated with chunking upon ingest</span>
            </li>
          </ul>
        </Card>

        <Card title="Admissibility Standard">
          <p className="text-[#536050] leading-relaxed">
            All registered evidence artifacts retain immutable provenance records documenting acquisition timestamp, acquiring collector ID, physical byte size, and SHA-256 cryptographic signatures. Initial integrity status is set to ACQUIRED.
          </p>
        </Card>
      </div>
    </div>
  );
}
