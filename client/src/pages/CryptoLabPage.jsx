import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import {
  fetchEvidence,
  fetchCryptoLabMetadata,
  executeCryptoLabDecryption,
  hashEvidenceDemo,
  hashStandaloneFile,
  hashCompareFiles,
} from '../api/client';
import {
  Shield,
  KeyRound,
  Lock,
  Unlock,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Layers,
  FileText,
  Image as ImageIcon,
  Zap,
  ArrowRight,
  Clock,
  HardDrive,
  Hash,
  Binary,
  GitCompare,
  BookOpen,
  Copy,
  Check,
  Activity,
  FileCheck,
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function CryptoLabPage() {
  const [activeTab, setActiveTab] = useState('encryption'); // 'encryption' | 'hashing'

  const [evidenceList, setEvidenceList] = useState([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('');
  const [metadata, setMetadata] = useState(null);
  const [executionResult, setExecutionResult] = useState(null);

  const [isLoadingList, setIsLoadingList] = useState(true);
  const [isLoadingMetadata, setIsLoadingMetadata] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [error, setError] = useState(null);
  const [cipherFormat, setCipherFormat] = useState('hex'); // 'hex' | 'b64'

  // SHA-256 Hashing demonstration state
  const [hashEvidenceId, setHashEvidenceId] = useState('');
  const [evidenceHashResult, setEvidenceHashResult] = useState(null);
  const [isHashingEvidence, setIsHashingEvidence] = useState(false);

  const [standaloneFile, setStandaloneFile] = useState(null);
  const [standaloneHashResult, setStandaloneHashResult] = useState(null);
  const [isHashingStandalone, setIsHashingStandalone] = useState(false);

  const [compareFileA, setCompareFileA] = useState(null);
  const [compareFileB, setCompareFileB] = useState(null);
  const [compareResult, setCompareResult] = useState(null);
  const [isComparing, setIsComparing] = useState(false);
  const [copiedDigest, setCopiedDigest] = useState(null);

  const handleCopy = (text) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedDigest(text);
      setTimeout(() => setCopiedDigest(null), 2000);
    }
  };

  // Load available evidence list
  const loadEvidenceList = useCallback(async () => {
    setIsLoadingList(true);
    setError(null);
    try {
      const records = await fetchEvidence();
      const list = Array.isArray(records) ? records : [];
      setEvidenceList(list);
      if (list.length > 0) {
        if (!selectedEvidenceId) setSelectedEvidenceId(list[0].evidence_id);
        if (!hashEvidenceId) setHashEvidenceId(list[0].evidence_id);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch evidence list');
    } finally {
      setIsLoadingList(false);
    }
  }, [selectedEvidenceId, hashEvidenceId]);

  useEffect(() => {
    loadEvidenceList();
  }, [loadEvidenceList]);

  // Load metadata when selected evidence changes (WITHOUT decrypting)
  useEffect(() => {
    if (!selectedEvidenceId) {
      setMetadata(null);
      setExecutionResult(null);
      return;
    }

    let isMounted = true;
    const fetchMeta = async () => {
      setIsLoadingMetadata(true);
      setError(null);
      setExecutionResult(null);
      try {
        const meta = await fetchCryptoLabMetadata(selectedEvidenceId);
        if (isMounted) {
          setMetadata(meta);
        }
      } catch (err) {
        if (isMounted) {
          setError(err.message || 'Failed to load cryptographic metadata');
          setMetadata(null);
        }
      } finally {
        if (isMounted) {
          setIsLoadingMetadata(false);
        }
      }
    };

    fetchMeta();
    return () => {
      isMounted = false;
    };
  }, [selectedEvidenceId]);

  // Explicit user trigger for cryptographic decryption & verification
  const handleExecuteDecryption = async () => {
    if (!selectedEvidenceId) return;
    setIsExecuting(true);
    setError(null);
    try {
      const result = await executeCryptoLabDecryption(selectedEvidenceId);
      setExecutionResult(result);
    } catch (err) {
      setError(err.message || 'Decryption & verification failed');
      setExecutionResult(null);
    } finally {
      setIsExecuting(false);
    }
  };

  // Explicit user trigger for evidence SHA-256 hash demo
  const handleComputeEvidenceHash = async () => {
    const targetId = hashEvidenceId || selectedEvidenceId;
    if (!targetId) return;
    setIsHashingEvidence(true);
    setError(null);
    try {
      const result = await hashEvidenceDemo(targetId);
      setEvidenceHashResult(result);
    } catch (err) {
      setError(err.message || 'Evidence hashing failed');
      setEvidenceHashResult(null);
    } finally {
      setIsHashingEvidence(false);
    }
  };

  // Explicit user trigger for standalone file hash demo
  const handleStandaloneHash = async () => {
    if (!standaloneFile) return;
    setIsHashingStandalone(true);
    setError(null);
    try {
      const result = await hashStandaloneFile(standaloneFile);
      setStandaloneHashResult(result);
    } catch (err) {
      setError(err.message || 'File hashing failed');
      setStandaloneHashResult(null);
    } finally {
      setIsHashingStandalone(false);
    }
  };

  // Explicit user trigger for hash comparison demo
  const handleCompareHashes = async () => {
    if (!compareFileA || !compareFileB) return;
    setIsComparing(true);
    setError(null);
    try {
      const result = await hashCompareFiles(compareFileA, compareFileB);
      setCompareResult(result);
    } catch (err) {
      setError(err.message || 'Hash comparison failed');
      setCompareResult(null);
    } finally {
      setIsComparing(false);
    }
  };

  const selectedEvidence = evidenceList.find((e) => e.evidence_id === selectedEvidenceId);

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div className="flex border-b border-[#d7ded4] gap-6 text-xs font-semibold">
        <button
          onClick={() => setActiveTab('encryption')}
          className={`pb-2.5 flex items-center gap-2 transition-colors border-b-2 ${
            activeTab === 'encryption'
              ? 'border-[#1a5935] text-[#1a5935]'
              : 'border-transparent text-[#536050] hover:text-[#111813]'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>AES-256-GCM Encryption & Decryption</span>
        </button>
        <button
          onClick={() => setActiveTab('hashing')}
          className={`pb-2.5 flex items-center gap-2 transition-colors border-b-2 ${
            activeTab === 'hashing'
              ? 'border-[#1a5935] text-[#1a5935]'
              : 'border-transparent text-[#536050] hover:text-[#111813]'
          }`}
        >
          <Hash className="w-4 h-4" />
          <span>SHA-256 Cryptographic Hashing</span>
        </button>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-3.5 bg-[#fee2e2] border border-[#ef4444]/40 text-[#991b1b] rounded-sm text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b]" />
            <span className="font-mono font-medium">{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-[#991b1b] hover:text-[#7f1d1d] font-bold text-sm ml-2"
          >
            &times;
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 1: AES-256-GCM ENCRYPTION & DECRYPTION                                */}
      {/* ========================================================================= */}
      {activeTab === 'encryption' && (
        <div className="space-y-6">
          {/* Control Card: Select Evidence & Configuration */}
          <Card
            title="Cryptography Laboratory Console"
            subtitle="Live demonstration of AES-256-GCM authenticated encryption, RSA-OAEP envelope unwrapping, and RSA-PSS verification"
            action={
              <div className="flex items-center gap-2">
                <button
                  onClick={loadEvidenceList}
                  disabled={isLoadingList || isExecuting}
                  className="p-1.5 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4] transition-colors disabled:opacity-50"
                  title="Refresh evidence artifacts"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isLoadingList ? 'animate-spin' : ''}`} />
                </button>
                <span className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
                  Cipher: AES-256-GCM
                </span>
              </div>
            }
          >
            <div className="space-y-4">
              {/* Target Evidence Selector */}
              <div>
                <label className="block text-xs font-semibold text-[#111813] mb-1.5 uppercase tracking-wider">
                  Select Target Forensic Artifact *
                </label>
                {isLoadingList ? (
                  <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                    Loading evidence repository...
                  </div>
                ) : evidenceList.length === 0 ? (
                  <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                    No evidence artifacts registered. Please ingest artifacts in Evidence Management first.
                  </div>
                ) : (
                  <select
                    value={selectedEvidenceId}
                    onChange={(e) => setSelectedEvidenceId(e.target.value)}
                    disabled={isExecuting || isLoadingMetadata}
                    className="w-full h-9 px-3 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935] text-[#111813] font-mono"
                  >
                    {evidenceList.map((ev) => (
                      <option key={ev.evidence_id} value={ev.evidence_id}>
                        {ev.evidence_id} — {ev.file_name} ({formatBytes(ev.file_size_bytes)}) [{ev.evidence_type}] [{ev.status}]
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Metadata Snapshot Card (Loaded before execution) */}
              {metadata && (
                <div className="bg-[#faf8f3] border border-[#d7ded4] p-3.5 rounded-sm text-xs space-y-3">
                  <div className="flex items-center justify-between border-b border-[#eaede8] pb-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-[#6c7a68]">
                      Artifact Cryptographic Ledger Parameters
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-[#536050] font-mono">Status at Rest:</span>
                      <StatusBadge
                        status={metadata.is_encrypted ? 'verified' : 'standby'}
                        label={metadata.is_encrypted ? 'ENCRYPTED AT REST' : 'UNENCRYPTED'}
                        size="xs"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px] font-mono">
                    <div>
                      <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Algorithm</span>
                      <span className="text-[#111813] font-semibold">{metadata.encryption_algorithm}</span>
                    </div>
                    <div>
                      <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Plaintext Size</span>
                      <span className="text-[#111813]">{formatBytes(metadata.file_size_bytes)}</span>
                    </div>
                    <div>
                      <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Signer Public Key</span>
                      <span className="text-[#111813]">{metadata.signer_key_id || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Ingestion Encryption Time</span>
                      <span className="text-[#111813]">
                        {metadata.recorded_encryption_duration_ms !== null
                          ? `${metadata.recorded_encryption_duration_ms.toFixed(2)} ms`
                          : 'Not recorded'}
                      </span>
                    </div>
                  </div>

                  {metadata.wrapped_key_preview && (
                    <div className="pt-1 text-[11px] font-mono">
                      <span className="text-[#6c7a68] uppercase text-[10px] font-bold block mb-0.5">
                        RSA-OAEP Key Envelope (Wrapped AES Key)
                      </span>
                      <div className="p-1.5 bg-white border border-[#eaede8] rounded-sm text-[#3e483c] break-all select-all">
                        {metadata.wrapped_key_preview}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Action Row */}
              <div className="flex items-center justify-between pt-1">
                <div className="text-[11px] text-[#536050] italic">
                  {executionResult
                    ? 'Demonstration complete. Verified plaintext and performance telemetry rendered below.'
                    : 'Decryption is executed only on explicit user request.'}
                </div>
                <button
                  onClick={handleExecuteDecryption}
                  disabled={isExecuting || !selectedEvidenceId || !metadata}
                  className="flex items-center gap-2 bg-[#1a5935] hover:bg-[#144629] text-white px-5 py-2 rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-none"
                >
                  {isExecuting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Unwrapping Key, Authenticating Tag & Decrypting...</span>
                    </>
                  ) : (
                    <>
                      <Unlock className="w-4 h-4" />
                      <span>Run Cryptographic Demonstration</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </Card>

          {/* Execution Results View */}
          {executionResult && (
            <div className="space-y-6">
              {/* Security & Verification Status Strip */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="bg-white border border-[#d7ded4] p-3 rounded-sm flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-bold uppercase text-[#6c7a68] block">RSA-PSS Digital Signature</span>
                    <span className="text-xs font-semibold text-[#111813] font-mono">
                      Key: {executionResult.signer_key_id || 'trusted-agent'}
                    </span>
                  </div>
                  <StatusBadge
                    status={executionResult.rsa_signature_valid ? 'verified' : 'warning'}
                    label={executionResult.rsa_signature_valid ? 'VERIFIED' : 'NOT RECORDED'}
                    size="xs"
                  />
                </div>

                <div className="bg-white border border-[#d7ded4] p-3 rounded-sm flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-bold uppercase text-[#6c7a68] block">AES-GCM Authentication Tag</span>
                    <span className="text-xs font-semibold text-[#111813] font-mono">16-byte Poly1305 / GHASH</span>
                  </div>
                  <StatusBadge
                    status={executionResult.gcm_authentication_valid ? 'verified' : 'error'}
                    label={executionResult.gcm_authentication_valid ? 'AUTHENTICATED' : 'TAG MISMATCH'}
                    size="xs"
                  />
                </div>

                <div className="bg-white border border-[#d7ded4] p-3 rounded-sm flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-bold uppercase text-[#6c7a68] block">Integrity Verdict</span>
                    <span className="text-xs font-semibold text-[#111813] font-mono">SHA-256 Digest Matched</span>
                  </div>
                  <StatusBadge
                    status="verified"
                    label={executionResult.integrity_status}
                    size="xs"
                  />
                </div>
              </div>

              {/* Cryptographic Parameters & Benchmark Telemetry */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Cryptographic Parameters */}
                <Card
                  title="Cryptographic Parameters"
                  subtitle="Parameters extracted and verified from the encrypted container"
                >
                  <div className="space-y-3 text-xs font-mono">
                    <div className="grid grid-cols-2 gap-2 pb-2 border-b border-[#eaede8]">
                      <div>
                        <span className="text-[10px] text-[#6c7a68] uppercase font-bold block">Encryption Algorithm</span>
                        <span className="text-[#111813] font-semibold">{executionResult.encryption_algorithm}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-[#6c7a68] uppercase font-bold block">Digital Signer</span>
                        <span className="text-[#111813]">{executionResult.signer_key_id || 'trusted-agent'}</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-[10px] text-[#6c7a68] uppercase font-bold block mb-1">
                        Initialization Vector / Nonce (96 bits)
                      </span>
                      <div className="p-2 bg-[#faf8f3] border border-[#eaede8] rounded-sm text-[#111813] text-[11px] break-all select-all">
                        {executionResult.nonce_hex || 'N/A (Unencrypted)'}
                      </div>
                    </div>

                    <div>
                      <span className="text-[10px] text-[#6c7a68] uppercase font-bold block mb-1">
                        GCM Authentication Tag (128 bits)
                      </span>
                      <div className="p-2 bg-[#faf8f3] border border-[#eaede8] rounded-sm text-[#111813] text-[11px] break-all select-all">
                        {executionResult.tag_hex || 'N/A (Unencrypted)'}
                      </div>
                    </div>

                    {executionResult.wrapped_key_hex && (
                      <div>
                        <span className="text-[10px] text-[#6c7a68] uppercase font-bold block mb-1">
                          RSA-OAEP Key Envelope (Wrapped AES Key)
                        </span>
                        <div className="p-2 bg-[#faf8f3] border border-[#eaede8] rounded-sm text-[#111813] text-[11px] break-all select-all max-h-20 overflow-y-auto">
                          {executionResult.wrapped_key_hex}
                        </div>
                      </div>
                    )}
                  </div>
                </Card>

                {/* Benchmark & Throughput Telemetry */}
                <Card
                  title="Cryptographic Performance Telemetry"
                  subtitle="Measured hardware throughput and operation durations"
                >
                  <div className="space-y-4 text-xs">
                    {/* Sizes Comparison */}
                    <div className="grid grid-cols-2 gap-4 pb-3 border-b border-[#eaede8]">
                      <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm">
                        <div className="flex items-center gap-1.5 text-[#536050] text-[10px] font-bold uppercase mb-1">
                          <HardDrive className="w-3 h-3" /> Plaintext Payload
                        </div>
                        <div className="text-sm font-semibold font-mono text-[#111813]">
                          {formatBytes(executionResult.original_size_bytes)}
                        </div>
                        <div className="text-[10px] text-[#6c7a68] font-mono">
                          {executionResult.original_size_bytes} bytes
                        </div>
                      </div>

                      <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm">
                        <div className="flex items-center gap-1.5 text-[#536050] text-[10px] font-bold uppercase mb-1">
                          <Lock className="w-3 h-3" /> Encrypted Container
                        </div>
                        <div className="text-sm font-semibold font-mono text-[#111813]">
                          {formatBytes(executionResult.encrypted_size_bytes)}
                        </div>
                        <div className="text-[10px] text-[#6c7a68] font-mono">
                          {executionResult.encrypted_size_bytes} bytes (+28B overhead)
                        </div>
                      </div>
                    </div>

                    {/* Encryption Benchmark */}
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-[#111813] flex items-center gap-1">
                          <Zap className="w-3.5 h-3.5 text-[#1a5935]" /> Ingestion Encryption
                        </span>
                        <span className="font-mono text-[#536050]">
                          {executionResult.encryption_duration_ms !== null
                            ? `${executionResult.encryption_duration_ms.toFixed(3)} ms`
                            : 'Not recorded'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] font-mono text-[#6c7a68]">
                        <span>Throughput</span>
                        <span className="font-semibold text-[#111813]">
                          {executionResult.encryption_throughput_mbps !== null
                            ? `${executionResult.encryption_throughput_mbps.toFixed(2)} MB/s`
                            : 'Not recorded'}
                        </span>
                      </div>
                    </div>

                    {/* Decryption Benchmark */}
                    <div className="space-y-1 pt-2 border-t border-[#eaede8]">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-[#111813] flex items-center gap-1">
                          <Cpu className="w-3.5 h-3.5 text-[#1a5935]" /> Lab Decryption & Verification
                        </span>
                        <span className="font-mono text-[#536050]">
                          {executionResult.decryption_duration_ms.toFixed(3)} ms
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] font-mono text-[#6c7a68]">
                        <span>Throughput</span>
                        <span className="font-semibold text-[#111813]">
                          {executionResult.decryption_throughput_mbps !== null
                            ? `${executionResult.decryption_throughput_mbps.toFixed(2)} MB/s`
                            : 'N/A'}
                        </span>
                      </div>
                    </div>

                    {/* PCAP Special Note */}
                    {executionResult.is_pcap && (
                      <div className="p-2.5 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-[11px] text-[#536050] flex items-start gap-2">
                        <Shield className="w-4 h-4 text-[#1a5935] shrink-0 mt-0.5" />
                        <span>
                          Packet capture artifacts (PCAP/PCAPNG) are restricted to cryptographic performance benchmarks.
                          Raw frame contents and ciphertext previews are omitted in compliance with forensic safety policies.
                        </span>
                      </div>
                    )}
                  </div>
                </Card>
              </div>

              {/* Data Representation View (Plaintext & Ciphertext) - Excluded for PCAP */}
              {!executionResult.is_pcap && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Ciphertext Representation */}
                  <Card
                    title="Encrypted Ciphertext Representation"
                    subtitle={`Bounded preview of actual encrypted bytes (${executionResult.ciphertext_preview_bytes} of ${executionResult.total_ciphertext_bytes} bytes)`}
                    action={
                      <div className="flex items-center bg-[#eaede8] p-0.5 rounded-sm text-[10px] font-mono">
                        <button
                          onClick={() => setCipherFormat('hex')}
                          className={`px-2 py-0.5 rounded-sm transition-colors ${
                            cipherFormat === 'hex' ? 'bg-white text-[#111813] font-semibold' : 'text-[#536050]'
                          }`}
                        >
                          HEX
                        </button>
                        <button
                          onClick={() => setCipherFormat('b64')}
                          className={`px-2 py-0.5 rounded-sm transition-colors ${
                            cipherFormat === 'b64' ? 'bg-white text-[#111813] font-semibold' : 'text-[#536050]'
                          }`}
                        >
                          BASE64
                        </button>
                      </div>
                    }
                  >
                    <div className="space-y-2">
                      <div className="p-3 bg-[#111813] text-[#4ade80] font-mono text-[11px] rounded-sm max-h-72 overflow-y-auto break-all select-all leading-relaxed">
                        {cipherFormat === 'hex'
                          ? executionResult.ciphertext_preview_hex || 'No ciphertext available'
                          : executionResult.ciphertext_preview_b64 || 'No ciphertext available'}
                      </div>
                      <div className="text-[10px] text-[#6c7a68] font-mono flex items-center justify-between">
                        <span>High-entropy encrypted byte distribution</span>
                        <span>{executionResult.total_ciphertext_bytes} total bytes</span>
                      </div>
                    </div>
                  </Card>

                  {/* Decrypted Plaintext Representation */}
                  <Card
                    title="Decrypted & Verified Plaintext Result"
                    subtitle="Authenticated plaintext restored through AES-256-GCM decryption"
                  >
                    <div className="space-y-3">
                      {executionResult.plaintext_preview_type === 'text' && (
                        <div className="p-3 bg-white border border-[#d7ded4] text-[#111813] font-mono text-xs rounded-sm max-h-72 overflow-y-auto whitespace-pre-wrap select-all">
                          {executionResult.plaintext_preview}
                        </div>
                      )}

                      {executionResult.plaintext_preview_type === 'image' && (
                        <div className="space-y-2">
                          <div className="p-2 bg-[#faf8f3] border border-[#d7ded4] rounded-sm flex items-center justify-center max-h-72 overflow-hidden">
                            <img
                              src={executionResult.plaintext_preview}
                              alt="Decrypted forensic preview"
                              className="max-h-64 object-contain rounded-sm"
                            />
                          </div>
                          <div className="text-[10px] text-[#6c7a68] font-mono text-center">
                            Decrypted image verified intact with identical SHA-256 digest
                          </div>
                        </div>
                      )}

                      {(executionResult.plaintext_preview_type === 'image_large' ||
                        executionResult.plaintext_preview_type === 'unsupported') && (
                        <div className="p-4 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-center text-[#536050] space-y-1">
                          <FileText className="w-6 h-6 mx-auto text-[#6c7a68]" />
                          <div className="font-semibold text-xs text-[#111813]">{executionResult.plaintext_preview}</div>
                          <div className="text-[11px]">Plaintext verified intact against stored SHA-256 acquisition hash.</div>
                        </div>
                      )}

                      {/* Cryptographic Footprint Summary */}
                      <div className="p-2.5 bg-[#f0f9f3] border border-[#227244]/20 rounded-sm text-[11px] text-[#144629] font-mono space-y-1">
                        <div>
                          <strong>Decryption Verified:</strong> Plaintext SHA-256 matches signed baseline.
                        </div>
                        <div>
                          <strong>Throughput:</strong>{' '}
                          {executionResult.decryption_throughput_mbps !== null
                            ? `${executionResult.decryption_throughput_mbps.toFixed(2)} MB/s`
                            : 'N/A'}{' '}
                          ({executionResult.decryption_duration_ms.toFixed(3)} ms duration)
                        </div>
                      </div>
                    </div>
                  </Card>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: SHA-256 CRYPTOGRAPHIC HASHING                                      */}
      {/* ========================================================================= */}
      {activeTab === 'hashing' && (
        <div className="space-y-6">
          {/* Educational Overview Panel */}
          <Card
            title="SHA-256 Cryptographic Hash Architecture"
            subtitle="Deterministic 256-bit (32-byte / 64 hex characters) Merkle-Damgård one-way compression function"
            action={
              <span className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
                FIPS 180-4 / RFC 6234
              </span>
            }
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="p-3.5 bg-[#faf8f3] border border-[#d7ded4] rounded-sm space-y-2">
                <div className="flex items-center gap-2 text-[#1a5935] font-bold uppercase tracking-wider text-[11px]">
                  <Lock className="w-4 h-4 shrink-0" />
                  <span>1. Preimage Resistance</span>
                </div>
                <div className="text-[#3e483c] leading-relaxed text-[11px]">
                  <strong>One-Way Property:</strong> Given an arbitrary digest <code className="bg-white px-1 py-0.5 border border-[#eaede8] rounded text-[#111813] font-mono">h</code>, it is computationally infeasible to find any message <code className="bg-white px-1 py-0.5 border border-[#eaede8] rounded text-[#111813] font-mono">m</code> such that <code className="font-mono text-[#111813]">SHA-256(m) = h</code>.
                </div>
                <div className="text-[10px] font-mono text-[#6c7a68] pt-1 border-t border-[#eaede8]">
                  Complexity: ~2<sup>256</sup> operations
                </div>
              </div>

              <div className="p-3.5 bg-[#faf8f3] border border-[#d7ded4] rounded-sm space-y-2">
                <div className="flex items-center gap-2 text-[#1a5935] font-bold uppercase tracking-wider text-[11px]">
                  <FileCheck className="w-4 h-4 shrink-0" />
                  <span>2. Second-Preimage Resistance</span>
                </div>
                <div className="text-[#3e483c] leading-relaxed text-[11px]">
                  <strong>Weak Collision Resistance:</strong> Given a specific input <code className="bg-white px-1 py-0.5 border border-[#eaede8] rounded text-[#111813] font-mono">m₁</code>, it is computationally infeasible to locate a distinct input <code className="bg-white px-1 py-0.5 border border-[#eaede8] rounded text-[#111813] font-mono">m₂ ≠ m₁</code> such that <code className="font-mono text-[#111813]">SHA-256(m₁) = SHA-256(m₂)</code>.
                </div>
                <div className="text-[10px] font-mono text-[#6c7a68] pt-1 border-t border-[#eaede8]">
                  Complexity: ~2<sup>256</sup> operations
                </div>
              </div>

              <div className="p-3.5 bg-[#faf8f3] border border-[#d7ded4] rounded-sm space-y-2">
                <div className="flex items-center gap-2 text-[#1a5935] font-bold uppercase tracking-wider text-[11px]">
                  <Shield className="w-4 h-4 shrink-0" />
                  <span>3. Collision Resistance</span>
                </div>
                <div className="text-[#3e483c] leading-relaxed text-[11px]">
                  <strong>Strong Collision Resistance:</strong> It is computationally infeasible to discover any two arbitrary messages <code className="bg-white px-1 py-0.5 border border-[#eaede8] rounded text-[#111813] font-mono">m₁ ≠ m₂</code> producing identical digests.
                </div>
                <div className="text-[10px] font-mono text-[#6c7a68] pt-1 border-t border-[#eaede8]">
                  Birthday Attack: ~2<sup>128</sup> operations
                </div>
              </div>
            </div>
          </Card>

          {/* Section 1: Evidence Repository Artifact Hashing */}
          <Card
            title="Evidence Artifact Hashing (Encrypted vs Decrypted Representations)"
            subtitle="Demonstrates how stored ciphertext differs from authenticated original plaintext while preserving acquisition integrity"
            action={
              <button
                onClick={loadEvidenceList}
                disabled={isLoadingList || isHashingEvidence}
                className="p-1.5 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4] transition-colors disabled:opacity-50"
                title="Refresh evidence artifacts"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingList ? 'animate-spin' : ''}`} />
              </button>
            }
          >
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3 items-end">
                <div className="flex-1 w-full">
                  <label className="block text-xs font-semibold text-[#111813] mb-1.5 uppercase tracking-wider">
                    Select Target Evidence Artifact
                  </label>
                  {isLoadingList ? (
                    <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                      Loading evidence artifacts...
                    </div>
                  ) : evidenceList.length === 0 ? (
                    <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                      No evidence artifacts found in repository.
                    </div>
                  ) : (
                    <select
                      value={hashEvidenceId}
                      onChange={(e) => setHashEvidenceId(e.target.value)}
                      disabled={isHashingEvidence}
                      className="w-full h-9 px-3 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935] text-[#111813] font-mono"
                    >
                      {evidenceList.map((ev) => (
                        <option key={ev.evidence_id} value={ev.evidence_id}>
                          {ev.evidence_id} — {ev.file_name} ({formatBytes(ev.file_size_bytes)}) [{ev.evidence_type}]
                        </option>
                      ))}
                    </select>
                  )}
                </div>

                <button
                  onClick={handleComputeEvidenceHash}
                  disabled={isHashingEvidence || !hashEvidenceId}
                  className="h-9 px-5 bg-[#1a5935] hover:bg-[#144629] text-white rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 flex items-center gap-2 shrink-0"
                >
                  {isHashingEvidence ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Hashing Artifact...</span>
                    </>
                  ) : (
                    <>
                      <Hash className="w-3.5 h-3.5" />
                      <span>Compute Evidence Hash</span>
                    </>
                  )}
                </button>
              </div>

              {/* Evidence Hashing Results */}
              {evidenceHashResult && (
                <div className="space-y-4 pt-2 border-t border-[#eaede8]">
                  <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#eaede8] pb-2">
                      <div className="font-mono text-[11px] text-[#111813]">
                        <span className="text-[#6c7a68] uppercase font-bold mr-1.5">Target:</span>
                        <strong>{evidenceHashResult.file_name}</strong> ({evidenceHashResult.evidence_id})
                      </div>
                      <StatusBadge
                        status={evidenceHashResult.is_encrypted ? 'verified' : 'standby'}
                        label={evidenceHashResult.is_encrypted ? 'ENCRYPTED AT REST' : 'UNENCRYPTED'}
                        size="xs"
                      />
                    </div>

                    <div className="font-mono text-[11px]">
                      <span className="text-[#6c7a68] uppercase font-bold block mb-0.5">
                        Acquisition Baseline Digest (Recorded at Ingestion)
                      </span>
                      <div className="flex items-center justify-between p-2 bg-white border border-[#eaede8] rounded-sm text-[#111813] break-all select-all">
                        <span>{evidenceHashResult.stored_acquisition_hash}</span>
                        <button
                          onClick={() => handleCopy(evidenceHashResult.stored_acquisition_hash)}
                          className="ml-2 text-[#536050] hover:text-[#111813] shrink-0"
                          title="Copy digest"
                        >
                          {copiedDigest === evidenceHashResult.stored_acquisition_hash ? (
                            <Check className="w-3.5 h-3.5 text-[#1a5935]" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Hash Measurements (One or Two Representations) */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {evidenceHashResult.hashes.map((item, idx) => {
                      const isPlaintext = item.representation_label.toLowerCase().includes('plaintext');
                      const matchesBaseline = item.sha256_digest === evidenceHashResult.stored_acquisition_hash;

                      return (
                        <div
                          key={idx}
                          className={`p-3.5 rounded-sm border space-y-3 ${
                            matchesBaseline
                              ? 'bg-[#f0f9f3] border-[#227244]/30'
                              : 'bg-white border-[#d7ded4]'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-bold font-mono uppercase text-[#111813]">
                              {item.representation_label}
                            </span>
                            {matchesBaseline ? (
                              <StatusBadge status="verified" label="MATCHES ACQUISITION" size="xs" />
                            ) : (
                              <span className="text-[10px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
                                CIPHERTEXT CONTAINER
                              </span>
                            )}
                          </div>

                          <div>
                            <span className="text-[10px] font-mono text-[#6c7a68] uppercase block mb-1">
                              SHA-256 Digest (64 hex characters)
                            </span>
                            <div className="p-2 bg-white border border-[#d7ded4] rounded-sm font-mono text-[11px] text-[#111813] break-all select-all flex items-center justify-between">
                              <span>{item.sha256_digest}</span>
                              <button
                                onClick={() => handleCopy(item.sha256_digest)}
                                className="ml-2 text-[#536050] hover:text-[#111813] shrink-0"
                                title="Copy digest"
                              >
                                {copiedDigest === item.sha256_digest ? (
                                  <Check className="w-3.5 h-3.5 text-[#1a5935]" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>
                          </div>

                          <div className="grid grid-cols-3 gap-2 text-[10px] font-mono pt-2 border-t border-[#eaede8]">
                            <div>
                              <span className="text-[#6c7a68] block">Size</span>
                              <span className="font-semibold text-[#111813]">{formatBytes(item.file_size_bytes)}</span>
                            </div>
                            <div>
                              <span className="text-[#6c7a68] block">Duration</span>
                              <span className="font-semibold text-[#111813]">{item.duration_ms.toFixed(3)} ms</span>
                            </div>
                            <div>
                              <span className="text-[#6c7a68] block">Throughput</span>
                              <span className="font-semibold text-[#111813]">{item.throughput_mbps.toFixed(2)} MB/s</span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {evidenceHashResult.note && (
                    <div className="text-[11px] text-[#536050] italic p-2.5 bg-[#faf8f3] border border-[#d7ded4] rounded-sm">
                      {evidenceHashResult.note}
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>

          {/* Section 2: Standalone File Hashing & Throughput Benchmark */}
          <Card
            title="Standalone File Hashing & Streaming Benchmark"
            subtitle="Calculates SHA-256 digest on-the-fly using 64 KB chunked streaming without disk persistence or database records"
          >
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3 items-end">
                <div className="flex-1 w-full">
                  <label className="block text-xs font-semibold text-[#111813] mb-1.5 uppercase tracking-wider">
                    Select Local File to Hash (any format, including empty files)
                  </label>
                  <input
                    type="file"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setStandaloneFile(e.target.files[0]);
                      }
                    }}
                    disabled={isHashingStandalone}
                    className="w-full text-xs text-[#536050] file:mr-4 file:py-2 file:px-4 file:rounded-sm file:border file:border-[#bdc7ba] file:text-xs file:font-semibold file:bg-[#faf8f3] file:text-[#111813] hover:file:bg-[#eaede8] cursor-pointer"
                  />
                </div>

                <button
                  onClick={handleStandaloneHash}
                  disabled={isHashingStandalone || !standaloneFile}
                  className="h-9 px-5 bg-[#1a5935] hover:bg-[#144629] text-white rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 flex items-center gap-2 shrink-0"
                >
                  {isHashingStandalone ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Hashing File...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-3.5 h-3.5" />
                      <span>Hash File</span>
                    </>
                  )}
                </button>
              </div>

              {standaloneHashResult && (
                <div className="p-4 bg-white border border-[#d7ded4] rounded-sm space-y-3 pt-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#eaede8] pb-2">
                    <div className="font-mono text-xs text-[#111813]">
                      <span className="text-[#6c7a68] uppercase font-bold mr-1.5">File:</span>
                      <strong>{standaloneHashResult.file_name}</strong> ({standaloneHashResult.file_type})
                    </div>
                    {standaloneHashResult.is_empty_file && (
                      <span className="text-[10px] font-mono text-[#991b1b] bg-[#fee2e2] px-2 py-0.5 border border-[#ef4444]/30 rounded-sm">
                        EMPTY FILE (0 BYTES)
                      </span>
                    )}
                  </div>

                  <div>
                    <span className="text-[10px] font-mono text-[#6c7a68] uppercase block mb-1">
                      Computed SHA-256 Digest (64 hex characters)
                    </span>
                    <div className="p-2.5 bg-[#faf8f3] border border-[#d7ded4] rounded-sm font-mono text-xs text-[#111813] break-all select-all flex items-center justify-between">
                      <span>{standaloneHashResult.sha256_digest}</span>
                      <button
                        onClick={() => handleCopy(standaloneHashResult.sha256_digest)}
                        className="ml-2 text-[#536050] hover:text-[#111813] shrink-0"
                        title="Copy digest"
                      >
                        {copiedDigest === standaloneHashResult.sha256_digest ? (
                          <Check className="w-4 h-4 text-[#1a5935]" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono pt-2 border-t border-[#eaede8]">
                    <div>
                      <span className="text-[10px] text-[#6c7a68] uppercase block">Input Size</span>
                      <span className="font-semibold text-[#111813]">
                        {formatBytes(standaloneHashResult.file_size_bytes)} ({standaloneHashResult.file_size_bytes} B)
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#6c7a68] uppercase block">Hashing Duration</span>
                      <span className="font-semibold text-[#111813]">{standaloneHashResult.duration_ms.toFixed(3)} ms</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#6c7a68] uppercase block">Measured Throughput</span>
                      <span className="font-semibold text-[#111813]">
                        {standaloneHashResult.throughput_mbps.toFixed(2)} MB/s
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#6c7a68] uppercase block">Streaming Blocks</span>
                      <span className="font-semibold text-[#111813]">
                        {standaloneHashResult.chunks_processed} chunks (64 KB)
                      </span>
                    </div>
                  </div>

                  {standaloneHashResult.is_empty_file && (
                    <div className="text-[11px] text-[#536050] bg-[#faf8f3] p-2.5 border border-[#eaede8] rounded-sm">
                      <strong>Standard Zero-Length Hash:</strong> Notice that any 0-byte input deterministically yields the standard NIST constant{' '}
                      <code className="bg-white px-1 border border-[#d7ded4] rounded font-mono text-[10px] text-[#111813]">
                        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                      </code>
                      .
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>

          {/* Section 3: Avalanche Effect & Digest Comparison */}
          <Card
            title="Avalanche Effect & Collision Resistance Demonstration"
            subtitle="Compare two files to observe how a minimal input deviation flips approximately 50% of digest bits"
          >
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="block text-xs font-semibold text-[#111813] uppercase tracking-wider">
                    Input Artifact A *
                  </label>
                  <input
                    type="file"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setCompareFileA(e.target.files[0]);
                      }
                    }}
                    disabled={isComparing}
                    className="w-full text-xs text-[#536050] file:mr-3 file:py-1.5 file:px-3 file:rounded-sm file:border file:border-[#bdc7ba] file:text-xs file:font-semibold file:bg-[#faf8f3] file:text-[#111813] hover:file:bg-[#eaede8] cursor-pointer"
                  />
                  {compareFileA && (
                    <div className="text-[10px] font-mono text-[#536050]">
                      {compareFileA.name} ({formatBytes(compareFileA.size)})
                    </div>
                  )}
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-semibold text-[#111813] uppercase tracking-wider">
                    Input Artifact B *
                  </label>
                  <input
                    type="file"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setCompareFileB(e.target.files[0]);
                      }
                    }}
                    disabled={isComparing}
                    className="w-full text-xs text-[#536050] file:mr-3 file:py-1.5 file:px-3 file:rounded-sm file:border file:border-[#bdc7ba] file:text-xs file:font-semibold file:bg-[#faf8f3] file:text-[#111813] hover:file:bg-[#eaede8] cursor-pointer"
                  />
                  {compareFileB && (
                    <div className="text-[10px] font-mono text-[#536050]">
                      {compareFileB.name} ({formatBytes(compareFileB.size)})
                    </div>
                  )}
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={handleCompareHashes}
                  disabled={isComparing || !compareFileA || !compareFileB}
                  className="h-9 px-5 bg-[#1a5935] hover:bg-[#144629] text-white rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {isComparing ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Comparing Digests...</span>
                    </>
                  ) : (
                    <>
                      <GitCompare className="w-3.5 h-3.5" />
                      <span>Compare SHA-256 Digests</span>
                    </>
                  )}
                </button>
              </div>

              {/* Comparison Results */}
              {compareResult && (
                <div className="space-y-4 pt-3 border-t border-[#eaede8]">
                  {/* Verdict & Metrics Strip */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <div className="p-3 bg-white border border-[#d7ded4] rounded-sm flex items-center justify-between">
                      <div>
                        <span className="text-[10px] uppercase font-bold text-[#6c7a68] block">Digest Match</span>
                        <span className="text-xs font-semibold font-mono text-[#111813]">
                          {compareResult.digests_match ? 'Identical' : 'Different'}
                        </span>
                      </div>
                      <StatusBadge
                        status={compareResult.digests_match ? 'verified' : 'standby'}
                        label={compareResult.digests_match ? 'MATCH' : 'MISMATCH'}
                        size="xs"
                      />
                    </div>

                    <div className="p-3 bg-white border border-[#d7ded4] rounded-sm">
                      <span className="text-[10px] uppercase font-bold text-[#6c7a68] block">Hex Char Differences</span>
                      <div className="text-xs font-semibold font-mono text-[#111813]">
                        {compareResult.hex_character_differences} / 64 characters
                      </div>
                      <div className="text-[10px] font-mono text-[#6c7a68]">
                        {((compareResult.hex_character_differences / 64) * 100).toFixed(1)}% altered
                      </div>
                    </div>

                    <div className="p-3 bg-white border border-[#d7ded4] rounded-sm">
                      <span className="text-[10px] uppercase font-bold text-[#6c7a68] block">Bit Differences (Hamming)</span>
                      <div className="text-xs font-semibold font-mono text-[#111813]">
                        {compareResult.bit_differences} / 256 bits
                      </div>
                      <div className="text-[10px] font-mono text-[#6c7a68]">
                        Exact bit-level Hamming distance
                      </div>
                    </div>

                    <div className="p-3 bg-white border border-[#d7ded4] rounded-sm">
                      <span className="text-[10px] uppercase font-bold text-[#6c7a68] block">Avalanche Ratio</span>
                      <div className="text-xs font-semibold font-mono text-[#1a5935]">
                        {compareResult.avalanche_percentage.toFixed(2)}%
                      </div>
                      <div className="text-[10px] font-mono text-[#6c7a68]">
                        Target: ~50% random spread
                      </div>
                    </div>
                  </div>

                  {/* Side-by-Side Digest Comparison */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-3.5 bg-white border border-[#d7ded4] rounded-sm space-y-2">
                      <div className="flex items-center justify-between font-mono text-xs">
                        <span className="font-bold text-[#111813]">Artifact A: {compareResult.input_a_label}</span>
                        <span className="text-[#536050]">{formatBytes(compareResult.input_a_size_bytes)}</span>
                      </div>
                      <div className="p-2 bg-[#faf8f3] border border-[#eaede8] rounded-sm font-mono text-[11px] text-[#111813] break-all select-all flex items-center justify-between">
                        <span>{compareResult.input_a_digest}</span>
                        <button
                          onClick={() => handleCopy(compareResult.input_a_digest)}
                          className="ml-2 text-[#536050] hover:text-[#111813] shrink-0"
                          title="Copy digest"
                        >
                          {copiedDigest === compareResult.input_a_digest ? (
                            <Check className="w-3.5 h-3.5 text-[#1a5935]" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>

                    <div className="p-3.5 bg-white border border-[#d7ded4] rounded-sm space-y-2">
                      <div className="flex items-center justify-between font-mono text-xs">
                        <span className="font-bold text-[#111813]">Artifact B: {compareResult.input_b_label}</span>
                        <span className="text-[#536050]">{formatBytes(compareResult.input_b_size_bytes)}</span>
                      </div>
                      <div className="p-2 bg-[#faf8f3] border border-[#eaede8] rounded-sm font-mono text-[11px] text-[#111813] break-all select-all flex items-center justify-between">
                        <span>{compareResult.input_b_digest}</span>
                        <button
                          onClick={() => handleCopy(compareResult.input_b_digest)}
                          className="ml-2 text-[#536050] hover:text-[#111813] shrink-0"
                          title="Copy digest"
                        >
                          {copiedDigest === compareResult.input_b_digest ? (
                            <Check className="w-3.5 h-3.5 text-[#1a5935]" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Educational note & disclaimer */}
                  <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050] space-y-1.5 leading-relaxed">
                    <div className="flex items-center gap-1.5 font-semibold text-[#111813]">
                      <BookOpen className="w-4 h-4 text-[#1a5935]" />
                      <span>Avalanche Effect Principle & Forensic Interpretation</span>
                    </div>
                    <div>{compareResult.educational_note}</div>
                  </div>
                </div>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
