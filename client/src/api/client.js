/**
 * ForenSight API Client
 * Connects to the FastAPI Investigation Server REST API
 */

// Use VITE_API_URL if explicitly set (e.g. for standalone static production deployments),
// otherwise default to '' so all browser requests route through the Vite /api proxy seamlessly.
const BASE_URL = import.meta.env.VITE_API_URL || '';

export async function fetchHealth() {
  const response = await fetch(`${BASE_URL}/api/health`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`Health check returned HTTP ${response.status}`);
  }
  return await response.json();
}

export async function fetchSystemStats() {
  const response = await fetch(`${BASE_URL}/api/system/stats`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`System stats returned HTTP ${response.status}`);
  }
  return await response.json();
}

export async function fetchServerPublicKey() {
  const response = await fetch(`${BASE_URL}/api/system/public-keys`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch server public keys: HTTP ${response.status}`);
  }
  return await response.json();
}

export async function fetchEvidence() {
  const response = await fetch(`${BASE_URL}/api/evidence`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch evidence: HTTP ${response.status}`);
  }
  return await response.json();
}

export async function uploadEvidence(formData) {
  const response = await fetch(`${BASE_URL}/api/evidence`, {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Upload failed: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function verifyEvidence(evidenceId) {
  const response = await fetch(`${BASE_URL}/api/evidence/${encodeURIComponent(evidenceId)}/verify`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Integrity verification failed: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export function getEvidenceDownloadUrl(evidenceId) {
  return `${BASE_URL}/api/evidence/${encodeURIComponent(evidenceId)}/download`;
}

export async function triggerAnalysis(evidenceId) {
  const response = await fetch(`${BASE_URL}/api/analysis/${encodeURIComponent(evidenceId)}`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Analysis failed: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function fetchParserBackend() {
  const response = await fetch(`${BASE_URL}/api/analysis/backend`, {
    headers: { 'Accept': 'application/json' },
  });
  if (!response.ok) throw new Error(`Parser backend query returned HTTP ${response.status}`);
  return await response.json();
}

export async function fetchFindings(evidenceId = null) {
  const url = evidenceId
    ? `${BASE_URL}/api/analysis/findings/${encodeURIComponent(evidenceId)}`
    : `${BASE_URL}/api/analysis/findings`;
  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Failed to fetch findings: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function fetchCustodyChain(evidenceId) {
  const response = await fetch(`${BASE_URL}/api/custody/${encodeURIComponent(evidenceId)}`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Failed to fetch custody chain: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function fetchTimeline(evidenceId = null) {
  const url = evidenceId
    ? `${BASE_URL}/api/timeline/${encodeURIComponent(evidenceId)}`
    : `${BASE_URL}/api/timeline`;
  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Failed to fetch timeline: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function fetchBenchmarks(filters = {}) {
  const params = new URLSearchParams();
  if (filters.benchmark_name) params.append('benchmark_name', filters.benchmark_name);
  if (filters.evidence_id) params.append('evidence_id', filters.evidence_id);

  const query = params.toString() ? `?${params.toString()}` : '';
  const response = await fetch(`${BASE_URL}/api/benchmarks${query}`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Failed to fetch benchmarks: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function fetchBenchmarksSummary() {
  const response = await fetch(`${BASE_URL}/api/benchmarks/summary`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Failed to fetch benchmarks summary: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function fetchReports(filters = {}) {
  const params = new URLSearchParams();
  if (filters.evidence_id) params.append('evidence_id', filters.evidence_id);
  if (filters.report_scope) params.append('report_scope', filters.report_scope);

  const query = params.toString() ? `?${params.toString()}` : '';
  const response = await fetch(`${BASE_URL}/api/reports${query}`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (response.status === 404) {
    return [];
  }
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Failed to fetch reports: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function fetchReport(reportId) {
  const response = await fetch(`${BASE_URL}/api/reports/${encodeURIComponent(reportId)}`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Failed to fetch report: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export async function generateReport(payload) {
  const response = await fetch(`${BASE_URL}/api/reports`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const message = errorData?.detail || `Report generation failed: HTTP ${response.status}`;
    throw new Error(message);
  }
  return await response.json();
}

export function getReportDownloadUrl(reportId) {
  return `${BASE_URL}/api/reports/${encodeURIComponent(reportId)}/download`;
}

/**
 * Downloads a PDF report as a binary Blob, then triggers a browser save-as dialog.
 * Throws if the server does not return a valid application/pdf response.
 */
export async function downloadReport(reportId) {
  const url = `${BASE_URL}/api/reports/${encodeURIComponent(reportId)}/download`;
  const response = await fetch(url, {
    headers: { Accept: 'application/pdf' },
  });

  if (!response.ok) {
    let detailMsg = `HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData?.detail) {
        detailMsg = `${errorData.detail} (HTTP ${response.status})`;
      }
    } catch {
      const text = await response.text().catch(() => '');
      if (text) detailMsg += ` — ${text.slice(0, 100)}`;
    }
    throw new Error(`PDF download failed: ${detailMsg}`);
  }

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/pdf')) {
    throw new Error(
      `Server returned unexpected content type "${contentType}". Expected application/pdf.`,
    );
  }

  const blob = await response.blob();
  if (blob.size === 0) {
    throw new Error('Downloaded PDF file is empty (0 bytes).');
  }

  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = `${reportId}.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000);
}
