/**
 * ForenSight API Client
 * Connects to the FastAPI Investigation Server REST API
 */

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



