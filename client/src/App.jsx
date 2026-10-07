import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { DashboardPage } from './pages/DashboardPage';
import { EvidencePage } from './pages/EvidencePage';
import { AnalysisPage } from './pages/AnalysisPage';
import { TimelinePage } from './pages/TimelinePage';
import { CustodyPage } from './pages/CustodyPage';
import { PerformancePage } from './pages/PerformancePage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { fetchHealth, fetchSystemStats } from './api/client';

const TAB_TITLES = {
  dashboard: { title: 'Investigation Console', subtitle: 'Real-time telemetry and database status' },
  evidence: { title: 'Evidence Repository', subtitle: 'Forensic artifacts storage and integrity registry' },
  analysis: { title: 'Forensic Analysis', subtitle: 'Packet analysis and security anomaly detection' },
  timeline: { title: 'Investigation Timeline', subtitle: 'Chronological security event audit logs' },
  custody: { title: 'Chain of Custody', subtitle: 'Tamper-evident evidence handling log' },
  performance: { title: 'Performance Benchmark', subtitle: 'Throughput and latency benchmark measurements' },
  reports: { title: 'Case Reports', subtitle: 'Court-admissible forensic summaries and case reports' },
  settings: { title: 'System Settings', subtitle: 'Investigation server and collector node configuration' },
};

export default function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [healthData, setHealthData] = useState(null);
  const [statsData, setStatsData] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  const loadSystemStatus = useCallback(async () => {
    setIsRefreshing(true);
    setError(null);
    try {
      const [health, stats] = await Promise.all([
        fetchHealth(),
        fetchSystemStats().catch(() => null), // Graceful fallback
      ]);
      setHealthData(health);
      setStatsData(stats);
      setLastChecked(new Date().toISOString());
    } catch (err) {
      setError(err.message || 'Failed to reach FastAPI backend');
      setHealthData(null);
      setStatsData(null);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadSystemStatus();
    // Poll every 15 seconds to keep health indicators up-to-date
    const interval = setInterval(loadSystemStatus, 15000);
    return () => clearInterval(interval);
  }, [loadSystemStatus]);

  const activeMeta = TAB_TITLES[currentTab] || TAB_TITLES.dashboard;

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#f4f1ea] text-[#111813]">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        isServerOnline={healthData?.status === 'ok'}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-[#f4f1ea]">
        {/* Top Header */}
        <Header
          title={activeMeta.title}
          subtitle={activeMeta.subtitle}
          healthData={healthData}
          isRefreshing={isRefreshing}
          onRefresh={loadSystemStatus}
          lastChecked={lastChecked}
        />

        {/* Scrollable Viewport */}
        <main className="flex-1 overflow-y-auto p-5 sm:p-6 bg-[#f4f1ea]">
          <div className="max-w-7xl mx-auto">
            {currentTab === 'dashboard' && (
              <DashboardPage
                healthData={healthData}
                statsData={statsData}
                error={error}
                isLoading={isRefreshing && !healthData}
              />
            )}
            {currentTab === 'evidence' && <EvidencePage onEvidenceUploaded={loadSystemStatus} />}
            {currentTab === 'analysis' && <AnalysisPage />}
            {currentTab === 'timeline' && <TimelinePage />}
            {currentTab === 'custody' && <CustodyPage />}
            {currentTab === 'performance' && <PerformancePage />}
            {currentTab === 'reports' && <ReportsPage />}
            {currentTab === 'settings' && <SettingsPage healthData={healthData} />}
          </div>
        </main>
      </div>
    </div>
  );
}
