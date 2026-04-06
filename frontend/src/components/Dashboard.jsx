import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert, Globe, Server, Lock, AlertTriangle, CheckCircle, XCircle, Cpu, Zap } from 'lucide-react';
import '../styles/Dashboard.css';

const Dashboard = ({ data, url, onReset }) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Animate score from 0 to target over 1s
    let current = 0;
    const interval = setInterval(() => {
      current += 1;
      if (current >= data.score) {
        setAnimatedScore(data.score);
        clearInterval(interval);
      } else {
        setAnimatedScore(current);
      }
    }, 10);
    return () => clearInterval(interval);
  }, [data.score]);

  // Determine colors based on score
  const getColor = (s) => {
    if (s >= 80) return '#00ff66'; // Safe (Green)
    if (s >= 50) return '#ffaa00'; // Warning (Yellow)
    return '#ff3333'; // Critical (Red)
  };

  const getThreatBadgeBg = (t) => {
    if (t === 'Safe') return 'rgba(0, 255, 102, 0.15)';
    if (t === 'Warning') return 'rgba(255, 170, 0, 0.15)';
    return 'rgba(255, 51, 51, 0.15)';
  };

  const color = getColor(data.score);
  const strokeDasharray = `${animatedScore}, 100`;

  return (
    <div className="dashboard-container fade-in">
      <div className="dashboard-header">
        <div className="target-info">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2>Analysis Complete</h2>
            <span style={{ 
              fontSize: '0.65rem', 
              background: 'linear-gradient(90deg, #00f0ff, #aa3bff)', 
              color: 'white', 
              padding: '2px 8px', 
              borderRadius: '10px', 
              fontWeight: '800',
              textTransform: 'uppercase',
              letterSpacing: '1px'
            }}>PRO ACTIVE</span>
          </div>
          <p>Target: <strong>{url}</strong></p>
          {data.phishingIndicators?.finalUrl && data.phishingIndicators.finalUrl !== url && (
            <p style={{ fontSize: '0.75rem', marginTop: '2px', color: 'var(--accent-blue)' }}>
              ↳ Ends at: <strong>{data.phishingIndicators.finalUrl}</strong>
            </p>
          )}
        </div>
        <button onClick={onReset} className="close-btn">NEW SCAN</button>
      </div>

      <div className="dashboard-grid">
        {/* Score Gauge */}
        <div className="glass-panel score-card">
          <h3>Trust Score</h3>
          <svg viewBox="0 0 36 36" className="circular-chart">
            <path className="circle-bg"
              d="M18 2.0845
                a 15.9155 15.9155 0 0 1 0 31.831
                a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path className="circle"
              strokeDasharray={strokeDasharray}
              style={{ stroke: color }}
              d="M18 2.0845
                a 15.9155 15.9155 0 0 1 0 31.831
                a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <text x="18" y="20.35" className="percentage" style={{ fill: color }}>{animatedScore}</text>
          </svg>
          <div 
            className="threat-badge" 
            style={{ backgroundColor: getThreatBadgeBg(data.threatLevel), color: color, border: `1px solid ${color}` }}
          >
            {data.threatLevel}
          </div>
        </div>

        {/* Breakdown Metrics */}
        <div className="metrics-grid">
          {/* SSL Metric */}
          <div className="glass-panel metric-card">
            <div className="metric-header">
              <Lock className="metric-icon" size={20} />
              SSL & Encryption
            </div>
            <div className="metric-content">
              <div className="metric-item">
                <span className="item-label">Status</span>
                <span className={`item-value ${data.ssl.isSecure ? 'secure' : 'critical'}`}>
                  {data.ssl.status}
                </span>
              </div>
              <div className="metric-item">
                <span className="item-label">Issuer</span>
                <span className="item-value">{data.ssl.issuer}</span>
              </div>
            </div>
          </div>

          {/* Domain Info Metric */}
          <div className="glass-panel metric-card">
            <div className="metric-header">
              <Globe className="metric-icon" size={20} />
              Domain Info
            </div>
            <div className="metric-content">
              <div className="metric-item">
                <span className="item-label">Age</span>
                <span className="item-value">{data.domain.age}</span>
              </div>
              <div className="metric-item">
                <span className="item-label">Reputation</span>
                <span className={`item-value ${data.domain.reputation === 'Good' ? 'secure' : data.domain.reputation === 'Deceptive' ? 'critical' : 'warning'}`}>
                  {data.domain.reputation}
                </span>
              </div>
            </div>
          </div>

          {/* Server Metric */}
          <div className="glass-panel metric-card">
            <div className="metric-header">
              <Server className="metric-icon" size={20} />
              Server Fingerprint
            </div>
            <div className="metric-content">
              <div className="metric-item">
                <span className="item-label">Location</span>
                <span className="item-value">{data.serverInfo.location}</span>
              </div>
              <div className="metric-item" style={{ marginTop: '4px', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.05)'}}>
                <span className="item-label">Status Code</span>
                <span className={`item-value ${data.serverInfo.statusCode === 200 ? 'secure' : data.serverInfo.statusCode >= 400 ? 'critical' : 'warning'}`}>
                  HTTP {data.serverInfo.statusCode}
                </span>
              </div>
            </div>
          </div>

          {/* Global Intelligence Metric */}
          <div className="glass-panel metric-card intel-card">
            <div className="metric-header" style={{ color: 'var(--accent-blue)' }}>
              <Zap className="metric-icon" size={20} />
              Global Intelligence
            </div>
            <div className="metric-content">
              <div className="metric-item">
                <span className="item-label">Google Safe Browsing</span>
                <span className={`item-value ${data.phishingIndicators?.intel?.googleFlagged === true ? 'critical' : data.phishingIndicators?.intel?.googleFlagged === null ? 'warning' : 'secure'}`}>
                  {data.phishingIndicators?.intel?.googleFlagged === true ? 'BLACKLISTED' : data.phishingIndicators?.intel?.googleFlagged === null ? 'Inactive' : 'Clean'}
                </span>
              </div>
              <div className="metric-item">
                <span className="item-label">VirusTotal Consensus</span>
                <span className={`item-value ${data.phishingIndicators?.intel?.vtStatus?.malicious > 0 ? 'critical' : data.phishingIndicators?.intel?.vtStatus === null ? 'warning' : 'secure'}`}>
                  {data.phishingIndicators?.intel?.vtStatus ? `${data.phishingIndicators.intel.vtStatus.malicious} Engines Flagged` : 'Inactive'}
                </span>
              </div>
            </div>
          </div>

          {/* Forensic Diagnostics Metric */}
          <div className="glass-panel metric-card forensic-card">
            <div className="metric-header" style={{ color: 'var(--accent-crimson)' }}>
              <ShieldAlert className="metric-icon" size={20} />
              Forensic Diagnostics
            </div>
            <div className="metric-content">
              <div className="metric-item">
                <span className="item-label">Domain Entropy</span>
                <span className={`item-value ${data.phishingIndicators?.entropy > 4.2 ? 'critical' : 'secure'}`}>
                  {data.phishingIndicators?.entropy ? data.phishingIndicators.entropy.toFixed(2) : '0.00'} / 5.0
                </span>
              </div>
              <div className="metric-item">
                <span className="item-label">Identity Match</span>
                <span className={`item-value ${data.phishingIndicators?.isSslMismatch ? 'critical' : 'secure'}`}>
                  {data.phishingIndicators?.isSslMismatch ? 'Mismatch Found' : 'Verified Issuer'}
                </span>
              </div>
            </div>
          </div>

          {/* AI Neural Analysis Metric */}
          <div className="glass-panel metric-card ai-card">
            <div className="metric-header">
              <Cpu className="metric-icon ai-icon" size={20} />
              Neural AI Verdict
            </div>
            <div className="metric-content">
              <div className="ai-verdict-container">
                <span className={`ai-verdict-tag ${data.aiAnalysis.verdict.toLowerCase()}`}>
                  {data.aiAnalysis.verdict}
                </span>
              </div>
              <p className="ai-insight-text">
                {data.aiAnalysis.insight}
              </p>
            </div>
          </div>

          {/* Threats Metric List */}
          <div className="glass-panel metric-card threats-list">
            <div className="metric-header" style={{marginBottom: 0}}>
              {data.score < 50 ? <ShieldAlert className="metric-icon" style={{color: 'var(--border-neon-red)'}} size={20} /> : <ShieldCheck className="metric-icon" size={20} />}
              Security Signatures
            </div>
            <div className="threats-grid">
              {data.threats.map((threat, idx) => (
                <div key={idx} className={`threat-item ${threat.detected ? 'detected' : ''}`}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {threat.detected ? (
                      <AlertTriangle size={18} color="var(--border-neon-red)" />
                    ) : (
                      <CheckCircle size={18} color="var(--border-neon-green)" />
                    )}
                    <span style={{ fontSize: '0.9rem', fontWeight: '600', color: threat.detected ? '#ff3333' : 'var(--text-secondary)'}}>
                      {threat.name}
                    </span>
                  </div>
                  {threat.explanation && (
                    <p style={{ 
                      fontSize: '0.75rem', 
                      color: 'var(--text-secondary)', 
                      marginTop: '4px', 
                      paddingLeft: '28px',
                      lineHeight: '1.4',
                      opacity: 0.8
                    }}>
                      {threat.explanation}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
