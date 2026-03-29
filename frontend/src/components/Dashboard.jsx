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
          <h2>Analysis Complete</h2>
          <p>Target: <strong>{url}</strong></p>
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
                <span className={`item-value ${data.domain.reputation === 'Good' ? 'secure' : 'warning'}`}>
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
              <div className="metric-item">
                <span className="item-label">IP Address</span>
                <span className="item-value">{data.serverInfo.ip}</span>
              </div>
              <div className="metric-item" style={{ marginTop: '4px', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.05)'}}>
                <span className="item-label">Status Code</span>
                <span className={`item-value ${data.serverInfo.statusCode === 200 ? 'secure' : data.serverInfo.statusCode >= 400 ? 'critical' : 'warning'}`}>
                  HTTP {data.serverInfo.statusCode}
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
                  {threat.detected ? (
                    <AlertTriangle size={18} color="var(--border-neon-red)" />
                  ) : (
                    <CheckCircle size={18} color="var(--border-neon-green)" />
                  )}
                  <span style={{ fontSize: '0.9rem', color: threat.detected ? '#ff3333' : 'var(--text-secondary)'}}>
                    {threat.name}
                  </span>
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
