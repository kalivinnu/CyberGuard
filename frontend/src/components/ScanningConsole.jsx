import React, { useEffect, useState } from 'react';
import '../styles/Scanner.css';

const LOG_MESSAGES = [
  "Resolving DNS records...",
  "Establishing secure connection to target...",
  "Analyzing SSL/TLS certificates...",
  "Querying global threat intelligence databases...",
  "Checking for known phishing vectors...",
  "Scanning domain age and reputation history...",
  "Inspecting HTTP headers for security policies...",
  "Searching for malware signatures...",
  "Correlating data & computing final risk score...",
  "Analysis complete. Generating dashboard..."
];

const ScanningConsole = ({ targetUrl }) => {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    let currentIndex = 0;
    
    // Add first log immediately
    setLogs([{ time: getTime(), msg: `Initiated scan for: ${targetUrl}`, type: 'normal' }]);

    const interval = setInterval(() => {
      if (currentIndex < LOG_MESSAGES.length) {
        setLogs(prev => [...prev, {
          time: getTime(),
          msg: LOG_MESSAGES[currentIndex],
          type: currentIndex === LOG_MESSAGES.length - 1 ? 'success' : 'normal'
        }]);
        currentIndex++;
      } else {
        clearInterval(interval);
      }
    }, 400); // Add a new log every 400ms

    return () => clearInterval(interval);
  }, [targetUrl]);

  return (
    <div className="console-container fade-in">
      <div className="console-window">
        <div className="console-header">
          <span className="console-title">TARGET ANALYSIS TERMINAL // V.1.0</span>
          <div className="status-indicator">
            <span style={{color: 'var(--accent-blue)', fontSize: '0.8rem'}}>SCANNING IN PROGRESS...</span>
          </div>
        </div>
        
        <div className="console-body">
          {logs.map((log, i) => (
            <div key={i} className="log-entry">
              <span className="log-time">[{log.time}]</span>
              <span className={`log-content ${log.type}`}>
                {"> "} {log.msg}
              </span>
            </div>
          ))}
          <div className="log-entry">
             <span className="cursor-blink"></span>
          </div>
        </div>
      </div>
    </div>
  );
};

function getTime() {
  const now = new Date();
  return `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}.${Math.floor(now.getMilliseconds()/10).toString().padStart(2,'0')}`;
}

export default ScanningConsole;
