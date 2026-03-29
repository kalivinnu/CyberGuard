import React, { useState } from 'react';
import { Target } from 'lucide-react';

const ScannerInput = ({ onScan }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    
    // Basic validation
    if (!url) {
      setError('Please enter a URL.');
      return;
    }
    
    // Add protocol if missing
    let parsedUrl = url;
    if (!/^https?:\/\//i.test(url)) {
      parsedUrl = 'http://' + url;
    }

    try {
      new URL(parsedUrl); // throws if invalid
      onScan(parsedUrl);
    } catch (err) {
      setError('Please enter a valid URL.');
    }
  };

  return (
    <div className="scanner-input-container fade-in">
      <div className="scanner-header">
        <h2>Enter target URL below</h2>
        <p>Initialize deep-scan protocols to analyze domain infrastructure, SSL security, and potential phishing vectors.</p>
      </div>

      <form onSubmit={handleSubmit} className="scanner-form">
        <div className="input-wrapper">
          <Target className="target-icon" size={24} />
          <input 
            type="text" 
            placeholder="e.g., https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="neon-input"
            autoComplete="off"
          />
          <button type="submit" className="scan-btn">
             INITIATE SCAN
          </button>
        </div>
        {error && <div className="error-text fade-in">{error}</div>}
      </form>
    </div>
  );
};

export default ScannerInput;
