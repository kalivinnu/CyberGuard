import { useState } from 'react'
import ScannerInput from './components/ScannerInput'
import ScanningConsole from './components/ScanningConsole'
import Dashboard from './components/Dashboard'

function App() {
  const [phase, setPhase] = useState('input'); // 'input', 'scanning', 'dashboard'
  const [targetUrl, setTargetUrl] = useState('');
  const [analysisData, setAnalysisData] = useState(null);

  const startScan = async (url) => {
    setTargetUrl(url);
    setPhase('scanning');

    try {
      // Fetch analysis data from our new backend API
      const response = await fetch('http://localhost:5000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      
      if (!response.ok) {
        throw new Error('Backend analysis failed');
      }
      
      const data = await response.json();

      // Ensure the cool scanning animation plays entirely (minimum 4.5 seconds)
      setTimeout(() => {
        setAnalysisData(data);
        setPhase('dashboard');
      }, 4500);
      
    } catch (err) {
      console.error(err);
      alert('Error connecting to scanning server. Is the backend running?');
      setPhase('input');
    }
  };

  const resetScanner = () => {
    setPhase('input');
    setTargetUrl('');
    setAnalysisData(null);
  }

  return (
    <div className="app-container">
      <header className="app-header fade-in">
        <div className="logo-container" onClick={resetScanner} style={{cursor: 'pointer'}}>
          <div className="logo-icon"></div>
          <h1>CyberGuard</h1>
        </div>
      </header>
      
      <main className="main-content">
        {phase === 'input' && <ScannerInput onScan={startScan} />}
        {phase === 'scanning' && <ScanningConsole targetUrl={targetUrl} />}
        {phase === 'dashboard' && <Dashboard data={analysisData} url={targetUrl} onReset={resetScanner} />}
      </main>

      <style>{`
        .app-container {
          min-height: 100vh;
          display: flex;
          flex-direction: column;
        }
        .app-header {
          padding: 2rem 5%;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .logo-container {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .logo-icon {
          width: 32px;
          height: 32px;
          border-radius: 8px;
          background: linear-gradient(135deg, var(--border-neon-green) 0%, var(--accent-blue) 100%);
          box-shadow: 0 0 15px rgba(0, 255, 102, 0.4);
          position: relative;
        }
        .logo-icon::after {
          content: '';
          position: absolute;
          inset: 4px;
          background: var(--bg-dark);
          border-radius: 4px;
        }
        .app-header h1 {
          font-family: var(--font-cyber);
          font-size: 1.5rem;
          font-weight: 700;
          letter-spacing: 2px;
          text-transform: uppercase;
          background: linear-gradient(to right, #fff, #a0aab5);
          -webkit-background-clip: text;
          color: transparent;
        }
        .main-content {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 2rem 5%;
          position: relative;
        }
      `}</style>
    </div>
  )
}

export default App
