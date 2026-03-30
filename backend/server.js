const express = require('express');
const cors = require('cors');
const https = require('https');
const dns = require('dns').promises;
const { URL } = require('url');
const whois = require('whois');
const axios = require('axios');
const { GoogleGenerativeAI } = require("@google/generative-ai");
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Gemini with v1 API for broader model compatibility
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY); 
// Note: We'll use the default or explicitly set v1 if needed in calls

app.use(cors());
app.use(express.json());

// Helper to extract the root domain for WHOIS
function getBaseDomain(hostname) {
  // If it's an IP, return as is
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname)) return hostname;
  
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  
  // Handle common multi-part TLDs (e.g., co.uk, com.br)
  const lastTwo = parts.slice(-2).join('.');
  const multiPartTLDs = ['co.uk', 'com.br', 'org.uk', 'net.in', 'gov.in'];
  
  if (multiPartTLDs.includes(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join('.');
  }
  
  return parts.slice(-2).join('.');
}

// Promisify WHOIS lookup
function lookupWhois(domain) {
  return new Promise((resolve) => {
    whois.lookup(domain, (err, data) => {
      if (err) return resolve(null);
      resolve(data);
    });
  });
}

function parseDomainAge(whoisData) {
  if (!whoisData) return { ageDays: 0, text: 'Unknown' };
  
  // Try to find common creation date fields
  const match = whoisData.match(/(?:Creation Date|Created On|Registration Date|Registered On):\s*(.+)/i);
  if (match && match[1]) {
    const creationDate = new Date(match[1].trim());
    if (!isNaN(creationDate.getTime())) {
      const diffMs = Date.now() - creationDate.getTime();
      const ageDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      
      let text = `${ageDays} Days`;
      if (ageDays > 365) {
        text = `${Math.floor(ageDays/365)} Years, ${Math.floor((ageDays%365)/30)} Months`;
      } else if (ageDays > 30) {
        text = `${Math.floor(ageDays/30)} Months`;
      }
      return { ageDays, text };
    }
  }
  return { ageDays: 0, text: 'Unknown' };
}

async function runAiAnalysis(data) {
  // Verified working models for this environment:
  const modelsToTry = ["gemini-3-flash-preview", "gemini-flash-latest"];
  let lastError = null;

  for (const modelName of modelsToTry) {
    try {
      if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'PLACEHOLDER') {
        throw new Error("GEMINI_API_KEY is missing.");
      }

      const model = genAI.getGenerativeModel({ model: modelName });
      
      const prompt = `
        As a Lead Cybersecurity Analyst, analyze the following website data for potential threats, phishing indicators, or technical vulnerabilities.
        
        URL: ${data.url}
        SSL Valid: ${data.isSslValid}
        SSL Issuer: ${data.sslIssuer}
        Missing Security Headers: ${data.hasMissingHeaders} (HSTS, CSP, X-Frame-Options)
        Domain Age: ${data.domainAge}
        HTTP Status Code: ${data.statusCode}
        Server Location: ${data.serverLocation}
        
        Provide your analysis in JSON format with exactly two fields:
        1. "verdict": One of ["Safe", "Suspicious", "Malicious"]
        2. "insight": A concise, highly professional 2-sentence explanation of your finding.
        
        Return ONLY the JSON.
      `;

      const result = await model.generateContent(prompt);
      const text = result.response.text();
      const jsonStr = text.replace(/```json|```/g, "").trim();
      return JSON.parse(jsonStr);
    } catch (err) {
      console.error(`Attempt with ${modelName} failed:`, err.message);
      lastError = err;
      // If quota or API key issue, stop trying other models
      if (err.message.includes("API key") || err.message.includes("429")) break;
      continue; 
    }
  }

  return { 
    verdict: "Unknown", 
    insight: `Neural Analysis Error: ${lastError?.message || 'Connection failed'} (Tried ${modelsToTry.join(", ")})`
  };
}

app.post('/api/analyze', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  // Add protocol if missing
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL Format' });
  }

  const hostname = parsedUrl.hostname;
  const isHttps = parsedUrl.protocol === 'https:';

  // State variables mapping to user requirements
  let finalScore = 0; // Starts at 0
  let isSslValid = false;
  let sslIssuer = 'N/A';
  let hasMissingHeaders = true; 
  let statusCode = 'Unknown';
  let serverIp = 'Unknown';
  let serverLocation = 'Unknown';

  // --- F. Suspicious Keyword Detection ---
  const suspiciousKeywords = ['login', 'free', 'verify', 'bank', 'update', 'secure', 'account', '.xyz', '.top'];
  const isSuspiciousUrl = suspiciousKeywords.some(keyword => url.toLowerCase().includes(keyword));

  try {
    // --- Server Fingerprint (DNS & IP-API Geolocation) ---
    const dnsResult = await dns.lookup(hostname);
    serverIp = dnsResult.address;
    
    // Non-blocking fetch for geolocation
    axios.get(`http://ip-api.com/json/${serverIp}`).then(geo => {
       if (geo.data && geo.data.status === 'success') {
         serverLocation = `${geo.data.city}, ${geo.data.countryCode}`;
       }
    }).catch(() => {});

    // --- B. SSL & D. Security Headers & E. Status Code ---
    const headersRes = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
      },
      validateStatus: () => true, // Don't throw on 404/500
      timeout: 8000,
      httpsAgent: new https.Agent({
        rejectUnauthorized: false // Allow self-signed/expired so we can manually inspect them
      })
    });
    
    statusCode = headersRes.status;
    const headers = headersRes.headers;

    // Check Security Headers: CSP, X-Frame-Options, HSTS
    const hasCsp = !!headers['content-security-policy'];
    const hasXFrame = !!headers['x-frame-options'];
    const hasHsts = !!headers['strict-transport-security'];
    
    if (hasCsp && hasXFrame && hasHsts) {
      hasMissingHeaders = false; // All present
    }
  } catch (err) {
    console.warn(`Connection logic bypassed for ${hostname}:`, err.message);
    statusCode = 'Connection Failed';
  }

  // --- SSL Inspection (Native TLS) ---
  if (isHttps) {
    const tls = require('tls');
    try {
      await new Promise((resolve) => {
        const socket = tls.connect({
          host: hostname,
          port: 443,
          servername: hostname,
          rejectUnauthorized: false
        }, () => {
          const cert = socket.getPeerCertificate(true);
          if (cert && Object.keys(cert).length > 0) {
            sslIssuer = cert.issuer ? cert.issuer.O || cert.issuer.CN : 'Unknown';
            const validTo = new Date(cert.valid_to);
            const validFrom = new Date(cert.valid_from);
            const now = new Date();
            
            if (now >= validFrom && now <= validTo) {
               const identityErr = tls.checkServerIdentity(hostname, cert);
               if (!identityErr) isSslValid = true;
            }
          }
          socket.end();
          resolve();
        });
        socket.on('error', () => resolve());
        setTimeout(() => { socket.destroy(); resolve(); }, 5000); // 5s timeout
      });
    } catch (err) {
      console.warn(`SSL Socket Check Failed for ${hostname}`);
    }
  }

  // --- C. WHOIS Domain Age ---
  const baseDomain = getBaseDomain(hostname);
  const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(baseDomain);
  
  let whoisText = '';
  if (!isIp) {
    whoisText = await lookupWhois(baseDomain);
  }
  
  const domainAgeResult = parseDomainAge(whoisText);
  const isOldDomain = domainAgeResult.ageDays > 180; // 6 months

  // --- 3. APPLY RISK SCORING SYSTEM ---
  // Base points mapping directly to user spec:
  // HTTPS = +1
  // Valid SSL = +1
  // Old domain = +1
  // Missing headers = -1
  // Suspicious URL = -1
  if (isHttps) finalScore += 1;
  if (isSslValid) finalScore += 1;
  if (isOldDomain) finalScore += 1;
  if (hasMissingHeaders) finalScore -= 1;
  if (isSuspiciousUrl) finalScore -= 1;
  if (isIp) finalScore -= 1; // URLs that are raw IPs are suspicious

  // Max score is +3, Min is -2. Convert this to a 0-100 gauge scale
  // Mapping: -2=10, -1=30, 0=50, 1=70, 2=85, 3=100
  let normalizedScore = 50;
  if (finalScore >= 3) normalizedScore = 100;
  else if (finalScore === 2) normalizedScore = 85;
  else if (finalScore === 1) normalizedScore = 70;
  else if (finalScore === 0) normalizedScore = 50;
  else if (finalScore === -1) normalizedScore = 30;
  else normalizedScore = 10;

  let threatLevel = 'Safe';
  if (normalizedScore < 50) threatLevel = 'Critical / High Risk';
  else if (normalizedScore < 80) threatLevel = 'Warning / Medium Risk';

  // --- 4. NEURAL AI ANALYSIS ---
  const aiResult = await runAiAnalysis({
    url,
    isSslValid,
    sslIssuer,
    hasMissingHeaders,
    domainAge: domainAgeResult.text,
    statusCode,
    serverLocation
  });

  // Format to original Dashboard structure
  setTimeout(() => {
    res.json({
      score: normalizedScore,
      threatLevel,
      ssl: {
        status: isSslValid ? '✅ Valid & Encrypted' : '❌ Invalid or HTTP',
        issuer: sslIssuer,
        isSecure: isSslValid
      },
      domain: {
        age: domainAgeResult.text + (isOldDomain ? ' 🟢' : ' ⚠️ (<6m)'),
        registrar: 'Realtime WHOIS Query',
        reputation: isSuspiciousUrl ? 'Suspicious' : 'Good'
      },
      threats: [
        { name: 'Missing HSTS/CSP Headers', detected: hasMissingHeaders },
        { name: 'Suspicious URL Keywords', detected: isSuspiciousUrl },
        { name: 'Missing Secure Protocol (HTTPS)', detected: !isHttps },
        { name: 'Invalid SSL Certificate', detected: !isSslValid }
      ],
      serverInfo: {
        location: serverLocation || 'Unknown API Error',
        ip: serverIp,
        statusCode: statusCode
      },
      aiAnalysis: {
        verdict: aiResult.verdict,
        insight: aiResult.insight
      }
    });
  }, 1000); // Wait 1s for IP Geolocation callback to definitely resolve
});

app.listen(PORT, () => {
  console.log(`Deep Scanner API running on http://localhost:${PORT}`);
});
