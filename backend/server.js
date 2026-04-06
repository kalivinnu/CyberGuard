const express = require('express');
const cors = require('cors');
const https = require('https');
const dns = require('dns').promises;
const { URL } = require('url');
const whois = require('whois');
const axios = require('axios');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const ipaddr = require('ipaddr.js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security Middleware
app.use(helmet());
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: { error: 'Too many security scans from this IP, please try again later.' }
});
app.use('/api/', limiter);

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

// --- ACCURACY PRO: TYPOSQUATTING DETECTION ---
function levenshtein(a, b) {
  const tmp = [];
  for (let i = 0; i <= a.length; i++) { tmp[i] = [i]; }
  for (let j = 0; j <= b.length; j++) { tmp[0][j] = j; }
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      tmp[i][j] = Math.min(
        tmp[i - 1][j] + 1,
        tmp[i][j - 1] + 1,
        tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return tmp[a.length][b.length];
}

const TOP_BRANDS = [
    'google', 'facebook', 'instagram', 'paypal', 'amazon', 'microsoft', 'apple', 'netflix', 
    'twitter', 'linkedin', 'spotify', 'roblox', 'whatsapp', 'telegram', 'bankofamerica', 
    'wellsfargo', 'chase', 'binance', 'coinbase', 'kraken', 'github', 'dropbox', 'icloud', 'adobe'
];

function checkTyposquatting(hostname) {
  const name = hostname.split('.')[0].toLowerCase();
  if (TOP_BRANDS.includes(name)) return { isBrand: true, distance: 0, brand: name };
  
  for (const brand of TOP_BRANDS) {
    const distance = levenshtein(name, brand);
    // Threshold depends on length; distance 1 or 2 for common names
    if (distance > 0 && distance <= 2 && name.length >= 4) {
      return { isBrand: false, distance, brand };
    }
  }
  return null;
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

// --- INDUSTRIAL INTELLIGENCE: GOOGLE SAFE BROWSING ---
async function checkSafeBrowsing(url) {
  if (!process.env.SAFE_BROWSING_API_KEY || process.env.SAFE_BROWSING_API_KEY === 'PLACEHOLDER') return null;
  try {
    const res = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.SAFE_BROWSING_API_KEY}`, {
      client: { clientId: "CyberGuard", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    });
    return res.data.matches && res.data.matches.length > 0;
  } catch (err) {
    console.error("Safe Browsing Error:", err.message);
    return null;
  }
}

// --- INDUSTRIAL INTELLIGENCE: VIRUSTOTAL ---
async function checkVirusTotal(url) {
  if (!process.env.VIRUS_TOTAL_API_KEY || process.env.VIRUS_TOTAL_API_KEY === 'PLACEHOLDER') return null;
  try {
    // VirusTotal base64 (no padding)
    const encodedUrl = Buffer.from(url).toString('base64').replace(/=/g, '');
    const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: { 'x-apikey': process.env.VIRUS_TOTAL_API_KEY }
    });
    const stats = res.data.data.attributes.last_analysis_stats;
    return { malicious: stats.malicious, suspicious: stats.suspicious };
  } catch (err) {
    console.error("VirusTotal Error:", err.message);
    return null;
  }
}

// --- SSL & TLS INSPECTOR ---
async function checkSsl(hostname) {
  const tls = require('tls');
  return new Promise((resolve) => {
    try {
      const socket = tls.connect({
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false
      }, () => {
        const cert = socket.getPeerCertificate(true);
        let sslData = { isSslValid: false, issuer: 'N/A' };
        if (cert && Object.keys(cert).length > 0) {
          sslData.issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN) : 'Unknown';
          const validTo = new Date(cert.valid_to);
          const validFrom = new Date(cert.valid_from);
          const now = new Date();
          if (now >= validFrom && now <= validTo) {
            const identityErr = tls.checkServerIdentity(hostname, cert);
            if (!identityErr) sslData.isSslValid = true;
          }
        }
        socket.end();
        resolve(sslData);
      });
      socket.on('error', () => resolve({ isSslValid: false, issuer: 'Connection Failed' }));
      setTimeout(() => { socket.destroy(); resolve({ isSslValid: false, issuer: 'Timeout' }); }, 5000);
    } catch (err) {
      resolve({ isSslValid: false, issuer: 'N/A' });
    }
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
        As a Lead Cybersecurity Analyst, analyze the following website data for potential PHISHING, SCAMS, or technical vulnerabilities.
        
        TECHNICAL TRUST SCORE: ${data.trustScore}% (A lower score indicates higher risk based on rule-based analysis)
        
        URL: ${data.url}
        SSL Valid: ${data.isSslValid}
        SSL Issuer: ${data.sslIssuer}
        Missing Security Headers: ${data.hasMissingHeaders}
        Domain Age: ${data.domainAge}
        HTTP Status Code: ${data.statusCode}
        Server Location: ${data.serverLocation}
        
        PHISHING HEURISTICS:
        - Is Punycode/Homograph: ${data.phishingIndicators.isPunycode}
        - Shortened Link Detected: ${data.phishingIndicators.isShortened}
        - Suspicious TLD: ${data.phishingIndicators.hasSuspiciousTld}
        - Deep Subdomains: ${data.phishingIndicators.hasDeepSubdomains}
        - Suspicious Keywords: ${data.phishingIndicators.isSuspiciousUrl}
        
        ACCURACY PRO INDICATORS:
        - Brand Impersonation Suspected: ${data.phishingIndicators.brandImpersonation?.brand || 'None'} (Fuzzy Distance: ${data.phishingIndicators.brandImpersonation?.distance || 'N/A'})
        - Redirects Found: ${data.phishingIndicators.redirectCount}
        - Final Destination: ${data.phishingIndicators.finalUrl}
        - Sensitive Forms Found (Login/Password): ${data.phishingIndicators.hasSensitivedata}
        
        GLOBAL INTELLIGENCE (INDUSTRIAL GRADE):
        - Google Safe Browsing Flagged: ${data.phishingIndicators.intel.googleFlagged ? 'YES (MALICIOUS)' : 'No'}
        - VirusTotal Flagged Engines: ${data.phishingIndicators.intel.vtStatus ? data.phishingIndicators.intel.vtStatus.malicious + ' engines' : 'Unknown'}

        Analyze the URL structure and technical indicators for deceptive patterns. You must provide a verdict that is consistent with the Technical Trust Score unless you have a strong, justifiable reason for a different conclusion.
        
        Provide your analysis in JSON format with exactly two fields:
        1. "verdict": One of ["Safe", "Suspicious", "Malicious"]
        2. "insight": A concise, highly professional 2-sentence explanation focusing on why it was flagged (or why it is safe).
        
        Return ONLY the JSON.
      `;

      const result = await model.generateContent(prompt);
      const text = result.response.text();
      // More robust JSON extraction: Find content between first { and last }
      const match = text.match(/\{[\s\S]*\}/);
      if (!match) throw new Error("No JSON object found in AI response");
      const jsonStr = match[0].trim();
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

  // --- F. Suspicious Keyword & Shortener Detection & Phishing Heuristics ---
  const suspiciousKeywords = ['login', 'free', 'verify', 'bank', 'update', 'secure', 'account', 'signin', 'auth', 'payment', 'confirm', 'password', 'urgent', 'offer', 'redirect'];
  const isSuspiciousUrl = suspiciousKeywords.some(keyword => url.toLowerCase().includes(keyword));
  
  // Shortener Detection
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'shorturl.at', 'is.gd', 'buff.ly', 'ow.ly'];
  const isShortened = shorteners.some(shortener => hostname.toLowerCase() === shortener || hostname.toLowerCase().endsWith('.' + shortener));
  
  // Punycode/Homograph Detection
  const isPunycode = hostname.toLowerCase().startsWith('xn--');
  
  // High-risk TLDs
  const suspiciousTlds = ['.xyz', '.top', '.site', '.online', '.tk', '.ga', '.cf', '.gq', '.zip', '.click'];
  const hasSuspiciousTld = suspiciousTlds.some(tld => hostname.toLowerCase().endsWith(tld));
  
  // Subdomain profiling
  const subdomains = hostname.split('.');
  const hasDeepSubdomains = subdomains.length > 3;

  try {
    // --- SSRF PROTECTION ---
    // Validate that the IP is NOT private, reserved, or loopback
    const dnsResult = await dns.lookup(hostname);
    serverIp = dnsResult.address;
    
    const addr = ipaddr.parse(serverIp);
    const range = addr.range();
    const untrustedRanges = ['loopback', 'linkLocal', 'private', 'uniqueLocal', 'reserved'];
    
    if (untrustedRanges.includes(range)) {
      console.warn(`[Blocked SSRF Attempt]: Target ${hostname} resolved to ${range} IP ${serverIp}`);
      return res.status(403).json({ error: 'Access Denied: Scanning internal/private network resources is prohibited.' });
    }
  } catch (err) {
    console.warn(`DNS pre-check failed for ${hostname}`);
  }

  const baseDomain = getBaseDomain(hostname);
  const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(baseDomain);

  // --- INDUSTRIAL PARALLEL ANALYSIS (OPTIMIZED) ---
  let whoisText = '';
  let googleFlagged = null;
  let vtStatus = null;
  let headersRes = null;
  let sslData = { isSslValid: false, issuer: 'N/A' };
  let geoData = { city: 'Unknown', countryCode: '??' };

  try {
    const results = await Promise.allSettled([
       isIp ? Promise.resolve(null) : lookupWhois(baseDomain),
       checkSafeBrowsing(url),
       checkVirusTotal(url),
       axios.get(url, {
         headers: {
           'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
         },
         validateStatus: () => true, 
         timeout: 10000,
         maxRedirects: 5,
         httpsAgent: new https.Agent({ rejectUnauthorized: false })
       }),
       checkSsl(hostname),
       axios.get(`http://ip-api.com/json/${serverIp}`).catch(() => ({ data: null }))
    ]);
    
    whoisText = results[0].status === 'fulfilled' ? results[0].value : '';
    googleFlagged = results[1].status === 'fulfilled' ? results[1].value : null;
    vtStatus = results[2].status === 'fulfilled' ? results[2].value : null;
    headersRes = results[3].status === 'fulfilled' ? results[3].value : null;
    if (results[4].status === 'fulfilled' && results[4].value) sslData = results[4].value;
    if (results[5].status === 'fulfilled' && results[5].value?.data) {
       geoData = { city: results[5].value.data.city, countryCode: results[5].value.data.countryCode };
    }
  } catch (err) {
    console.warn(`Fatal error in parallel pipeline:`, err.message);
  }

  isSslValid = sslData.isSslValid;
  sslIssuer = sslData.issuer;
  serverLocation = `${geoData.city}, ${geoData.countryCode}`;

  const domainAgeResult = parseDomainAge(whoisText);
  const isOldDomain = domainAgeResult.ageDays > 180;

  // Capture final URL and redirect depth
  let redirectCount = 0;
  let finalUrl = url;
  let hasSensitivedata = false;
  
  if (headersRes) {
    finalUrl = headersRes.request?.res?.responseUrl || url;
    if (headersRes.request?._redirectable?._redirects) {
      redirectCount = headersRes.request._redirectable._redirects.length;
    }
    statusCode = headersRes.status;
    const body = headersRes.data;
    if (typeof body === 'string') {
       const lowerBody = body.toLowerCase();
       if (lowerBody.includes('type="password"') || lowerBody.includes('type=\'password\'') || 
          (lowerBody.includes('id="login"') && lowerBody.includes('form'))) {
         hasSensitivedata = true;
       }
    }
    
    const headers = headersRes.headers;
    const hasCsp = !!headers['content-security-policy'];
    const hasXFrame = !!headers['x-frame-options'];
    const hasHsts = !!headers['strict-transport-security'];
    if (hasCsp && hasXFrame && hasHsts) hasMissingHeaders = false;
  }

  // --- ACCURACY PRO HEURISTICS ---
  const brandImpersonation = checkTyposquatting(hostname);
  const isHighRiskRedirect = redirectCount > 2 || (redirectCount > 0 && new URL(finalUrl).hostname !== hostname);

  // --- 3. APPLY RISK SCORING SYSTEM ---
  if (isHttps) finalScore += 1;
  if (isSslValid) finalScore += 1;
  if (isOldDomain) finalScore += 1;
  if (hasMissingHeaders) finalScore -= 1;
  if (isSuspiciousUrl) finalScore -= 1;
  if (isIp) finalScore -= 1; // URLs that are raw IPs are suspicious
  if (isShortened) finalScore -= 1; // Shortened URLs mask destination
  if (isPunycode) finalScore -= 2; // Homograph attack is critical
  if (hasSuspiciousTld) finalScore -= 1; 

  // Accuracy Pro Deductions
  if (brandImpersonation && !brandImpersonation.isBrand) finalScore -= 3; // Severe: Looks like a brand but isn't
  if (isHighRiskRedirect) finalScore -= 1;
  if (hasSensitivedata && (!isHttps || !isOldDomain || (brandImpersonation && !brandImpersonation.isBrand))) {
    finalScore -= 2; // Dangerous: Password form on suspicious site
  }

  // --- INDUSTRIAL INTELLIGENCE SCORING ---
  const intelFlagged = googleFlagged === true || (vtStatus && vtStatus.malicious > 2);
  if (intelFlagged) {
    finalScore = -10; // Forced to zero trust
  }

  // Max score is +3, Min is -5. Convert this to a 0-100 gauge scale
  // Mapping: -10=0 Trust, -5=0, -3=10, -2=20, -1=30, 0=50, 1=70, 2=85, 3=100
  let normalizedScore = 50;
  if (finalScore <= -10) normalizedScore = 0;
  else if (finalScore >= 3) normalizedScore = 100;
  else if (finalScore === 2) normalizedScore = 85;
  else if (finalScore === 1) normalizedScore = 70;
  else if (finalScore === 0) normalizedScore = 50;
  else if (finalScore === -1) normalizedScore = 30;
  else if (finalScore === -2) normalizedScore = 20;
  else if (finalScore === -3) normalizedScore = 10;
  else normalizedScore = 5;

  let threatLevel = 'Safe';
  if (normalizedScore < 20) threatLevel = 'High Risk / Malicious (Threat Intelligence Flagged)';
  else if (normalizedScore < 40) threatLevel = 'Critical / High Risk (Phishing Suspected)';
  else if (normalizedScore < 75) threatLevel = 'Warning / Medium Risk';

  // --- 4. NEURAL AI ANALYSIS ---
  const aiResult = await runAiAnalysis({
    url,
    trustScore: normalizedScore,
    isSslValid,
    sslIssuer,
    hasMissingHeaders,
    domainAge: domainAgeResult.text,
    statusCode,
    serverLocation,
    phishingIndicators: {
        isPunycode,
        isShortened,
        hasSuspiciousTld,
        hasDeepSubdomains,
        isSuspiciousUrl,
        brandImpersonation,
        redirectCount,
        finalUrl,
        hasSensitivedata,
        intel: {
          googleFlagged,
          vtStatus
        }
    }
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
        reputation: (isSuspiciousUrl || isPunycode || hasSuspiciousTld) ? 'Deceptive' : 'Good'
      },
      threats: [
        { name: 'Missing HSTS/CSP Headers', detected: hasMissingHeaders, explanation: 'HSTS/CSP - These are special security instructions that help protect your browser from attacks.' },
        { name: 'Suspicious URL Keywords', detected: isSuspiciousUrl, explanation: 'Suspicious Words - The link uses terms often found in fake or scam websites (e.g., "bank", "free", "urgent").' },
        { name: 'Shortened Link Detected', detected: isShortened, explanation: 'Shortened URL - The link is hidden behind a shortening service, making its true destination unknown.' },
        { name: 'Punycode/Homograph Attack', detected: isPunycode, explanation: 'Lookalike Link - The web address uses special characters to "look like" a famous site while actually being fake.' },
        { name: 'Untrusted/High-Risk TLD', detected: hasSuspiciousTld, explanation: 'Risk Domain Extension - The site uses a cheap or untrusted domain type (.xyz, .tk) often used by scammers.' },
        { name: 'Invalid SSL Certificate', detected: !isSslValid, explanation: 'SSL Certificate - A valid certificate ensures your connection is encrypted and the site is who it says it is.' },
        { name: 'Brand Impersonation', detected: (brandImpersonation && !brandImpersonation.isBrand), explanation: 'Lookalike Brand - This site appears to be impersonating a well-known brand (e.g., Google or PayPal).' },
        { name: 'Hidden Redirects', detected: isHighRiskRedirect, explanation: 'Redirect Chain - The URL bounced through multiple hidden addresses before arriving at the final page.' },
        { name: 'Insecure Login Form', detected: hasSensitivedata && (!isHttps || (brandImpersonation && !brandImpersonation.isBrand)), explanation: 'Critical Leak - Found a login or password form on a suspicious or unencrypted website.' },
        { name: 'Blacklisted (Google Intelligence)', detected: googleFlagged === true, explanation: 'Global Intelligence - This URL has been confirmed as malicious by the Google Safe Browsing database.' },
        { name: 'Threat Engine Detection (VT)', detected: (vtStatus && vtStatus.malicious > 0), explanation: 'Antivirus Consensus - Multiple security engines on VirusTotal have flagged this site as dangerous.' }
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
  }, 1000); 
});

app.listen(PORT, () => {
  console.log(`Deep Scanner API running on http://localhost:${PORT}`);
});
