const axios = require('axios');

const testUrls = [
  'google.com',
  '1.1.1.1',
  'https://www.bbc.co.uk',
  'xn--80ak6aa92e.com',
  'login-secure-auth.xyz',
  'not-a-link'
];

async function runTests() {
  console.log('--- STARTING SYSTEM VERIFICATION ---\n');
  for (const url of testUrls) {
    try {
      console.log(`Analyzing: ${url}...`);
      const res = await axios.post('http://localhost:5000/api/analyze', { url });
      console.log(`Verdict: ${res.data.aiAnalysis.verdict}`);
      console.log(`Score: ${res.data.score}/100`);
      console.log(`Insight: ${res.data.aiAnalysis.insight}\n`);
    } catch (err) {
      console.log(`Error analyzing ${url}: ${err.response?.data?.error || err.message}\n`);
    }
  }
  console.log('--- VERIFICATION COMPLETE ---');
}

runTests();
