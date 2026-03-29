=========================================================
CYBERGUARD - Website Strength & Safety Checker
=========================================================

--- SYSTEM REQUIREMENTS ---
Operating System    : Windows, macOS, or Linux
Runtime Environment : Node.js (v18.0.0 or higher recommended)
Package Manager     : npm (Node Package Manager)

--- BACKEND DEPENDENCIES (Folder: /backend) ---
Framework           : Express.js (High-performance API routing)
Middleware          : cors (Handles Cross-Origin Requests from frontend)
Network Clients     : axios (Executes HTTP routing & header inspection)
Domain Resolvers    : whois (Parses global domain registries)
Native Modules      : https, http, dns, tls (For deep-socket SSL parsing)

To Install Backend Dependencies:
  > cd backend
  > npm install

--- FRONTEND DEPENDENCIES (Folder: /frontend) ---
Core Library        : React 18
Build Tooling       : Vite.js (Ultra-fast development server & compiling)
UI Elements         : lucide-react (Premium SVG UI iconography)

To Install Frontend Dependencies:
  > cd frontend
  > npm install

--- CYBERGUARD SCANNER LOGIC / CAPABILITIES ---
CyberGuard was engineered strictly to the following parameters:

1. Protocol Validation: Forces tracking of Secure vs Non-Secure schema.
2. Cryptography Validation: Connects natively to secure server sockets to inspect exact SSL/TLS Certificate expiration dates and Subject Alt-Names (SNI).
3. Reputation Engine: Fetches massive WHOIS string payloads to extract domain creation dates. Automatically flags networks younger than 6 months.
4. Security Header Evasion: Parses server responses to verify strict implementation of `X-Frame-Options`, `Content-Security-Policy`, and `Strict-Transport-Security`.
5. Availability Matrix: Provides instant readout of HTTP Response status codes (200 OK, 403 Forbidden Firewall Blocks, etc.)
6. Keyword Mapping: Scans root URLs for highly-suspicious, phishing-style namespaces ('login', 'free', 'verify', 'update', 'bank').
7. Circular UI Scoring algorithm enforcing a mapped +3/-2 score differential mapped onto a 0-100 gauge visual.
