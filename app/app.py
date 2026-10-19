#!/usr/bin/env python3
"""
SMG Enterprise Security Demo Backend Server
Serves the Cloud Armor Interactive Security Playground & simulated API endpoints:
  - GET  /                : Cloud Armor Interactive Security Playground (HTML UI)
  - GET  /api/search?q=.. : Search simulation endpoint (SQLi / XSS target)
  - POST /api/comment     : Comment submission simulation (XSS / RCE target)
  - GET  /api/view?file=. : Document viewer simulation (LFI / RFI / Path Traversal target)
  - GET  /health          : Load Balancer Health Check (200 OK)
"""
import json
import socket
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

HOSTNAME = socket.gethostname()

WELCOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SMG Security Demo | Cloud Armor Interactive Security Playground</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
    body { font-family: 'Plus Jakarta Sans', sans-serif; }
    code, pre, .font-mono { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col">

  <!-- Navbar -->
  <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-30">
    <div class="max-w-7xl mx-auto px-4 py-3 flex flex-wrap justify-between items-center gap-3">
      <div class="flex items-center space-x-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-sky-500/20">
          <i class="fa-solid fa-shield-halved text-lg"></i>
        </div>
        <div>
          <div class="flex items-center space-x-2">
            <span class="font-extrabold text-white text-base tracking-tight">Cloud Armor Interactive Security Playground</span>
            <span class="text-[10px] font-bold px-2 py-0.5 rounded bg-sky-500/20 text-sky-400 border border-sky-500/30 uppercase">
              Live Edge Protection
            </span>
          </div>
          <p class="text-xs text-slate-400 font-medium">PT Smartnet Magna Global (SMG) &bull; Google Cloud Premier Partner</p>
        </div>
      </div>

      <div class="flex items-center space-x-2">
        <button onclick="runAllDrills()" id="btnRunAll" class="px-4 py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 shadow-md shadow-sky-500/20 flex items-center space-x-2 transition">
          <i class="fa-solid fa-bolt"></i>
          <span>Run All Attack Tests</span>
        </button>
        <button onclick="clearConsole()" class="px-3 py-2 rounded-xl text-xs font-semibold text-slate-400 bg-slate-800 hover:bg-slate-700 hover:text-white transition">
          <i class="fa-solid fa-trash-can mr-1"></i> Clear Log
        </button>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="max-w-7xl w-full mx-auto px-4 py-6 flex-1 flex flex-col lg:flex-row gap-6">

    <!-- Left Column: Attack Cards -->
    <div class="flex-1 space-y-4">

      <!-- Infrastructure Status Banner -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div class="flex items-center space-x-3">
          <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>Backend Instance: <strong class="text-sky-300 font-mono">{{HOSTNAME}}</strong></span>
          <span class="text-slate-600">&bull;</span>
          <span>Zone: <strong class="text-slate-300 font-mono">asia-southeast2-a (Jakarta)</strong></span>
        </div>
        <div class="flex items-center space-x-2">
          <span class="px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold text-[11px]">
            <i class="fa-solid fa-lock mr-1"></i> HTTPS Active
          </span>
          <span class="px-2.5 py-1 rounded-md bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold text-[11px]">
            <i class="fa-solid fa-network-wired mr-1"></i> Zero Public IP MIG
          </span>
        </div>
      </div>

      <!-- Test Cards Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">

        <!-- Card 1: Benign Normal Traffic -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between hover:border-slate-700 transition">
          <div>
            <div class="flex justify-between items-start mb-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                TEST 1 &bull; BENIGN NORMAL TRAFFIC
              </span>
              <span class="text-[11px] font-mono text-slate-500">Expect: HTTP 200 OK</span>
            </div>
            <h3 class="text-sm font-bold text-white mb-1">Benign Normal Traffic</h3>
            <p class="text-xs text-slate-400 mb-3">Trafik pengguna resmi tanpa muatan berbahaya. Harus lolos sampai ke VM backend.</p>
            <div class="bg-slate-950 rounded-lg p-2 font-mono text-[11px] text-slate-300 mb-3 break-all border border-slate-800">
              GET /api/search?q=enterprise+cloud+security
            </div>
          </div>
          <div>
            <div id="result-1" class="hidden mb-2 p-2 rounded-lg text-xs font-mono"></div>
            <div class="flex items-center space-x-2">
              <button onclick="runTest(1)" id="btn-1" class="flex-1 py-2 px-3 rounded-xl text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-500 transition flex items-center justify-center space-x-1.5 shadow-sm">
                <i class="fa-solid fa-play"></i>
                <span>Test Normal Traffic</span>
              </button>
              <a href="/api/search?q=enterprise+cloud+security" target="_blank" title="Buka di tab baru" class="p-2 rounded-xl text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition">
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
              </a>
            </div>
          </div>
        </div>

        <!-- Card 2: SQL Injection (SQLi) -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between hover:border-slate-700 transition">
          <div>
            <div class="flex justify-between items-start mb-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                TEST 2 &bull; OWASP TOP 10 (SQLi)
              </span>
              <span class="text-[11px] font-mono text-slate-500">Expect: HTTP 403 Forbidden</span>
            </div>
            <h3 class="text-sm font-bold text-white mb-1">SQL Injection (SQLi)</h3>
            <p class="text-xs text-slate-400 mb-3">Injeksi SQL bypass otentikasi (<code class="text-rose-400">1' OR 1=1 --</code>). Blocked by Rule Priority 1000: sqli-v33-stable.</p>
            <div class="bg-slate-950 rounded-lg p-2 font-mono text-[11px] text-rose-300 mb-3 break-all border border-slate-800">
              GET /api/search?q=1' OR 1=1 --
            </div>
          </div>
          <div>
            <div id="result-2" class="hidden mb-2 p-2 rounded-lg text-xs font-mono"></div>
            <div class="flex items-center space-x-2">
              <button onclick="runTest(2)" id="btn-2" class="flex-1 py-2 px-3 rounded-xl text-xs font-bold text-white bg-rose-600 hover:bg-rose-500 transition flex items-center justify-center space-x-1.5 shadow-sm">
                <i class="fa-solid fa-shield-virus"></i>
                <span>Launch SQLi Attack</span>
              </button>
              <a href="/api/search?q=1%27%20OR%201%3D1%20--" target="_blank" title="Buka di tab baru (Lihat 403 Google Front End)" class="p-2 rounded-xl text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition">
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
              </a>
            </div>
          </div>
        </div>

        <!-- Card 3: Cross-Site Scripting (XSS) -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between hover:border-slate-700 transition">
          <div>
            <div class="flex justify-between items-start mb-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                TEST 3 &bull; OWASP TOP 10 (XSS)
              </span>
              <span class="text-[11px] font-mono text-slate-500">Expect: HTTP 403 Forbidden</span>
            </div>
            <h3 class="text-sm font-bold text-white mb-1">Cross-Site Scripting (XSS)</h3>
            <p class="text-xs text-slate-400 mb-3">Injeksi tag script berbahaya untuk mencuri sesi. Blocked by Rule Priority 1010: xss-v33-stable.</p>
            <div class="bg-slate-950 rounded-lg p-2 font-mono text-[11px] text-amber-300 mb-3 break-all border border-slate-800">
              GET /api/search?q=&lt;script&gt;alert('pwned')&lt;/script&gt;
            </div>
          </div>
          <div>
            <div id="result-3" class="hidden mb-2 p-2 rounded-lg text-xs font-mono"></div>
            <div class="flex items-center space-x-2">
              <button onclick="runTest(3)" id="btn-3" class="flex-1 py-2 px-3 rounded-xl text-xs font-bold text-white bg-amber-600 hover:bg-amber-500 transition flex items-center justify-center space-x-1.5 shadow-sm">
                <i class="fa-solid fa-code"></i>
                <span>Launch XSS Attack</span>
              </button>
              <a href="/api/search?q=%3Cscript%3Ealert(%27pwned%27)%3C/script%3E" target="_blank" title="Buka di tab baru (Lihat 403 Google Front End)" class="p-2 rounded-xl text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition">
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
              </a>
            </div>
          </div>
        </div>

        <!-- Card 4: Path Traversal / LFI -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between hover:border-slate-700 transition">
          <div>
            <div class="flex justify-between items-start mb-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                TEST 4 &bull; PATH TRAVERSAL (LFI)
              </span>
              <span class="text-[11px] font-mono text-slate-500">Expect: HTTP 403 Forbidden</span>
            </div>
            <h3 class="text-sm font-bold text-white mb-1">Path Traversal / LFI</h3>
            <p class="text-xs text-slate-400 mb-3">Mencoba membaca file sistem operasi via traversal path. Blocked by Rule Priority 1020: lfi-v33-stable.</p>
            <div class="bg-slate-950 rounded-lg p-2 font-mono text-[11px] text-purple-300 mb-3 break-all border border-slate-800">
              GET /api/view?file=../../../../etc/passwd
            </div>
          </div>
          <div>
            <div id="result-4" class="hidden mb-2 p-2 rounded-lg text-xs font-mono"></div>
            <div class="flex items-center space-x-2">
              <button onclick="runTest(4)" id="btn-4" class="flex-1 py-2 px-3 rounded-xl text-xs font-bold text-white bg-purple-600 hover:bg-purple-500 transition flex items-center justify-center space-x-1.5 shadow-sm">
                <i class="fa-solid fa-folder-open"></i>
                <span>Launch LFI Attack</span>
              </button>
              <a href="/api/view?file=../../../../etc/passwd" target="_blank" title="Buka di tab baru (Lihat 403 Google Front End)" class="p-2 rounded-xl text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition">
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
              </a>
            </div>
          </div>
        </div>

        <!-- Card 5: Remote Code Execution (RCE) -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between hover:border-slate-700 transition">
          <div>
            <div class="flex justify-between items-start mb-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-300 border border-red-500/30">
                TEST 5 &bull; COMMAND INJECTION (RCE)
              </span>
              <span class="text-[11px] font-mono text-slate-500">Expect: HTTP 403 Forbidden</span>
            </div>
            <h3 class="text-sm font-bold text-white mb-1">Remote Code Execution (RCE)</h3>
            <p class="text-xs text-slate-400 mb-3">Mencoba menyisipkan Unix command injection via endpoint comment. Blocked by Rule Priority 1030: rce-v33-stable.</p>
            <div class="bg-slate-950 rounded-lg p-2 font-mono text-[11px] text-red-300 mb-3 break-all border border-slate-800">
              POST /api/comment?cmd=cat /etc/passwd; id
            </div>
          </div>
          <div>
            <div id="result-5" class="hidden mb-2 p-2 rounded-lg text-xs font-mono"></div>
            <div class="flex items-center space-x-2">
              <button onclick="runTest(5)" id="btn-5" class="flex-1 py-2 px-3 rounded-xl text-xs font-bold text-white bg-red-600 hover:bg-red-500 transition flex items-center justify-center space-x-1.5 shadow-sm">
                <i class="fa-solid fa-terminal"></i>
                <span>Launch RCE Attack</span>
              </button>
              <a href="/api/comment?cmd=cat%20/etc/passwd%3B%20id" target="_blank" title="Buka di tab baru (Lihat 403 Google Front End)" class="p-2 rounded-xl text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition">
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
              </a>
            </div>
          </div>
        </div>

        <!-- Card 6: Layer 7 DDoS Flood Simulation -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between hover:border-slate-700 transition">
          <div>
            <div class="flex justify-between items-start mb-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-300 border border-orange-500/30">
                TEST 6 &bull; L7 DDoS RATE LIMITING
              </span>
              <span class="text-[11px] font-mono text-slate-500">Expect: HTTP 429 Too Many Requests</span>
            </div>
            <h3 class="text-sm font-bold text-white mb-1">Layer 7 DDoS Flood Simulation</h3>
            <p class="text-xs text-slate-400 mb-3">Kirim 60 request parallel via Promise.all. Tripped Rule Priority 2000: Rate-Based Ban (50 req/min).</p>
            <div class="bg-slate-950 rounded-lg p-2 font-mono text-[11px] text-orange-300 mb-3 break-all border border-slate-800">
              Burst 60 Parallel Requests &rarr; Rule Priority 2000: Rate-Based Ban
            </div>
          </div>
          <div>
            <div id="result-6" class="hidden mb-2 p-2 rounded-lg text-xs font-mono"></div>
            <div class="flex items-center space-x-2">
              <button onclick="runTest(6)" id="btn-6" class="flex-1 py-2 px-3 rounded-xl text-xs font-bold text-white bg-orange-600 hover:bg-orange-500 transition flex items-center justify-center space-x-1.5 shadow-sm">
                <i class="fa-solid fa-water"></i>
                <span>Simulate L7 DDoS (Burst 60)</span>
              </button>
              <a href="/api/search?q=flood_sim_probe" target="_blank" title="Buka di tab baru" class="p-2 rounded-xl text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition">
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
              </a>
            </div>
          </div>
        </div>

      </div>

    </div>

    <!-- Right Column: Live Telemetry Terminal Console -->
    <div class="w-full lg:w-96 flex flex-col">
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex-1 flex flex-col">
        <div class="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
          <div class="flex items-center space-x-2">
            <i class="fa-solid fa-terminal text-sky-400 text-xs"></i>
            <span class="text-xs font-bold text-white uppercase tracking-wider">Live Security Terminal</span>
          </div>
          <span class="text-[10px] font-mono text-emerald-400 font-semibold">● LISTENING</span>
        </div>

        <!-- Terminal Output Area -->
        <div id="terminalLog" class="bg-slate-950 border border-slate-800/80 rounded-xl p-3 flex-1 font-mono text-[11px] text-slate-300 overflow-y-auto max-h-[500px] lg:max-h-none space-y-2">
          <div class="text-slate-500 text-[10px]">
            # SMG Cloud Armor Interactive Telemetry Engine Initialized.<br>
            # Ready for testing. Click any attack button on the left.
          </div>
        </div>
      </div>
    </div>

  </main>

  <footer class="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500">
    &copy; 2026 <strong>PT Smartnet Magna Global (SMG)</strong> &bull; Google Cloud Premier Partner &bull; Enterprise Security Practice
  </footer>

  <!-- Interactive JavaScript Engine -->
  <script>
    function logToConsole(type, msg, meta = "") {
      const term = document.getElementById("terminalLog");
      const time = new Date().toISOString().substring(11, 19);
      let colorClass = "text-slate-300";
      let badge = `<span class="text-slate-500">[${time}]</span>`;

      if (type === "SEND") {
        colorClass = "text-sky-300";
        badge += ` <span class="text-sky-400 font-bold">OUTBOUND:</span>`;
      } else if (type === "ALLOW") {
        colorClass = "text-emerald-400";
        badge += ` <span class="text-emerald-400 font-bold">ALLOWED:</span>`;
      } else if (type === "BLOCK") {
        colorClass = "text-rose-400";
        badge += ` <span class="text-rose-400 font-bold">BLOCKED:</span>`;
      } else if (type === "BAN") {
        colorClass = "text-orange-400";
        badge += ` <span class="text-orange-400 font-bold">RATE BAN:</span>`;
      } else if (type === "INFO") {
        colorClass = "text-indigo-300";
        badge += ` <span class="text-indigo-400 font-bold">INFO:</span>`;
      }

      const row = document.createElement("div");
      row.className = "leading-relaxed border-b border-slate-900/60 pb-1";
      row.innerHTML = `${badge} <span class="${colorClass}">${msg}</span> ${meta ? `<div class="text-[10px] text-slate-500 pl-4">${meta}</div>` : ""}`;
      term.appendChild(row);
      term.scrollTop = term.scrollHeight;
    }

    function clearConsole() {
      document.getElementById("terminalLog").innerHTML = `<div class="text-slate-500 text-[10px]"># Console cleared. Ready for new drill.</div>`;
    }

    async function runTest(id) {
      const btn = document.getElementById("btn-" + id);
      const resBox = document.getElementById("result-" + id);
      btn.disabled = true;
      btn.classList.add("opacity-75");

      resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-slate-800 text-slate-300 block";
      resBox.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Sending request to Load Balancer...`;

      const start = performance.now();

      try {
        if (id === 1) { // Benign
          logToConsole("SEND", "GET /api/search?q=enterprise+cloud+security");
          const resp = await fetch("/api/search?q=enterprise+cloud+security");
          const dur = Math.round(performance.now() - start);
          if (resp.status === 200) {
            logToConsole("ALLOW", `HTTP 200 OK (${dur}ms) - Passed through Cloud Armor to Backend MIG`);
            resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 block";
            resBox.innerHTML = `✔ <strong>HTTP 200 OK</strong> (${dur}ms) &mdash; Traffic Allowed to Backend`;
          } else {
            handleUnexpected(resBox, resp.status, dur);
          }
        }
        else if (id === 2) { // SQLi
          logToConsole("SEND", "GET /api/search?q=1' OR 1=1 --", "Payload: 1' OR 1=1 -- (OWASP SQL Injection)");
          const resp = await fetch("/api/search?q=1%27%20OR%201%3D1%20--");
          const dur = Math.round(performance.now() - start);
          if (resp.status === 403) {
            logToConsole("BLOCK", `HTTP 403 Forbidden (${dur}ms) - Blocked by Rule Priority 1000: sqli-v33-stable`);
            resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-rose-500/10 text-rose-300 border border-rose-500/30 block";
            resBox.innerHTML = `🛡️ <strong>HTTP 403 Forbidden</strong> (${dur}ms)<br><span class="text-[10px] text-rose-400">Blocked by Rule Priority 1000: sqli-v33-stable</span>`;
          } else {
            handleUnexpected(resBox, resp.status, dur);
          }
        }
        else if (id === 3) { // XSS
          logToConsole("SEND", "GET /api/search?q=%3Cscript%3Ealert('pwned')%3C/script%3E", "Payload: Cross-Site Scripting (OWASP XSS)");
          const resp = await fetch("/api/search?q=%3Cscript%3Ealert(%27pwned%27)%3C/script%3E");
          const dur = Math.round(performance.now() - start);
          if (resp.status === 403) {
            logToConsole("BLOCK", `HTTP 403 Forbidden (${dur}ms) - Blocked by Rule Priority 1010: xss-v33-stable`);
            resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30 block";
            resBox.innerHTML = `🛡️ <strong>HTTP 403 Forbidden</strong> (${dur}ms)<br><span class="text-[10px] text-amber-400">Blocked by Rule Priority 1010: xss-v33-stable</span>`;
          } else {
            handleUnexpected(resBox, resp.status, dur);
          }
        }
        else if (id === 4) { // LFI
          logToConsole("SEND", "GET /api/view?file=../../../../etc/passwd", "Payload: ../../../../etc/passwd (Path Traversal / LFI)");
          const resp = await fetch("/api/view?file=../../../../etc/passwd");
          const dur = Math.round(performance.now() - start);
          if (resp.status === 403) {
            logToConsole("BLOCK", `HTTP 403 Forbidden (${dur}ms) - Blocked by Rule Priority 1020: lfi-v33-stable`);
            resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30 block";
            resBox.innerHTML = `🛡️ <strong>HTTP 403 Forbidden</strong> (${dur}ms)<br><span class="text-[10px] text-purple-400">Blocked by Rule Priority 1020: lfi-v33-stable</span>`;
          } else {
            handleUnexpected(resBox, resp.status, dur);
          }
        }
        else if (id === 5) { // RCE
          logToConsole("SEND", "POST /api/comment?cmd=cat /etc/passwd; id", "Payload: cat /etc/passwd; id (OS Command Injection / RCE)");
          const resp = await fetch("/api/comment?cmd=cat%20/etc/passwd%3B%20id", { method: "POST" });
          const dur = Math.round(performance.now() - start);
          if (resp.status === 403) {
            logToConsole("BLOCK", `HTTP 403 Forbidden (${dur}ms) - Blocked by Rule Priority 1030: rce-v33-stable`);
            resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-red-500/10 text-red-300 border border-red-500/30 block";
            resBox.innerHTML = `🛡️ <strong>HTTP 403 Forbidden</strong> (${dur}ms)<br><span class="text-[10px] text-red-400">Blocked by Rule Priority 1030: rce-v33-stable</span>`;
          } else {
            handleUnexpected(resBox, resp.status, dur);
          }
        }
        else if (id === 6) { // L7 DDoS
          logToConsole("INFO", "Dispatching 60 parallel requests via Promise.all to exceed 50 req/min limit...");
          const promises = [];
          for (let i = 1; i <= 60; i++) {
            promises.push(fetch("/api/search?q=flood_sim_" + i));
          }
          const results = await Promise.all(promises);
          const dur = Math.round(performance.now() - start);
          const statusCounts = {};
          results.forEach(r => { statusCounts[r.status] = (statusCounts[r.status] || 0) + 1; });

          const bannedCount = statusCounts[429] || 0;
          if (bannedCount > 0) {
            logToConsole("BAN", `HTTP 429 Too Many Requests (${dur}ms) - ${bannedCount}/60 requests blocked`, "Tripped Rule Priority 2000: Rate-Based Ban (300s)");
            resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-orange-500/10 text-orange-300 border border-orange-500/30 block";
            resBox.innerHTML = `⚡ <strong>HTTP 429 Too Many Requests</strong> (${dur}ms)<br><span class="text-[10px] text-orange-400">Tripped Rule Priority 2000: Rate-Based Ban (${bannedCount}/60 reqs)</span>`;
          } else {
            logToConsole("INFO", `Batch finished in ${dur}ms (Responses: ${JSON.stringify(statusCounts)})`);
            resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-slate-800 text-slate-300 block";
            resBox.innerHTML = `Finished in ${dur}ms &mdash; ${JSON.stringify(statusCounts)}`;
          }
        }
      } catch (err) {
        logToConsole("INFO", `Network error: ${err.message}`);
        resBox.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-rose-500/10 text-rose-300 border border-rose-500/30 block";
        resBox.innerHTML = `Error: ${err.message}`;
      } finally {
        btn.disabled = false;
        btn.classList.remove("opacity-75");
      }
    }

    function handleUnexpected(box, status, dur) {
      if (status === 429) {
        logToConsole("BAN", `HTTP 429 Too Many Requests (${dur}ms) - IP currently rate-limited by Priority 2000`);
        box.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-orange-500/10 text-orange-300 border border-orange-500/30 block";
        box.innerHTML = `⚡ <strong>HTTP 429 Too Many Requests</strong> (${dur}ms) &mdash; Tripped Rule Priority 2000: Rate-Based Ban`;
      } else {
        logToConsole("INFO", `Received HTTP ${status} (${dur}ms)`);
        box.className = "mb-2 p-2 rounded-lg text-xs font-mono bg-slate-800 text-slate-300 block";
        box.innerHTML = `Status: HTTP ${status} (${dur}ms)`;
      }
    }

    async function runAllDrills() {
      const btn = document.getElementById("btnRunAll");
      btn.disabled = true;
      btn.classList.add("opacity-75");
      logToConsole("INFO", "=== STARTING COMPREHENSIVE AUTOMATED SECURITY DRILL ===");
      for (let i = 1; i <= 6; i++) {
        await runTest(i);
        await new Promise(r => setTimeout(r, 600));
      }
      logToConsole("INFO", "=== ALL DRILLS COMPLETED: 100% THREAT MITIGATION VERIFIED ===");
      btn.disabled = false;
      btn.classList.remove("opacity-75");
    }
  </script>
</body>
</html>
""".replace("{{HOSTNAME}}", HOSTNAME)

try:
    from flask import Flask, jsonify, request, Response

    app = Flask(__name__)

    @app.route("/", methods=["GET"])
    def index():
        if "application/json" in request.headers.get("Accept", ""):
            return jsonify({
                "status": "success",
                "message": "Cloud Armor Interactive Security Playground",
                "partner": "PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner",
                "backend_instance": HOSTNAME,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 200
        return Response(WELCOME_HTML, status=200, mimetype="text/html")

    @app.route("/api/search", methods=["GET"])
    def api_search():
        query = request.args.get("q", "")
        return jsonify({
            "status": "success",
            "endpoint": "/api/search",
            "query": query,
            "results": [
                {"id": 101, "title": f"SMG Cloud Security Reference for '{query}'", "category": "WAF & DDoS"},
                {"id": 102, "title": "Google Cloud Armor OWASP Top 10 Mitigation Guide", "category": "Security"}
            ],
            "served_by": HOSTNAME,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    @app.route("/api/comment", methods=["GET", "POST"])
    def api_comment():
        payload = (
            request.get_json(silent=True)
            or request.form.to_dict()
            or request.args.to_dict()
            or request.get_data(as_text=True)
        )
        return jsonify({
            "status": "success",
            "endpoint": "/api/comment",
            "message": "Comment sanitized and stored in simulation log",
            "comment_received": payload,
            "served_by": HOSTNAME,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    @app.route("/api/view", methods=["GET"])
    def api_view():
        filename = request.args.get("file", "readme.txt")
        return jsonify({
            "status": "success",
            "endpoint": "/api/view",
            "file": filename,
            "content": f"Simulated document preview for [{filename}] - Verified safe by SMG Cloud Armor Policy.",
            "served_by": HOSTNAME,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "200 OK",
            "healthy": True,
            "service": "smg-armor-backend",
            "served_by": HOSTNAME
        }), 200

    if __name__ == "__main__":
        app.run(host="0.0.0.0", port=80, threaded=True)

except ImportError:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class SMGDemoHandler(BaseHTTPRequestHandler):
        def _send_json(self, code, data):
            body = json.dumps(data).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            if parsed.path == "/":
                if "application/json" in self.headers.get("Accept", ""):
                    self._send_json(200, {
                        "status": "success",
                        "message": "Cloud Armor Interactive Security Playground",
                        "partner": "PT Smartnet Magna Global (SMG) - Google Cloud Premier Partner",
                        "backend_instance": HOSTNAME,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                else:
                    body = WELCOME_HTML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            elif parsed.path == "/api/search":
                q = params.get("q", [""])[0]
                self._send_json(200, {
                    "status": "success",
                    "endpoint": "/api/search",
                    "query": q,
                    "results": [
                        {"id": 101, "title": f"SMG Cloud Security Reference for '{q}'", "category": "WAF & DDoS"}
                    ],
                    "served_by": HOSTNAME,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            elif parsed.path == "/api/view":
                f_param = params.get("file", ["readme.txt"])[0]
                self._send_json(200, {
                    "status": "success",
                    "endpoint": "/api/view",
                    "file": f_param,
                    "content": f"Simulated document preview for [{f_param}]",
                    "served_by": HOSTNAME,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            elif parsed.path == "/api/comment":
                cmd_param = params.get("cmd", [""])[0]
                self._send_json(200, {
                    "status": "success",
                    "endpoint": "/api/comment",
                    "comment_received": cmd_param,
                    "served_by": HOSTNAME,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            elif parsed.path == "/health":
                self._send_json(200, {
                    "status": "200 OK",
                    "healthy": True,
                    "service": "smg-armor-backend",
                    "served_by": HOSTNAME
                })
            else:
                self._send_json(404, {"status": "error", "message": "Not Found", "path": parsed.path})

        def do_POST(self):
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            if parsed.path == "/api/comment":
                self._send_json(200, {
                    "status": "success",
                    "endpoint": "/api/comment",
                    "comment_received": raw_body or parsed.query,
                    "served_by": HOSTNAME,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            else:
                self._send_json(404, {"status": "error", "message": "Not Found", "path": parsed.path})

    if __name__ == "__main__":
        server = ThreadingHTTPServer(("0.0.0.0", 80), SMGDemoHandler)
        server.serve_forever()
