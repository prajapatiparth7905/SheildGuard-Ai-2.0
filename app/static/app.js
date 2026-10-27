/**
 * ShieldGuard AI 2.0 - Multi-Vector Threat Intelligence Platform Frontend Client
 */

// Global State
let latestBulkResults = [];
let categoriesChartInstance = null;
let verdictsChartInstance = null;
let lastScanResult = null;

// API Endpoint & Connectivity Helper
function getApiBase() {
  return (localStorage.getItem("shieldguard_api_base") || "").trim().replace(/\/+$/, "");
}

async function apiFetch(endpoint, options = {}) {
  const base = getApiBase();
  const url = base ? `${base}${endpoint}` : endpoint;
  return fetch(url, options);
}

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initSidebar();
  initInputErgonomics();
  initCopySummary();
  initApiConfig();
  initTabs();
  initHealthMonitor();
  initStats();
  initPhoneScanner();
  initEmailScanner();
  initContentScanner();
  initUrlScanner();
  initQrScanner();
  initCombinedScanner();
  initBulkScanner();
  initThreatVisualizations();
  initScamReports();
  initAcademicModal();
  initApiDirectoryModal();
  initPrintReport();
});

// ==========================================================================
// Toast Notification Helper
// ==========================================================================
function showToast(message, isError = false) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.style.borderColor = isError ? "#ef4444" : "#10b981";
  toast.className = "show";
  setTimeout(() => {
    toast.className = "";
  }, 3500);
}

// ==========================================================================
// Live Backend Health & Latency Monitor
// ==========================================================================
async function initHealthMonitor() {
  const pill = document.getElementById("backendStatusPill");
  const text = document.getElementById("backendStatusText");
  const dot = pill ? pill.querySelector(".badge-dot") : null;

  async function checkHealth() {
    const startTime = performance.now();
    try {
      const res = await apiFetch("/api/health");
      const latency = Math.round(performance.now() - startTime);

      if (res.ok) {
        const data = await res.json();
        if (text) text.textContent = `Backend Online (${latency}ms)`;
        if (dot) {
          dot.className = "badge-dot pulse";
        }
        if (pill) {
          pill.style.borderColor = "rgba(16, 185, 129, 0.4)";
          pill.title = `Connected to ShieldGuard ${data.system_version} | DB: ${data.database_status} | Latency: ${latency}ms`;
        }
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (err) {
      if (text) text.textContent = "Backend Offline / Disconnected";
      if (dot) {
        dot.className = "badge-dot offline";
      }
      if (pill) {
        pill.style.borderColor = "rgba(239, 68, 68, 0.4)";
        pill.title = "Failed to connect to backend. Please check server status.";
      }
    }
  }

  checkHealth();
  // Check health every 15 seconds
  setInterval(checkHealth, 15000);
}

// ==========================================================================
// Theme Handling (Light / Dark)
// ==========================================================================
function initTheme() {
  const toggleBtn = document.getElementById("themeToggle");
  const themeIcon = document.getElementById("themeIcon");
  const currentTheme = localStorage.getItem("sg_theme") || "dark";

  document.documentElement.setAttribute("data-theme", currentTheme);
  if (themeIcon) {
    themeIcon.textContent = currentTheme === "dark" ? "☀️" : "🌙";
  }

  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const active = document.documentElement.getAttribute("data-theme");
      const next = active === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("sg_theme", next);
      if (themeIcon) {
        themeIcon.textContent = next === "dark" ? "☀️" : "🌙";
      }
      if (categoriesChartInstance || verdictsChartInstance) {
        initThreatVisualizations();
      }
    });
  }
}

// ==========================================================================
// API Endpoint Configuration Modal Handler
// ==========================================================================
function initApiConfig() {
  const modal = document.getElementById("apiConfigModal");
  const openBtn = document.getElementById("apiConfigBtn");
  const closeBtn = document.getElementById("closeApiModalBtn");
  const saveBtn = document.getElementById("saveApiUrlBtn");
  const resetBtn = document.getElementById("resetApiUrlBtn");
  const input = document.getElementById("apiBaseUrlInput");
  const docsLink = document.getElementById("apiDocsLink");

  const currentBase = getApiBase();
  if (docsLink && currentBase) {
    docsLink.href = `${currentBase}/docs`;
  }

  if (openBtn && modal) {
    openBtn.addEventListener("click", () => {
      if (input) input.value = getApiBase();
      modal.style.display = "flex";
    });
  }

  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => {
      modal.style.display = "none";
    });
  }

  if (modal) {
    modal.addEventListener("click", e => {
      if (e.target === modal) modal.style.display = "none";
    });
  }

  if (saveBtn) {
    saveBtn.addEventListener("click", () => {
      const val = input ? input.value.trim().replace(/\/+$/, "") : "";
      if (val) {
        localStorage.setItem("shieldguard_api_base", val);
        showToast("Backend API URL set to: " + val);
      } else {
        localStorage.removeItem("shieldguard_api_base");
        showToast("Backend API reset to same-origin / local server.");
      }
      if (docsLink) {
        docsLink.href = val ? `${val}/docs` : "/docs";
      }
      if (modal) modal.style.display = "none";
      initStats();
      initHealthMonitor();
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      localStorage.removeItem("shieldguard_api_base");
      if (input) input.value = "";
      if (docsLink) docsLink.href = "/docs";
      showToast("Reset to default same-origin backend.");
      if (modal) modal.style.display = "none";
      initStats();
      initHealthMonitor();
    });
  }
}

// ==========================================================================
// Sidebar Controller & Navigation
// ==========================================================================
function initSidebar() {
  const sidebar = document.getElementById("sidebar");
  const collapseBtn = document.getElementById("sidebarCollapseBtn");
  const mobileMenuBtn = document.getElementById("mobileMenuBtn");
  const backdrop = document.getElementById("sidebarBackdrop");

  // Restore collapsed state preference from localStorage
  const isCollapsed = localStorage.getItem("sg_sidebar_collapsed") === "1";
  if (isCollapsed && sidebar) {
    sidebar.classList.add("collapsed");
  }

  if (collapseBtn && sidebar) {
    collapseBtn.addEventListener("click", () => {
      sidebar.classList.toggle("collapsed");
      localStorage.setItem("sg_sidebar_collapsed", sidebar.classList.contains("collapsed") ? "1" : "0");
    });
  }

  if (mobileMenuBtn && sidebar && backdrop) {
    mobileMenuBtn.addEventListener("click", () => {
      sidebar.classList.toggle("mobile-open");
      backdrop.classList.toggle("mobile-open");
    });

    backdrop.addEventListener("click", () => {
      sidebar.classList.remove("mobile-open");
      backdrop.classList.remove("mobile-open");
    });
  }

  // Sidebar modal shortcuts
  const sidebarReportBtn = document.getElementById("sidebarPrintReportBtn");
  const sidebarAcademicBtn = document.getElementById("sidebarAcademicInfoBtn");
  const sidebarApiBtn = document.getElementById("sidebarApiDirectoryBtn");

  if (sidebarReportBtn) {
    sidebarReportBtn.addEventListener("click", () => {
      const mainBtn = document.getElementById("printReportBtn");
      if (mainBtn) mainBtn.click();
    });
  }

  if (sidebarAcademicBtn) {
    sidebarAcademicBtn.addEventListener("click", () => {
      const mainBtn = document.getElementById("academicInfoBtn");
      if (mainBtn) mainBtn.click();
    });
  }

  if (sidebarApiBtn) {
    sidebarApiBtn.addEventListener("click", () => {
      const mainBtn = document.getElementById("apiDirectoryBtn");
      if (mainBtn) mainBtn.click();
    });
  }
}

// ==========================================================================
// Input Ergonomics (1-Click Paste & Clear)
// ==========================================================================
function initInputErgonomics() {
  document.querySelectorAll(".btn-paste").forEach(btn => {
    btn.addEventListener("click", async () => {
      const targetId = btn.getAttribute("data-target");
      const input = document.getElementById(targetId);
      if (!input) return;

      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          input.value = text.trim();
          input.dispatchEvent(new Event("input", { bubbles: true }));
          input.dispatchEvent(new Event("change", { bubbles: true }));
          input.focus();
          showToast("Pasted from clipboard!");
        } else {
          showToast("Clipboard is empty or does not contain text.", true);
        }
      } catch (err) {
        showToast("Please allow clipboard permissions or use Ctrl+V.", true);
      }
    });
  });

  document.querySelectorAll(".btn-clear").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const input = document.getElementById(targetId);
      if (input) {
        input.value = "";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
        input.focus();
      }
    });
  });
}

// ==========================================================================
// Copy Analysis Summary to Clipboard
// ==========================================================================
function initCopySummary() {
  document.querySelectorAll(".btn-copy-summary").forEach(btn => {
    btn.addEventListener("click", () => {
      if (!lastScanResult || !lastScanResult.data) {
        showToast("No active scan findings to copy.", true);
        return;
      }

      const d = lastScanResult.data;
      const target = d.phone_number || d.email || d.url || d.raw_payload || "Evaluated Entity";
      const score = d.risk_score || d.overall_risk_score || 0;
      const level = d.risk_level || d.overall_risk_level || "SAFE";
      const verdict = d.verdict || "COMPLETE";
      const threats = (d.threat_factors || []).map(t => `- ${t.name || t}`).join("\n") || "- No threat factors identified.";
      const recs = (d.recommendations || []).map(r => `- ${r}`).join("\n") || "- Standard defensive telemetry.";

      const summaryText = [
        `🛡️ [ShieldGuard AI Threat Intelligence Report]`,
        `Target: ${target}`,
        `Threat Level: ${level} (${score}/100)`,
        `Verdict: ${verdict}`,
        `\nIdentified Threat Indicators:\n${threats}`,
        `\nAnalyst Recommendations:\n${recs}`,
        `\nTimestamp: ${new Date().toUTCString()}`
      ].join("\n");

      navigator.clipboard.writeText(summaryText)
        .then(() => showToast("Forensic analysis summary copied to clipboard!"))
        .catch(() => showToast("Failed to copy summary to clipboard.", true));
    });
  });
}

// ==========================================================================
// Tab Navigation
// ==========================================================================
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const breadcrumb = document.getElementById("activeBreadcrumb");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => (c.style.display = "none"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.style.display = "block";
      }

      const title = btn.getAttribute("data-title") || btn.querySelector(".nav-label")?.textContent || "Threat Intelligence";
      if (breadcrumb) {
        breadcrumb.textContent = title;
      }

      // Close mobile drawer on navigation
      const sidebar = document.getElementById("sidebar");
      const backdrop = document.getElementById("sidebarBackdrop");
      if (sidebar && sidebar.classList.contains("mobile-open")) {
        sidebar.classList.remove("mobile-open");
        backdrop?.classList.remove("mobile-open");
      }

      if (targetId === "analyticsTab") {
        initThreatVisualizations();
      }
    });
  });
}

// ==========================================================================
// Statistics Loader
// ==========================================================================
async function initStats() {
  try {
    const res = await apiFetch("/api/stats");
    if (!res.ok) return;
    const data = await res.json();
    const scansEl = document.getElementById("statTotalScans");
    const threatsEl = document.getElementById("statThreatsDetected");
    const reportsEl = document.getElementById("statCommunityReports");

    if (scansEl) scansEl.textContent = Number(data.total_scans_performed || 0).toLocaleString();
    if (threatsEl) threatsEl.textContent = Number(data.threats_detected || 0).toLocaleString();
    if (reportsEl) reportsEl.textContent = Number(data.total_scam_reports || 0).toLocaleString();
  } catch (err) {
    console.error("Failed to load stats:", err);
  }
}

// ==========================================================================
// Animated Risk Gauge Meter Helper
// ==========================================================================
function updateGauge(gaugeSectionId, progressId, valId, badgeId, titleId, score, level, verdictText) {
  const section = document.getElementById(gaugeSectionId);
  const progress = document.getElementById(progressId);
  const val = document.getElementById(valId);
  const badge = document.getElementById(badgeId);
  const title = document.getElementById(titleId);

  if (section) section.className = `gauge-section ${level.toLowerCase()}`;

  if (progress) {
    const maxCircumference = 251.2;
    const offset = maxCircumference - (score / 100) * maxCircumference;
    progress.style.strokeDashoffset = offset;

    let strokeColor = "#10b981"; // Safe green
    if (level === "DANGEROUS") strokeColor = "#ef4444";
    else if (level === "SUSPICIOUS") strokeColor = "#f97316";
    else if (level === "LOW_RISK") strokeColor = "#f59e0b";
    progress.style.stroke = strokeColor;
  }

  if (val) val.textContent = `${score}%`;
  if (badge) {
    badge.className = `verdict-badge badge-${level.toLowerCase()}`;
    badge.textContent = level.replace("_", " ");
  }
  if (title) title.textContent = verdictText;
}

// Render Threat Factors
function renderThreatFactors(containerId, countId, threats) {
  const container = document.getElementById(containerId);
  const countEl = document.getElementById(countId);
  if (!container || !countEl) return;

  container.innerHTML = "";
  countEl.textContent = threats.length;

  if (threats.length === 0) {
    container.innerHTML = `
      <div style="font-size: 13.5px; color: #10b981; padding: 10px 0; display: flex; align-items: center; gap: 8px;">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        No malicious patterns or reputation threats identified.
      </div>
    `;
    return;
  }

  threats.forEach(t => {
    const item = document.createElement("div");
    item.className = `threat-item ${t.severity}`;
    item.innerHTML = `
      <div class="threat-title-row">
        <h5>${escapeHtml(t.name)}</h5>
        <span class="threat-severity sev-${t.severity}">${t.severity}</span>
      </div>
      <p>${escapeHtml(t.description)}</p>
    `;
    container.appendChild(item);
  });
}

// Render Recommendations
function renderRecommendations(containerId, recs) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = "";
  recs.forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    container.appendChild(li);
  });
}

// Render AI Threat Briefing
function renderAiBriefing(briefingBoxId, textId, text) {
  const box = document.getElementById(briefingBoxId);
  const textEl = document.getElementById(textId);
  if (!box || !textEl) return;

  if (text) {
    box.style.display = "block";
    textEl.textContent = text;
  } else {
    box.style.display = "none";
  }
}

// ==========================================================================
// Phone Scanner Controller
// ==========================================================================
function initPhoneScanner() {
  const form = document.getElementById("phoneForm");
  const phoneInput = document.getElementById("phoneInput");
  const countrySelect = document.getElementById("countrySelect");
  const submitBtn = document.getElementById("phoneSubmitBtn");
  const emptyView = document.getElementById("phoneEmpty");
  const resultView = document.getElementById("phoneResult");

  if (!form) return;

  document.querySelectorAll("#phoneTab .preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      phoneInput.value = chip.getAttribute("data-phone");
      countrySelect.value = chip.getAttribute("data-country");
      form.dispatchEvent(new Event("submit"));
    });
  });

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const phone = phoneInput.value.trim();
    if (!phone) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = "Scanning Phone Intelligence...";

    try {
      const res = await apiFetch("/api/check/phone", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          phone_number: phone,
          default_country: countrySelect.value
        })
      });

      if (!res.ok) throw new Error("Server scan error");
      const data = await res.json();
      lastScanResult = { type: "phone", data };

      emptyView.style.display = "none";
      resultView.style.display = "block";

      document.getElementById("phoneTargetDisplay").textContent = data.phone_details.international_format || phone;
      updateGauge("phoneGaugeSection", "phoneGaugeProgress", "phoneGaugeVal", "phoneVerdictBadge", "phoneVerdictTitle", data.risk_score, data.risk_level, data.verdict);

      renderAiBriefing("phoneAiBriefingBox", "phoneAiBriefingText", data.ai_threat_briefing);

      document.getElementById("phoneLineType").textContent = data.phone_details.line_type || "Unknown";
      document.getElementById("phoneCountry").textContent = `${data.phone_details.location_name || "Unknown"} (${data.phone_details.country_iso || "N/A"})`;
      document.getElementById("phoneCarrier").textContent = data.phone_details.carrier_name || "Unknown / Virtual";
      document.getElementById("phoneE164").textContent = data.phone_details.e164_format || "N/A";
      document.getElementById("phoneValid").textContent = data.is_valid ? "✅ Valid Telecom Format" : "⚠️ Invalid / Non-standard";

      renderThreatFactors("phoneThreatsList", "phoneThreatsCount", data.threat_factors);
      renderRecommendations("phoneRecsList", data.recommendations);

      initStats();
    } catch (err) {
      showToast("Error scanning phone number: " + err.message, true);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Scan Phone Intelligence`;
    }
  });
}

// ==========================================================================
// Email Scanner Controller
// ==========================================================================
function initEmailScanner() {
  const form = document.getElementById("emailForm");
  const emailInput = document.getElementById("emailInput");
  const dnsCheck = document.getElementById("emailDnsCheck");
  const submitBtn = document.getElementById("emailSubmitBtn");
  const emptyView = document.getElementById("emailEmpty");
  const resultView = document.getElementById("emailResult");

  if (!form) return;

  document.querySelectorAll("#emailTab .preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      emailInput.value = chip.getAttribute("data-email");
      form.dispatchEvent(new Event("submit"));
    });
  });

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const email = emailInput.value.trim();
    if (!email) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = "Analyzing Domain & DNS...";

    try {
      const res = await apiFetch("/api/check/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email,
          perform_dns_check: dnsCheck ? dnsCheck.checked : true
        })
      });

      if (!res.ok) throw new Error("Server scan error");
      const data = await res.json();
      lastScanResult = { type: "email", data };

      emptyView.style.display = "none";
      resultView.style.display = "block";

      document.getElementById("emailTargetDisplay").textContent = data.email;
      updateGauge("emailGaugeSection", "emailGaugeProgress", "emailGaugeVal", "emailVerdictBadge", "emailVerdictTitle", data.risk_score, data.risk_level, data.verdict);

      renderAiBriefing("emailAiBriefingBox", "emailAiBriefingText", data.ai_threat_briefing);

      document.getElementById("emailDomain").textContent = data.email_details.domain || "N/A";
      document.getElementById("emailDisposable").textContent = data.email_details.is_disposable ? "🚨 YES (Burner / Disposable)" : "No (Standard Domain)";
      document.getElementById("emailBrand").textContent = data.email_details.typosquatting_detected ? `🚨 Spoofing '${data.email_details.impersonated_brand}'` : "None Detected";
      document.getElementById("emailMx").textContent = data.email_details.mx_records_found ? `✅ Active (${data.email_details.mx_hosts.length} found)` : "⚠️ No MX Records";
      document.getElementById("emailDns").textContent = data.email_details.dns_resolvable ? "✅ Resolvable Domain" : "❌ Dead / Non-existent Domain";

      renderThreatFactors("emailThreatsList", "emailThreatsCount", data.threat_factors);
      renderRecommendations("emailRecsList", data.recommendations);

      initStats();
    } catch (err) {
      showToast("Error scanning email: " + err.message, true);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Analyze Email Threat`;
    }
  });
}

// ==========================================================================
// Message Scanner & Interactive Phishing Threat Highlighter
// ==========================================================================
function initContentScanner() {
  const form = document.getElementById("contentForm");
  const contentInput = document.getElementById("contentInput");
  const submitBtn = document.getElementById("contentSubmitBtn");
  const emptyView = document.getElementById("contentEmpty");
  const resultView = document.getElementById("contentResult");
  const highlighterBox = document.getElementById("contentHighlighterBox");

  if (!form) return;

  document.querySelectorAll("#contentTab .preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      contentInput.value = chip.getAttribute("data-text");
      form.dispatchEvent(new Event("submit"));
    });
  });

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const text = contentInput.value.trim();
    if (!text) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = "Scanning Content Patterns...";

    try {
      const res = await apiFetch("/api/check/content", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text })
      });

      if (!res.ok) throw new Error("Server scan error");
      const data = await res.json();
      lastScanResult = { type: "content", data };

      emptyView.style.display = "none";
      resultView.style.display = "block";

      const categoriesStr = data.detected_categories.length > 0 ? data.detected_categories.join(", ") : "None Detected";
      const catBadge = document.getElementById("contentCategoriesBadge");
      if (catBadge) catBadge.textContent = categoriesStr;

      updateGauge("contentGaugeSection", "contentGaugeProgress", "contentGaugeVal", "contentVerdictBadge", "contentVerdictTitle", data.risk_score, data.risk_level, data.verdict);

      // Render Interactive Phishing Highlighter
      renderInteractiveHighlighter(highlighterBox, text, data);

      document.getElementById("contentCategories").textContent = categoriesStr;
      document.getElementById("contentKeywords").textContent = data.flagged_keywords.length > 0 ? data.flagged_keywords.join(", ") : "None";
      document.getElementById("contentLinks").textContent = data.extracted_urls.length > 0 ? data.extracted_urls.join(", ") : "None";

      renderThreatFactors("contentThreatsList", "contentThreatsCount", data.threat_factors);
      renderRecommendations("contentRecsList", data.recommendations);

      initStats();
    } catch (err) {
      showToast("Error scanning text: " + err.message, true);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Scan & Highlight Threats`;
    }
  });
}

function renderInteractiveHighlighter(container, rawText, data) {
  if (!container) return;
  let highlighted = escapeHtml(rawText);

  // 1. Highlight extracted URLs
  if (data.extracted_urls) {
    data.extracted_urls.forEach(url => {
      const escUrl = escapeHtml(url);
      highlighted = highlighted.split(escUrl).join(`<span class="hl-tag hl-link" title="Deceptive / Unverified Web Link">${escUrl}</span>`);
    });
  }

  // 2. Highlight Flagged Keywords
  if (data.flagged_keywords) {
    data.flagged_keywords.forEach(kw => {
      const escKw = escapeHtml(kw);
      if (escKw.length >= 3) {
        const regex = new RegExp(`(${escKw})`, "gi");
        highlighted = highlighted.replace(regex, `<span class="hl-tag hl-critical" title="High-Risk Scam Trigger Pattern">$1</span>`);
      }
    });
  }

  container.innerHTML = highlighted;
}

// ==========================================================================
// URL Phishing Deep Inspector Controller
// ==========================================================================
function initUrlScanner() {
  const form = document.getElementById("urlForm");
  const urlInput = document.getElementById("urlInput");
  const submitBtn = document.getElementById("urlSubmitBtn");
  const emptyView = document.getElementById("urlEmpty");
  const resultView = document.getElementById("urlResult");

  if (!form) return;

  document.querySelectorAll("#urlTab .preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      urlInput.value = chip.getAttribute("data-url");
      form.dispatchEvent(new Event("submit"));
    });
  });

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = "Deep Inspecting URL Structure...";

    try {
      const res = await apiFetch("/api/check/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
      });

      if (!res.ok) throw new Error("Server URL scan error");
      const data = await res.json();
      lastScanResult = { type: "url", data };

      emptyView.style.display = "none";
      resultView.style.display = "block";

      document.getElementById("urlTargetDisplay").textContent = data.url;
      updateGauge("urlGaugeSection", "urlGaugeProgress", "urlGaugeVal", "urlVerdictBadge", "urlVerdictTitle", data.risk_score, data.risk_level, data.verdict);

      renderAiBriefing("urlAiBriefingBox", "urlAiBriefingText", data.ai_threat_briefing);

      document.getElementById("urlDomain").textContent = data.components.registered_domain || "N/A";
      document.getElementById("urlSubdomain").textContent = data.components.subdomain ? `${data.components.subdomain} (${data.components.subdomain_count} levels)` : "None (Apex Domain)";
      document.getElementById("urlTld").textContent = data.components.tld ? `.${data.components.tld}` : "None";
      document.getElementById("urlBrand").textContent = data.impersonated_brand ? `🚨 Targeted Brand: '${data.impersonated_brand}'` : "None Detected";
      document.getElementById("urlProtocol").textContent = data.components.scheme.toUpperCase() + (data.components.port ? ` (Port ${data.components.port})` : "");

      renderThreatFactors("urlThreatsList", "urlThreatsCount", data.threat_factors);
      renderRecommendations("urlRecsList", data.recommendations);

      initStats();
    } catch (err) {
      showToast("Error inspecting URL: " + err.message, true);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Deep Inspect URL`;
    }
  });
}

// ==========================================================================
// QR Code ("Quishing") Scanner Controller
// ==========================================================================
function initQrScanner() {
  const dropZone = document.getElementById("qrDropZone");
  const fileInput = document.getElementById("qrFileInput");
  const manualForm = document.getElementById("qrManualForm");
  const manualInput = document.getElementById("qrManualInput");
  const submitBtn = document.getElementById("qrSubmitBtn");
  const emptyView = document.getElementById("qrEmpty");
  const resultView = document.getElementById("qrResult");

  if (!dropZone) return;

  // 1-Click Presets
  document.querySelectorAll("#qrTab .preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      manualInput.value = chip.getAttribute("data-qr");
      manualForm.dispatchEvent(new Event("submit"));
    });
  });

  // Dropzone click
  dropZone.addEventListener("click", () => fileInput.click());

  // Drag-and-Drop
  dropZone.addEventListener("dragover", e => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleQrImageFile(e.dataTransfer.files[0]);
    }
  });

  if (fileInput) {
    fileInput.addEventListener("change", e => {
      if (e.target.files && e.target.files[0]) {
        handleQrImageFile(e.target.files[0]);
      }
    });
  }

  function handleQrImageFile(file) {
    const reader = new FileReader();
    reader.onload = function(evt) {
      const img = new Image();
      img.onload = function() {
        const canvas = document.createElement("canvas");
        const ctx = canvas.getContext("2d");
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0, img.width, img.height);
        const imageData = ctx.getImageData(0, 0, img.width, img.height);

        // Try decoding with jsQR
        if (window.jsQR) {
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          if (code && code.data) {
            manualInput.value = code.data;
            showToast("QR Code successfully decoded!");
            manualForm.dispatchEvent(new Event("submit"));
            return;
          }
        }
        showToast("Could not decode QR image. Please paste decoded text manually.", true);
      };
      img.src = evt.target.result;
    };
    reader.readAsDataURL(file);
  }

  if (manualForm) {
    manualForm.addEventListener("submit", async e => {
      e.preventDefault();
      const qrData = manualInput.value.trim();
      if (!qrData) return;

      submitBtn.disabled = true;
      submitBtn.innerHTML = "Evaluating QR Payload...";

      try {
        const res = await apiFetch("/api/check/qr", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ qr_data: qrData })
        });

        if (!res.ok) throw new Error("Quishing scan error");
        const data = await res.json();
        lastScanResult = { type: "qr", data };

        emptyView.style.display = "none";
        resultView.style.display = "block";

        document.getElementById("qrTargetDisplay").textContent = qrData.slice(0, 45) + (qrData.length > 45 ? "..." : "");
        updateGauge("qrGaugeSection", "qrGaugeProgress", "qrGaugeVal", "qrVerdictBadge", "qrVerdictTitle", data.risk_score, data.risk_level, data.verdict);

        document.getElementById("qrType").textContent = data.payload_type.toUpperCase();
        document.getElementById("qrPayload").textContent = data.raw_payload;
        document.getElementById("qrRiskLevel").textContent = data.risk_level;

        renderThreatFactors("qrThreatsList", "qrThreatsCount", data.threat_factors);
        renderRecommendations("qrRecsList", data.recommendations);

        initStats();
      } catch (err) {
        showToast("Error scanning QR payload: " + err.message, true);
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Scan Decoded QR Payload`;
      }
    });
  }
}

// ==========================================================================
// Combined 360 Scanner Controller
// ==========================================================================
function initCombinedScanner() {
  const form = document.getElementById("combinedForm");
  const phoneIn = document.getElementById("combPhone");
  const emailIn = document.getElementById("combEmail");
  const textIn = document.getElementById("combText");
  const submitBtn = document.getElementById("combSubmitBtn");
  const resultView = document.getElementById("combResult");

  if (!form) return;

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const text = textIn.value.trim();
    if (!text) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = "Executing 360° Threat Scan...";

    try {
      const res = await apiFetch("/api/check/combined", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender_phone: phoneIn.value.trim() || null,
          sender_email: emailIn.value.trim() || null,
          message_text: text
        })
      });

      if (!res.ok) throw new Error("Combined scan error");
      const data = await res.json();
      lastScanResult = { type: "combined", data };

      resultView.style.display = "block";
      updateGauge("combGaugeSection", "combGaugeProgress", "combGaugeVal", "combVerdictBadge", "combVerdictTitle", data.overall_risk_score, data.overall_risk_level, data.verdict);

      const threatsContainer = document.getElementById("combThreatsList");
      threatsContainer.innerHTML = "";
      if (data.summary_threats.length === 0) {
        threatsContainer.innerHTML = `<div style="color: #10b981; font-size: 13.5px;">✅ No critical threat indicators found across phone, email, or message.</div>`;
      } else {
        data.summary_threats.forEach(st => {
          const div = document.createElement("div");
          div.className = "threat-item CRITICAL";
          div.innerHTML = `<p style="color: var(--text-main); font-weight: 600;">${escapeHtml(st)}</p>`;
          threatsContainer.appendChild(div);
        });
      }

      renderRecommendations("combRecsList", data.recommendations);
      resultView.scrollIntoView({ behavior: "smooth" });
      initStats();
    } catch (err) {
      showToast("Combined scan error: " + err.message, true);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Perform 360° Comprehensive Scan`;
    }
  });
}

// ==========================================================================
// Bulk Scanner Controller
// ==========================================================================
function initBulkScanner() {
  const form = document.getElementById("bulkForm");
  const input = document.getElementById("bulkInput");
  const submitBtn = document.getElementById("bulkSubmitBtn");
  const exportBtn = document.getElementById("bulkExportBtn");
  const resultsWrap = document.getElementById("bulkResultsWrap");
  const tbody = document.getElementById("bulkTableBody");

  if (!form) return;

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const rawLines = input.value.split("\n").map(l => l.trim()).filter(Boolean);
    if (rawLines.length === 0) return;

    submitBtn.disabled = true;
    submitBtn.innerHTML = `Batch Processing ${rawLines.length} Items...`;

    try {
      const res = await apiFetch("/api/check/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ items: rawLines })
      });

      if (!res.ok) throw new Error("Bulk scan error");
      const data = await res.json();
      latestBulkResults = data.results;

      resultsWrap.style.display = "block";
      if (exportBtn) exportBtn.style.display = "inline-flex";

      document.getElementById("bulkTotal").textContent = data.total_processed;
      document.getElementById("bulkSafe").textContent = data.safe_count;
      document.getElementById("bulkSuspicious").textContent = data.suspicious_count;
      document.getElementById("bulkDangerous").textContent = data.dangerous_count;

      tbody.innerHTML = "";
      data.results.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td style="font-family: monospace; font-weight: 600;">${escapeHtml(r.item)}</td>
          <td><span style="font-size: 11px; text-transform: uppercase; background: var(--bg-secondary); padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border-color);">${r.item_type}</span></td>
          <td style="font-weight: 800;">${r.risk_score}%</td>
          <td><span class="verdict-badge badge-${r.risk_level.toLowerCase()}">${r.risk_level}</span></td>
          <td style="color: var(--text-muted);">${escapeHtml(r.key_issue)}</td>
        `;
        tbody.appendChild(tr);
      });

      showToast(`Batch completed: ${data.total_processed} items processed.`);
      initStats();
    } catch (err) {
      showToast("Bulk scan failed: " + err.message, true);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Process Batch Items`;
    }
  });

  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      if (latestBulkResults.length === 0) return;
      let csv = "Target Item,Type,Risk Score,Verdict,Primary Threat Indicator\n";
      latestBulkResults.forEach(r => {
        csv += `"${r.item}","${r.item_type}",${r.risk_score},"${r.risk_level}","${r.key_issue}"\n`;
      });

      const blob = new Blob([csv], { type: "text/csv" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.setAttribute("href", url);
      a.setAttribute("download", `shieldguard_threat_scan_${Date.now()}.csv`);
      a.click();
    });
  }
}

// ==========================================================================
// Threat Visualizations & Live Chart.js Visualizer
// ==========================================================================
async function initThreatVisualizations() {
  const catCanvas = document.getElementById("categoriesChart");
  const verCanvas = document.getElementById("verdictsChart");
  const refreshBtn = document.getElementById("refreshChartsBtn");
  const recentTable = document.getElementById("recentScansTableBody");

  if (!catCanvas || !verCanvas || typeof Chart === "undefined") return;

  try {
    const [chartRes, recentRes] = await Promise.all([
      apiFetch("/api/analytics/charts"),
      apiFetch("/api/analytics/recent")
    ]);

    if (!chartRes.ok) return;
    const chartData = await chartRes.json();

    // Chart 1: Categories Doughnut
    if (categoriesChartInstance) categoriesChartInstance.destroy();
    categoriesChartInstance = new Chart(catCanvas, {
      type: "doughnut",
      data: {
        labels: chartData.categories.labels,
        datasets: [{
          data: chartData.categories.data,
          backgroundColor: ["#ef4444", "#f97316", "#8b5cf6", "#06b6d4", "#10b981", "#ec4899"],
          borderWidth: 1,
          borderColor: "#1e293b"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#9ca3af", font: { size: 11 } }
          }
        }
      }
    });

    // Chart 2: Verdicts Bar Chart
    if (verdictsChartInstance) verdictsChartInstance.destroy();
    verdictsChartInstance = new Chart(verCanvas, {
      type: "bar",
      data: {
        labels: ["Safe", "Low Risk", "Suspicious", "Dangerous"],
        datasets: [{
          label: "Scans Count",
          data: [
            chartData.verdicts.safe,
            chartData.verdicts.low_risk,
            chartData.verdicts.suspicious,
            chartData.verdicts.dangerous
          ],
          backgroundColor: ["#10b981", "#f59e0b", "#f97316", "#ef4444"],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#9ca3af" }, grid: { display: false } },
          y: { ticks: { color: "#9ca3af" }, grid: { color: "rgba(255,255,255,0.06)" } }
        }
      }
    });

    // Recent Scans Table
    if (recentRes.ok && recentTable) {
      const recentLogs = await recentRes.json();
      recentTable.innerHTML = "";
      if (recentLogs.length === 0) {
        recentTable.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No scan logs recorded yet.</td></tr>`;
      } else {
        recentLogs.forEach(log => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td style="color: var(--text-muted); font-size: 11.5px;">${new Date(log.created_at).toLocaleTimeString()}</td>
            <td><span style="font-size: 11px; text-transform: uppercase; background: var(--bg-secondary); padding: 2px 7px; border-radius: 4px;">${log.scan_type}</span></td>
            <td style="font-family: monospace; font-size: 12.5px;">${escapeHtml(log.target_value)}</td>
            <td style="font-weight: 700;">${log.risk_score}%</td>
            <td><span class="verdict-badge badge-${log.verdict.toLowerCase()}">${log.verdict}</span></td>
          `;
          recentTable.appendChild(tr);
        });
      }
    }
  } catch (err) {
    console.error("Failed to render threat visualizations:", err);
  }

  if (refreshBtn) {
    refreshBtn.onclick = () => initThreatVisualizations();
  }
}

// ==========================================================================
// Academic Presentation & Viva Specifications Modal
// ==========================================================================
function initAcademicModal() {
  const modal = document.getElementById("academicModal");
  const openBtn = document.getElementById("academicInfoBtn");
  const closeBtn = document.getElementById("closeAcademicModalBtn");

  if (openBtn && modal) {
    openBtn.addEventListener("click", () => {
      modal.style.display = "flex";
    });
  }

  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => {
      modal.style.display = "none";
    });
  }

  if (modal) {
    modal.addEventListener("click", e => {
      if (e.target === modal) modal.style.display = "none";
    });
  }
}

// ==========================================================================
// API Directory & Free Tier Modal
// ==========================================================================
function initApiDirectoryModal() {
  const modal = document.getElementById("apiDirectoryModal");
  const openBtn = document.getElementById("apiDirectoryBtn");
  const closeBtn = document.getElementById("closeApiDirectoryModalBtn");
  const container = document.getElementById("apisListContainer");

  async function loadApis() {
    if (!container) return;
    try {
      const res = await apiFetch("/api/system/apis");
      if (!res.ok) return;
      const apis = await res.json();

      container.innerHTML = "";
      apis.forEach(api => {
        const card = document.createElement("div");
        card.className = "api-card";
        card.innerHTML = `
          <div class="api-card-top">
            <div class="api-card-title">${escapeHtml(api.name)}</div>
            <span class="api-price-badge">${escapeHtml(api.cost)}</span>
          </div>
          <p class="api-desc">${escapeHtml(api.description)}</p>
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <div class="api-limit">Free Limit: ${escapeHtml(api.free_limit)}</div>
            <span style="font-size: 11px; padding: 2px 8px; border-radius: 4px; ${api.is_active ? "background: rgba(16,185,129,0.2); color: #10b981;" : "background: rgba(148,163,184,0.15); color: #94a3b8;"}">
              ${api.is_active ? "🟢 Active & Connected" : "⚪ Key Optional (Fallback Active)"}
            </span>
          </div>
        `;
        container.appendChild(card);
      });
    } catch (err) {
      console.error("Failed to load APIs directory:", err);
    }
  }

  if (openBtn && modal) {
    openBtn.addEventListener("click", () => {
      loadApis();
      modal.style.display = "flex";
    });
  }

  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => {
      modal.style.display = "none";
    });
  }

  if (modal) {
    modal.addEventListener("click", e => {
      if (e.target === modal) modal.style.display = "none";
    });
  }
}

// ==========================================================================
// Printable Incident Audit Report Generator
// ==========================================================================
function initPrintReport() {
  const openBtn = document.getElementById("printReportBtn");
  const modal = document.getElementById("printableReportModal");
  const closeBtn = document.getElementById("closePrintModalBtn");
  const printArea = document.getElementById("reportPrintArea");

  if (openBtn && modal) {
    openBtn.addEventListener("click", () => {
      const timestamp = new Date().toUTCString();
      const auditId = "SG-AUDIT-" + Math.floor(100000 + Math.random() * 900000);

      let targetInfo = "General Multi-Vector Audit";
      let riskScore = 0;
      let riskLevel = "SAFE";
      let verdict = "NO RECENT SCAN EXECUTED";
      let threats = [];
      let recs = [];

      if (lastScanResult && lastScanResult.data) {
        const d = lastScanResult.data;
        riskScore = d.risk_score || d.overall_risk_score || 0;
        riskLevel = d.risk_level || d.overall_risk_level || "SAFE";
        verdict = d.verdict || "ANALYSIS COMPLETE";
        threats = d.threat_factors || [];
        recs = d.recommendations || [];
        targetInfo = d.phone_number || d.email || d.url || (d.raw_payload) || "Multi-Vector Payload";
      }

      printArea.innerHTML = `
        <div style="border-bottom: 2px solid #0f172a; padding-bottom: 12px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <h2 style="margin: 0; font-size: 22px; color: #0f172a;">🛡️ ShieldGuard AI - Cyber Incident & Threat Audit Report</h2>
            <p style="margin: 4px 0 0; font-size: 13px; color: #64748b;">Academic Final Year Project Demonstration | System Version 2.0</p>
          </div>
          <div style="text-align: right; font-size: 12.5px; color: #64748b;">
            <div><strong>Audit Reference:</strong> ${auditId}</div>
            <div><strong>Generated:</strong> ${timestamp}</div>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;">
            <div style="font-size: 12px; font-weight: 700; color: #64748b; text-transform: uppercase;">Evaluated Target Entity</div>
            <div style="font-size: 16px; font-weight: 700; font-family: monospace; color: #0f172a; margin-top: 4px;">${escapeHtml(targetInfo)}</div>
          </div>
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px;">
            <div style="font-size: 12px; font-weight: 700; color: #64748b; text-transform: uppercase;">Calculated Threat Risk</div>
            <div style="font-size: 18px; font-weight: 800; color: ${riskLevel === "DANGEROUS" ? "#dc2626" : riskLevel === "SUSPICIOUS" ? "#ea580c" : "#16a34a"}; margin-top: 4px;">
              ${riskScore}/100 (${riskLevel}) - ${escapeHtml(verdict)}
            </div>
          </div>
        </div>

        <h3 style="font-size: 15px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 12px;">Identified Forensic Threat Factors</h3>
        <div style="margin-bottom: 20px;">
          ${threats.length === 0 ? "<p style='color: #16a34a; font-size: 13.5px;'>No threat factors detected. Target passed all heuristic and signature checks.</p>" : threats.map(t => `
            <div style="margin-bottom: 10px; padding: 10px; background: #fff1f2; border-left: 4px solid #e11d48; border-radius: 4px;">
              <div style="font-weight: 700; font-size: 13.5px; color: #9f1239;">${escapeHtml(t.name || t)}</div>
              <div style="font-size: 12.5px; color: #475569; margin-top: 2px;">${escapeHtml(t.description || "Identified security threat anomaly.")}</div>
            </div>
          `).join("")}
        </div>

        <h3 style="font-size: 15px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 12px;">Analyst Defensive Mitigation Protocol</h3>
        <ul style="font-size: 13.5px; color: #334155; line-height: 1.6; margin-left: 20px;">
          ${recs.length === 0 ? "<li>Maintain continuous telemetry and zero-trust authentication protocols.</li>" : recs.map(r => `<li>${escapeHtml(r)}</li>`).join("")}
        </ul>

        <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 11px; color: #94a3b8; text-align: center;">
          ShieldGuard AI Threat Intelligence System • Department of Computer Science & Engineering • Academic Project Proof of Concept
        </div>
      `;

      modal.style.display = "flex";
    });
  }

  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => {
      modal.style.display = "none";
    });
  }

  if (modal) {
    modal.addEventListener("click", e => {
      if (e.target === modal) modal.style.display = "none";
    });
  }
}

// ==========================================================================
// Community Scam Watch & Reports Controller
// ==========================================================================
function initScamReports() {
  const form = document.getElementById("reportForm");
  const feed = document.getElementById("reportsFeed");
  const refreshBtn = document.getElementById("refreshReportsBtn");
  const searchInput = document.getElementById("searchReportsInput");

  async function loadReports(searchQuery = "") {
    if (!feed) return;
    try {
      const url = searchQuery ? `/api/reports?search=${encodeURIComponent(searchQuery)}` : "/api/reports";
      const res = await apiFetch(url);
      if (!res.ok) return;
      const reports = await res.json();

      feed.innerHTML = "";
      if (reports.length === 0) {
        feed.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 40px 0;">No scam records found matching your query.</div>`;
        return;
      }

      reports.forEach(r => {
        const card = document.createElement("div");
        card.className = "report-item-card";
        card.innerHTML = `
          <div class="report-card-top">
            <div class="report-identifier">${escapeHtml(r.identifier)}</div>
            <span class="report-category">${escapeHtml(r.scam_category)}</span>
          </div>
          <div class="report-desc">${escapeHtml(r.description)}</div>
          <div class="report-footer">
            <span>Reported by: <strong>${escapeHtml(r.reported_by || "Anonymous")}</strong></span>
            <div class="vote-actions">
              <button class="btn-vote" onclick="voteReport(${r.id}, true)">👍 <span>${r.upvotes}</span></button>
              <button class="btn-vote" onclick="voteReport(${r.id}, false)">👎 <span>${r.downvotes}</span></button>
            </div>
          </div>
        `;
        feed.appendChild(card);
      });
    } catch (err) {
      console.error("Failed to load reports feed:", err);
    }
  }

  loadReports();

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      const q = searchInput ? searchInput.value.trim() : "";
      loadReports(q);
    });
  }

  if (searchInput) {
    let debounceTimer;
    searchInput.addEventListener("input", e => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        loadReports(e.target.value.trim());
      }, 300);
    });
  }

  if (form) {
    form.addEventListener("submit", async e => {
      e.preventDefault();
      const payload = {
        target_type: document.getElementById("reportTargetType").value,
        identifier: document.getElementById("reportIdentifier").value.trim(),
        scam_category: document.getElementById("reportCategory").value,
        description: document.getElementById("reportDescription").value.trim(),
        reported_by: document.getElementById("reportUser").value.trim() || "Anonymous"
      };

      try {
        const res = await apiFetch("/api/reports", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Failed to submit report");
        showToast("Scam report indexed into threat intelligence database!");
        form.reset();
        loadReports();
        initStats();
      } catch (err) {
        showToast("Error submitting report: " + err.message, true);
      }
    });
  }
}

// Global Upvote / Downvote Function
window.voteReport = async function(reportId, isUpvote) {
  try {
    const res = await apiFetch(`/api/reports/${reportId}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report_id: reportId, is_upvote: isUpvote })
    });
    if (res.ok) {
      const refreshBtn = document.getElementById("refreshReportsBtn");
      if (refreshBtn) refreshBtn.click();
      showToast(isUpvote ? "Report upvoted (+1)" : "Report downvoted (-1)");
    }
  } catch (err) {
    console.error("Vote failed:", err);
  }
};

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
