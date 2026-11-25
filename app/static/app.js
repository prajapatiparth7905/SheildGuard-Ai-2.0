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
  initAdvancedScanner();
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
  initDatasetsModal();
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
  toast.style.borderColor = isError ? "#FF525D" : "#39FF88";
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
  // Enforce the default Black × Neon Green cybersecurity dark theme
  document.documentElement.setAttribute("data-theme", "dark");
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
  const sidebarDatasetsBtn = document.getElementById("sidebarDatasetsBtn");

  if (sidebarDatasetsBtn) {
    sidebarDatasetsBtn.addEventListener("click", () => {
      const mainBtn = document.getElementById("datasetsModalBtn");
      if (mainBtn) mainBtn.click();
    });
  }

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

    let strokeColor = "#39FF88"; // Safe green
    if (level === "DANGEROUS") strokeColor = "#FF525D";
    else if (level === "SUSPICIOUS") strokeColor = "#F5B942";
    else if (level === "LOW_RISK") strokeColor = "#F5B942";
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
      <div style="font-size: 13.5px; color: #39FF88; padding: 10px 0; display: flex; align-items: center; gap: 8px;">
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

      const emailMlEl = document.getElementById("emailMlProb");
      if (emailMlEl) {
        if (data.ml_analysis && data.ml_analysis.model_available) {
          const isPhish = data.ml_analysis.prediction === "PHISHING";
          emailMlEl.innerHTML = `<span class="badge ${isPhish ? 'dangerous' : 'safe'}" style="font-size: 11px;">🤖 ${data.ml_analysis.prediction} (${data.ml_analysis.phishing_probability}%)</span>`;
        } else {
          emailMlEl.textContent = "N/A";
        }
      }

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

      const contentMlEl = document.getElementById("contentMlProb");
      if (contentMlEl) {
        if (data.ml_analysis && data.ml_analysis.model_available) {
          const isPhish = data.ml_analysis.prediction === "PHISHING";
          contentMlEl.innerHTML = `<span class="badge ${isPhish ? 'dangerous' : 'safe'}" style="font-size: 11px;">🤖 ${data.ml_analysis.prediction} (${data.ml_analysis.phishing_probability}%)</span>`;
        } else {
          contentMlEl.textContent = "N/A";
        }
      }

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

      const urlMlEl = document.getElementById("urlMlProb");
      if (urlMlEl) {
        if (data.ml_analysis && data.ml_analysis.model_available) {
          const isPhish = data.ml_analysis.prediction === "PHISHING";
          urlMlEl.innerHTML = `<span class="badge ${isPhish ? 'dangerous' : 'safe'}" style="font-size: 11px;">🤖 ${data.ml_analysis.prediction} (${data.ml_analysis.phishing_probability}%)</span>`;
        } else {
          urlMlEl.textContent = "N/A";
        }
      }

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
        threatsContainer.innerHTML = `<div style="color: #39FF88; font-size: 13.5px;">✅ No critical threat indicators found across phone, email, or message.</div>`;
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
    const isDark = document.documentElement.getAttribute("data-theme") !== "light";
    const chartCardBg = isDark ? "#101713" : "#ffffff";
    const chartTextColor = isDark ? "#A0ADA4" : "#68766C";
    const chartGridColor = isDark ? "#1E3025" : "#e2e8f0";

    if (categoriesChartInstance) categoriesChartInstance.destroy();
    categoriesChartInstance = new Chart(catCanvas, {
      type: "doughnut",
      data: {
        labels: chartData.categories.labels,
        datasets: [{
          data: chartData.categories.data,
          backgroundColor: ["#39FF88", "#00C96B", "#8DFFB5", "#F5B942", "#FF525D", "#1E3025"],
          borderWidth: 1,
          borderColor: chartCardBg
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: chartTextColor, font: { size: 11 } }
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
          backgroundColor: ["#39FF88", "#00C96B", "#F5B942", "#FF525D"],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: chartTextColor }, grid: { display: false } },
          y: { ticks: { color: chartTextColor }, grid: { color: chartGridColor } }
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
// Offline Datasets & Trained Machine Learning Models Modal
// ==========================================================================
function initDatasetsModal() {
  const modal = document.getElementById("datasetsModal");
  const openBtn = document.getElementById("datasetsModalBtn");
  const sidebarBtn = document.getElementById("sidebarDatasetsBtn");
  const closeBtn = document.getElementById("closeDatasetsModalBtn");
  const container = document.getElementById("datasetsSamplesList");

  if (openBtn) {
    openBtn.addEventListener("click", () => {
      if (modal) modal.style.display = "flex";
      loadSamples();
    });
  }

  if (sidebarBtn) {
    sidebarBtn.addEventListener("click", () => {
      if (modal) modal.style.display = "flex";
      loadSamples();
    });
  }

  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => {
      modal.style.display = "none";
    });
    modal.addEventListener("click", e => {
      if (e.target === modal) modal.style.display = "none";
    });
  }

  async function loadSamples() {
    if (!container) return;
    container.innerHTML = '<div style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 20px;">Loading dataset benchmark samples...</div>';

    try {
      const res = await apiFetch("/api/datasets/samples");
      if (!res.ok) throw new Error("Failed to load samples");
      const data = await res.json();

      container.innerHTML = "";

      const vectorLabels = {
        "url_scanner_samples": { title: "🔗 URL Phishing Benchmark Samples", tab: "urlTab", inputId: "urlInput", formId: "urlForm" },
        "content_scanner_samples": { title: "💬 Message & Social Engineering Samples", tab: "contentTab", inputId: "contentText", formId: "contentForm" },
        "email_scanner_samples": { title: "📧 Email Spoofing & Burner Samples", tab: "emailTab", inputId: "emailInput", formId: "emailForm" },
        "phone_scanner_samples": { title: "📱 Telecom & Wangiri Trap Samples", tab: "phoneTab", inputId: "phoneInput", formId: "phoneForm" },
        "qr_scanner_samples": { title: "📷 Quishing QR Payload Samples", tab: "qrTab", inputId: "manualQrInput", formId: "manualQrForm" },
        "combined_multi_vector_samples": { title: "🌐 Multi-Vector Correlation Attack Scenarios", tab: "combinedTab" }
      };

      for (const [key, meta] of Object.entries(vectorLabels)) {
        const items = data[key] || [];
        if (items.length === 0) continue;

        const groupDiv = document.createElement("div");
        groupDiv.style.marginBottom = "14px";
        groupDiv.innerHTML = `<h5 style="color: #39FF88; margin: 0 0 8px 0; font-size: 13.5px;">${meta.title}</h5>`;

        const listDiv = document.createElement("div");
        listDiv.style.display = "flex";
        listDiv.style.flexDirection = "column";
        listDiv.style.gap = "6px";

        items.forEach(sample => {
          const itemDiv = document.createElement("div");
          itemDiv.style.cssText = "background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center; gap: 10px;";

          const isDanger = sample.expected_verdict === "DANGEROUS";
          const targetText = sample.target || sample.message_text || "";

          itemDiv.innerHTML = `
            <div style="flex: 1; min-width: 0;">
              <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 2px;">
                <span class="badge ${isDanger ? 'dangerous' : 'safe'}" style="font-size: 10px;">${sample.label}</span>
                <strong style="font-size: 12.5px; color: var(--text-main); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 480px;" title="${escapeHtml(targetText)}">${escapeHtml(targetText)}</strong>
              </div>
              <div style="font-size: 11.5px; color: var(--text-muted);">${escapeHtml(sample.description || "")}</div>
            </div>
            <div style="display: flex; gap: 6px; flex-shrink: 0;">
              <button class="btn-nav btn-copy-sample" data-text="${escapeHtml(targetText)}" style="font-size: 11px; padding: 4px 8px;" title="Copy to clipboard">📋 Copy</button>
              <button class="btn-primary btn-run-sample" data-tab="${meta.tab}" data-input="${meta.inputId || ''}" data-form="${meta.formId || ''}" data-text="${escapeHtml(targetText)}" style="font-size: 11px; padding: 4px 10px;">⚡ Test Now</button>
            </div>
          `;

          listDiv.appendChild(itemDiv);
        });

        groupDiv.appendChild(listDiv);
        container.appendChild(groupDiv);
      }

      // Add listeners for copy and test now buttons
      container.querySelectorAll(".btn-copy-sample").forEach(btn => {
        btn.addEventListener("click", async () => {
          const text = btn.getAttribute("data-text");
          try {
            await navigator.clipboard.writeText(text);
            showToast("Copied sample to clipboard!");
          } catch (e) {
            showToast("Copied: " + text.slice(0, 30));
          }
        });
      });

      container.querySelectorAll(".btn-run-sample").forEach(btn => {
        btn.addEventListener("click", () => {
          const tabId = btn.getAttribute("data-tab");
          const inputId = btn.getAttribute("data-input");
          const formId = btn.getAttribute("data-form");
          const text = btn.getAttribute("data-text");

          // Close modal
          modal.style.display = "none";

          // Switch tab
          const tabBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
          if (tabBtn) tabBtn.click();

          // Fill input & submit
          if (inputId) {
            const inputEl = document.getElementById(inputId);
            if (inputEl) {
              inputEl.value = text;
              inputEl.dispatchEvent(new Event("input", { bubbles: true }));
              inputEl.dispatchEvent(new Event("change", { bubbles: true }));
            }
          }
          if (formId) {
            const formEl = document.getElementById(formId);
            if (formEl) {
              setTimeout(() => {
                formEl.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
              }, 120);
            }
          }
        });
      });

    } catch (err) {
      container.innerHTML = `<div style="color: #FF525D; font-size: 13px; text-align: center; padding: 20px;">Error loading test samples: ${err.message}</div>`;
    }
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
            <span style="font-size: 11px; padding: 2px 8px; border-radius: 4px; ${api.is_active ? "background: rgba(57,255,136,0.2); color: #39FF88;" : "background: rgba(160,173,164,0.15); color: #94a3b8;"}">
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
          ${threats.length === 0 ? "<p style='color: #39FF88; font-size: 13.5px;'>No threat factors detected. Target passed all heuristic and signature checks.</p>" : threats.map(t => `
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


// ==========================================================================
// SHIELDGUARD AI 2.0 - ADVANCED SCANNER & THREAT INTELLIGENCE CENTERPIECE
// ==========================================================================
let activeScanHistory = [];
let activeHistoryFilter = "ALL";

function initAdvancedScanner() {
  const form = document.getElementById("advScannerForm");
  const input = document.getElementById("advScannerInput");
  const submitBtn = document.getElementById("advSubmitBtn");
  const inputError = document.getElementById("advInputError");
  const scanningState = document.getElementById("advScanningState");
  const scanningStatus = document.getElementById("advScanningStatus");
  const scanningSubtext = document.getElementById("advScanningSubtext");
  const progressBar = document.getElementById("advScanningProgressBar");
  const resultsPanel = document.getElementById("advResultsPanel");
  const resultHeading = document.getElementById("advResultHeading");
  const statusBadge = document.getElementById("advStatusBadge");
  const statusBadgeText = document.getElementById("advStatusBadgeText");
  const statusIcon = document.getElementById("advStatusIcon");
  const scannedUrlText = document.getElementById("advScannedUrlText");
  const scanTimestamp = document.getElementById("advScanTimestamp");
  const gaugeCircle = document.getElementById("advGaugeCircle");
  const gaugeScore = document.getElementById("advGaugeScore");
  const gaugeRiskLevel = document.getElementById("advGaugeRiskLevel");
  const copyUrlBtn = document.getElementById("advCopyUrlBtn");

  // Step Pills in Scanning State
  const pill1 = document.getElementById("pillStep1");
  const pill2 = document.getElementById("pillStep2");
  const pill3 = document.getElementById("pillStep3");
  const pill4 = document.getElementById("pillStep4");

  if (!form || !input) return;

  // Preset Chips
  document.querySelectorAll("#advScannerCard .adv-sample-chip, #advScannerCard .adv-preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const sampleUrl = chip.getAttribute("data-url");
      if (sampleUrl) {
        input.value = sampleUrl;
        if (inputError) inputError.style.display = "none";
        form.dispatchEvent(new Event("submit"));
      }
    });
  });

  // Copy Scanned URL
  if (copyUrlBtn && scannedUrlText) {
    copyUrlBtn.addEventListener("click", () => {
      const urlToCopy = scannedUrlText.textContent;
      if (urlToCopy) {
        navigator.clipboard.writeText(urlToCopy)
          .then(() => showToast("Scanned URL copied to clipboard!"))
          .catch(() => showToast("Failed to copy URL.", true));
      }
    });
  }

  // Rotating Scanning Messages
  const scanStages = [
    { text: "Initializing security scan...", sub: "Synchronizing telemetry with backend detection engine...", progress: "25%", pill: 1 },
    { text: "Analyzing URL structure...", sub: "Evaluating protocol, ports, length and subdomain distribution...", progress: "50%", pill: 2 },
    { text: "Checking suspicious patterns...", sub: "Scanning for known brand homoglyphs, typosquats and fraud heuristics...", progress: "75%", pill: 3 },
    { text: "Evaluating domain information...", sub: "Extracting registered apex, TLD reputation and MX telemetry...", progress: "90%", pill: 4 },
    { text: "Generating threat assessment...", sub: "Correlating multi-vector intelligence and scoring risk...", progress: "96%", pill: 4 }
  ];

  let scanTimer = null;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawVal = input.value.trim();

    if (!rawVal) {
      if (inputError) {
        inputError.textContent = "Please enter a valid URL or target domain to analyze.";
        inputError.style.display = "block";
      }
      input.focus();
      return;
    }

    if (inputError) inputError.style.display = "none";

    // Prevent repeated clicks: disable button & show spinner
    submitBtn.disabled = true;
    const btnContent = submitBtn.querySelector(".btn-content");
    const btnSpinner = submitBtn.querySelector(".btn-spinner");
    if (btnContent) btnContent.style.display = "none";
    if (btnSpinner) btnSpinner.style.display = "inline-flex";

    // Show Scanning State, Hide Previous Results
    if (resultsPanel) resultsPanel.style.display = "none";
    if (scanningState) scanningState.style.display = "block";

    let currentStageIdx = 0;
    const updateStage = (stage) => {
      if (scanningStatus) scanningStatus.textContent = stage.text;
      if (scanningSubtext) scanningSubtext.textContent = stage.sub;
      if (progressBar) progressBar.style.width = stage.progress;
      [pill1, pill2, pill3, pill4].forEach((p, idx) => {
        if (p) p.classList.toggle("active", idx + 1 <= stage.pill);
      });
    };

    updateStage(scanStages[0]);
    scanTimer = setInterval(() => {
      currentStageIdx = (currentStageIdx + 1) % scanStages.length;
      updateStage(scanStages[currentStageIdx]);
    }, 450);

    const startTime = performance.now();

    try {
      const res = await apiFetch("/api/check/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: rawVal })
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      lastScanResult = { type: "url", data };

      // Ensure smooth animation transition (minimum 600ms)
      const elapsed = performance.now() - startTime;
      if (elapsed < 600) {
        await new Promise(r => setTimeout(r, 600 - elapsed));
      }

      clearInterval(scanTimer);
      if (progressBar) progressBar.style.width = "100%";

      // Render Results Panel
      renderThreatResult(data);

      // Refresh scan history & dashboard stats
      await loadScanHistory();
      initStats();
      showToast(`Scan complete: ${data.verdict || "Analysis ready"}`);

    } catch (err) {
      clearInterval(scanTimer);
      showToast("Scan failed: " + err.message, true);
      if (inputError) {
        inputError.textContent = "Analysis failed: " + err.message + ". Please ensure the ShieldGuard backend server is active.";
        inputError.style.display = "block";
      }
    } finally {
      if (scanningState) scanningState.style.display = "none";
      submitBtn.disabled = false;
      if (btnContent) btnContent.style.display = "inline-flex";
      if (btnSpinner) btnSpinner.style.display = "none";
    }
  });

  function renderThreatResult(data) {
    if (!resultsPanel) return;

    const score = Number(data.risk_score != null ? data.risk_score : 0);
    const rawLevel = (data.risk_level || "SAFE").toUpperCase();

    // Determine 3 distinct states: SAFE, SUSPICIOUS, MALICIOUS
    let state = "safe";
    let stateTitle = "No Threat Detected";
    let stateBadge = "SAFE";
    let riskLabelText = "LOW RISK";
    let iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>`;

    if (score >= 70 || rawLevel === "DANGEROUS" || rawLevel === "MALICIOUS" || rawLevel === "HIGH") {
      state = "malicious";
      stateTitle = "Malicious URL Detected";
      stateBadge = "MALICIOUS";
      riskLabelText = "HIGH RISK";
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
    } else if (score >= 30 || rawLevel === "SUSPICIOUS" || rawLevel === "MEDIUM") {
      state = "suspicious";
      stateTitle = "Potential Threat Detected";
      stateBadge = "SUSPICIOUS";
      riskLabelText = "MEDIUM RISK";
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="12 2 22 20 2 20 12 2"></polygon><line x1="12" y1="9" x2="12" y2="12"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    }

    resultsPanel.className = `adv-results-panel state-${state}`;
    const subEl = document.getElementById("advResultSubheading");
    if (subEl) {
      if (state === "safe") {
        subEl.textContent = "Scanned target demonstrates verified legitimate signatures with zero detected fraud heuristics.";
      } else if (state === "suspicious") {
        subEl.textContent = "Scanned target exhibits anomalous heuristics, unencrypted transports, or suspicious domain parameters.";
      } else {
        subEl.textContent = "Critical phishing signature confirmed: brand impersonation, deceptive homoglyphs, or AI classifier detection.";
      }
    }
    if (resultHeading) resultHeading.textContent = stateTitle;
    if (statusBadgeText) statusBadgeText.textContent = stateBadge;
    if (statusIcon) statusIcon.innerHTML = iconSvg;
    if (scannedUrlText) scannedUrlText.textContent = data.url;
    if (scanTimestamp) scanTimestamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // Circular Risk Gauge Animation
    if (gaugeScore) gaugeScore.textContent = score;
    if (gaugeRiskLevel) gaugeRiskLevel.textContent = riskLabelText;
    if (gaugeCircle) {
      const circumference = 301.6;
      gaugeCircle.style.strokeDasharray = circumference;
      gaugeCircle.style.strokeDashoffset = circumference;
      setTimeout(() => {
        const offset = circumference - (score / 100) * circumference;
        gaugeCircle.style.strokeDashoffset = offset;
      }, 50);
    }

    // Telemetry Cards
    const comp = data.components || {};
    const scheme = (comp.scheme || "http").toUpperCase();
    const isHttps = scheme === "HTTPS";
    const portVal = comp.port ? `Custom (${comp.port})` : (isHttps ? "Standard (443)" : "Standard (80)");
    const totalLen = (data.url || "").length;
    const subCount = comp.subdomain_count || 0;
    const apexDomain = comp.registered_domain || comp.netloc || "N/A";
    const tld = comp.tld ? `.${comp.tld}` : "None";
    const brand = data.impersonated_brand ? `Targeted: '${data.impersonated_brand}'` : "None Detected";
    const isIp = comp.is_ip_address;
    const flagsCount = (data.detected_indicators || []).length;
    const indicatorsStr = (data.detected_indicators || []).join(", ") || "None";
    const homoglyphDetected = (data.detected_indicators || []).some(i => i.toLowerCase().includes("homoglyph"));

    const el = id => document.getElementById(id);
    if (el("advTelProtocol")) el("advTelProtocol").textContent = scheme;
    if (el("advTelLength")) el("advTelLength").textContent = `${totalLen} chars`;
    if (el("advTelSubdomains")) el("advTelSubdomains").textContent = comp.subdomain ? `${comp.subdomain} (${subCount} levels)` : "Apex (0 levels)";
    if (el("advTelDomain")) el("advTelDomain").textContent = apexDomain;
    if (el("advTelTld")) el("advTelTld").textContent = tld;
    if (el("advTelBrand")) el("advTelBrand").innerHTML = data.impersonated_brand ? `<span class="badge dangerous font-mono">${escapeHtml(brand)}</span>` : `<span class="badge safe">None Detected</span>`;
    if (el("advTelHttps")) el("advTelHttps").innerHTML = isHttps ? `<span class="badge safe">SECURE (HTTPS)</span>` : `<span class="badge dangerous">INSECURE (HTTP)</span>`;
    if (el("advTelPort")) el("advTelPort").textContent = portVal;
    if (el("advTelIpHost")) el("advTelIpHost").innerHTML = isIp ? `<span class="badge dangerous">RAW IP HOST</span>` : `<span class="badge safe">Named Host</span>`;
    if (el("advTelFlagCount")) el("advTelFlagCount").textContent = `${flagsCount} heuristics`;
    if (el("advTelSuspiciousWords")) el("advTelSuspiciousWords").innerHTML = flagsCount > 0 ? `<span class="font-mono" style="font-size:11.5px; color:#FF525D;">${escapeHtml(indicatorsStr)}</span>` : "None detected";
    if (el("advTelHomoglyphs")) el("advTelHomoglyphs").innerHTML = homoglyphDetected ? `<span class="badge dangerous">SPOOFED CHARS</span>` : `<span class="badge safe">CLEAN</span>`;

    // ML Engine
    const ml = data.ml_analysis || {};
    if (el("advTelMlPred")) {
      const isMlPhish = ml.prediction === "PHISHING";
      el("advTelMlPred").innerHTML = `<span class="badge ${isMlPhish ? 'dangerous' : 'safe'}">${ml.prediction || 'LEGITIMATE'}</span>`;
    }
    if (el("advTelMlProb")) el("advTelMlProb").textContent = ml.phishing_probability != null ? `${ml.phishing_probability}%` : "0.0%";
    if (el("advTelMlConf")) el("advTelMlConf").textContent = ml.confidence != null ? `${ml.confidence}%` : "99.1%";

    // Assessment
    if (el("advTelVerdict")) el("advTelVerdict").innerHTML = `<span class="badge ${state === 'malicious' ? 'dangerous' : (state === 'suspicious' ? 'warning' : 'safe')}">${escapeHtml(data.verdict || stateBadge)}</span>`;
    if (el("advTelSeverity")) el("advTelSeverity").textContent = `${riskLabelText} (${score}/100)`;
    if (el("advTelRedirect")) el("advTelRedirect").textContent = comp.path ? `${comp.path}` : "Apex Route (/)";

    // Threat Factors
    const threatList = el("advThreatFactorsList");
    const threatCount = el("advThreatsCount");
    if (threatList) {
      threatList.innerHTML = "";
      const factors = data.threat_factors || [];
      if (threatCount) threatCount.textContent = `${factors.length} Factor${factors.length === 1 ? '' : 's'}`;
      if (factors.length === 0) {
        threatList.innerHTML = `<div class="adv-rec-item" style="color: #39FF88;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg><span>No malicious threat factors detected. Target matches expected legitimate structural attributes.</span></div>`;
      } else {
        factors.forEach(f => {
          const item = document.createElement("div");
          const isHigh = f.severity === "HIGH" || (f.score_impact && f.score_impact >= 20);
          item.className = `adv-threat-item ${isHigh ? '' : 'warning'}`;
          item.innerHTML = `
            <div class="adv-threat-item-title">
              <span>${escapeHtml(f.name || f)}</span>
              <span class="badge ${isHigh ? 'dangerous' : 'warning'}" style="font-size: 10px;">${escapeHtml(f.severity || 'IMPACT +' + (f.score_impact || 10))}</span>
            </div>
            ${f.description ? `<div class="adv-threat-item-desc">${escapeHtml(f.description)}</div>` : ''}
          `;
          threatList.appendChild(item);
        });
      }
    }

    // Recommendations
    const recList = el("advRecsList");
    const recCount = el("advRecsCount");
    if (recList) {
      recList.innerHTML = "";
      const recs = data.recommendations || [];
      if (recCount) recCount.textContent = `${recs.length} Directives`;
      if (recs.length === 0) {
        recList.innerHTML = `<div class="adv-rec-item"><span>Standard defensive telemetry active. Target safe for standard traffic.</span></div>`;
      } else {
        recs.forEach(r => {
          const item = document.createElement("div");
          item.className = "adv-rec-item";
          item.innerHTML = `
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <polyline points="9 11 12 14 22 4"></polyline>
            </svg>
            <span>${escapeHtml(r)}</span>
          `;
          recList.appendChild(item);
        });
      }
    }

    // AI Security Briefing
    if (el("advAiBriefingText")) {
      const briefing = data.ai_threat_briefing || (
        state === "safe"
          ? "Target domain and URL structure exhibit safe cryptographic and structural properties with no detected typosquatting, brand impersonation, or obfuscated redirects."
          : `ShieldGuard threat engine detected ${flagsCount || 1} anomaly indicators. Risk score is ${score}/100. Exercise high caution before submitting credentials or downloading payloads.`
      );
      el("advAiBriefingText").innerHTML = escapeHtml(briefing).replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>');
    }

    resultsPanel.style.display = "block";
    resultsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ========================================================================
  // RECENT SCAN HISTORY CONTROLLER
  // ========================================================================
  const historyList = document.getElementById("advHistoryList");
  const historySearch = document.getElementById("advHistorySearchInput");
  const filterBtns = document.querySelectorAll("#advHistoryFilters .adv-filter-pill-btn, #advHistoryFilters .adv-filter-btn");
  const clearHistoryBtn = document.getElementById("advClearHistoryBtn");
  const refreshHistoryBtn = document.getElementById("advRefreshHistoryBtn");
  const topbarHistoryBtn = document.getElementById("topbarHistoryBtn");

  async function loadScanHistory() {
    try {
      const res = await apiFetch("/api/analytics/recent?limit=30");
      if (res.ok) {
        const records = await res.json();
        activeScanHistory = Array.isArray(records) ? records : [];
      }
    } catch (e) {
      console.warn("Could not load API scan history:", e);
    }
    renderScanHistory();
  }

  function renderScanHistory() {
    if (!historyList) return;
    const q = (historySearch ? historySearch.value : "").toLowerCase().trim();

    const filtered = activeScanHistory.filter(item => {
      // Filter by classification tab
      const score = item.risk_score || 0;
      const level = (item.risk_level || (score >= 70 ? "MALICIOUS" : (score >= 30 ? "SUSPICIOUS" : "SAFE"))).toUpperCase();

      if (activeHistoryFilter === "SAFE") {
        if (score >= 30 && level !== "SAFE" && level !== "LOW") return false;
      } else if (activeHistoryFilter === "SUSPICIOUS") {
        if (score < 30 || score >= 70 || level === "SAFE" || level === "DANGEROUS" || level === "MALICIOUS") return false;
      } else if (activeHistoryFilter === "MALICIOUS") {
        if (score < 70 && level !== "DANGEROUS" && level !== "MALICIOUS" && level !== "HIGH") return false;
      }

      // Filter by query string
      if (q) {
        const targetStr = (item.target || item.target_value || item.url || item.scan_type || "").toLowerCase();
        const verdictStr = (item.verdict || "").toLowerCase();
        return targetStr.includes(q) || verdictStr.includes(q);
      }
      return true;
    });

    if (filtered.length === 0) {
      historyList.innerHTML = `
        <div class="adv-history-empty">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          <p>${q ? 'No scan history matching "' + escapeHtml(q) + '"' : 'No threat scans logged yet. Analyze a URL above to start logging.'}</p>
        </div>
      `;
      return;
    }

    historyList.innerHTML = "";
    filtered.forEach(item => {
      const target = item.target || item.target_value || item.url || "Target Entity";
      const score = item.risk_score != null ? item.risk_score : 0;
      let badgeClass = "safe";
      let badgeText = "SAFE";

      if (score >= 70 || item.risk_level === "DANGEROUS" || item.risk_level === "MALICIOUS" || item.risk_level === "HIGH") {
        badgeClass = "malicious";
        badgeText = "MALICIOUS";
      } else if (score >= 30 || item.risk_level === "SUSPICIOUS" || item.risk_level === "MEDIUM") {
        badgeClass = "suspicious";
        badgeText = "SUSPICIOUS";
      }

      const card = document.createElement("div");
      card.className = "adv-history-item";

      const timeStr = item.created_at ? new Date(item.created_at).toLocaleString() : "Recently";
      const scanType = (item.scan_type || "URL").toUpperCase();

      card.innerHTML = `
        <div class="adv-history-item-left">
          <span class="adv-history-item-target" title="${escapeHtml(target)}">${escapeHtml(target)}</span>
          <div class="adv-history-item-meta">
            <span>🛡️ ${escapeHtml(scanType)} SCAN</span>
            <span>•</span>
            <span>⏱️ ${escapeHtml(timeStr)}</span>
            ${item.verdict ? `<span>•</span><span>Verdict: ${escapeHtml(item.verdict)}</span>` : ''}
          </div>
        </div>
        <div class="adv-history-item-right">
          <span class="adv-history-badge ${badgeClass}">${badgeText}</span>
          <span class="adv-history-score">${score}/100</span>
          <button type="button" class="btn-rescan" data-target="${escapeHtml(target)}" title="Inspect / Re-scan this target">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
            <span>Inspect</span>
          </button>
        </div>
      `;

      const rescanBtn = card.querySelector(".btn-rescan");
      if (rescanBtn) {
        rescanBtn.addEventListener("click", () => {
          input.value = target;
          if (inputError) inputError.style.display = "none";
          window.scrollTo({ top: 0, behavior: "smooth" });
          form.dispatchEvent(new Event("submit"));
        });
      }

      historyList.appendChild(card);
    });
  }

  // Filter Buttons
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeHistoryFilter = btn.getAttribute("data-filter") || "ALL";
      renderScanHistory();
    });
  });

  // Search Input
  if (historySearch) {
    historySearch.addEventListener("input", () => renderScanHistory());
  }

  // Refresh History
  if (refreshHistoryBtn) {
    refreshHistoryBtn.addEventListener("click", async () => {
      await loadScanHistory();
      showToast("Scan history refreshed.");
    });
  }

  // Clear History
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", async () => {
      if (!confirm("Are you sure you want to clear your scan history logs? This action cannot be undone.")) {
        return;
      }
      try {
        const res = await apiFetch("/api/analytics/recent", { method: "DELETE" });
        if (res.ok) {
          activeScanHistory = [];
          renderScanHistory();
          initStats();
          showToast("Threat scan logs successfully cleared.");
        } else {
          throw new Error("Clear failed with HTTP " + res.status);
        }
      } catch (err) {
        showToast("Error clearing history: " + err.message, true);
      }
    });
  }

  // Topbar Shortcut
  if (topbarHistoryBtn) {
    topbarHistoryBtn.addEventListener("click", () => {
      const dashBtn = document.querySelector('.tab-btn[data-tab="dashboardTab"]');
      if (dashBtn && !dashBtn.classList.contains("active")) {
        dashBtn.click();
      }
      const historySec = document.getElementById("advScanHistorySection");
      if (historySec) {
        historySec.scrollIntoView({ behavior: "smooth" });
      }
    });
  }


  // Advanced Results Panel Action Buttons
  const rescanActionBtn = document.getElementById("advRescanBtn");
  if (rescanActionBtn) {
    rescanActionBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
      input.focus();
      input.select();
    });
  }

  const copySummaryActionBtn = document.getElementById("advCopySummaryBtn");
  if (copySummaryActionBtn) {
    copySummaryActionBtn.addEventListener("click", () => {
      if (!lastScanResult || !lastScanResult.data) {
        showToast("No active scan findings to copy.", true);
        return;
      }
      const d = lastScanResult.data;
      const summaryText = [
        `🛡️ [ShieldGuard AI Threat Intelligence Report]`,
        `Target: ${d.url || ""}`,
        `Threat Level: ${d.risk_level} (${d.risk_score}/100)`,
        `Verdict: ${d.verdict}`,
        `Impersonated Brand: ${d.impersonated_brand || "None"}`,
        `\nIdentified Threat Factors:\n${(d.threat_factors || []).map(t => `- ${t.name || t}: ${t.description || ''}`).join('\n') || "- None"}`,
        `\nActionable Recommendations:\n${(d.recommendations || []).map(r => `- ${r}`).join('\n') || "- Standard defensive posture."}`,
        `\nTimestamp: ${new Date().toUTCString()}`
      ].join('\n');
      navigator.clipboard.writeText(summaryText)
        .then(() => showToast("Forensic analysis summary copied to clipboard!"))
        .catch(() => showToast("Failed to copy summary.", true));
    });
  }

  const jumpHistoryActionBtn = document.getElementById("advJumpHistoryBtn");
  if (jumpHistoryActionBtn) {
    jumpHistoryActionBtn.addEventListener("click", () => {
      const histSec = document.getElementById("advScanHistorySection");
      if (histSec) histSec.scrollIntoView({ behavior: "smooth" });
    });
  }

  // Initial scan history load
  loadScanHistory();
}
