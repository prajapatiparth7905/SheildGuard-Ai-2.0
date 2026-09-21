/**
 * ShieldGuard AI - Frontend Intelligence Client
 */

// Global State
let latestBulkResults = [];

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
  initApiConfig();
  initTabs();
  initStats();
  initPhoneScanner();
  initEmailScanner();
  initContentScanner();
  initCombinedScanner();
  initBulkScanner();
  initScamReports();
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
    });
  }
}

// ==========================================================================
// Tab Navigation
// ==========================================================================
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

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

  // Sample presets
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

      emptyView.style.display = "none";
      resultView.style.display = "block";

      document.getElementById("phoneTargetDisplay").textContent = data.phone_details.international_format || phone;
      updateGauge("phoneGaugeSection", "phoneGaugeProgress", "phoneGaugeVal", "phoneVerdictBadge", "phoneVerdictTitle", data.risk_score, data.risk_level, data.verdict);

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
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Scan Phone Number`;
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

      emptyView.style.display = "none";
      resultView.style.display = "block";

      document.getElementById("emailTargetDisplay").textContent = data.email;
      updateGauge("emailGaugeSection", "emailGaugeProgress", "emailGaugeVal", "emailVerdictBadge", "emailVerdictTitle", data.risk_score, data.risk_level, data.verdict);

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
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Analyze Email Address`;
    }
  });
}

// ==========================================================================
// Message / Content Scanner Controller
// ==========================================================================
function initContentScanner() {
  const form = document.getElementById("contentForm");
  const contentInput = document.getElementById("contentInput");
  const submitBtn = document.getElementById("contentSubmitBtn");
  const emptyView = document.getElementById("contentEmpty");
  const resultView = document.getElementById("contentResult");

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

      emptyView.style.display = "none";
      resultView.style.display = "block";

      const categoriesStr = data.detected_categories.length > 0 ? data.detected_categories.join(", ") : "None Detected";
      const catBadge = document.getElementById("contentCategoriesBadge");
      if (catBadge) catBadge.textContent = categoriesStr;

      updateGauge("contentGaugeSection", "contentGaugeProgress", "contentGaugeVal", "contentVerdictBadge", "contentVerdictTitle", data.risk_score, data.risk_level, data.verdict);

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
      submitBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Scan Message Content`;
    }
  });
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

  // Initial load
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
        reported_by: document.getElementById("reportUser").value.trim() || (currentUser ? currentUser.username : "Anonymous")
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
        if (currentUser) {
          document.getElementById("reportUser").value = currentUser.username;
        }
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
      const searchVal = document.getElementById("searchReportsInput")?.value.trim() || "";
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
