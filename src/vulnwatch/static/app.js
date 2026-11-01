const $ = (selector) => document.querySelector(selector);
const severityNames = ["Critical", "High", "Medium", "Low", "Unknown"];
let noticeTimer;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new Error(data?.detail || `Request failed (${response.status})`);
  return data;
}

function showNotice(message, isError = false) {
  const notice = $("#notice");
  notice.textContent = message;
  notice.className = `notice show${isError ? " error" : ""}`;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { notice.className = "notice"; }, 4000);
}

async function refreshDashboard() {
  const [summary, findings] = await Promise.all([
    api("/api/summary"),
    loadFindings(),
  ]);
  $("#total-findings").textContent = summary.finding_count;
  $("#open-findings").textContent = summary.open_count;
  $("#critical-findings").textContent = summary.critical_count;
  $("#asset-count").textContent = summary.asset_count;
  $("#unverified-findings").textContent = summary.unverified_count;
  drawSeverity(summary.severity_counts);
  return findings;
}

function drawSeverity(counts) {
  const max = Math.max(1, ...severityNames.map((name) => counts[name] || 0));
  $("#severity-chart").innerHTML = severityNames.map((name) => {
    const className = name.toLowerCase();
    const count = counts[name] || 0;
    const width = count ? Math.max(3, (count / max) * 100) : 0;
    return `<div class="severity-row"><span class="label">${name}</span><div class="bar-track"><div class="bar-fill ${className}" style="width:${width}%"></div></div><strong>${count}</strong></div>`;
  }).join("");
}

async function loadFindings() {
  const params = new URLSearchParams();
  if ($("#finding-search").value.trim()) params.set("search", $("#finding-search").value.trim());
  if ($("#severity-filter").value) params.set("severity", $("#severity-filter").value);
  if ($("#status-filter").value) params.set("status", $("#status-filter").value);
  const rows = await api(`/api/findings?${params}`);
  const body = $("#findings-table");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty-state">No findings match these filters.</td></tr>';
    return rows;
  }
  body.innerHTML = rows.map((finding) => {
    const severity = finding.severity.toLowerCase();
    const statusClass = finding.status === "Resolved" ? "resolved" : "";
    const verifiedClass = finding.verified ? "verified" : "unverified";
    return `<tr>
      <td><span class="cve-id">${escapeHtml(finding.cve_id)}</span><div class="finding-title" title="${escapeHtml(finding.title)}">${escapeHtml(finding.title)}</div></td>
      <td class="asset-cell"><strong>${escapeHtml(finding.asset_name)}</strong><small>${escapeHtml(finding.asset_ip)}</small></td>
      <td><span class="severity-pill ${severity}">${escapeHtml(finding.severity)}</span></td>
      <td><select class="status-select status-pill ${statusClass}" data-status-id="${finding.id}" aria-label="Status for ${escapeHtml(finding.cve_id)}"><option ${finding.status === "Open" ? "selected" : ""}>Open</option><option ${finding.status === "In Progress" ? "selected" : ""}>In Progress</option><option ${finding.status === "Resolved" ? "selected" : ""}>Resolved</option></select></td>
      <td><span class="verify-pill ${verifiedClass}">${finding.verified ? "Verified" : "Unverified"}</span></td>
      <td>${escapeHtml(finding.discovered_date)}</td>
      <td><div class="row-actions"><button class="mini-button" data-view-id="${finding.id}" title="View details">View</button><button class="mini-button danger" data-delete-id="${finding.id}" title="Delete finding">Delete</button></div></td>
    </tr>`;
  }).join("");
  return rows;
}

async function loadAssets() {
  const assets = await api("/api/assets");
  const list = $("#asset-list");
  const select = $("#finding-form [name=asset_id]");
  if (!assets.length) {
    list.innerHTML = '<div class="empty-state">No assets yet. Add one or import Nmap XML.</div>';
    select.innerHTML = '<option value="">Add an asset first</option>';
    return assets;
  }
  list.innerHTML = assets.slice(0, 6).map((asset) => `<div class="asset-row"><div class="asset-ident"><span class="asset-icon">▦</span><div><strong>${escapeHtml(asset.name)}</strong><small>${escapeHtml(asset.ip_address)}${asset.hostname ? ` · ${escapeHtml(asset.hostname)}` : ""}</small></div></div><span class="asset-count">${asset.finding_count} findings</span></div>`).join("");
  select.innerHTML = assets.map((asset) => `<option value="${asset.id}">${escapeHtml(asset.name)} — ${escapeHtml(asset.ip_address)}</option>`).join("");
  return assets;
}

async function loadIntelligence() {
  const records = await api("/api/nvd");
  $("#intel-list").innerHTML = records.length ? records.slice(0, 4).map((record) => `<div class="intel-row"><div class="intel-ident"><strong>${escapeHtml(record.cve_id)}</strong><small>${escapeHtml(record.severity)}${record.cvss_score != null ? ` · CVSS ${escapeHtml(record.cvss_score)}` : ""}</small></div><a href="${escapeHtml(record.nvd_url)}" target="_blank" rel="noopener">NVD ↗</a></div>`).join("") : '<div class="empty-state">No imported records yet.</div>';
}

function showDialog(dialog) { dialog.showModal(); }
document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
$("#show-finding-form").addEventListener("click", async () => {
  try {
    const assets = await loadAssets();
    if (!assets.length) { showNotice("Add an asset before creating a finding.", true); return; }
    const form = $("#finding-form");
    form.reset();
    form.elements.discovered_date.value = new Date().toISOString().slice(0, 10);
    showDialog($("#finding-dialog"));
  } catch (error) { showNotice(error.message, true); }
});
$("#show-asset-form").addEventListener("click", () => { $("#asset-form").reset(); showDialog($("#asset-dialog")); });

$("#asset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form));
  for (const key of ["hostname", "operating_system"]) if (!payload[key]) payload[key] = null;
  try {
    await api("/api/assets", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    $("#asset-dialog").close(); await loadAssets(); await refreshDashboard(); showNotice("Asset added to inventory.");
  } catch (error) { showNotice(error.message, true); }
});

$("#finding-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form));
  payload.asset_id = Number(payload.asset_id);
  payload.verified = form.elements.verified.checked;
  payload.cvss_score = payload.cvss_score ? Number(payload.cvss_score) : null;
  try {
    await api("/api/findings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    $("#finding-dialog").close(); await refreshDashboard(); showNotice("Finding created.");
  } catch (error) { showNotice(error.message, true); }
});

let searchTimer;
$("#finding-search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => loadFindings().catch((error) => showNotice(error.message, true)), 200); });
$("#severity-filter").addEventListener("change", () => loadFindings().catch((error) => showNotice(error.message, true)));
$("#status-filter").addEventListener("change", () => loadFindings().catch((error) => showNotice(error.message, true)));

$("#findings-table").addEventListener("change", async (event) => {
  const id = event.target.dataset.statusId;
  if (!id) return;
  try {
    await api(`/api/findings/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: event.target.value }) });
    await refreshDashboard(); showNotice("Finding status updated.");
  } catch (error) { showNotice(error.message, true); }
});

$("#findings-table").addEventListener("click", async (event) => {
  const viewId = event.target.dataset.viewId;
  const deleteId = event.target.dataset.deleteId;
  try {
    if (viewId) {
      const finding = await api(`/api/findings/${viewId}`);
      $("#detail-title").textContent = finding.cve_id;
      const fields = [["Title", finding.title], ["Affected asset", `${finding.asset_name} (${finding.asset_ip})`], ["Severity / score", `${finding.severity}${finding.cvss_score != null ? ` · CVSS ${finding.cvss_score}` : ""}`], ["Status", finding.status], ["Discovered", finding.discovered_date], ["Asset relationship", finding.verified ? "Analyst verified" : "Unverified; review before treating as affected"], ["Description", finding.description || "No description supplied"], ["Remediation notes", finding.remediation_notes || "No notes yet"]];
      $("#detail-content").innerHTML = `<div class="detail-grid">${fields.map(([label, value]) => `<div class="detail-item"><small>${escapeHtml(label)}</small><p>${escapeHtml(value)}</p></div>`).join("")}</div>`;
      showDialog($("#detail-dialog"));
    }
    if (deleteId && window.confirm("Delete this vulnerability finding? This action cannot be undone.")) {
      await api(`/api/findings/${deleteId}`, { method: "DELETE" });
      await refreshDashboard(); showNotice("Finding deleted.");
    }
  } catch (error) { showNotice(error.message, true); }
});

$("#nvd-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const cveId = $("#nvd-cve").value.trim().toUpperCase();
  const result = $("#nvd-result");
  result.innerHTML = '<p class="muted">Contacting the NVD CVE API…</p>';
  try {
    const cve = await api(`/api/nvd/${encodeURIComponent(cveId)}`);
    result.innerHTML = `<div class="nvd-card"><div class="nvd-card-head"><span class="cve-id">${escapeHtml(cve.cve_id)}</span><span class="severity-pill ${cve.severity.toLowerCase()}">${escapeHtml(cve.severity)}${cve.cvss_score != null ? ` · ${escapeHtml(cve.cvss_score)}` : ""}</span></div><p>${escapeHtml(cve.description || "NVD did not supply an English description.")}</p><button class="button button-primary" id="import-cve">Save intelligence record</button> <a class="text-link" href="${escapeHtml(cve.nvd_url)}" target="_blank" rel="noopener">View on NVD ↗</a></div>`;
    $("#import-cve").addEventListener("click", async () => {
      try { await api("/api/nvd/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cve_id: cve.cve_id }) }); await loadIntelligence(); showNotice("NVD intelligence saved. No asset finding was created."); }
      catch (error) { showNotice(error.message, true); }
    });
  } catch (error) { result.innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`; }
});

$("#refresh-intel").addEventListener("click", () => loadIntelligence().catch((error) => showNotice(error.message, true)));
$("#nmap-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 5_000_000) { showNotice("Choose an XML file smaller than 5 MB.", true); event.target.value = ""; return; }
  try {
    const query = new URLSearchParams({ filename: file.name });
    const result = await api(`/api/scans/nmap?${query}`, { method: "POST", headers: { "Content-Type": "application/xml" }, body: file });
    await loadAssets(); await refreshDashboard();
    showNotice(`Imported ${result.assets_imported} assets and ${result.services_imported} services. No findings were inferred.`);
  } catch (error) { showNotice(error.message, true); }
  finally { event.target.value = ""; }
});

async function startDashboard() {
  try { await Promise.all([refreshDashboard(), loadAssets(), loadIntelligence()]); }
  catch (error) { showNotice(`Could not load dashboard: ${error.message}`, true); }
}
startDashboard();
