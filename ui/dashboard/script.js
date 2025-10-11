const API_BASE = window.API_BASE || "http://localhost:8000";

async function fetchJSON(path) {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function updateGauge(value) {
  const gauge = document.getElementById("sbom-gauge");
  const label = document.getElementById("sbom-gauge-value");
  const pct = Math.round(value || 0);
  gauge.style.setProperty("--value", pct);
  label.textContent = `${pct}%`;
}

function renderSBOMMetrics(metrics) {
  const list = document.getElementById("sbom-metrics");
  list.innerHTML = "";
  Object.entries(metrics || {}).forEach(([key, value]) => {
    const item = document.createElement("li");
    item.textContent = `${key.replace(/_/g, " ")}: ${value}`;
    list.appendChild(item);
  });
}

function renderReproStatus(evaluations) {
  const list = document.getElementById("repro-status");
  list.innerHTML = "";
  const repro = evaluations?.checks?.repro_match;
  if (!repro) {
    list.innerHTML = "<li>No reproducibility data</li>";
    return;
  }
  const item = document.createElement("li");
  item.innerHTML = `<span class="status-pill">${repro.status.toUpperCase()}</span> reproducible: ${repro.value}`;
  list.appendChild(item);
}

function renderKevTable(entries) {
  const tbody = document.querySelector("#kev-table tbody");
  tbody.innerHTML = "";
  entries.forEach((release) => {
    release.components.forEach((component) => {
      const row = document.createElement("tr");
      row.innerHTML = `<td>${release.release}</td><td>${component.component}</td><td>${component.cves.join(", ")}</td>`;
      tbody.appendChild(row);
    });
  });
}

function renderEvidenceTable(releases) {
  const tbody = document.querySelector("#evidence-table tbody");
  tbody.innerHTML = "";
  releases.forEach((release) => {
    const row = document.createElement("tr");
    const status = release.bundle_available ? "available" : "pending";
    row.innerHTML = `<td>${release.tag}</td><td>${release.bundle_available ? "✅" : "⏳"}</td><td>${status}</td>`;
    tbody.appendChild(row);
  });
}

async function loadDashboard() {
  try {
    const evidence = await fetchJSON("/evidence/");
    renderEvidenceTable(evidence.releases || []);
    if (evidence.releases?.length) {
      const manifest = await fetchJSON(`/evidence/${evidence.releases[0].tag}`);
      const metrics = manifest.manifest?.metrics || {};
      updateGauge(metrics.sbom?.coverage_percent || 0);
      renderSBOMMetrics(metrics.sbom || {});
      const risk = metrics.risk || {};
      document.getElementById("risk-components").textContent = risk.component_count ?? 0;
      document.getElementById("risk-cves").textContent = risk.cve_count ?? 0;
      document.getElementById("risk-max").textContent = risk.max_risk_score ?? 0;
      renderReproStatus(manifest.manifest?.evaluations);
    }
  } catch (error) {
    console.warn("Unable to load evidence data", error);
  }

  try {
    const kev = await fetchJSON("/graph/kev-components?last=3");
    renderKevTable(kev || []);
  } catch (error) {
    console.warn("Unable to load graph data", error);
  }
}

document.addEventListener("DOMContentLoaded", loadDashboard);
