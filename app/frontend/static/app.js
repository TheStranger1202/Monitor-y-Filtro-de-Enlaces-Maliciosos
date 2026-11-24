/*
 * Controlador Frontend puramente funcional.
 * Inmunidad total contra Blind Stored XSS (OWASP A03 / EC-XSS-01):
 * Jamás inyecta HTML crudo con datos externos; todo el árbol DOM se construye
 * mediante `document.createElement` y asignación segura por `.textContent`.
 */

(() => {
  "use strict";

  const VIEW_META = Object.freeze({
    overview: Object.freeze({
      title: "Panel de Mando",
      subtitle: "Telemetría preventiva en tiempo real para correo institucional de comercio exterior",
    }),
    forensics: Object.freeze({
      title: "Bitácora Forense",
      subtitle: "Auditoría histórica de mensajes interceptados y autopsia de enlaces por capa",
    }),
    oracle: Object.freeze({
      title: "Oráculo de URLs",
      subtitle: "Inspección manual bajo demanda contra Caché Local, VirusTotal v3 y Heurística Aduanera",
    }),
  });

  const state = {
    activeView: "overview",
    statusFilter: "ALL",
    searchQuery: "",
    emails: [],
  };

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };

  const clearNode = (node) => {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  };

  const formatUtcShort = (isoStr) => {
    if (!isoStr) return "--";
    return String(isoStr).replace("T", " ").slice(0, 19);
  };

  const makeStatusBadge = (status) => {
    const normalized = String(status || "CLEAN").toUpperCase();
    const cssSuffix = normalized.toLowerCase();
    return el("span", `badge badge-${cssSuffix}`, normalized);
  };

  const switchView = (viewName) => {
    if (!VIEW_META[viewName]) return;
    state.activeView = viewName;

    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === viewName);
    });
    document.querySelectorAll(".view-section").forEach((sec) => {
      sec.classList.toggle("active", sec.id === `view-${viewName}`);
    });

    document.getElementById("view-heading").textContent = VIEW_META[viewName].title;
    document.getElementById("view-subtitle").textContent = VIEW_META[viewName].subtitle;
  };

  const renderEmailRows = (tbody, records, detailedMode) => {
    clearNode(tbody);
    if (!records.length) {
      const tr = el("tr");
      const td = el("td", "mono", "Sin registros que coincidan con el filtro actual.");
      td.colSpan = detailedMode ? 7 : 5;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    records.forEach((rec) => {
      const tr = el("tr");
      tr.addEventListener("click", () => openAutopsyDrawer(rec));

      if (detailedMode) {
        tr.appendChild(el("td", "mono", `#${rec.id}`));
      }

      const tdStatus = el("td");
      tdStatus.appendChild(makeStatusBadge(rec.status));
      tr.appendChild(tdStatus);

      tr.appendChild(el("td", "mono", `${rec.max_risk_score} / 100`));
      tr.appendChild(el("td", "mono", rec.sender));
      tr.appendChild(el("td", "", rec.subject));
      tr.appendChild(el("td", "mono", formatUtcShort(rec.processed_at)));

      if (detailedMode) {
        const tdAction = el("td");
        const btn = el("button", "btn btn-ghost", "Autopsia");
        btn.type = "button";
        tdAction.appendChild(btn);
        tr.appendChild(tdAction);
      }

      tbody.appendChild(tr);
    });
  };

  const applyForensicsFilters = () => {
    const query = state.searchQuery.trim().toLowerCase();
    const filtered = state.emails.filter((item) => {
      const matchesStatus =
        state.statusFilter === "ALL" || String(item.status).toUpperCase() === state.statusFilter;
      if (!matchesStatus) return false;
      if (!query) return true;
      return (
        String(item.sender).toLowerCase().includes(query) ||
        String(item.subject).toLowerCase().includes(query)
      );
    });

    renderEmailRows(document.getElementById("forensics-tbody"), filtered, true);
  };

  const openAutopsyDrawer = async (emailRecord) => {
    const drawer = document.getElementById("autopsy-drawer");
    const backdrop = document.getElementById("drawer-backdrop");
    const metaBox = document.getElementById("drawer-meta");
    const urlsList = document.getElementById("drawer-urls-list");

    document.getElementById("drawer-subject").textContent = emailRecord.subject;
    clearNode(metaBox);
    metaBox.appendChild(el("div", "mono", `Remitente: ${emailRecord.sender}`));
    metaBox.appendChild(el("div", "mono", `Message-ID: ${emailRecord.message_id}`));
    metaBox.appendChild(
      el("div", "mono", `Estado: ${emailRecord.status} | Riesgo Máximo: ${emailRecord.max_risk_score}/100`)
    );

    clearNode(urlsList);
    urlsList.appendChild(el("p", "mono", "Extrayendo evidencia de enlaces..."));

    backdrop.hidden = false;
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");

    try {
      const res = await fetch(`/api/v1/emails/${encodeURIComponent(emailRecord.id)}/urls`);
      if (!res.ok) throw new Error("Error al consultar URLs");
      const payload = await res.json();

      clearNode(urlsList);
      if (!payload.items || !payload.items.length) {
        urlsList.appendChild(el("p", "mono", "Este mensaje no contenía enlaces HTTP/HTTPS."));
        return;
      }

      payload.items.forEach((u) => {
        const card = el("article", "url-autopsy-card");
        const top = el("div", "result-header");
        top.appendChild(makeStatusBadge(u.verdict));
        top.appendChild(el("span", "mono", `${u.final_score} / 100 pts`));
        card.appendChild(top);

        card.appendChild(el("div", "defanged-box", u.defanged_url));
        card.appendChild(
          el(
            "div",
            "mono",
            `Dominio: ${u.domain} | Capa 1: ${u.layer1_status} | VT Maliciosos: ${u.vt_malicious_count} | Heurística: ${u.heuristic_score}`
          )
        );

        if (u.heuristic_reasons && u.heuristic_reasons.length) {
          const ul = el("ul", "reasons-list");
          u.heuristic_reasons.forEach((reason) => ul.appendChild(el("li", "reason-tag", reason)));
          card.appendChild(ul);
        }
        urlsList.appendChild(card);
      });
    } catch (_err) {
      clearNode(urlsList);
      urlsList.appendChild(el("p", "form-error", "No se pudo cargar el detalle de enlaces."));
    }
  };

  const closeAutopsyDrawer = () => {
    const drawer = document.getElementById("autopsy-drawer");
    const backdrop = document.getElementById("drawer-backdrop");
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    backdrop.hidden = true;
  };

  const renderOracleResult = (data) => {
    const container = document.getElementById("oracle-result-card");
    container.classList.remove("empty-state");
    clearNode(container);

    const header = el("div", "result-header");
    header.appendChild(makeStatusBadge(data.verdict));
    header.appendChild(el("span", "result-score", `${data.final_score} / 100`));
    container.appendChild(header);

    container.appendChild(el("span", "kpi-label", "URL NEUTRALIZADA (DEFANGED)"));
    container.appendChild(el("div", "defanged-box", data.defanged_url));

    container.appendChild(
      el(
        "p",
        "mono",
        `Dominio: ${data.domain} | Capa 1: ${data.layer1_status} | VT Maliciosos: ${data.vt_malicious_count} | Heurística: ${data.heuristic_score}`
      )
    );

    if (data.heuristic_reasons && data.heuristic_reasons.length) {
      container.appendChild(el("span", "field-label", "Señales Detectadas:"));
      const ul = el("ul", "reasons-list");
      data.heuristic_reasons.forEach((r) => ul.appendChild(el("li", "reason-tag", r)));
      container.appendChild(ul);
    }
  };

  const refreshTelemetry = async () => {
    try {
      const [healthRes, statsRes, emailsRes] = await Promise.all([
        fetch("/api/v1/health"),
        fetch("/api/v1/stats"),
        fetch("/api/v1/emails?limit=100"),
      ]);

      const dot = document.getElementById("daemon-dot");
      const statusText = document.getElementById("daemon-status-text");
      if (healthRes.ok) {
        dot.classList.add("online");
        statusText.textContent = "Núcleo Activo // TLS OK";
      } else {
        dot.classList.remove("online");
        statusText.textContent = "Núcleo Degradado";
      }

      if (statsRes.ok) {
        const stats = await statsRes.json();
        document.getElementById("kpi-total").textContent = String(stats.total_emails ?? 0);
        document.getElementById("kpi-quarantined").textContent = String(stats.quarantined_emails ?? 0);
        document.getElementById("kpi-malicious-urls").textContent = String(stats.total_malicious_urls ?? 0);
        document.getElementById("kpi-clean").textContent = String(stats.clean_emails ?? 0);
        document.getElementById("nav-quarantine-badge").textContent = String(stats.quarantined_emails ?? 0);
      }

      if (emailsRes.ok) {
        const payload = await emailsRes.json();
        state.emails = Array.isArray(payload.items) ? payload.items : [];
        renderEmailRows(document.getElementById("overview-tbody"), state.emails.slice(0, 6), false);
        applyForensicsFilters();
      }

      const nowTime = new Date().toTimeString().slice(0, 8);
      document.getElementById("last-sync-label").textContent = `Sincronizado: ${nowTime}`;
    } catch (_err) {
      document.getElementById("daemon-dot").classList.remove("online");
      document.getElementById("daemon-status-text").textContent = "Sin conexión al servidor";
    }
  };

  const bindEvents = () => {
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view));
    });

    document.querySelectorAll("[data-jump-view]").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.jumpView));
    });

    document.getElementById("btn-refresh-all").addEventListener("click", refreshTelemetry);

    document.querySelectorAll(".pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        document.querySelectorAll(".pill").forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        state.statusFilter = pill.dataset.filter || "ALL";
        applyForensicsFilters();
      });
    });

    document.getElementById("forensics-search").addEventListener("input", (ev) => {
      state.searchQuery = ev.target.value || "";
      applyForensicsFilters();
    });

    document.getElementById("drawer-close-btn").addEventListener("click", closeAutopsyDrawer);
    document.getElementById("drawer-backdrop").addEventListener("click", closeAutopsyDrawer);
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") closeAutopsyDrawer();
    });

    const oracleForm = document.getElementById("oracle-form");
    const oracleError = document.getElementById("oracle-error");

    oracleForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      oracleError.textContent = "";

      const urlInput = document.getElementById("oracle-url").value.trim();
      const subjectInput = document.getElementById("oracle-subject").value.trim();
      const bodyInput = document.getElementById("oracle-body").value.trim();

      if (!urlInput) {
        oracleError.textContent = "Debes ingresar una URL para analizar.";
        return;
      }

      const submitBtn = document.getElementById("oracle-submit-btn");
      submitBtn.disabled = true;
      submitBtn.textContent = "Analizando...";

      try {
        const res = await fetch("/api/v1/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            url: urlInput,
            subject: subjectInput,
            body: bodyInput,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          oracleError.textContent = data.detail || "Error al validar la URL.";
          return;
        }
        renderOracleResult(data);
        refreshTelemetry();
      } catch (_err) {
        oracleError.textContent = "Fallo de comunicación con el motor de análisis.";
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = "⚚ Ejecutar Análisis Forense";
      }
    });

    document.getElementById("oracle-clear-btn").addEventListener("click", () => {
      oracleForm.reset();
      oracleError.textContent = "";
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    bindEvents();
    refreshTelemetry();
    window.setInterval(refreshTelemetry, 15000);
  });
})();
