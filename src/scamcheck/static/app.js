"use strict";

// scamcheck demo UI. Talks only to this service's own API (same origin).
// All server data is rendered with textContent / createElement; never as HTML.
(function () {
  const byId = (id) => document.getElementById(id);

  // Class names come from this fixed table, never from server data.
  const DECISION_CLASS = {
    ALLOW: "allow",
    WARN: "warn",
    HOLD: "hold",
    REJECT: "reject",
  };
  const decisionClass = (decision) => DECISION_CLASS[decision] || "unknown";

  let scenarios = [];
  let demoToggle = null;

  // ---- small helpers -------------------------------------------------------------------

  function el(tag, options, ...children) {
    const node = document.createElement(tag);
    const opts = options || {};
    if (opts.className) node.className = opts.className;
    if (opts.text !== undefined) node.textContent = opts.text;
    if (opts.attrs) {
      for (const [name, value] of Object.entries(opts.attrs)) node.setAttribute(name, value);
    }
    for (const child of children) {
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  async function callApi(path, options) {
    const response = await fetch(path, options);
    let data = null;
    try {
      data = await response.json();
    } catch (error) {
      data = null; // not JSON; callers treat this as an unexpected response
    }
    return { status: response.status, ok: response.ok, data };
  }

  function showError(id, message) {
    const node = byId(id);
    node.textContent = message || "";
    node.hidden = !message;
  }

  function describeFailure(error) {
    return "Could not reach the service: " + (error && error.message ? error.message : "unknown error");
  }

  // Disables a button while its action runs, and reports failures in the panel's error line.
  async function runAction(button, errorId, action) {
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    showError(errorId, "");
    try {
      await action();
    } catch (error) {
      showError(errorId, describeFailure(error));
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  function table(caption, headers, rows) {
    const head = el("tr", {}, ...headers.map((h) => el("th", { text: h, attrs: { scope: "col" } })));
    const body = rows.map((cells) =>
      el("tr", {}, ...cells.map((cell) => el("td", {}, cell instanceof Node ? cell : String(cell))))
    );
    return el(
      "table",
      {},
      el("caption", { className: "visually-hidden", text: caption }),
      el("thead", {}, head),
      el("tbody", {}, ...body)
    );
  }

  const tag = (text, kind) => el("span", { className: "tag tag-" + kind, text });
  const decisionTag = (decision) => tag(decision, decisionClass(decision));
  const passTag = (passed) => tag(passed ? "PASS" : "FAIL", passed ? "pass" : "fail");
  const score = (value) => (value === null || value === undefined ? "n/a" : Number(value).toFixed(4));

  // ---- health ---------------------------------------------------------------------------

  function renderHealth(health) {
    const banner = byId("health-banner");
    const text = byId("health-text");
    if (!health) {
      banner.className = "banner banner-unknown";
      text.textContent = "UNREACHABLE: the service did not answer /health.";
      renderDemoControls(null);
      return;
    }
    const normal = health.status === "ok";
    banner.className = "banner " + (normal ? "banner-ok" : "banner-degraded");
    if (normal) {
      text.textContent =
        "NORMAL. Risk model " + health.model_version + ", policy " + health.policy_version + ".";
    } else {
      const rulesOnly = health.mode === "DEGRADED_RULES_ONLY";
      text.textContent =
        "DEGRADED" +
        (rulesOnly ? " (rules only, no risk model)" : "") +
        ": " +
        (health.reasons || []).join(", ") +
        ". Policy " +
        (health.policy_version || "unknown") +
        ".";
    }
    renderDemoControls(health);
  }

  function renderDemoControls(health) {
    const holder = byId("demo-controls");
    if (!health || !health.demo_mode) {
      demoToggle = null;
      holder.replaceChildren();
      return;
    }
    if (!demoToggle) {
      demoToggle = el("input", { attrs: { type: "checkbox", id: "demo-toggle" } });
      demoToggle.addEventListener("change", () => setModelFailure(demoToggle.checked));
      holder.replaceChildren(
        demoToggle,
        el("label", { text: "Simulate model failure", attrs: { for: "demo-toggle" } })
      );
    }
    demoToggle.checked = Boolean(health.demo_model_failure);
  }

  async function loadHealth() {
    try {
      const result = await callApi("/health");
      renderHealth(result.ok ? result.data : null);
    } catch (error) {
      renderHealth(null);
    }
  }

  async function setModelFailure(enabled) {
    demoToggle.disabled = true;
    showError("assess-error", "");
    try {
      const result = await callApi("/v1/demo/model-failure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      });
      if (!result.ok) {
        const detail = result.data && result.data.detail ? result.data.detail : "HTTP " + result.status;
        showError("assess-error", "Could not switch the model failure simulation: " + detail);
      }
    } catch (error) {
      showError("assess-error", describeFailure(error));
    } finally {
      await loadHealth();
      if (demoToggle) demoToggle.disabled = false;
    }
  }

  // ---- assess ---------------------------------------------------------------------------

  async function loadScenarios() {
    const select = byId("scenario-select");
    try {
      const result = await callApi("/v1/scenarios");
      if (!result.ok || !Array.isArray(result.data)) throw new Error("HTTP " + result.status);
      scenarios = result.data;
    } catch (error) {
      showError("assess-error", "Could not load the scenario list. " + describeFailure(error));
      return;
    }
    select.replaceChildren(
      ...scenarios.map((s, index) =>
        el("option", { text: s.id + " – " + s.typology, attrs: { value: String(index) } })
      )
    );
    if (scenarios.length) chooseScenario(0);
  }

  function chooseScenario(index) {
    const scenario = scenarios[index];
    if (!scenario) return;
    byId("request-json").value = JSON.stringify(scenario.request, null, 2);
    byId("scenario-description").textContent = scenario.description;
  }

  function renderDecision(data) {
    const card = byId("decision-card");
    const kind = decisionClass(data.decision);
    card.className = "decision-card decision-" + kind;
    const rejected = data.decision === "REJECT";
    const rulesOnly = data.mode === "DEGRADED_RULES_ONLY";

    const facts = el("dl", { className: "facts" });
    const addFact = (label, value) => {
      facts.append(el("dt", { text: label }), el("dd", { text: String(value) }));
    };
    addFact("Risk score", score(data.risk_score) + (rulesOnly ? " (rules only, no model)" : ""));
    addFact("Mode", data.mode);
    addFact("Model version", data.model_version || "none");
    addFact("Policy version", data.policy_version);
    addFact("Latency", data.latency_ms + " ms");
    addFact("Request ID", data.request_id === null ? "none" : data.request_id);
    addFact("Decision ID", data.decision_id);

    const reasons = el("ul", { className: "reasons" });
    for (const reason of data.reasons || []) {
      reasons.append(el("li", {}, el("code", { text: reason.code }), " – " + reason.detail));
    }

    card.replaceChildren(
      el("div", { className: "decision-title", text: "Decision: " + data.decision }),
      el(
        "div",
        { className: "decision-body" },
        facts,
        el("h3", { text: rejected ? "Error codes" : "Reasons" }),
        reasons
      )
    );
    card.hidden = false;
  }

  async function submitAssess() {
    const result = await callApi("/v1/assess", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: byId("request-json").value, // sent exactly as typed, so invalid JSON is rejected by the API
    });
    if (!result.data || !result.data.decision) {
      throw new Error("unexpected response (HTTP " + result.status + ")");
    }
    renderDecision(result.data);
    await Promise.all([loadHealth(), loadAudit()]);
  }

  // ---- audit ----------------------------------------------------------------------------

  async function loadAudit() {
    const holder = byId("audit-table");
    try {
      const result = await callApi("/v1/audit?limit=20");
      if (!result.ok || !result.data) {
        showError("audit-error", "The audit trail cannot be read (HTTP " + result.status + ").");
        holder.replaceChildren();
        return;
      }
      showError("audit-error", "");
      const rows = result.data.records.map((r) => [
        r.ts.replace("T", " ").slice(0, 19),
        decisionTag(r.decision),
        r.customer_id === null ? "" : r.customer_id,
        r.payee_account_masked === null ? "" : r.payee_account_masked,
        score(r.risk_score),
        r.mode,
        r.reasons.map((x) => x.code).join(", "),
        r.record_hash.slice(0, 10),
      ]);
      if (!rows.length) {
        holder.replaceChildren(el("p", { className: "hint", text: "No records yet." }));
        return;
      }
      holder.replaceChildren(
        table(
          "Most recent audit records, newest first",
          ["Time (UTC)", "Decision", "Customer", "Payee account", "Score", "Mode", "Reasons", "Hash"],
          rows
        )
      );
    } catch (error) {
      showError("audit-error", describeFailure(error));
    }
  }

  async function verifyAudit() {
    const result = await callApi("/v1/audit/verify", { method: "POST" });
    const out = byId("verify-result");
    if (!result.data || typeof result.data.ok !== "boolean") {
      throw new Error("unexpected response (HTTP " + result.status + ")");
    }
    if (result.data.ok) {
      out.className = "result result-ok";
      out.textContent = "OK: " + result.data.message + ".";
    } else {
      out.className = "result result-bad";
      out.textContent =
        "BROKEN: first bad record is line " + result.data.first_bad_line + ". " + result.data.message + ".";
    }
    out.hidden = false;
    await loadHealth();
  }

  // ---- evaluation -----------------------------------------------------------------------

  function scenarioRows(items) {
    return items.map((s) => [
      s.id,
      s.typology,
      s.expected,
      decisionTag(s.actual),
      score(s.risk_score),
      passTag(s.passed),
    ]);
  }

  const SCENARIO_HEADERS = ["ID", "Typology", "Expected", "Actual", "Score", "Result"];

  function renderEvaluation(data) {
    const gates = el("ul", { className: "gates" });
    for (const gate of data.gates) {
      gates.append(el("li", {}, passTag(gate.passed), " ", el("strong", { text: gate.name }), " – " + gate.detail));
    }
    const known = data.known_limitations;
    byId("eval-results").replaceChildren(
      el("p", {}, "Overall: ", passTag(data.overall_pass), " (policy " + data.policy_version + ", model " + data.model_version + ")"),
      el("h3", { text: "Gates" }),
      gates,
      el("h3", { text: "Scenarios (" + data.scenarios.length + ")" }),
      el(
        "div",
        { className: "table-wrap" },
        table("Evaluation results per scenario", SCENARIO_HEADERS, scenarioRows(data.scenarios))
      ),
      el(
        "details",
        {},
        el("summary", {
          text:
            "Known limitations, not part of the gates: " +
            known.matching_correct_answer +
            " of " +
            known.total +
            " match the correct answer",
        }),
        el(
          "div",
          { className: "table-wrap" },
          table("Known limitation scenarios", SCENARIO_HEADERS, scenarioRows(known.scenarios))
        )
      )
    );
  }

  async function runEvaluation() {
    const result = await callApi("/v1/eval", { method: "POST" });
    if (!result.ok || !result.data || !Array.isArray(result.data.gates)) {
      const detail = result.data && result.data.detail ? result.data.detail : "HTTP " + result.status;
      throw new Error(detail);
    }
    renderEvaluation(result.data);
    await loadHealth();
  }

  // ---- start up -------------------------------------------------------------------------

  function init() {
    byId("scenario-select").addEventListener("change", (event) => chooseScenario(Number(event.target.value)));
    byId("submit-btn").addEventListener("click", (event) =>
      runAction(event.currentTarget, "assess-error", submitAssess)
    );
    byId("audit-refresh-btn").addEventListener("click", (event) =>
      runAction(event.currentTarget, "audit-error", async () => {
        await loadAudit();
        await loadHealth();
      })
    );
    byId("verify-btn").addEventListener("click", (event) =>
      runAction(event.currentTarget, "audit-error", verifyAudit)
    );
    byId("eval-btn").addEventListener("click", (event) =>
      runAction(event.currentTarget, "eval-error", runEvaluation)
    );
    loadHealth();
    loadScenarios();
    loadAudit();
  }

  init();
})();
