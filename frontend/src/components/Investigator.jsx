import { useState } from "react";
import { investigate } from "../api/client";
import "./Investigator.css";

function formatLabel(value) {
  return String(value || "Unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatConfidence(value) {
  if (value === null || value === undefined || value === "") return "N/A";
  const number = Number(value);
  if (!Number.isFinite(number)) return String(value);
  return `${Math.round(number <= 1 ? number * 100 : number)}%`;
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") return "Not provided";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    return value.length ? value.map((item) => formatValue(item)).join(", ") : "None";
  }
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

/*
 * Evidence is sometimes returned as an object and sometimes as a JSON string.
 * Parse JSON strings for display without changing the original API response.
 */
function normalizeRecord(item) {
  if (typeof item !== "string") return item;
  const trimmed = item.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return item;
  try {
    return JSON.parse(trimmed);
  } catch {
    return item;
  }
}

function EvidenceList({ title, items, emptyMessage, variant = "" }) {
  const list = Array.isArray(items) ? items : [];

  return (
    <section className={`section evidence-section ${variant}`}>
      <div className="section-heading">
        <h3>{title}</h3>
        <span className="section-count">{list.length}</span>
      </div>

      {list.length === 0 ? (
        <p className="muted">{emptyMessage}</p>
      ) : (
        <div className="evidence-grid">
          {list.map((rawItem, index) => {
            const item = normalizeRecord(rawItem);
            const isObject = typeof item === "object" && item !== null && !Array.isArray(item);

            return (
              <article className="evidence-card" key={`${title}-${index}`}>
                {isObject ? (
                  <>
                    <div className="evidence-meta">
                      <span className="evidence-source">
                        {formatLabel(item.source || item.provider || item.tool || "Evidence")}
                      </span>
                      {item.indicator_type && (
                        <span className="result-tag">{formatLabel(item.indicator_type)}</span>
                      )}
                    </div>

                    {(item.indicator || item.value || item.cve || item.ip || item.url) && (
                      <p className="evidence-indicator">
                        {formatValue(item.indicator || item.value || item.cve || item.ip || item.url)}
                      </p>
                    )}

                    <p className="evidence-finding">
                      {formatValue(
                        item.finding ||
                          item.description ||
                          item.details ||
                          item.reason ||
                          item
                      )}
                    </p>

                    {item.severity && (
                      <span className="result-tag">
                        Severity: {formatLabel(item.severity)}
                      </span>
                    )}
                  </>
                ) : (
                  <p className="evidence-finding">{formatValue(item)}</p>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function MitreFindings({ findings }) {
  const items = Array.isArray(findings) ? findings : [];

  return (
    <section className="section">
      <div className="section-heading">
        <h3>MITRE ATT&CK Findings</h3>
        <span className="section-count">{items.length}</span>
      </div>

      {items.length === 0 ? (
        <div className="empty-state">
          <span className="empty-state-icon">◎</span>
          <div>
            <strong>No techniques mapped</strong>
            <p className="muted">
              No MITRE ATT&CK techniques were returned for this investigation.
            </p>
          </div>
        </div>
      ) : (
        <div className="result-list">
          {items.map((rawItem, index) => {
            const item = normalizeRecord(rawItem);
            if (typeof item !== "object" || item === null || Array.isArray(item)) {
              return (
                <article className="result-item" key={`mitre-${index}`}>
                  <p>{formatValue(item)}</p>
                </article>
              );
            }

            const techniqueId = item.technique_id || item.technique || item.id;
            const techniqueName =
              item.technique_name || item.name || item.technique_description;
            const detection =
              item.detection_recommendations || item.detection || item.detection_guidance;
            const evidence = item.evidence || item.supporting_evidence;

            return (
              <article className="result-item" key={`mitre-${index}`}>
                <div className="result-item-header">
                  <strong>
                    {techniqueId || "Technique"}
                    {techniqueName ? ` — ${techniqueName}` : ""}
                  </strong>
                </div>

                {item.tactic && (
                  <p><strong>Tactic:</strong> {formatValue(item.tactic)}</p>
                )}
                {item.justification && (
                  <p><strong>Justification:</strong> {formatValue(item.justification)}</p>
                )}
                {evidence && (
                  <p><strong>Evidence:</strong> {formatValue(evidence)}</p>
                )}
                {detection && (
                  <p><strong>Detection recommendations:</strong> {formatValue(detection)}</p>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function CveFindings({ findings }) {
  const items = Array.isArray(findings) ? findings : [];

  return (
    <section className="section">
      <div className="section-heading">
        <h3>CVE Findings</h3>
        <span className="section-count">{items.length}</span>
      </div>

      {items.length === 0 ? (
        <p className="muted">No CVE findings were returned.</p>
      ) : (
        <div className="result-list">
          {items.map((rawItem, index) => {
            const item = normalizeRecord(rawItem);
            if (typeof item !== "object" || item === null || Array.isArray(item)) {
              return (
                <article className="result-item" key={`cve-${index}`}>
                  <p>{formatValue(item)}</p>
                </article>
              );
            }

            const cveId = item.cve || item.cve_id || item.id;
            const description = item.description || item.finding;
            const severity = item.severity || item.cvss_severity;
            const score = item.cvss_score ?? item.cvss ?? item.base_score;

            return (
              <article className="result-item" key={`cve-${index}`}>
                <div className="result-item-header">
                  <strong>{cveId || "CVE finding"}</strong>
                </div>
                {(severity || score !== undefined) && (
                  <p>
                    <strong>Severity:</strong> {formatValue(severity)}
                    {score !== undefined && ` · CVSS: ${formatValue(score)}`}
                  </p>
                )}
                {description && <p><strong>Description:</strong> {formatValue(description)}</p>}
                {item.affected_products && (
                  <p><strong>Affected products:</strong> {formatValue(item.affected_products)}</p>
                )}
                {item.justification && (
                  <p><strong>Incident relevance:</strong> {formatValue(item.justification)}</p>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function InvestigationTimeline({ timeline }) {
  const items = Array.isArray(timeline) ? timeline : [];

  return (
    <section className="section">
      <div className="section-heading">
        <h3>Investigation Timeline</h3>
        <span className="section-count">{items.length} steps</span>
      </div>

      {items.length === 0 ? (
        <p className="muted">No investigation timeline was returned.</p>
      ) : (
        <div className="timeline-list">
          {items.map((entry, index) => {
            const toolName = entry?.tool || entry?.name || `Investigation step ${index + 1}`;
            const status = entry?.status || entry?.result?.status || "unknown";
            const toolResult = entry?.result;
            const argumentsUsed = entry?.arguments;
            const statusClass = String(status).toLowerCase().replaceAll(" ", "-");

            return (
              <details className="timeline-item" key={`${toolName}-${index}`}>
                <summary>
                  <span className="timeline-number">{index + 1}</span>
                  <span className="timeline-tool">{formatLabel(toolName)}</span>
                  <span className={`status-tag status-${statusClass}`}>
                    {formatLabel(status)}
                  </span>
                </summary>

                <div className="timeline-content">
                  {argumentsUsed && (
                    <div className="timeline-block">
                      <h4>Arguments</h4>
                      <pre>{JSON.stringify(argumentsUsed, null, 2)}</pre>
                    </div>
                  )}

                  {toolResult && (
                    <div className="timeline-block">
                      <h4>Result</h4>
                      {toolResult.error ? (
                        <p className="error">{formatValue(toolResult.error)}</p>
                      ) : (
                        <>
                          {toolResult.finding && (
                            <p className="timeline-finding">{formatValue(toolResult.finding)}</p>
                          )}
                          <details className="nested-raw">
                            <summary>View technical details</summary>
                            <pre>{JSON.stringify(toolResult, null, 2)}</pre>
                          </details>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </details>
            );
          })}
        </div>
      )}
    </section>
  );
}

export default function Investigator() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function handleSubmit(event) {
    event?.preventDefault();
    if (!input.trim() || loading) return;

    setLoading(true);
    setResult(null);

    try {
      // URL normalization is handled centrally by frontend/src/api/client.js.
      // Keeping this value as plain trimmed text avoids fragile duplicate regexes.
      const cleanedInput = input.trim();
      const response = await investigate(cleanedInput);
      setResult(response);
    } catch (error) {
      setResult({
        success: false,
        error: error?.message || "An unexpected error occurred.",
      });
    } finally {
      setLoading(false);
    }
  }

  const data = result?.data;
  const verdict = data?.verdict || "Unknown";
  const verdictClass = String(verdict).toLowerCase().replaceAll(" ", "-");

  return (
    <main className="page">
      <header className="header">
        <div className="brand-mark" aria-hidden="true">🛡️</div>
        <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
        <h1>SentinelAI SOC Analyst</h1>
        <p className="subtitle">
          Autonomous security investigation and threat intelligence
        </p>
      </header>

      <section className="investigation-panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">NEW INVESTIGATION</p>
            <h2>Analyze an incident</h2>
          </div>
          <span className="live-indicator"><span /> AI ANALYST</span>
        </div>

        <form onSubmit={handleSubmit}>
          <textarea
            className="input-box"
            rows={6}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder={`Enter a suspicious URL, CVE, IP address, or email:

Investigate http://suspicious-example.com

Analyze CVE-2021-44228

Review this suspicious email...`}
            disabled={loading}
            aria-label="Incident details to investigate"
          />

          <div className="input-footer">
            <span className="muted">Include any available incident context.</span>
            <button
              className="button"
              type="submit"
              disabled={loading || !input.trim()}
            >
              {loading ? "🔍 Investigating…" : "▶  Investigate"}
            </button>
          </div>
        </form>
      </section>

      {loading && (
        <section className="section loading-message" role="status">
          <div className="loading-spinner" />
          <div>
            <strong>Investigation in progress</strong>
            <p className="muted">
              SentinelAI is collecting threat intelligence and analyzing evidence…
            </p>
          </div>
        </section>
      )}

      {result?.success && data && (
        <div className="results">
          <div className="results-title">
            <div>
              <p className="eyebrow">ANALYSIS COMPLETE</p>
              <h2>Investigation Report</h2>
            </div>
            <span className="report-status">● Completed</span>
          </div>

          <section className="metrics">
            <article className="card verdict-card">
              <div className="card-title">VERDICT</div>
              <div className={`card-value verdict-value ${verdictClass}`}>
                {String(verdict).toUpperCase()}
              </div>
            </article>

            <article className="card">
              <div className="card-title">RISK SCORE</div>
              <div className="card-value">
                {formatValue(data.risk_score)}
                <span className="metric-unit"> / 100</span>
              </div>
              {data.risk_level && (
                <div className="muted">Risk level: {formatLabel(data.risk_level)}</div>
              )}
            </article>

            <article className="card">
              <div className="card-title">CONFIDENCE</div>
              <div className="card-value">{formatConfidence(data.confidence)}</div>
            </article>

            <article className="card">
              <div className="card-title">INCIDENT TYPE</div>
              <div className="card-value incident-value">
                {formatValue(data.incident_type)}
              </div>
            </article>
          </section>

          <section className="section summary-section">
            <div className="section-heading">
              <h3>Executive Summary</h3>
              <span className="summary-icon">✦</span>
            </div>
            <p>{formatValue(data.executive_summary)}</p>
          </section>

          <section className="section">
            <h3>Analyst Assessment</h3>
            <p>{formatValue(data.reason || data.rationale)}</p>
          </section>

          <EvidenceList
            title="Supporting Evidence"
            items={data.supporting_evidence}
            emptyMessage="No supporting evidence was returned."
            variant="supporting"
          />

          <EvidenceList
            title="Contradictory Evidence"
            items={data.contradictory_evidence}
            emptyMessage="No contradictory evidence was returned."
            variant="contradictory"
          />

          <EvidenceList
            title="Missing Evidence"
            items={data.missing_evidence}
            emptyMessage="No missing evidence was reported."
            variant="missing"
          />

          <MitreFindings findings={data.mitre_findings} />
          <CveFindings findings={data.cve_findings} />

          {Array.isArray(data.recommended_actions) && data.recommended_actions.length > 0 && (
            <section className="section">
              <div className="section-heading">
                <h3>Recommended Actions</h3>
                <span className="section-count">{data.recommended_actions.length}</span>
              </div>
              <ol className="action-list">
                {data.recommended_actions.map((action, index) => (
                  <li key={`action-${index}`}>
                    <span className="action-number">{index + 1}</span>
                    <span>{formatValue(action)}</span>
                  </li>
                ))}
              </ol>
            </section>
          )}

          <InvestigationTimeline timeline={data.investigation_log} />

          <details className="section raw-result">
            <summary>View Raw Investigation Response</summary>
            <pre>{JSON.stringify(data, null, 2)}</pre>
          </details>
        </div>
      )}

      {result?.success === false && (
        <section className="section error-message" role="alert">
          <h3>Investigation Failed</h3>
          <p>{result.error || "The backend request failed."}</p>
        </section>
      )}

      <footer className="page-footer">
        SentinelAI SOC Analyst <span>•</span> AI-assisted investigation
      </footer>
    </main>
  );
}
