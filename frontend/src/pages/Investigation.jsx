import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  useNavigate,
  useParams,
} from "react-router-dom";

import api from "../api/client";

import "../styles/investigation.css";


function Investigation() {
  const { id } = useParams();

  const navigate = useNavigate();

  const [report, setReport] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [generating, setGenerating] =
    useState(false);

  const [error, setError] =
    useState("");


  const loadReport = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          `/investigator/incident/${id}`
        );

        setReport(response.data);
        setError("");
      } catch (requestError) {
        console.error(requestError);

        if (
          requestError.response?.status
          === 404
        ) {
          setReport(null);

          setError(
            "Investigation report not found"
          );
        } else {
          setError(
            requestError.response?.data?.detail
            || "Could not load investigation report"
          );
        }
      } finally {
        setLoading(false);
      }
    },
    [id]
  );


  useEffect(() => {
    loadReport();
  }, [loadReport]);


  async function generateReport() {
    try {
      setGenerating(true);
      setError("");

      await api.post(
        `/investigator/incident/${id}/generate`
      );

      await loadReport();
    } catch (requestError) {
      console.error(requestError);

      setError(
        requestError.response?.data?.detail
        || "Could not generate report"
      );
    } finally {
      setGenerating(false);
    }
  }


  function formatConfidence(value) {
    if (
      value === null
      || value === undefined
    ) {
      return "Unknown";
    }

    const numericValue = Number(value);

    if (Number.isNaN(numericValue)) {
      return String(value);
    }

    if (numericValue <= 1) {
      return `${Math.round(
        numericValue * 100
      )}%`;
    }

    return `${Math.round(
      numericValue
    )}%`;
  }


  if (loading) {
    return (
      <div className="screen-message">
        Loading investigation...
      </div>
    );
  }


  if (!report) {
    return (
      <div className="screen-message">

        <div className="investigation-empty-state">

          <h2>
            {error
              || "Investigation report not found"}
          </h2>

          <p>
            Generate an AI-assisted report
            for incident #{id}.
          </p>

          <div className="investigation-empty-actions">

            <button
              type="button"
              disabled={generating}
              onClick={generateReport}
            >
              {generating
                ? "Generating..."
                : "Generate AI Report"}
            </button>

            <button
              type="button"
              onClick={() =>
                navigate(
                  `/incidents/${id}`
                )
              }
            >
              Back to Incident
            </button>

          </div>

        </div>

      </div>
    );
  }


  return (
    <div className="investigation-page">

      <header className="investigation-header">

        <div>
          <p className="investigation-eyebrow">
            AI-Assisted Investigation
          </p>

          <h1>
            Investigation Report
          </h1>

          <p>
            Incident #{report.incident_id}
          </p>
        </div>


        <div className="investigation-header-actions">

          <div className="confidence">
            <span>Confidence</span>

            <strong>
              {formatConfidence(
                report.confidence
              )}
            </strong>
          </div>

          <button
            type="button"
            disabled={generating}
            onClick={generateReport}
          >
            {generating
              ? "Regenerating..."
              : "Regenerate Report"}
          </button>

          <button
            type="button"
            onClick={() =>
              navigate(
                `/incidents/${report.incident_id}`
              )
            }
          >
            Back to Incident
          </button>

        </div>

      </header>


      {error && (
        <div className="investigation-error">
          {error}
        </div>
      )}


      <article className="investigation-document">

        <header className="report-document-header">

          <div>
            <span>Incident</span>

            <strong>
              #{report.incident_id}
            </strong>
          </div>

          <div>
            <span>Model</span>

            <strong>
              {report.model_name
                || "Unknown"}
            </strong>
          </div>

          <div>
            <span>Generated</span>

            <strong>
              {report.created_at
                ? new Date(
                    report.created_at
                  ).toLocaleString()
                : "Unknown"}
            </strong>
          </div>

          <div>
            <span>Confidence</span>

            <strong>
              {formatConfidence(
                report.confidence
              )}
            </strong>
          </div>

        </header>


        <section className="report-section">

          <h2>
            1. Executive Summary
          </h2>

          <p>
            {report.summary
              || "No executive summary was generated."}
          </p>

        </section>


        <section className="report-section">

          <h2>
            2. Technical Analysis
          </h2>

          <p>
            {report.analysis
              || "No technical analysis was generated."}
          </p>

        </section>


        <section className="report-section">

          <h2>
            3. MITRE ATT&amp;CK Mapping
          </h2>

          {report.mitre_techniques
          && report.mitre_techniques.length > 0 ? (
            <div className="report-text-list">

              {report.mitre_techniques.map(
                (item, index) => (
                  <p key={`${item}-${index}`}>
                    {index + 1}. {item}
                  </p>
                )
              )}

            </div>
          ) : (
            <p>
              No MITRE ATT&amp;CK techniques
              were identified.
            </p>
          )}

        </section>


        <section className="report-section">

          <h2>
            4. Recommended Actions
          </h2>

          {report.recommendations
          && report.recommendations.length > 0 ? (
            <div className="report-text-list">

              {report.recommendations.map(
                (item, index) => (
                  <p key={`${item}-${index}`}>
                    {index + 1}. {item}
                  </p>
                )
              )}

            </div>
          ) : (
            <p>
              No recommendations were generated.
            </p>
          )}

        </section>


        <section className="report-section">

          <h2>
            5. Analyst Notes
          </h2>

          <p>
            This report was generated to assist
            security analysts during incident
            triage and investigation. The findings
            should be validated against the related
            Windows events, evidence records,
            affected user profile and device
            activity before remediation actions
            are completed.
          </p>

        </section>


        <footer className="report-document-footer">

          <p>
            Generated by{" "}
            <strong>
              {report.model_name
                || "InsiderGuard AI"}
            </strong>
          </p>

          <p>
            Report generated at{" "}
            {report.created_at
              ? new Date(
                  report.created_at
                ).toLocaleString()
              : "an unknown time"}
          </p>

        </footer>

      </article>

    </div>
  );
}


export default Investigation;