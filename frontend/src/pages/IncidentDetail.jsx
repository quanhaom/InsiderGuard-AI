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

import "../styles/cases.css";


function IncidentDetail() {
  const { id } = useParams();

  const navigate = useNavigate();

  const [incident, setIncident] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  const loadIncident = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          `/case-explorer/incidents/${id}`
        );

        setIncident(response.data);
      } catch (requestError) {
        console.error(requestError);

        setError(
          "Could not load incident."
        );
      } finally {
        setLoading(false);
      }
    },
    [id]
  );


  useEffect(() => {
    loadIncident();
  }, [loadIncident]);


  if (loading) {
    return (
      <div className="case-message">
        Loading incident...
      </div>
    );
  }


  if (error || !incident) {
    return (
      <div className="case-message">
        <h2>
          {error || "Incident not found"}
        </h2>

        <button
          type="button"
          onClick={() =>
            navigate("/incidents")
          }
        >
          Back
        </button>
      </div>
    );
  }


  return (
    <div className="cases-page">

      <header className="cases-header">
        <div>
          <h1>
            Incident #{incident.id}
          </h1>

          <p>{incident.title}</p>
        </div>

        <div className="case-actions">
          <button
            type="button"
            className="case-button"
            onClick={() =>
              navigate(
                `/investigation/${incident.id}`
              )
            }
          >
            AI Investigation
          </button>

          <button
            type="button"
            className="case-button"
            onClick={() =>
              navigate("/incidents")
            }
          >
            Back
          </button>
        </div>
      </header>


      <section className="case-summary-grid">

        <article>
          <span>User</span>
          <strong>
            {incident.username}
          </strong>
        </article>

        <article>
          <span>Severity</span>
          <strong>
            {incident.severity}
          </strong>
        </article>

        <article>
          <span>Status</span>
          <strong>
            {incident.status}
          </strong>
        </article>

        <article>
          <span>Created</span>
          <strong>
            {new Date(
              incident.created_at
            ).toLocaleString()}
          </strong>
        </article>

      </section>


      <section className="case-panel case-content">
        <h2>Description</h2>

        <p>
          {incident.description ||
            "No description"}
        </p>
      </section>


      <section className="case-panel case-content">
        <h2>Related Alert</h2>

        {incident.alert ? (
          <div className="case-detail-grid">
            <div>
              <span>Alert Type</span>
              <strong>
                {incident.alert.alert_type}
              </strong>
            </div>

            <div>
              <span>Risk Score</span>
              <strong>
                {incident.alert.risk_score}
              </strong>
            </div>

            <div>
              <span>Reason</span>
              <strong>
                {incident.alert.reason}
              </strong>
            </div>
          </div>
        ) : (
          <p>No related alert.</p>
        )}
      </section>


      <section className="case-panel case-content">
        <h2>Evidence</h2>

        {incident.evidences.length === 0 ? (
          <p>No evidence attached.</p>
        ) : (
          <div className="evidence-list">
            {incident.evidences.map(
              (evidence) => (
                <button
                  type="button"
                  key={evidence.id}
                  className="evidence-list-item"
                  onClick={() =>
                    navigate(
                      `/evidences/${evidence.id}`
                    )
                  }
                >
                  <span>
                    Evidence #{evidence.id}
                  </span>

                  <strong>
                    {evidence.evidence_type}
                  </strong>
                </button>
              )
            )}
          </div>
        )}
      </section>

    </div>
  );
}


export default IncidentDetail;