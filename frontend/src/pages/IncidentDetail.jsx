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

  const [timeline, setTimeline] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [updating, setUpdating] =
    useState(false);


  const loadIncident = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const [
          incidentResponse,
          timelineResponse,
        ] = await Promise.all([
          api.get(
            `/case-explorer/incidents/${id}`
          ),
          api.get(
            `/incidents/${id}/timeline`
          ),
        ]);

        setIncident(
          incidentResponse.data
        );

        setTimeline(
          Array.isArray(timelineResponse.data)
            ? timelineResponse.data
            : []
        );
      } catch (requestError) {
        console.error(requestError);

        setError(
          requestError.response?.data?.detail
          || "Could not load incident."
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


  async function updateStatus(
    newStatus
  ) {
    try {
      setUpdating(true);
      setError("");

      await api.patch(
        `/incidents/${id}/status`,
        {
          status: newStatus,
        }
      );

      await loadIncident();
    } catch (requestError) {
      console.error(requestError);

      setError(
        requestError.response?.data?.detail
        || "Could not update incident status."
      );
    } finally {
      setUpdating(false);
    }
  }


  function getActorIcon(
    actorType
  ) {
    switch (actorType) {
      case "SYSTEM":
        return "🖥";

      case "ANALYST":
        return "👤";

      case "AI_ENGINE":
        return "🤖";

      case "BLOCKCHAIN":
        return "⛓";

      default:
        return "📌";
    }
  }


  function getEventClass(
    eventType
  ) {
    switch (eventType) {
      case "INCIDENT_CREATED":
      case "CREATED":
        return "timeline-created";

      case "STATUS_CHANGED":
      case "STATUS_CHANGE":
        return "timeline-status";

      case "EVIDENCE_CREATED":
        return "timeline-evidence";

      case "BLOCKCHAIN_SEALED":
      case "BLOCKCHAIN_VERIFIED":
        return "timeline-blockchain";

      case "AI_INVESTIGATION":
      case "AI_INVESTIGATION_STARTED":
      case "AI_REPORT_GENERATED":
        return "timeline-ai";

      case "COMMENT_ADDED":
        return "timeline-comment";

      case "INCIDENT_ASSIGNED":
        return "timeline-assigned";

      default:
        return "timeline-default";
    }
  }


  function formatEventTitle(
    eventType
  ) {
    if (!eventType) {
      return "Audit Event";
    }

    return eventType
      .replaceAll("_", " ")
      .toLowerCase()
      .replace(
        /\b\w/g,
        (character) =>
          character.toUpperCase()
      );
  }


  function formatDate(
    value
  ) {
    if (!value) {
      return "Unknown time";
    }

    const parsedDate =
      new Date(value);

    if (
      Number.isNaN(
        parsedDate.getTime()
      )
    ) {
      return "Unknown time";
    }

    return parsedDate
      .toLocaleString();
  }


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

          <p>
            {incident.title}
          </p>
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

          <strong
            className={
              `severity-value severity-${
                incident.severity
                  ?.toLowerCase()
              }`
            }
          >
            {incident.severity}
          </strong>
        </article>


        <article>
          <span>Status</span>

          <select
            value={incident.status}
            disabled={updating}
            onChange={(event) =>
              updateStatus(
                event.target.value
              )
            }
          >
            <option value="OPEN">
              OPEN
            </option>

            <option value="INVESTIGATING">
              INVESTIGATING
            </option>

            <option value="RESOLVED">
              RESOLVED
            </option>

            <option value="CLOSED">
              CLOSED
            </option>
          </select>

          {updating && (
            <small className="status-updating">
              Updating...
            </small>
          )}
        </article>


        <article>
          <span>Created</span>

          <strong>
            {formatDate(
              incident.created_at
            )}
          </strong>
        </article>

      </section>


      <section className="case-panel case-content">

        <h2>Description</h2>

        <p>
          {incident.description
            || "No description"}
        </p>

      </section>


      <section className="case-panel case-content">

        <div className="audit-trail-heading">

          <div>
            <p className="audit-trail-label">
              Case history
            </p>

            <h2>
              SOC Audit Trail
            </h2>

            <p>
              System, analyst, AI and
              forensic actions recorded
              for this incident.
            </p>
          </div>


          <div className="audit-event-count">
            <strong>
              {timeline.length}
            </strong>

            <span>
              Events
            </span>
          </div>

        </div>


        {timeline.length === 0 ? (
          <div className="audit-empty-state">

            <h3>
              No audit events
            </h3>

            <p>
              Events will appear here when
              the system or an analyst acts
              on this incident.
            </p>

          </div>
        ) : (
          <div className="timeline">

            {timeline.map(
              (
                timelineEvent,
                index
              ) => {
                const actorType =
                  timelineEvent.actor_type
                  || "SYSTEM";

                const metadata =
                  timelineEvent
                    .event_metadata;

                return (
                  <article
                    key={
                      timelineEvent.id
                      ?? `${timelineEvent.event_type}-${index}`
                    }
                    className={
                      `timeline-item ${getEventClass(
                        timelineEvent.event_type
                      )}`
                    }
                  >

                    <div className="timeline-marker">

                      <div className="timeline-dot">
                        <span>
                          {getActorIcon(
                            actorType
                          )}
                        </span>
                      </div>

                    </div>


                    <div className="timeline-content">

                      <header className="timeline-header">

                        <div>

                          <span
                            className={
                              `timeline-actor actor-${actorType.toLowerCase()}`
                            }
                          >
                            {actorType}
                          </span>

                          {timelineEvent.actor_name && (
                            <span className="timeline-actor-name">
                              {
                                timelineEvent
                                  .actor_name
                              }
                            </span>
                          )}

                        </div>


                        <time>
                          {formatDate(
                            timelineEvent
                              .created_at
                          )}
                        </time>

                      </header>


                      <h3>
                        {formatEventTitle(
                          timelineEvent
                            .event_type
                        )}
                      </h3>


                      <p>
                        {
                          timelineEvent
                            .description
                        }
                      </p>


                      {timelineEvent.old_status
                      && timelineEvent.new_status && (
                        <div className="timeline-status-change">

                          <span
                            className={
                              `timeline-status-pill status-${timelineEvent.old_status.toLowerCase()}`
                            }
                          >
                            {
                              timelineEvent
                                .old_status
                            }
                          </span>

                          <span className="timeline-status-arrow">
                            →
                          </span>

                          <span
                            className={
                              `timeline-status-pill status-${timelineEvent.new_status.toLowerCase()}`
                            }
                          >
                            {
                              timelineEvent
                                .new_status
                            }
                          </span>

                        </div>
                      )}


                      {metadata
                      && Object.keys(metadata).length > 0 && (
                        <details className="timeline-metadata">

                          <summary>
                            Event metadata
                          </summary>

                          <div className="timeline-metadata-grid">

                            {Object.entries(
                              metadata
                            ).map(
                              (
                                [
                                  metadataKey,
                                  metadataValue,
                                ]
                              ) => (
                                <div
                                  key={
                                    metadataKey
                                  }
                                >
                                  <span>
                                    {metadataKey
                                      .replaceAll(
                                        "_",
                                        " "
                                      )}
                                  </span>

                                  <strong>
                                    {typeof metadataValue
                                      === "object"
                                      ? JSON.stringify(
                                          metadataValue
                                        )
                                      : String(
                                          metadataValue
                                        )}
                                  </strong>
                                </div>
                              )
                            )}

                          </div>

                        </details>
                      )}

                    </div>

                  </article>
                );
              }
            )}

          </div>
        )}

      </section>


      <section className="case-panel case-content">

        <h2>
          Related Alert
        </h2>

        {incident.alert ? (
          <div className="case-detail-grid">

            <div>
              <span>
                Alert Type
              </span>

              <strong>
                {
                  incident.alert
                    .alert_type
                }
              </strong>
            </div>


            <div>
              <span>
                Risk Score
              </span>

              <strong>
                {
                  incident.alert
                    .risk_score
                }
              </strong>
            </div>


            <div>
              <span>
                Reason
              </span>

              <strong>
                {
                  incident.alert
                    .reason
                }
              </strong>
            </div>

          </div>
        ) : (
          <p>
            No related alert.
          </p>
        )}

      </section>


      <section className="case-panel case-content">

        <h2>Evidence</h2>

        {!incident.evidences
        || incident.evidences.length === 0 ? (
          <p>
            No evidence attached.
          </p>
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
                    {
                      evidence
                        .evidence_type
                    }
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