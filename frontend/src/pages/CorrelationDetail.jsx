import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  useNavigate,
  useParams,
} from "react-router-dom";

import api from "../api/client";

import "../styles/correlation-detail.css";


function processName(image) {
  if (!image) {
    return "Unknown process";
  }

  return (
    image
      .replaceAll("/", "\\")
      .split("\\")
      .pop()
    || image
  );
}


function severityClass(severity) {
  return String(
    severity || "LOW"
  )
    .trim()
    .toLowerCase();
}


function eventLabel(eventId) {
  const labels = {
    1: "Process Create",
    3: "Network Connection",
    11: "File Create",
    13: "Registry Modification",
    22: "DNS Query",
  };

  return (
    labels[eventId]
    || `Sysmon Event ${eventId}`
  );
}


function eventTime(event) {
  return (
    event.created_at
    || event.time_created
    || event.timestamp
    || event.event_time
    || event.utc_time
    || "-"
  );
}


function eventDetails(event) {
  if (
    event.details
    && typeof event.details === "object"
  ) {
    return event.details;
  }

  return event;
}


function importantDetail(event) {
  const details =
    eventDetails(event);

  switch (
    Number(
      event.event_id
    )
  ) {
    case 1:
      return (
        details.command_line
        || details.CommandLine
        || details.image
        || details.Image
        || "Process created"
      );

    case 3: {
      const destinationIp = (
        details.destination_ip
        || details.DestinationIp
      );

      const destinationPort = (
        details.destination_port
        || details.DestinationPort
      );

      const destination = [
        destinationIp,
        destinationPort,
      ]
        .filter(Boolean)
        .join(":");

      return (
        destination
        || "Network connection"
      );
    }

    case 11:
      return (
        details.target_filename
        || details.TargetFilename
        || "File created"
      );

    case 13:
      return (
        details.target_object
        || details.TargetObject
        || "Registry modified"
      );

    case 22:
      return (
        details.query_name
        || details.QueryName
        || "DNS query"
      );

    default:
      return (
        "Windows telemetry event"
      );
  }
}


function CorrelationDetail() {
  const {
    processGuid,
  } = useParams();

  const navigate =
    useNavigate();

  const [
    correlation,
    setCorrelation,
  ] = useState(null);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [
    creatingIncident,
    setCreatingIncident,
  ] = useState(false);

  const [
    incidentResult,
    setIncidentResult,
  ] = useState(null);

  const [
    verifyingEvidence,
    setVerifyingEvidence,
  ] = useState(false);

  const [
    evidenceVerification,
    setEvidenceVerification,
  ] = useState(null);

  const [
    error,
    setError,
  ] = useState("");


  // =========================
  // LOAD CORRELATION
  // =========================

  const loadCorrelation =
    useCallback(
      async (
        manualRefresh = false
      ) => {
        try {
          if (manualRefresh) {
            setRefreshing(true);
          }

          setError("");

          const response =
            await api.get(
              `/correlation/tree/${
                encodeURIComponent(
                  processGuid
                )
              }`,
              {
                params: {
                  window_minutes: 60,
                },
              }
            );

          setCorrelation(
            response.data
          );

        } catch (
          requestError
        ) {
          console.error(
            requestError
          );

          setError(
            requestError
              ?.response
              ?.data
              ?.detail
            || (
              "Could not load "
              + "correlation investigation."
            )
          );

        } finally {
          setLoading(false);
          setRefreshing(false);
        }
      },
      [
        processGuid,
      ]
    );


  // =========================
  // CREATE INCIDENT
  // =========================

  const createIncident =
    useCallback(
      async () => {
        try {
          setCreatingIncident(
            true
          );

          setError("");
          setIncidentResult(null);
          setEvidenceVerification(null);

          const response =
            await api.post(
              `/correlation/tree/${
                encodeURIComponent(
                  processGuid
                )
              }/incident`,
              null,
              {
                params: {
                  window_minutes: 60,
                },
              }
            );

          setIncidentResult(
            response.data
          );

        } catch (
          requestError
        ) {
          console.error(
            requestError
          );

          setError(
            requestError
              ?.response
              ?.data
              ?.detail
            || (
              "Could not create "
              + "incident."
            )
          );

        } finally {
          setCreatingIncident(
            false
          );
        }
      },
      [
        processGuid,
      ]
    );


  // =========================
  // VERIFY EVIDENCE
  // =========================

  const verifyEvidence =
    useCallback(
      async () => {
        const evidenceId =
          incidentResult
            ?.evidence
            ?.id;

        if (!evidenceId) {
          return;
        }

        try {
          setVerifyingEvidence(
            true
          );

          setError("");

          const response =
            await api.get(
              `/evidence/${
                evidenceId
              }/verify`
            );

          setEvidenceVerification(
            response.data
          );

        } catch (
          requestError
        ) {
          console.error(
            requestError
          );

          setError(
            requestError
              ?.response
              ?.data
              ?.detail
            || (
              "Could not verify "
              + "evidence integrity."
            )
          );

        } finally {
          setVerifyingEvidence(
            false
          );
        }
      },
      [
        incidentResult,
      ]
    );


  // =========================
  // INITIAL LOAD
  // =========================

  useEffect(
    () => {
      loadCorrelation();
    },
    [
      loadCorrelation,
    ]
  );


  // =========================
  // TIMELINE
  // =========================

  const timeline =
    useMemo(
      () => {
        if (
          !Array.isArray(
            correlation?.events
          )
        ) {
          return [];
        }

        return [
          ...correlation.events,
        ]
          .sort(
            (
              eventA,
              eventB
            ) => {

              const timeA =
                new Date(
                  eventTime(
                    eventA
                  )
                )
                  .getTime();

              const timeB =
                new Date(
                  eventTime(
                    eventB
                  )
                )
                  .getTime();

              if (
                Number.isNaN(
                  timeA
                )
                || Number.isNaN(
                  timeB
                )
              ) {
                return 0;
              }

              return (
                timeA
                - timeB
              );
            }
          );
      },
      [
        correlation,
      ]
    );


  // =========================
  // LOADING
  // =========================

  if (loading) {
    return (
      <div className="screen-message">
        Loading investigation...
      </div>
    );
  }


  // =========================
  // NO CORRELATION
  // =========================

  if (!correlation) {
    return (
      <div className="correlation-detail-page">

        <button
          type="button"
          className="detail-back-button"
          onClick={
            () =>
              navigate(
                "/correlation"
              )
          }
        >
          ← Back
        </button>


        <div className="error-banner">

          {
            error
            || "Correlation not found."
          }

        </div>

      </div>
    );
  }


  const chain =
    Array.isArray(
      correlation.process_chain
    )
      ? correlation.process_chain
      : [];

  const reasons =
    Array.isArray(
      correlation.reasons
    )
      ? correlation.reasons
      : [];

  const mitre =
    Array.isArray(
      correlation.mitre_techniques
    )
      ? correlation.mitre_techniques
      : [];


  return (
    <div className="correlation-detail-page">

      {/* =====================
          TOOLBAR
      ====================== */}

      <section className="detail-toolbar">

        <div className="detail-toolbar-left">

          <button
            type="button"
            className="detail-back-button"
            onClick={
              () =>
                navigate(
                  "/correlation"
                )
            }
          >
            ← Correlations
          </button>

        </div>


        <div className="detail-toolbar-right">

          <button
            type="button"
            className="detail-refresh-button"
            disabled={
              refreshing
            }
            onClick={
              () =>
                loadCorrelation(
                  true
                )
            }
          >
            {
              refreshing
                ? "Refreshing..."
                : "Refresh"
            }
          </button>


          <button
            type="button"
            className="detail-incident-button"
            disabled={
              creatingIncident
              || !correlation.detected
            }
            onClick={
              createIncident
            }
          >
            {
              creatingIncident
                ? "Creating..."
                : "Create Incident"
            }
          </button>

        </div>

      </section>


      {/* =====================
          ERROR
      ====================== */}

      {error && (
        <div className="error-banner detail-error-banner">
          {error}
        </div>
      )}


      {/* =====================
          INCIDENT RESULT
      ====================== */}

      {incidentResult && (

        <div className="incident-success-banner">

          {
            incidentResult.incident
            ? (

              <div className="incident-result-content">

                <div>

                  <strong>
                    Incident #
                    {
                      incidentResult
                        .incident
                        .id
                    }
                    {" "}
                    created successfully.
                  </strong>


                  <span>
                    {
                      incidentResult
                        .incident
                        .severity
                    }
                    {" • "}
                    {
                      incidentResult
                        .incident
                        .status
                    }
                  </span>

                </div>


                <button
                  type="button"
                  onClick={
                    () =>
                      navigate(
                        `/incidents/${
                          incidentResult
                            .incident
                            .id
                        }`
                      )
                  }
                >
                  Open Incident
                </button>

              </div>

            )
            : (

              <div>

                <strong>
                  Alert created.
                </strong>

                <span>
                  Correlation severity
                  is not high enough
                  to create an incident.
                </span>

              </div>

            )
          }

        </div>

      )}


      {/* =====================
          EVIDENCE
      ====================== */}

      {incidentResult?.evidence && (

        <section className="investigation-panel">

          <div className="evidence-header">

            <div>

              <h3>
                Correlation Evidence
              </h3>

              <p>
                Immutable forensic snapshot
                captured when the incident
                was created.
              </p>

            </div>


            <span className="evidence-type-badge">

              {
                incidentResult
                  .evidence
                  .evidence_type
              }

            </span>

          </div>


          <div className="evidence-summary-grid">

            <div>

              <span>
                Evidence ID
              </span>

              <strong>
                #
                {
                  incidentResult
                    .evidence
                    .id
                }
              </strong>

            </div>


            <div>

              <span>
                Incident ID
              </span>

              <strong>
                #
                {
                  incidentResult
                    .evidence
                    .incident_id
                }
              </strong>

            </div>


            <div>

              <span>
                Integrity
              </span>

              <strong
                className={
                  evidenceVerification
                    ?.is_valid
                    === true
                    ? "integrity-valid"
                    : (
                      evidenceVerification
                        ?.is_valid
                        === false
                        ? "integrity-invalid"
                        : "integrity-pending"
                    )
                }
              >
                {
                  evidenceVerification
                    ?.is_valid
                    === true
                    ? "Verified"
                    : (
                      evidenceVerification
                        ?.is_valid
                        === false
                        ? "Failed"
                        : "SHA-256 sealed"
                    )
                }
              </strong>

            </div>

          </div>


          <div className="evidence-hash">

            <span>
              SHA-256
            </span>

            <code>
              {
                incidentResult
                  .evidence
                  .sha256_hash
              }
            </code>

          </div>


          <div className="evidence-actions">

            <button
              type="button"
              disabled={
                verifyingEvidence
              }
              onClick={
                verifyEvidence
              }
            >
              {
                verifyingEvidence
                  ? "Verifying..."
                  : "Verify Integrity"
              }
            </button>


            <button
              type="button"
              onClick={
                () =>
                  navigate(
                    `/evidences/${
                      incidentResult
                        .evidence
                        .id
                    }`
                  )
              }
            >
              Open Evidence
            </button>

          </div>


          {evidenceVerification && (

            <div
              className={
                evidenceVerification
                  .is_valid
                  ? (
                    "evidence-verification "
                    + "valid"
                  )
                  : (
                    "evidence-verification "
                    + "invalid"
                  )
              }
            >

              <strong>
                {
                  evidenceVerification
                    .is_valid
                    ? "Integrity Verified"
                    : "Integrity Failure"
                }
              </strong>


              <span>
                {
                  evidenceVerification
                    .is_valid
                    ? (
                      "Stored and calculated "
                      + "SHA-256 hashes match."
                    )
                    : (
                      "Evidence content does "
                      + "not match its stored hash."
                    )
                }
              </span>

            </div>

          )}

        </section>

      )}


      {/* =====================
          HEADER
      ====================== */}

      <section className="investigation-header">

        <div className="investigation-header-main">

          <div className="investigation-title">

            <h2>
              {
                processName(
                  correlation
                    .process_image
                )
              }
            </h2>


            <span
              className={
                "detail-severity "
                + severityClass(
                  correlation
                    .severity
                )
              }
            >
              {
                correlation
                  .severity
                || "LOW"
              }
            </span>

          </div>


          <p>
            Process Correlation Investigation
          </p>


          <code>
            {
              correlation
                .process_guid
              || "No ProcessGuid"
            }
          </code>

        </div>


        <div className="investigation-score">

          <span>
            Risk Score
          </span>

          <strong>
            {
              correlation
                .score
              ?? 0
            }
          </strong>

          <small>
            / 100
          </small>

        </div>

      </section>


      {/* =====================
          META
      ====================== */}

      <section className="investigation-meta">

        <div>

          <span>
            User
          </span>

          <strong>
            {
              correlation
                .username
              || "Unknown"
            }
          </strong>

        </div>


        <div>

          <span>
            Computer
          </span>

          <strong>
            {
              correlation
                .computer
              || "Unknown"
            }
          </strong>

        </div>


        <div>

          <span>
            PID
          </span>

          <strong>
            {
              correlation
                .process_id
              ?? "-"
            }
          </strong>

        </div>


        <div>

          <span>
            Events
          </span>

          <strong>
            {
              timeline.length
            }
          </strong>

        </div>

      </section>


      {/* =====================
          PARENT PROCESS
      ====================== */}

      {
        correlation.parent_image
        && (

          <section className="investigation-panel">

            <h3>
              Parent Process
            </h3>


            <div className="parent-process-card">

              <strong>
                {
                  processName(
                    correlation
                      .parent_image
                  )
                }
              </strong>


              <span>
                PID {
                  correlation
                    .parent_process_id
                  ?? "-"
                }
              </span>


              <code>
                {
                  correlation
                    .parent_process_guid
                  || "No ProcessGuid"
                }
              </code>

            </div>

          </section>

        )
      }


      {/* =====================
          PROCESS TREE
      ====================== */}

      <section className="investigation-panel">

        <h3>
          Process Tree
        </h3>


        {
          chain.length === 0
          ? (

            <p className="detail-muted">
              Process lineage unavailable.
            </p>

          )
          : (

            <div className="detail-process-tree">

              {
                chain.map(
                  (
                    process,
                    index
                  ) => (

                    <div
                      className="detail-process-wrapper"
                      key={
                        process
                          .process_guid
                        || index
                      }
                    >

                      {
                        index > 0
                        && (

                          <div className="tree-connector">
                            ↓
                          </div>

                        )
                      }


                      <div className="detail-process-node">

                        <strong>
                          {
                            processName(
                              process.image
                            )
                          }
                        </strong>


                        <span>
                          PID {
                            process
                              .process_id
                            ?? "-"
                          }
                        </span>


                        <code>
                          {
                            process
                              .process_guid
                            || "No ProcessGuid"
                          }
                        </code>

                      </div>

                    </div>

                  )
                )
              }

            </div>

          )
        }

      </section>


      {/* =====================
          EVENT STAGES
      ====================== */}

      <section className="investigation-panel">

        <h3>
          Behavior Stages
        </h3>


        <div className="detail-event-stages">

          {
            Array.isArray(
              correlation
                .event_ids
            )
            && correlation
              .event_ids
              .length > 0
            ? (

              [
                ...new Set(
                  correlation
                    .event_ids
                ),
              ]
                .map(
                  (
                    eventId,
                    index
                  ) => (

                    <div
                      className="detail-event-stage"
                      key={
                        `${
                          eventId
                        }-${
                          index
                        }`
                      }
                    >

                      {
                        index > 0
                        && (

                          <span className="detail-event-arrow">
                            →
                          </span>

                        )
                      }


                      <div>

                        <strong>
                          Event {
                            eventId
                          }
                        </strong>

                        <small>
                          {
                            eventLabel(
                              Number(
                                eventId
                              )
                            )
                          }
                        </small>

                      </div>

                    </div>

                  )
                )

            )
            : (

              <span className="detail-muted">
                No behavior stages.
              </span>

            )
          }

        </div>

      </section>


      {/* =====================
          TIMELINE
      ====================== */}

      <section className="investigation-panel">

        <h3>
          Behavior Timeline
        </h3>


        {
          timeline.length === 0
          ? (

            <p className="detail-muted">
              No correlated events available.
            </p>

          )
          : (

            <div className="behavior-timeline">

              {
                timeline.map(
                  (
                    event,
                    index
                  ) => (

                    <div
                      className="timeline-event"
                      key={
                        event.id
                        || event.record_id
                        || index
                      }
                    >

                      <div className="timeline-marker">
                        <span />
                      </div>


                      <div className="timeline-content">

                        <div className="timeline-header">

                          <strong>
                            {
                              eventLabel(
                                Number(
                                  event
                                    .event_id
                                )
                              )
                            }
                          </strong>


                          <span>
                            Event {
                              event
                                .event_id
                            }
                          </span>

                        </div>


                        <div className="timeline-description">

                          {
                            importantDetail(
                              event
                            )
                          }

                        </div>


                        <div className="timeline-process">

                          {
                            processName(
                              event.image
                              || event
                                ?.details
                                ?.image
                              || event
                                ?.details
                                ?.Image
                            )
                          }

                        </div>


                        <time>
                          {
                            eventTime(
                              event
                            )
                          }
                        </time>

                      </div>

                    </div>

                  )
                )
              }

            </div>

          )
        }

      </section>


      {/* =====================
          MITRE + REASONS
      ====================== */}

      <div className="investigation-two-column">

        <section className="investigation-panel">

          <h3>
            MITRE ATT&CK
          </h3>


          <div className="detail-mitre-list">

            {
              mitre.length === 0
              ? (

                <span className="detail-muted">
                  No mapped techniques.
                </span>

              )
              : (

                mitre.map(
                  technique => (

                    <span
                      className="detail-mitre-tag"
                      key={
                        technique
                      }
                    >
                      {
                        technique
                      }
                    </span>

                  )
                )

              )
            }

          </div>

        </section>


        <section className="investigation-panel">

          <h3>
            Detection Reasons
          </h3>


          {
            reasons.length === 0
            ? (

              <span className="detail-muted">
                No detection reasons.
              </span>

            )
            : (

              <ul className="detail-reason-list">

                {
                  reasons.map(
                    (
                      reason,
                      index
                    ) => (

                      <li
                        key={
                          `${
                            index
                          }-${
                            reason
                          }`
                        }
                      >
                        {reason}
                      </li>

                    )
                  )
                }

              </ul>

            )
          }

        </section>

      </div>


      {/* =====================
          RAW
      ====================== */}

      <section className="investigation-panel">

        <details className="raw-correlation-details">

          <summary>
            Raw Correlation Data
          </summary>


          <pre>
            {
              JSON.stringify(
                correlation,
                null,
                2
              )
            }
          </pre>

        </details>

      </section>

    </div>
  );
}


export default CorrelationDetail;