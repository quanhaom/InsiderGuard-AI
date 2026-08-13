import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import api from "../api/client";

import "../styles/correlation.css";


const REFRESH_INTERVAL = 10000;


function severityClass(
  severity
) {
  return (
    String(
      severity || "LOW"
    )
      .trim()
      .toLowerCase()
  );
}


function processName(
  image
) {
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


function formatEventIds(
  eventIds
) {
  if (
    !Array.isArray(
      eventIds
    )
    || eventIds.length === 0
  ) {
    return "None";
  }

  return (
    [
      ...new Set(
        eventIds
      ),
    ]
      .join(" → ")
  );
}


function Correlation() {
  const navigate =
    useNavigate();

  const [
    correlations,
    setCorrelations,
  ] = useState([]);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState("");

  const [
    windowMinutes,
    setWindowMinutes,
  ] = useState(60);


  // =========================
  // LOAD CORRELATIONS
  // =========================

  const loadCorrelations =
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
              "/correlation/top",
              {
                params: {
                  window_minutes:
                    windowMinutes,

                  limit: 20,
                },
              }
            );

          const data =
            Array.isArray(
              response.data
            )
              ? response.data
              : [];

          setCorrelations(
            data
          );

        } catch (
          requestError
        ) {
          console.error(
            requestError
          );

          setError(
            "Could not load "
            + "correlation data."
          );

        } finally {
          setLoading(false);
          setRefreshing(false);
        }
      },
      [
        windowMinutes,
      ]
    );


  // =========================
  // AUTO REFRESH
  // =========================

  useEffect(
    () => {
      loadCorrelations();

      const intervalId =
        window.setInterval(
          () => {
            loadCorrelations();
          },
          REFRESH_INTERVAL
        );

      return () => {
        window.clearInterval(
          intervalId
        );
      };
    },
    [
      loadCorrelations,
    ]
  );


  // =========================
  // STATISTICS
  // =========================

  const stats =
    useMemo(
      () => {

        const critical =
          correlations.filter(
            (item) =>
              item.severity
              === "CRITICAL"
          ).length;

        const high =
          correlations.filter(
            (item) =>
              item.severity
              === "HIGH"
          ).length;

        const medium =
          correlations.filter(
            (item) =>
              item.severity
              === "MEDIUM"
          ).length;

        const relatedProcesses =
          correlations.reduce(
            (
              total,
              item
            ) => {

              const chain =
                Array.isArray(
                  item.process_chain
                )
                  ? item.process_chain
                  : [];

              return (
                total
                + (
                  chain.length
                  || 1
                )
              );
            },
            0
          );

        return {
          total:
            correlations.length,

          critical,

          high,

          medium,

          relatedProcesses,
        };
      },
      [
        correlations,
      ]
    );


  // =========================
  // LOADING
  // =========================

  if (loading) {
    return (
      <div className="screen-message">
        Loading process correlations...
      </div>
    );
  }


  // =========================
  // PAGE
  // =========================

  return (
    <div className="correlation-page">

      {/* =====================
          HEADER
      ====================== */}

      <section className="correlation-header">

        <div>

          <h2>
            Process Correlation
          </h2>

          <p>
            Tree-aware behavioral
            correlation across Sysmon
            process, DNS, network,
            file and registry activity.
          </p>

        </div>


        <div className="correlation-actions">

          <select
            value={
              windowMinutes
            }
            onChange={
              (event) => {
                setWindowMinutes(
                  Number(
                    event.target.value
                  )
                );
              }
            }
          >

            <option value={10}>
              Last 10 minutes
            </option>

            <option value={30}>
              Last 30 minutes
            </option>

            <option value={60}>
              Last 60 minutes
            </option>

            <option value={360}>
              Last 6 hours
            </option>

            <option value={1440}>
              Last 24 hours
            </option>

          </select>


          <button
            type="button"
            disabled={
              refreshing
            }
            onClick={
              () =>
                loadCorrelations(
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

        </div>

      </section>


      {/* =====================
          ERROR
      ====================== */}

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}


      {/* =====================
          SUMMARY
      ====================== */}

      <section className="correlation-summary">

        <div className="correlation-summary-card">

          <span>
            Correlations
          </span>

          <strong>
            {stats.total}
          </strong>

        </div>


        <div
          className={
            "correlation-summary-card "
            + "critical"
          }
        >

          <span>
            Critical
          </span>

          <strong>
            {stats.critical}
          </strong>

        </div>


        <div
          className={
            "correlation-summary-card "
            + "high"
          }
        >

          <span>
            High
          </span>

          <strong>
            {stats.high}
          </strong>

        </div>


        <div className="correlation-summary-card">

          <span>
            Medium
          </span>

          <strong>
            {stats.medium}
          </strong>

        </div>


        <div className="correlation-summary-card">

          <span>
            Related Processes
          </span>

          <strong>
            {
              stats
                .relatedProcesses
            }
          </strong>

        </div>

      </section>


      {/* =====================
          EMPTY
      ====================== */}

      {
        correlations.length
        === 0
        ? (

          <div className="correlation-empty">

            No suspicious process
            correlations detected
            in this time window.

          </div>

        )
        : (

          /* =====================
             LIST
          ====================== */

          <section className="correlation-list">

            {
              correlations.map(
                (
                  correlation,
                  index
                ) => {

                  const chain =
                    Array.isArray(
                      correlation
                        .process_chain
                    )
                      ? correlation
                          .process_chain
                      : [];

                  const reasons =
                    Array.isArray(
                      correlation.reasons
                    )
                      ? correlation.reasons
                      : [];

                  const mitre =
                    Array.isArray(
                      correlation
                        .mitre_techniques
                    )
                      ? correlation
                          .mitre_techniques
                      : [];

                  return (

                    <article
                      className="correlation-card"
                      key={
                        correlation
                          .process_guid
                        || index
                      }
                    >

                      {/* =================
                          CARD HEADER
                      ================== */}

                      <div className="correlation-card-header">

                        <div>

                          <div className="correlation-title-row">

                            <h3>
                              {
                                processName(
                                  correlation
                                    .process_image
                                )
                              }
                            </h3>


                            <span
                              className={
                                "severity-badge "
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


                          <p className="correlation-guid">

                            {
                              correlation
                                .process_guid
                              || (
                                "No "
                                + "ProcessGuid"
                              )
                            }

                          </p>

                        </div>


                        <div className="correlation-score">

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

                      </div>


                      {/* =================
                          INVESTIGATE
                      ================== */}

                      <div className="correlation-investigation-actions">

                        <button
                          type="button"
                          className="investigate-button"
                          disabled={
                            !correlation
                              .process_guid
                          }
                          onClick={
                            () => {

                              if (
                                !correlation
                                  .process_guid
                              ) {
                                return;
                              }

                              navigate(
                                `/correlation/${
                                  encodeURIComponent(
                                    correlation
                                      .process_guid
                                  )
                                }`
                              );
                            }
                          }
                        >
                          Investigate
                        </button>

                      </div>


                      {/* =================
                          META
                      ================== */}

                      <div className="correlation-meta">

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
                              formatEventIds(
                                correlation
                                  .event_ids
                              )
                            }
                          </strong>

                        </div>

                      </div>


                      {/* =================
                          PARENT
                      ================== */}

                      {
                        correlation
                          .parent_image
                        && (

                          <div className="correlation-parent">

                            <span>
                              Parent Process
                            </span>

                            <strong>
                              {
                                processName(
                                  correlation
                                    .parent_image
                                )
                              }
                            </strong>

                            {
                              correlation
                                .parent_process_id
                              != null
                              && (
                                <small>
                                  PID {
                                    correlation
                                      .parent_process_id
                                  }
                                </small>
                              )
                            }

                          </div>

                        )
                      }


                      {/* =================
                          PROCESS CHAIN
                      ================== */}

                      <div className="correlation-section">

                        <h4>
                          Process Chain
                        </h4>


                        {
                          chain.length
                          === 0
                          ? (

                            <div className="process-chain-empty">

                              No parent/child
                              lineage available.

                            </div>

                          )
                          : (

                            <div className="process-chain">

                              {
                                chain.map(
                                  (
                                    node,
                                    nodeIndex
                                  ) => (

                                    <div
                                      className="process-chain-node"
                                      key={
                                        node
                                          .process_guid
                                        || nodeIndex
                                      }
                                    >

                                      {
                                        nodeIndex > 0
                                        && (

                                          <div className="process-chain-arrow">
                                            ↓
                                          </div>

                                        )
                                      }


                                      <div className="process-node-box">

                                        <strong>
                                          {
                                            processName(
                                              node.image
                                            )
                                          }
                                        </strong>


                                        <span>
                                          PID {
                                            node
                                              .process_id
                                            ?? "-"
                                          }
                                        </span>


                                        <small>
                                          {
                                            node
                                              .process_guid
                                            || "No GUID"
                                          }
                                        </small>

                                      </div>

                                    </div>

                                  )
                                )
                              }

                            </div>

                          )
                        }

                      </div>


                      {/* =================
                          BEHAVIOR PATH
                      ================== */}

                      <div className="correlation-section">

                        <h4>
                          Behavior Sequence
                        </h4>

                        <div className="behavior-event-chain">

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
                                    eventIndex
                                  ) => (

                                    <div
                                      className="behavior-event-node"
                                      key={
                                        `${
                                          eventId
                                        }-${
                                          eventIndex
                                        }`
                                      }
                                    >

                                      {
                                        eventIndex
                                        > 0
                                        && (

                                          <span className="behavior-event-arrow">
                                            →
                                          </span>

                                        )
                                      }


                                      <strong>
                                        Event {
                                          eventId
                                        }
                                      </strong>

                                    </div>

                                  )
                                )

                            )
                            : (

                              <span className="muted-text">
                                No event sequence
                              </span>

                            )
                          }

                        </div>

                      </div>


                      {/* =================
                          MITRE + REASONS
                      ================== */}

                      <div className="correlation-columns">

                        <div className="correlation-section">

                          <h4>
                            MITRE ATT&CK
                          </h4>


                          <div className="mitre-list">

                            {
                              mitre.length
                              > 0
                              ? (

                                mitre.map(
                                  (
                                    technique
                                  ) => (

                                    <span
                                      key={
                                        technique
                                      }
                                      className="mitre-tag"
                                    >
                                      {
                                        technique
                                      }
                                    </span>

                                  )
                                )

                              )
                              : (

                                <span className="muted-text">

                                  No mapped
                                  techniques

                                </span>

                              )
                            }

                          </div>

                        </div>


                        <div className="correlation-section">

                          <h4>
                            Detection Reasons
                          </h4>


                          {
                            reasons.length
                            > 0
                            ? (

                              <ul className="reason-list">

                                {
                                  reasons.map(
                                    (
                                      reason,
                                      reasonIndex
                                    ) => (

                                      <li
                                        key={
                                          `${
                                            reasonIndex
                                          }-${
                                            reason
                                          }`
                                        }
                                      >
                                        {
                                          reason
                                        }
                                      </li>

                                    )
                                  )
                                }

                              </ul>

                            )
                            : (

                              <span className="muted-text">

                                No detection
                                reasons available

                              </span>

                            )
                          }

                        </div>

                      </div>

                    </article>

                  );
                }
              )
            }

          </section>

        )
      }

    </div>
  );
}


export default Correlation;