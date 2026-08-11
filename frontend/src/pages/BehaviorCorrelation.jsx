import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import api from "../api/client";

import "../styles/correlation.css";


const EVENT_LABELS = {
  1: "Process Create",
  3: "Network Connection",
  11: "File Create",
  13: "Registry Modification",
  22: "DNS Query",
};


function getProcessName(image) {
  if (!image) {
    return "Unknown process";
  }

  const normalized = image.replace(
    /\//g,
    "\\"
  );

  const parts = normalized.split("\\");

  return (
    parts[parts.length - 1]
    || image
  );
}


function severityClass(
  severity
) {
  return (
    severity
    || "LOW"
  ).toLowerCase();
}


function BehaviorCorrelation() {

  const [results, setResults] =
    useState([]);

  const [selected, setSelected] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [
    windowMinutes,
    setWindowMinutes,
  ] = useState(60);

  const [
    detectedOnly,
    setDetectedOnly,
  ] = useState(false);


  const loadCorrelations =
    useCallback(
      async () => {
        try {
          setLoading(true);
          setError("");

          const response =
            await api.get(
              "/correlation/processes",
              {
                params: {
                  window_minutes:
                    windowMinutes,
                },
              }
            );

          const items =
            Array.isArray(
              response.data
            )
              ? response.data
              : [];

          setResults(items);

          setSelected(
            (current) => {
              if (!items.length) {
                return null;
              }

              if (!current) {
                return items[0];
              }

              const existing =
                items.find(
                  (item) =>
                    item.process_guid
                    === current.process_guid
                    &&
                    item.process_id
                    === current.process_id
                );

              return (
                existing
                || items[0]
              );
            }
          );

        } catch (
          requestError
        ) {
          console.error(
            requestError
          );

          setError(
            requestError
              .response
              ?.data
              ?.detail
            ||
            "Could not load correlation data."
          );

        } finally {
          setLoading(false);
        }
      },
      [
        windowMinutes,
      ]
    );


  useEffect(() => {
    loadCorrelations();
  }, [
    loadCorrelations,
  ]);


  const visibleResults =
    useMemo(
      () => {
        if (!detectedOnly) {
          return results;
        }

        return results.filter(
          (item) =>
            item.detected
        );
      },
      [
        results,
        detectedOnly,
      ]
    );


  const statistics =
    useMemo(
      () => {
        return {
          total:
            results.length,

          detected:
            results.filter(
              (item) =>
                item.detected
            ).length,

          critical:
            results.filter(
              (item) =>
                item.severity
                === "CRITICAL"
            ).length,

          high:
            results.filter(
              (item) =>
                item.severity
                === "HIGH"
            ).length,
        };
      },
      [
        results,
      ]
    );


  return (
    <div className="correlation-page">

      <header className="correlation-header">

        <div>
          <p className="correlation-eyebrow">
            Process-Centric Analysis
          </p>

          <h1>
            Behavior Correlation
          </h1>

          <p>
            Correlate Sysmon process,
            DNS, network, file and registry
            telemetry using ProcessGuid.
          </p>
        </div>


        <div className="correlation-controls">

          <select
            value={windowMinutes}
            onChange={(event) =>
              setWindowMinutes(
                Number(
                  event.target.value
                )
              )
            }
          >
            <option value={10}>
              Last 10 minutes
            </option>

            <option value={30}>
              Last 30 minutes
            </option>

            <option value={60}>
              Last 1 hour
            </option>

            <option value={360}>
              Last 6 hours
            </option>

            <option value={1440}>
              Last 24 hours
            </option>
          </select>


          <label
            className="correlation-toggle"
          >
            <input
              type="checkbox"
              checked={
                detectedOnly
              }
              onChange={(
                event
              ) =>
                setDetectedOnly(
                  event.target
                    .checked
                )
              }
            />

            Detected only
          </label>


          <button
            type="button"
            onClick={
              loadCorrelations
            }
          >
            Refresh
          </button>

        </div>

      </header>


      <section
        className="correlation-stats"
      >

        <div className="correlation-stat">
          <span>
            Processes
          </span>

          <strong>
            {statistics.total}
          </strong>
        </div>


        <div className="correlation-stat">
          <span>
            Detected
          </span>

          <strong>
            {statistics.detected}
          </strong>
        </div>


        <div className="correlation-stat">
          <span>
            High
          </span>

          <strong>
            {statistics.high}
          </strong>
        </div>


        <div className="correlation-stat">
          <span>
            Critical
          </span>

          <strong>
            {statistics.critical}
          </strong>
        </div>

      </section>


      {error && (
        <div className="correlation-error">
          {error}
        </div>
      )}


      {loading ? (
        <div className="correlation-loading">
          Loading behavior chains...
        </div>
      ) : (
        <div
          className="correlation-layout"
        >

          <section
            className="correlation-list-panel"
          >

            <div
              className="correlation-panel-header"
            >
              <div>
                <h2>
                  Process Chains
                </h2>

                <p>
                  {
                    visibleResults
                      .length
                  } correlated
                  processes
                </p>
              </div>
            </div>


            <div
              className="correlation-list"
            >

              {visibleResults.length
              === 0 ? (
                <div
                  className="correlation-empty"
                >
                  No correlation
                  results found.
                </div>
              ) : (
                visibleResults.map(
                  (
                    item,
                    index
                  ) => {

                    const key =
                      item.process_guid
                      ||
                      `${item.computer}-${item.process_id}-${index}`;

                    const active =
                      selected
                      &&
                      selected
                        .process_guid
                        ===
                        item
                          .process_guid
                      &&
                      selected
                        .process_id
                        ===
                        item
                          .process_id;

                    return (
                      <button
                        key={key}
                        type="button"
                        className={
                          active
                            ? "correlation-item active"
                            : "correlation-item"
                        }
                        onClick={() =>
                          setSelected(
                            item
                          )
                        }
                      >

                        <div
                          className="correlation-item-top"
                        >

                          <div>
                            <strong>
                              {
                                getProcessName(
                                  item
                                    .process_image
                                )
                              }
                            </strong>

                            <span>
                              {
                                item.username
                                || "Unknown user"
                              }
                              {" · "}
                              {
                                item.computer
                                || "Unknown host"
                              }
                            </span>
                          </div>


                          <div
                            className={
                              `correlation-severity ${severityClass(
                                item.severity
                              )}`
                            }
                          >
                            {
                              item.severity
                            }
                          </div>

                        </div>


                        <div
                          className="correlation-item-score"
                        >
                          <span>
                            Risk score
                          </span>

                          <strong>
                            {
                              item.score
                            }
                          </strong>
                        </div>


                        <div
                          className="correlation-mini-chain"
                        >

                          {
                            item.event_ids
                              ?.map(
                                (
                                  eventId,
                                  eventIndex
                                ) => (
                                  <span
                                    key={
                                      `${eventId}-${eventIndex}`
                                    }
                                  >
                                    {
                                      EVENT_LABELS[
                                        eventId
                                      ]
                                      ||
                                      `Event ${eventId}`
                                    }
                                  </span>
                                )
                              )
                          }

                        </div>

                      </button>
                    );
                  }
                )
              )}

            </div>

          </section>


          <section
            className="correlation-detail-panel"
          >

            {!selected ? (
              <div
                className="correlation-empty"
              >
                Select a process
                correlation to inspect.
              </div>
            ) : (
              <>

                <header
                  className="correlation-detail-header"
                >

                  <div>
                    <p>
                      Process
                    </p>

                    <h2>
                      {
                        getProcessName(
                          selected
                            .process_image
                        )
                      }
                    </h2>

                    <span
                      className="correlation-image-path"
                    >
                      {
                        selected
                          .process_image
                        || "Unknown image"
                      }
                    </span>
                  </div>


                  <div
                    className="correlation-score-box"
                  >
                    <span>
                      Correlation Score
                    </span>

                    <strong>
                      {
                        selected.score
                      }
                    </strong>

                    <div
                      className={
                        `correlation-severity ${severityClass(
                          selected
                            .severity
                        )}`
                      }
                    >
                      {
                        selected.severity
                      }
                    </div>
                  </div>

                </header>


                <div
                  className="correlation-metadata"
                >

                  <div>
                    <span>
                      User
                    </span>

                    <strong>
                      {
                        selected
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
                        selected
                          .computer
                        || "Unknown"
                      }
                    </strong>
                  </div>


                  <div>
                    <span>
                      Process ID
                    </span>

                    <strong>
                      {
                        selected
                          .process_id
                        ?? "Unknown"
                      }
                    </strong>
                  </div>


                  <div>
                    <span>
                      Process GUID
                    </span>

                    <strong
                      className="correlation-guid"
                    >
                      {
                        selected
                          .process_guid
                        || "Unavailable"
                      }
                    </strong>
                  </div>

                </div>


                <section
                  className="correlation-section"
                >

                  <h3>
                    Behavior Chain
                  </h3>

                  <div
                    className="behavior-chain"
                  >

                    {
                      selected
                        .event_ids
                        ?.map(
                          (
                            eventId,
                            index
                          ) => (
                            <div
                              className="behavior-chain-node"
                              key={
                                `${eventId}-${index}`
                              }
                            >

                              <div
                                className="behavior-event"
                              >
                                <span>
                                  Event {
                                    eventId
                                  }
                                </span>

                                <strong>
                                  {
                                    EVENT_LABELS[
                                      eventId
                                    ]
                                    ||
                                    "Unknown Event"
                                  }
                                </strong>
                              </div>


                              {
                                index
                                <
                                selected
                                  .event_ids
                                  .length
                                  - 1
                                && (
                                  <div
                                    className="behavior-arrow"
                                  >
                                    ↓
                                  </div>
                                )
                              }

                            </div>
                          )
                        )
                    }

                  </div>

                </section>


                <section
                  className="correlation-section"
                >

                  <h3>
                    Detection Reasons
                  </h3>

                  {
                    selected
                      .reasons
                      ?.length
                    ? (
                      <div
                        className="correlation-reasons"
                      >
                        {
                          selected
                            .reasons
                            .map(
                              (
                                reason,
                                index
                              ) => (
                                <div
                                  key={
                                    `${reason}-${index}`
                                  }
                                >
                                  <span>
                                    {index + 1}
                                  </span>

                                  <p>
                                    {reason}
                                  </p>
                                </div>
                              )
                            )
                        }
                      </div>
                    )
                    : (
                      <p>
                        No correlation
                        reasons recorded.
                      </p>
                    )
                  }

                </section>


                <section
                  className="correlation-section"
                >

                  <h3>
                    MITRE ATT&amp;CK
                  </h3>

                  <div
                    className="correlation-mitre"
                  >
                    {
                      selected
                        .mitre_techniques
                        ?.length
                      ? (
                        selected
                          .mitre_techniques
                          .map(
                            (
                              technique
                            ) => (
                              <span
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
                      : (
                        <p>
                          No techniques
                          mapped.
                        </p>
                      )
                    }
                  </div>

                </section>


                <section
                  className="correlation-section"
                >

                  <h3>
                    Raw Correlated Events
                  </h3>

                  <div
                    className="correlation-events"
                  >
                    {
                      selected
                        .events
                        ?.map(
                          (
                            event,
                            index
                          ) => (
                            <div
                              className="correlation-event-row"
                              key={
                                event.id
                                ||
                                index
                              }
                            >

                              <span>
                                Event {
                                  event
                                    .event_id
                                }
                              </span>

                              <strong>
                                {
                                  EVENT_LABELS[
                                    event
                                      .event_id
                                  ]
                                  ||
                                  event
                                    .action
                                  ||
                                  "Event"
                                }
                              </strong>

                              <small>
                                {
                                  event
                                    .created_at
                                  ? new Date(
                                      event
                                        .created_at
                                    )
                                      .toLocaleString()
                                  : "Unknown time"
                                }
                              </small>

                            </div>
                          )
                        )
                    }
                  </div>

                </section>

              </>
            )}

          </section>

        </div>
      )}

    </div>
  );
}


export default BehaviorCorrelation;