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

import "../styles/events.css";


function EventDetail() {
  const {
    id,
  } = useParams();

  const navigate = useNavigate();

  const [eventData, setEventData] =
    useState(null);

  const [activeTab, setActiveTab] =
    useState("normalized");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  const loadEvent = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          `/event-explorer/events/${id}`
        );

        setEventData(response.data);
      } catch (requestError) {
        console.error(requestError);

        if (
          requestError.response?.status === 404
        ) {
          setError(
            "Raw Windows event not found."
          );
        } else {
          setError(
            "Could not load the Windows event."
          );
        }
      } finally {
        setLoading(false);
      }
    },
    [id]
  );


  useEffect(() => {
    loadEvent();
  }, [loadEvent]);


  const normalizedEntries = useMemo(
    () => {
      if (
        !eventData?.normalized_data
        ||
        typeof eventData.normalized_data
          !== "object"
      ) {
        return [];
      }

      return Object.entries(
        eventData.normalized_data
      );
    },
    [eventData]
  );


  async function copyToClipboard(
    value
  ) {
    try {
      await navigator.clipboard.writeText(
        value || ""
      );
    } catch (clipboardError) {
      console.error(
        clipboardError
      );
    }
  }


  if (loading) {
    return (
      <div className="event-detail-message">
        Loading Windows event...
      </div>
    );
  }


  if (error) {
    return (
      <div className="event-detail-message">
        <h2>{error}</h2>

        <button
          type="button"
          className="primary-button"
          onClick={() =>
            navigate("/events")
          }
        >
          Return to Event Explorer
        </button>
      </div>
    );
  }


  if (!eventData) {
    return null;
  }


  return (
    <div className="event-detail-page">

      <header className="event-detail-header">

        <div>
          <p className="event-detail-eyebrow">
            Raw Windows Event
          </p>

          <h1>
            Event #{eventData.id}
          </h1>

          <p>
            Record ID {eventData.record_id}
            {" · "}
            Event ID {eventData.event_id}
          </p>
        </div>


        <div className="event-detail-actions">

          <button
            type="button"
            className="secondary-button"
            onClick={loadEvent}
          >
            Refresh
          </button>

          <button
            type="button"
            className="primary-button"
            onClick={() =>
              navigate("/events")
            }
          >
            Back to Events
          </button>

        </div>

      </header>


      <section className="event-metadata-grid">

        <article className="event-metadata-card">
          <span>Event ID</span>
          <strong>
            {eventData.event_id}
          </strong>
        </article>

        <article className="event-metadata-card">
          <span>Record ID</span>
          <strong>
            {eventData.record_id}
          </strong>
        </article>

        <article className="event-metadata-card">
          <span>Computer</span>
          <strong>
            {eventData.computer ||
              "Unknown"}
          </strong>
        </article>

        <article className="event-metadata-card">
          <span>Provider</span>
          <strong>
            {eventData.provider ||
              "Unknown"}
          </strong>
        </article>

        <article className="event-metadata-card">
          <span>Received At</span>
          <strong>
            {eventData.received_at
              ? new Date(
                  eventData.received_at
                ).toLocaleString()
              : "Unknown"}
          </strong>
        </article>

      </section>


      <section className="event-detail-panel">

        <div className="event-detail-tabs">

          <button
            type="button"
            className={
              activeTab === "normalized"
                ? "event-tab active"
                : "event-tab"
            }
            onClick={() =>
              setActiveTab("normalized")
            }
          >
            Normalized Fields
          </button>

          <button
            type="button"
            className={
              activeTab === "xml"
                ? "event-tab active"
                : "event-tab"
            }
            onClick={() =>
              setActiveTab("xml")
            }
          >
            Raw XML
          </button>

          <button
            type="button"
            className={
              activeTab === "json"
                ? "event-tab active"
                : "event-tab"
            }
            onClick={() =>
              setActiveTab("json")
            }
          >
            Full JSON
          </button>

        </div>


        {activeTab === "normalized" && (
          <div className="normalized-panel">

            <div className="event-section-heading">

              <div>
                <h2>
                  Normalized Event Fields
                </h2>

                <p>
                  Parsed values extracted
                  from the Windows event XML.
                </p>
              </div>

              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  copyToClipboard(
                    JSON.stringify(
                      eventData.normalized_data,
                      null,
                      2
                    )
                  )
                }
              >
                Copy JSON
              </button>

            </div>


            {normalizedEntries.length === 0 ? (
              <div className="events-empty">
                No normalized fields were
                extracted from this event.
              </div>
            ) : (
              <div className="normalized-grid">

                {normalizedEntries.map(
                  ([key, value]) => (
                    <article
                      className="normalized-field"
                      key={key}
                    >
                      <span>{key}</span>

                      <strong>
                        {value === null ||
                        value === undefined ||
                        value === ""
                          ? "—"
                          : String(value)}
                      </strong>
                    </article>
                  )
                )}

              </div>
            )}

          </div>
        )}


        {activeTab === "xml" && (
          <div className="raw-content-panel">

            <div className="event-section-heading">

              <div>
                <h2>
                  Raw Windows Event XML
                </h2>

                <p>
                  Original event payload
                  received from the collector.
                </p>
              </div>

              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  copyToClipboard(
                    eventData.xml
                  )
                }
              >
                Copy XML
              </button>

            </div>

            <pre className="event-code-block">
              {eventData.xml ||
                "No XML content available."}
            </pre>

          </div>
        )}


        {activeTab === "json" && (
          <div className="raw-content-panel">

            <div className="event-section-heading">

              <div>
                <h2>
                  Complete Event Object
                </h2>

                <p>
                  API response containing
                  metadata, normalized values
                  and raw XML.
                </p>
              </div>

              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  copyToClipboard(
                    JSON.stringify(
                      eventData,
                      null,
                      2
                    )
                  )
                }
              >
                Copy JSON
              </button>

            </div>

            <pre className="event-code-block">
              {JSON.stringify(
                eventData,
                null,
                2
              )}
            </pre>

          </div>
        )}

      </section>

    </div>
  );
}


export default EventDetail;