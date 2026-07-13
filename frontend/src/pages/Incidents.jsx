import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import api from "../api/client";

import "../styles/cases.css";


function Incidents() {
  const navigate = useNavigate();

  const [incidents, setIncidents] =
    useState([]);

  const [page, setPage] =
    useState(1);

  const [totalPages, setTotalPages] =
    useState(1);

  const [statusFilter, setStatusFilter] =
    useState("");

  const [severity, setSeverity] =
    useState("");

  const [username, setUsername] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  const loadIncidents = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const params = {
          page,
          page_size: 20,
        };

        if (statusFilter) {
          params.status = statusFilter;
        }

        if (severity) {
          params.severity = severity;
        }

        if (username.trim()) {
          params.username =
            username.trim();
        }

        const response = await api.get(
          "/case-explorer/incidents",
          {
            params,
          }
        );

        setIncidents(
          response.data.items || []
        );

        setTotalPages(
          response.data.total_pages || 1
        );
      } catch (requestError) {
        console.error(requestError);

        setError(
          "Could not load incidents."
        );
      } finally {
        setLoading(false);
      }
    },
    [
      page,
      statusFilter,
      severity,
      username,
    ]
  );


  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);


  return (
    <div className="cases-page">

      <header className="cases-header">
        <div>
          <h1>Incident Center</h1>

          <p>
            Review security incidents and
            investigation status.
          </p>
        </div>

        <button
          type="button"
          className="case-button"
          onClick={() =>
            navigate("/")
          }
        >
          Dashboard
        </button>
      </header>


      <section className="case-filter-panel">

        <select
          value={statusFilter}
          onChange={(event) => {
            setStatusFilter(
              event.target.value
            );

            setPage(1);
          }}
        >
          <option value="">
            All statuses
          </option>

          <option value="OPEN">
            Open
          </option>

          <option value="CLOSED">
            Closed
          </option>
        </select>


        <select
          value={severity}
          onChange={(event) => {
            setSeverity(
              event.target.value
            );

            setPage(1);
          }}
        >
          <option value="">
            All severities
          </option>

          <option value="HIGH">
            High
          </option>

          <option value="MEDIUM">
            Medium
          </option>

          <option value="LOW">
            Low
          </option>
        </select>


        <input
          type="text"
          value={username}
          placeholder="Search username"
          onChange={(event) => {
            setUsername(
              event.target.value
            );

            setPage(1);
          }}
        />

      </section>


      <section className="case-panel">

        {error && (
          <div className="case-error">
            {error}
          </div>
        )}

        {loading ? (
          <div className="case-empty">
            Loading incidents...
          </div>
        ) : (
          <div className="case-table-wrapper">

            <table className="case-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>User</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {incidents.length === 0 ? (
                  <tr>
                    <td
                      colSpan="7"
                      className="case-empty"
                    >
                      No incidents found.
                    </td>
                  </tr>
                ) : (
                  incidents.map(
                    (incident) => (
                      <tr key={incident.id}>
                        <td>
                          #{incident.id}
                        </td>

                        <td>
                          {incident.username}
                        </td>

                        <td>
                          {incident.title}
                        </td>

                        <td>
                          <span
                            className={
                              `case-badge ${incident.severity?.toLowerCase()}`
                            }
                          >
                            {incident.severity}
                          </span>
                        </td>

                        <td>
                          {incident.status}
                        </td>

                        <td>
                          {new Date(
                            incident.created_at
                          ).toLocaleString()}
                        </td>

                        <td>
                          <button
                            type="button"
                            className="case-link"
                            onClick={() =>
                              navigate(
                                `/incidents/${incident.id}`
                              )
                            }
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    )
                  )
                )}
              </tbody>
            </table>

          </div>
        )}


        <div className="case-pagination">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() =>
              setPage(
                (current) =>
                  Math.max(
                    1,
                    current - 1
                  )
              )
            }
          >
            Previous
          </button>

          <span>
            Page {page} of {totalPages}
          </span>

          <button
            type="button"
            disabled={
              page >= totalPages
            }
            onClick={() =>
              setPage(
                (current) =>
                  Math.min(
                    totalPages,
                    current + 1
                  )
              )
            }
          >
            Next
          </button>
        </div>

      </section>

    </div>
  );
}


export default Incidents;