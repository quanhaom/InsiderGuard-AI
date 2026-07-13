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


function Evidences() {
  const navigate = useNavigate();

  const [evidences, setEvidences] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  const loadEvidences = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          "/case-explorer/evidences"
        );

        setEvidences(
          response.data.items || []
        );
      } catch (requestError) {
        console.error(requestError);

        setError(
          "Could not load evidences."
        );
      } finally {
        setLoading(false);
      }
    },
    []
  );


  useEffect(() => {
    loadEvidences();
  }, [loadEvidences]);


  return (
    <div className="cases-page">

      <header className="cases-header">
        <div>
          <h1>Evidence Center</h1>

          <p>
            Review forensic snapshots and
            blockchain integrity.
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


      <section className="case-panel">

        {error && (
          <div className="case-error">
            {error}
          </div>
        )}

        {loading ? (
          <div className="case-empty">
            Loading evidence...
          </div>
        ) : (
          <div className="case-table-wrapper">

            <table className="case-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Incident</th>
                  <th>User</th>
                  <th>Type</th>
                  <th>SHA256</th>
                  <th>Created</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {evidences.length === 0 ? (
                  <tr>
                    <td
                      colSpan="7"
                      className="case-empty"
                    >
                      No evidence found.
                    </td>
                  </tr>
                ) : (
                  evidences.map(
                    (evidence) => (
                      <tr key={evidence.id}>
                        <td>
                          #{evidence.id}
                        </td>

                        <td>
                          #{evidence.incident_id}
                        </td>

                        <td>
                          {evidence.username}
                        </td>

                        <td>
                          {evidence.evidence_type}
                        </td>

                        <td className="hash-cell">
                          {evidence.sha256_hash}
                        </td>

                        <td>
                          {new Date(
                            evidence.created_at
                          ).toLocaleString()}
                        </td>

                        <td>
                          <button
                            type="button"
                            className="case-link"
                            onClick={() =>
                              navigate(
                                `/evidences/${evidence.id}`
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

      </section>

    </div>
  );
}


export default Evidences;