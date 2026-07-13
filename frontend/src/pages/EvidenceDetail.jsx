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


function EvidenceDetail() {
  const { id } = useParams();

  const navigate = useNavigate();

  const [evidence, setEvidence] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  const loadEvidence = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          `/case-explorer/evidences/${id}`
        );

        setEvidence(response.data);
      } catch (requestError) {
        console.error(requestError);

        setError(
          "Could not load evidence."
        );
      } finally {
        setLoading(false);
      }
    },
    [id]
  );


  useEffect(() => {
    loadEvidence();
  }, [loadEvidence]);


  if (loading) {
    return (
      <div className="case-message">
        Loading evidence...
      </div>
    );
  }


  if (error || !evidence) {
    return (
      <div className="case-message">
        <h2>
          {error || "Evidence not found"}
        </h2>

        <button
          type="button"
          onClick={() =>
            navigate("/evidences")
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
            Evidence #{evidence.id}
          </h1>

          <p>
            Incident #{evidence.incident_id}
          </p>
        </div>

        <div className="case-actions">
          <button
            type="button"
            className="case-button"
            onClick={() =>
              navigate(
                `/incidents/${evidence.incident_id}`
              )
            }
          >
            Incident
          </button>

          <button
            type="button"
            className="case-button"
            onClick={() =>
              navigate("/evidences")
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
            {evidence.username}
          </strong>
        </article>

        <article>
          <span>Type</span>
          <strong>
            {evidence.evidence_type}
          </strong>
        </article>

        <article>
          <span>Created</span>
          <strong>
            {new Date(
              evidence.created_at
            ).toLocaleString()}
          </strong>
        </article>

        <article>
          <span>Integrity</span>
          <strong
            className={
              evidence.blockchain
                ?.is_hash_matching
                ? "valid-integrity"
                : "invalid-integrity"
            }
          >
            {evidence.blockchain
              ?.is_hash_matching
              ? "VERIFIED"
              : "CHECK REQUIRED"}
          </strong>
        </article>

      </section>


      <section className="case-panel case-content">
        <h2>SHA256</h2>

        <pre className="case-code-block">
          {evidence.sha256_hash}
        </pre>
      </section>


      <section className="case-panel case-content">
        <h2>Evidence Snapshot</h2>

        <pre className="case-code-block">
          {JSON.stringify(
            evidence.snapshot,
            null,
            2
          )}
        </pre>
      </section>


      <section className="case-panel case-content">
        <h2>Blockchain Block</h2>

        {evidence.blockchain ? (
          <div className="case-detail-grid">

            <div>
              <span>Block Index</span>
              <strong>
                {evidence.blockchain.block_index}
              </strong>
            </div>

            <div>
              <span>Nonce</span>
              <strong>
                {evidence.blockchain.nonce}
              </strong>
            </div>

            <div>
              <span>Previous Hash</span>
              <strong className="wrap-hash">
                {evidence.blockchain.previous_hash}
              </strong>
            </div>

            <div>
              <span>Block Hash</span>
              <strong className="wrap-hash">
                {evidence.blockchain.block_hash}
              </strong>
            </div>

          </div>
        ) : (
          <p>
            No blockchain block found.
          </p>
        )}
      </section>

    </div>
  );
}


export default EvidenceDetail;