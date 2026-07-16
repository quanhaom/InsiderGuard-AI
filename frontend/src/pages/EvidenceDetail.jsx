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

  const [
    blockchainVerification,
    setBlockchainVerification,
  ] = useState(null);

  const [
    verifyingBlockchain,
    setVerifyingBlockchain,
  ] = useState(false);

  const [
    blockchainError,
    setBlockchainError,
  ] = useState("");


  const verifyBlockchain = useCallback(
    async (evidenceId) => {
      if (!evidenceId) {
        return;
      }

      try {
        setVerifyingBlockchain(true);
        setBlockchainError("");

        const response = await api.get(
          `/blockchain/verify`
        );

        setBlockchainVerification(
          response.data
        );
      } catch (requestError) {
        console.error(requestError);

        setBlockchainVerification({
          verified: false,
          valid: false,
          integrity: "ERROR",
        });

        setBlockchainError(
          requestError.response?.data?.detail
          || "Could not verify blockchain integrity."
        );
      } finally {
        setVerifyingBlockchain(false);
      }
    },
    []
  );


  const loadEvidence = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");
        setBlockchainError("");
        setBlockchainVerification(null);

        const response = await api.get(
          `/case-explorer/evidences/${id}`
        );

        const loadedEvidence =
          response.data;

        setEvidence(loadedEvidence);

        await verifyBlockchain(
          loadedEvidence.id
        );
      } catch (requestError) {
        console.error(requestError);

        setError(
          requestError.response?.data?.detail
          || "Could not load evidence."
        );
      } finally {
        setLoading(false);
      }
    },
    [
      id,
      verifyBlockchain,
    ]
  );


  useEffect(() => {
    loadEvidence();
  }, [loadEvidence]);


  const blockchainIsValid =
    blockchainVerification?.is_valid
    ?? blockchainVerification?.verified
    ?? blockchainVerification?.valid
    ?? false;

  const verificationIntegrity =
    blockchainVerification?.integrity
    || (
      blockchainIsValid
        ? "VALID"
        : "INVALID"
    );


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
            {evidence.created_at
              ? new Date(
                  evidence.created_at
                ).toLocaleString()
              : "Unknown"}
          </strong>
        </article>


        <article>
          <span>Integrity</span>

          <strong
            className={
              verifyingBlockchain
                ? "checking-integrity"
                : blockchainIsValid
                  ? "valid-integrity"
                  : blockchainVerification
                    ? "invalid-integrity"
                    : "checking-integrity"
            }
          >
            {verifyingBlockchain
              ? "VERIFYING"
              : blockchainIsValid
                ? "VERIFIED"
                : blockchainVerification
                  ? "INVALID"
                  : "CHECK REQUIRED"}
          </strong>
        </article>

      </section>


      {blockchainError && (
        <section className="case-panel case-content">

          <div className="blockchain-verification-error">
            {blockchainError}
          </div>

          <button
            type="button"
            className="case-button"
            disabled={verifyingBlockchain}
            onClick={() =>
              verifyBlockchain(evidence.id)
            }
          >
            {verifyingBlockchain
              ? "Verifying..."
              : "Verify Again"}
          </button>

        </section>
      )}


      <section className="case-panel case-content">

        <div className="blockchain-verification-header">

          <div>
            <h2>
              Blockchain Verification
            </h2>

            <p>
              Evidence integrity is checked
              automatically when this page opens.
            </p>
          </div>


          <button
            type="button"
            className="case-button"
            disabled={verifyingBlockchain}
            onClick={() =>
              verifyBlockchain(evidence.id)
            }
          >
            {verifyingBlockchain
              ? "Verifying..."
              : "Verify Again"}
          </button>

        </div>


        <div className="case-detail-grid">

          <div>
            <span>Verified</span>

            <strong
              className={
                blockchainIsValid
                  ? "valid-integrity"
                  : "invalid-integrity"
              }
            >
              {blockchainIsValid
                ? "YES"
                : "NO"}
            </strong>
          </div>


          <div>
            <span>Integrity</span>

            <strong
              className={
                blockchainIsValid
                  ? "valid-integrity"
                  : "invalid-integrity"
              }
            >
              {verifyingBlockchain
                ? "VERIFYING"
                : verificationIntegrity}
            </strong>
          </div>


          {blockchainVerification?.blocks
            !== undefined && (
            <div>
              <span>Blocks Checked</span>

              <strong>
                {
                  blockchainVerification
                    .blocks
                }
              </strong>
            </div>
          )}


          <div>
            <span>Message</span>

            <strong>
              {
                blockchainVerification
                  ?.message
                || (
                  blockchainIsValid
                    ? "Evidence integrity verified successfully."
                    : "Evidence integrity could not be verified."
                )
              }
            </strong>
          </div>

        </div>

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
                {
                  evidence.blockchain
                    .block_index
                }
              </strong>
            </div>


            <div>
              <span>Nonce</span>

              <strong>
                {
                  evidence.blockchain
                    .nonce
                  ?? 0
                }
              </strong>
            </div>


            <div>
              <span>Evidence Hash</span>

              <strong className="wrap-hash">
                {
                  evidence.blockchain
                    .evidence_hash
                  || evidence.sha256_hash
                }
              </strong>
            </div>


            <div>
              <span>Previous Hash</span>

              <strong className="wrap-hash">
                {
                  evidence.blockchain
                    .previous_hash
                }
              </strong>
            </div>


            <div>
              <span>Block Hash</span>

              <strong className="wrap-hash">
                {
                  evidence.blockchain
                    .block_hash
                }
              </strong>
            </div>


            <div>
              <span>Hash Match</span>

              <strong
                className={
                  blockchainIsValid
                    ? "valid-integrity"
                    : "invalid-integrity"
                }
              >
                {blockchainIsValid
                  ? "MATCH"
                  : "MISMATCH"}
              </strong>
            </div>

          </div>
        ) : (
          <p>
            No blockchain block found for
            this evidence.
          </p>
        )}

      </section>

    </div>
  );
}


export default EvidenceDetail;