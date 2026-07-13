function EvidenceCard({ evidence }) {
  const verified =
    evidence.integrity_status === "VERIFIED";

  return (
    <section className="panel evidence-panel">
      <div className="panel-header">
        <div>
          <h2>Evidence Integrity</h2>
          <p>Forensic evidence hash status</p>
        </div>
      </div>

      <div className="evidence-content">
        <div>
          <span>Total Evidence</span>
          <strong>{evidence.total_evidence ?? 0}</strong>
        </div>

        <div>
          <span>Hashed Evidence</span>
          <strong>{evidence.hashed_evidence ?? 0}</strong>
        </div>

        <div>
          <span>Integrity Status</span>
          <strong
            className={
              verified
                ? "integrity-verified"
                : "integrity-warning"
            }
          >
            {evidence.integrity_status ||
              "UNKNOWN"}
          </strong>
        </div>
      </div>
    </section>
  );
}

export default EvidenceCard;