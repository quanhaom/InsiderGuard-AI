function AlertTable({ alerts }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2>Recent Alerts</h2>
          <p>Latest security detections</p>
        </div>
      </div>

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Risk</th>
              <th>Reason</th>
              <th>Created</th>
            </tr>
          </thead>

          <tbody>
            {alerts.length === 0 ? (
              <tr>
                <td colSpan="6" className="empty-state">
                  No alerts detected.
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>{alert.username}</td>
                  <td>{alert.alert_type}</td>
                  <td>
                    <span
                      className={`badge badge-${alert.severity?.toLowerCase()}`}
                    >
                      {alert.severity}
                    </span>
                  </td>
                  <td>{alert.risk_score}</td>
                  <td>{alert.reason || "No reason provided"}</td>
                  <td>
                    {new Date(
                      alert.created_at
                    ).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default AlertTable;