import {
  useCallback,
  useEffect,
  useState,
} from "react";

import api from "../api/client";
import AlertTable from "../components/AlertTable";
import EvidenceCard from "../components/EvidenceCard";
import IncidentTable from "../components/IncidentTable";
//import RiskChart from "../components/RiskChart";
import StatCard from "../components/StatCard";
import { useNavigate } from "react-router-dom";
import "../styles/dashboard.css";

const EMPTY_OVERVIEW = {
  login_events: 0,
  failed_logins: 0,
  alerts: 0,
  open_incidents: 0,
  high_risk_users: 0,
  evidence_count: 0,
};

const EMPTY_EVIDENCE = {
  total_evidence: 0,
  hashed_evidence: 0,
  integrity_status: "UNKNOWN",
};

function Dashboard() {
  const [overview, setOverview] =
    useState(EMPTY_OVERVIEW);

  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [riskTimeline, setRiskTimeline] =
    useState([]);

  const [evidence, setEvidence] =
    useState(EMPTY_EVIDENCE);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDashboard = useCallback(async () => {
    try {
      setError("");

      const [
        overviewResponse,
        alertsResponse,
        incidentsResponse,
        riskResponse,
        evidenceResponse,
      ] = await Promise.all([
        api.get("/dashboard/overview"),
        api.get("/dashboard/recent-alerts"),
        api.get("/dashboard/open-incidents"),
        api.get("/dashboard/risk-timeline"),
        api.get("/dashboard/evidence-status"),
      ]);

      setOverview(overviewResponse.data);
      setAlerts(alertsResponse.data);
      setIncidents(incidentsResponse.data);
      setRiskTimeline(riskResponse.data);
      setEvidence(evidenceResponse.data);
    } catch (requestError) {
      console.error(requestError);

      setError(
        "Could not connect to the InsiderGuard backend."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();

    const intervalId = window.setInterval(
      loadDashboard,
      10000
    );

    return () => {
      window.clearInterval(intervalId);
    };
  }, [loadDashboard]);

  if (loading) {
    return (
      <div className="screen-message">
        Loading InsiderGuard dashboard...
      </div>
    );
  }

  return (
    <div className="app-shell">

      <main className="dashboard-content">
        {error && (
          <div className="error-banner">
            {error}
          </div>
        )}

        <section className="dashboard-heading">
          <div>
            <h2>Security Overview</h2>
            <p>
              Live authentication, risk and incident
              monitoring
            </p>
          </div>
          <div className="dashboard-actions">

            <button
                type="button"
                className="refresh-button"
                onClick={() =>
                window.location.assign("/events")
                }
            >
                Event Explorer
            </button>

            <button
                type="button"
                className="refresh-button"
                onClick={loadDashboard}
            >
                Refresh
            </button>

            </div>
        </section>

        <section className="stat-grid">
          <StatCard
            title="Login Events"
            value={overview.login_events}
            description="Successful Windows logins"
            variant="blue"
          />

          <StatCard
            title="Alerts"
            value={overview.alerts}
            description="Security detections"
            variant="red"
          />

          <StatCard
            title="Open Incidents"
            value={overview.open_incidents}
            description="Pending investigations"
            variant="purple"
          />

          <StatCard
            title="High-Risk Users"
            value={overview.high_risk_users}
            description="Users with risk score ≥ 80"
            variant="orange"
          />

          <StatCard
            title="Evidence"
            value={overview.evidence_count}
            description="Stored forensic snapshots"
            variant="green"
          />
        </section>


        <div className="dashboard-grid">
          <AlertTable alerts={alerts} />
          <EvidenceCard evidence={evidence} />
        </div>

        <IncidentTable incidents={incidents} />
      </main>
    </div>
  );
}

export default Dashboard;