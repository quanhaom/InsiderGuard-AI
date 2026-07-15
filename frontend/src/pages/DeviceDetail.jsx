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

import "../styles/devices.css";


function DeviceDetail() {
  const { id } = useParams();

  const navigate = useNavigate();

  const [device, setDevice] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  const loadDevice = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          `/entities/devices/${id}`
        );

        setDevice(response.data);
      } catch (requestError) {
        console.error(requestError);

        setError(
          requestError.response?.status === 404
            ? "Device not found."
            : "Could not load device."
        );
      } finally {
        setLoading(false);
      }
    },
    [id]
  );


  useEffect(() => {
    loadDevice();
  }, [loadDevice]);


  if (loading) {
    return (
      <div className="device-full-message">
        Loading device...
      </div>
    );
  }


  if (error || !device) {
    return (
      <div className="device-full-message">

        <h2>
          {error || "Device not found"}
        </h2>

        <button
          type="button"
          onClick={() =>
            navigate("/devices")
          }
        >
          Back to Devices
        </button>

      </div>
    );
  }


  return (
    <div className="devices-page">

      <header className="devices-header">

        <div>
          <p className="device-eyebrow">
            Endpoint Entity
          </p>

          <h1>
            {device.hostname}
          </h1>

          <p>
            Agent ID:{" "}
            {device.agent_id || "Not registered"}
          </p>
        </div>


        <div className="device-header-actions">

          <button
            type="button"
            onClick={loadDevice}
          >
            Refresh
          </button>

          <button
            type="button"
            onClick={() =>
              navigate("/devices")
            }
          >
            Back
          </button>

        </div>

      </header>


      <section className="device-summary-grid">

        <article>
          <span>Status</span>

          <strong
            className={
              `device-status device-status-${
                device.status?.toLowerCase()
              }`
            }
          >
            {device.status}
          </strong>
        </article>


        <article>
          <span>Owner</span>

          <strong>
            {device.owner_username
              || "Unassigned"}
          </strong>
        </article>


        <article>
          <span>IP Address</span>

          <strong>
            {device.ip_address || "Unknown"}
          </strong>
        </article>


        <article>
          <span>Operating System</span>

          <strong>
            {device.os_name || "Unknown"}
          </strong>
        </article>

      </section>


      <section className="devices-panel device-detail-content">

        <h2>Device Information</h2>

        <div className="device-detail-grid">

          <div>
            <span>Hostname</span>
            <strong>{device.hostname}</strong>
          </div>

          <div>
            <span>MAC Address</span>
            <strong>
              {device.mac_address || "Unknown"}
            </strong>
          </div>

          <div>
            <span>OS Version</span>
            <strong>
              {device.os_version || "Unknown"}
            </strong>
          </div>

          <div>
            <span>Collector Version</span>
            <strong>
              {device.collector_version
                || "Unknown"}
            </strong>
          </div>

          <div>
            <span>First Seen</span>
            <strong>
              {device.first_seen
                ? new Date(
                    device.first_seen
                  ).toLocaleString()
                : "Unknown"}
            </strong>
          </div>

          <div>
            <span>Last Seen</span>
            <strong>
              {device.last_seen
                ? new Date(
                    device.last_seen
                  ).toLocaleString()
                : "Never"}
            </strong>
          </div>

        </div>

      </section>


      <section className="devices-panel device-detail-content">

        <h2>Recent Activity</h2>

        <p className="device-muted-text">
          Device activity correlation will be
          added after login events are linked to
          device entities.
        </p>

        <button
          type="button"
          className="device-secondary-action"
          onClick={() =>
            navigate(
              `/events?computer=${encodeURIComponent(
                device.hostname
              )}`
            )
          }
        >
          Search Related Events
        </button>

      </section>

    </div>
  );
}


export default DeviceDetail;