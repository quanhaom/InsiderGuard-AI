import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import api from "../api/client";

import "../styles/devices.css";


function Devices() {
  const navigate = useNavigate();

  const [devices, setDevices] = useState([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] =
    useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  const loadDevices = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const params = {
          page: 1,
          page_size: 100,
        };

        if (search.trim()) {
          params.search = search.trim();
        }

        if (statusFilter) {
          params.status = statusFilter;
        }

        const response = await api.get(
          "/entities/devices",
          {
            params,
          }
        );

        setDevices(
          response.data.items || []
        );
      } catch (requestError) {
        console.error(requestError);

        setError(
          "Could not load devices."
        );
      } finally {
        setLoading(false);
      }
    },
    [search, statusFilter]
  );


  useEffect(() => {
    const timerId = window.setTimeout(
      loadDevices,
      300
    );

    return () => {
      window.clearTimeout(timerId);
    };
  }, [loadDevices]);


  return (
    <div className="devices-page">

      <header className="devices-header">
        <div>
          <h1>Device Center</h1>

          <p>
            Monitor endpoint identity,
            collector status and ownership.
          </p>
        </div>
      </header>


      <section className="device-filter-panel">

        <input
          type="text"
          placeholder="Search hostname, IP, MAC or agent..."
          value={search}
          onChange={(event) =>
            setSearch(event.target.value)
          }
        />

        <select
          value={statusFilter}
          onChange={(event) =>
            setStatusFilter(
              event.target.value
            )
          }
        >
          <option value="">
            All statuses
          </option>

          <option value="ONLINE">
            Online
          </option>

          <option value="OFFLINE">
            Offline
          </option>

          <option value="INACTIVE">
            Inactive
          </option>
        </select>

        <button
          type="button"
          onClick={loadDevices}
        >
          Refresh
        </button>

      </section>


      <section className="devices-panel">

        {error && (
          <div className="device-error">
            {error}
          </div>
        )}


        {loading ? (
          <div className="device-message">
            Loading devices...
          </div>
        ) : (
          <div className="device-table-wrapper">

            <table className="device-table">

              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Owner</th>
                  <th>IP Address</th>
                  <th>Operating System</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                  <th>Action</th>
                </tr>
              </thead>


              <tbody>

                {devices.length === 0 ? (
                  <tr>
                    <td
                      colSpan="7"
                      className="device-message"
                    >
                      No devices found.
                    </td>
                  </tr>
                ) : (
                  devices.map((device) => (
                    <tr key={device.id}>

                      <td>
                        <strong>
                          {device.hostname}
                        </strong>
                      </td>

                      <td>
                        {device.owner_username
                          || "Unassigned"}
                      </td>

                      <td>
                        {device.ip_address
                          || "Unknown"}
                      </td>

                      <td>
                        {device.os_name
                          || "Unknown"}
                      </td>

                      <td>
                        <span
                          className={
                            `device-status device-status-${
                              device.status
                                ?.toLowerCase()
                            }`
                          }
                        >
                          {device.status}
                        </span>
                      </td>

                      <td>
                        {device.last_seen
                          ? new Date(
                              device.last_seen
                            ).toLocaleString()
                          : "Never"}
                      </td>

                      <td>
                        <button
                          type="button"
                          className="device-view-button"
                          onClick={() =>
                            navigate(
                              `/devices/${device.id}`
                            )
                          }
                        >
                          View
                        </button>
                      </td>

                    </tr>
                  ))
                )}

              </tbody>

            </table>

          </div>
        )}

      </section>

    </div>
  );
}


export default Devices;