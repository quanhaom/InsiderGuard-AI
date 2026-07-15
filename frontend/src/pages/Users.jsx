import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import api from "../api/client";

import "../styles/users.css";


function Users() {
  const navigate = useNavigate();

  const [users, setUsers] = useState([]);

  const [search, setSearch] =
    useState("");

  const [department, setDepartment] =
    useState("");

  const [role, setRole] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  const loadUsers = useCallback(
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

        if (department.trim()) {
          params.department =
            department.trim();
        }

        if (role.trim()) {
          params.role = role.trim();
        }

        const response = await api.get(
          "/entities/users",
          {
            params,
          }
        );

        setUsers(
          response.data.items || []
        );
      } catch (requestError) {
        console.error(requestError);

        setError(
          "Could not load users."
        );
      } finally {
        setLoading(false);
      }
    },
    [
      search,
      department,
      role,
    ]
  );


  useEffect(() => {
    const timerId = window.setTimeout(
      loadUsers,
      300
    );

    return () => {
      window.clearTimeout(timerId);
    };
  }, [loadUsers]);


  function riskClass(score) {
    if (score >= 80) {
      return "user-risk-critical";
    }

    if (score >= 60) {
      return "user-risk-high";
    }

    if (score >= 30) {
      return "user-risk-medium";
    }

    return "user-risk-low";
  }


  return (
    <div className="users-page">

      <header className="users-header">
        <div>
          <h1>User Center</h1>

          <p>
            Review users, associated devices,
            risk and security incidents.
          </p>
        </div>
      </header>


      <section className="user-filter-panel">

        <input
          type="text"
          placeholder="Search username..."
          value={search}
          onChange={(event) =>
            setSearch(event.target.value)
          }
        />

        <input
          type="text"
          placeholder="Department..."
          value={department}
          onChange={(event) =>
            setDepartment(
              event.target.value
            )
          }
        />

        <input
          type="text"
          placeholder="Role..."
          value={role}
          onChange={(event) =>
            setRole(event.target.value)
          }
        />

        <button
          type="button"
          onClick={loadUsers}
        >
          Refresh
        </button>

      </section>


      <section className="users-panel">

        {error && (
          <div className="user-error">
            {error}
          </div>
        )}


        {loading ? (
          <div className="user-message">
            Loading users...
          </div>
        ) : (
          <div className="user-table-wrapper">

            <table className="user-table">

              <thead>
                <tr>
                  <th>Username</th>
                  <th>Department</th>
                  <th>Role</th>
                  <th>Devices</th>
                  <th>Risk</th>
                  <th>Incidents</th>
                  <th>Unresolved</th>
                  <th>Action</th>
                </tr>
              </thead>


              <tbody>

                {users.length === 0 ? (
                  <tr>
                    <td
                      colSpan="8"
                      className="user-message"
                    >
                      No users found.
                    </td>
                  </tr>
                ) : (
                  users.map((user) => (
                    <tr key={user.id}>

                      <td>
                        <strong>
                          {user.username}
                        </strong>
                      </td>

                      <td>
                        {user.department
                          || "Unknown"}
                      </td>

                      <td>
                        {user.role
                          || "Unknown"}
                      </td>

                      <td>
                        {user.device_count ?? 0}
                      </td>

                      <td>
                        <span
                          className={
                            `user-risk-badge ${
                              riskClass(
                                user.risk_score || 0
                              )
                            }`
                          }
                        >
                          {user.risk_score || 0}
                        </span>
                      </td>

                      <td>
                        {user.incident_count ?? 0}
                      </td>

                      <td>
                        <span
                          className={
                            user.unresolved_incident_count > 0
                              ? "user-unresolved active"
                              : "user-unresolved"
                          }
                        >
                          {
                            user.unresolved_incident_count
                            ?? 0
                          }
                        </span>
                      </td>

                      <td>
                        <button
                          type="button"
                          className="user-view-button"
                          onClick={() =>
                            navigate(
                              `/users/${user.id}`
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


export default Users;