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

import "../styles/users.css";


function UserDetail() {
  const { id } = useParams();

  const navigate = useNavigate();

  const [user, setUser] =
    useState(null);

  const [
    behaviorProfile,
    setBehaviorProfile,
  ] = useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [
    buildingProfile,
    setBuildingProfile,
  ] = useState(false);

  const [
    profileError,
    setProfileError,
  ] = useState("");


  const loadUser = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");
        setProfileError("");

        const response = await api.get(
          `/entities/users/${id}`
        );

        const loadedUser = response.data;

        setUser(loadedUser);

        try {
          const profileResponse =
            await api.get(
              `/behavior-profile/${encodeURIComponent(
                loadedUser.username
              )}`
            );

          setBehaviorProfile(
            profileResponse.data
          );

        } catch (profileRequestError) {
          if (
            profileRequestError.response
              ?.status !== 404
          ) {
            console.error(
              profileRequestError
            );

            setProfileError(
              "Could not load behavior profile."
            );
          }

          setBehaviorProfile(null);
        }

      } catch (requestError) {
        console.error(requestError);

        setError(
          requestError.response?.status
            === 404
            ? "User not found."
            : "Could not load user."
        );

      } finally {
        setLoading(false);
      }
    },
    [id]
  );


  useEffect(() => {
    loadUser();
  }, [loadUser]);


  async function buildBehaviorProfile() {
    if (!user) {
      return;
    }

    try {
      setBuildingProfile(true);
      setProfileError("");

      const response = await api.post(
        `/behavior-profile/build/${encodeURIComponent(
          user.username
        )}`
      );

      setBehaviorProfile(
        response.data.profile
      );

    } catch (requestError) {
      console.error(requestError);

      setProfileError(
        requestError.response?.data?.detail
          || "Could not build behavior profile."
      );

    } finally {
      setBuildingProfile(false);
    }
  }


  if (loading) {
    return (
      <div className="user-full-message">
        Loading user...
      </div>
    );
  }


  if (error || !user) {
    return (
      <div className="user-full-message">

        <div>
          <h2>
            {error || "User not found"}
          </h2>

          <button
            type="button"
            onClick={() =>
              navigate("/users")
            }
          >
            Back to Users
          </button>
        </div>

      </div>
    );
  }


  const risk = user.current_risk || {
    score: 0,
    severity: "LOW",
    reason: null,
    created_at: null,
  };


  return (
    <div className="users-page">

      <header className="users-header">

        <div>
          <p className="user-eyebrow">
            User Entity
          </p>

          <h1>
            {user.username}
          </h1>

          <p>
            {user.department
              || "Unknown department"}

            {" · "}

            {user.role || "Unknown role"}
          </p>
        </div>


        <div className="user-header-actions">

          <button
            type="button"
            onClick={loadUser}
          >
            Refresh
          </button>

          <button
            type="button"
            onClick={() =>
              navigate("/users")
            }
          >
            Back
          </button>

        </div>

      </header>


      <section className="user-summary-grid">

        <article>
          <span>Department</span>

          <strong>
            {user.department || "Unknown"}
          </strong>
        </article>


        <article>
          <span>Role</span>

          <strong>
            {user.role || "Unknown"}
          </strong>
        </article>


        <article>
          <span>Current Risk</span>

          <strong
            className={
              `user-risk-value user-risk-${risk.severity
                ?.toLowerCase()}`
            }
          >
            {risk.score} {risk.severity}
          </strong>
        </article>


        <article>
          <span>Known Devices</span>

          <strong>
            {user.devices?.length || 0}
          </strong>
        </article>

      </section>


      <section className="users-panel user-detail-content">

        <div className="user-section-header">

          <div>
            <h2>Behavior Profile</h2>

            <p>
              Baseline derived from login
              and device activity.
            </p>
          </div>


          <button
            type="button"
            className="user-profile-button"
            disabled={buildingProfile}
            onClick={
              buildBehaviorProfile
            }
          >
            {buildingProfile
              ? "Building..."
              : behaviorProfile
                ? "Rebuild Profile"
                : "Build Profile"}
          </button>

        </div>


        {profileError && (
          <div className="user-profile-error">
            {profileError}
          </div>
        )}


        {!behaviorProfile ? (
          <div className="user-empty-profile">

            <p>
              No behavior profile has been
              built for this user.
            </p>

            <p>
              Build a profile to calculate
              login count, common IP and
              common device.
            </p>

          </div>
        ) : (
          <div className="user-detail-grid">

            <div>
              <span>Login Count</span>

              <strong>
                {
                  behaviorProfile
                    .login_count
                }
              </strong>
            </div>


            <div>
              <span>Common IP</span>

              <strong>
                {
                  behaviorProfile
                    .common_ip
                  || "Unknown"
                }
              </strong>
            </div>


            <div>
              <span>Common Host</span>

              <strong>
                {
                  behaviorProfile
                    .common_host
                  || "Unknown"
                }
              </strong>
            </div>


            <div>
              <span>First Seen</span>

              <strong>
                {behaviorProfile.first_seen
                  ? new Date(
                      behaviorProfile
                        .first_seen
                    ).toLocaleString()
                  : "Unknown"}
              </strong>
            </div>


            <div>
              <span>Last Login</span>

              <strong>
                {behaviorProfile.last_login
                  ? new Date(
                      behaviorProfile
                        .last_login
                    ).toLocaleString()
                  : "Unknown"}
              </strong>
            </div>


            <div>
              <span>Profile Updated</span>

              <strong>
                {behaviorProfile.last_seen
                  ? new Date(
                      behaviorProfile
                        .last_seen
                    ).toLocaleString()
                  : "Unknown"}
              </strong>
            </div>

          </div>
        )}

      </section>


      <section className="users-panel user-detail-content">

        <div className="user-section-header">

          <div>
            <h2>Current Risk</h2>

            <p>
              Latest recorded risk assessment
              for this user.
            </p>
          </div>

        </div>


        <div className="user-detail-grid">

          <div>
            <span>Score</span>

            <strong>
              {risk.score}
            </strong>
          </div>


          <div>
            <span>Severity</span>

            <strong>
              {risk.severity}
            </strong>
          </div>


          <div className="user-detail-wide">
            <span>Reason</span>

            <strong>
              {risk.reason
                || "No active risk reason"}
            </strong>
          </div>


          <div>
            <span>Assessed At</span>

            <strong>
              {risk.created_at
                ? new Date(
                    risk.created_at
                  ).toLocaleString()
                : "Not assessed"}
            </strong>
          </div>

        </div>

      </section>


      <section className="users-panel user-detail-content">

        <div className="user-section-header">

          <div>
            <h2>Known Devices</h2>

            <p>
              Devices currently associated
              with this username.
            </p>
          </div>

        </div>


        {!user.devices
        || user.devices.length === 0 ? (
          <p className="user-muted-text">
            No devices associated with
            this user.
          </p>
        ) : (
          <div className="user-entity-list">

            {user.devices.map(
              (device) => (
                <button
                  type="button"
                  key={device.id}
                  className="user-entity-item"
                  onClick={() =>
                    navigate(
                      `/devices/${device.id}`
                    )
                  }
                >

                  <div>
                    <strong>
                      {device.hostname}
                    </strong>

                    <small>
                      {device.ip_address
                        || "Unknown IP"}
                    </small>
                  </div>


                  <span
                    className={
                      `user-device-status user-device-${device.status
                        ?.toLowerCase()}`
                    }
                  >
                    {device.status}
                  </span>

                </button>
              )
            )}

          </div>
        )}

      </section>


      <section className="users-panel user-detail-content">

        <div className="user-section-header">

          <div>
            <h2>Incidents</h2>

            <p>
              Recent security incidents linked
              to this user.
            </p>
          </div>

        </div>


        {!user.incidents
        || user.incidents.length === 0 ? (
          <p className="user-muted-text">
            No incidents associated with
            this user.
          </p>
        ) : (
          <div className="user-entity-list">

            {user.incidents.map(
              (incident) => (
                <button
                  type="button"
                  key={incident.id}
                  className="user-entity-item"
                  onClick={() =>
                    navigate(
                      `/incidents/${incident.id}`
                    )
                  }
                >

                  <div>
                    <strong>
                      #{incident.id}{" "}
                      {incident.title}
                    </strong>

                    <small>
                      {incident.created_at
                        ? new Date(
                            incident.created_at
                          ).toLocaleString()
                        : "Unknown time"}
                    </small>
                  </div>


                  <div className="user-item-badges">

                    <span
                      className={
                        `user-incident-severity user-severity-${incident.severity
                          ?.toLowerCase()}`
                      }
                    >
                      {incident.severity}
                    </span>

                    <span className="user-incident-status">
                      {incident.status}
                    </span>

                  </div>

                </button>
              )
            )}

          </div>
        )}

      </section>


      <section className="users-panel user-detail-content">

        <div className="user-section-header">

          <div>
            <h2>Risk History</h2>

            <p>
              Recent UEBA and rule-based
              risk assessments.
            </p>
          </div>

        </div>


        {!user.risk_history
        || user.risk_history.length === 0 ? (
          <p className="user-muted-text">
            No risk history available.
          </p>
        ) : (
          <div className="user-history-list">

            {user.risk_history.map(
              (riskItem) => (
                <article
                  key={riskItem.id}
                  className="user-history-item"
                >

                  <div>
                    <strong>
                      Risk {
                        riskItem.risk_score
                      }
                    </strong>

                    <p>
                      {riskItem.reason
                        || "No reason provided"}
                    </p>
                  </div>


                  <div className="user-history-meta">

                    <span>
                      {riskItem.severity}
                    </span>

                    <small>
                      {riskItem.created_at
                        ? new Date(
                            riskItem.created_at
                          ).toLocaleString()
                        : "Unknown"}
                    </small>

                  </div>

                </article>
              )
            )}

          </div>
        )}

      </section>


      <section className="users-panel user-detail-content">

        <div className="user-section-header">

          <div>
            <h2>Recent Logins</h2>

            <p>
              Most recent successful login
              activity for this user.
            </p>
          </div>

        </div>


        {!user.recent_logins
        || user.recent_logins.length === 0 ? (
          <p className="user-muted-text">
            No recent login activity.
          </p>
        ) : (
          <div className="user-history-list">

            {user.recent_logins.map(
              (login) => (
                <article
                  key={login.id}
                  className="user-history-item"
                >

                  <div>
                    <strong>
                      {login.ip_address
                        || "Unknown IP"}
                    </strong>

                    <p>
                      Successful login event
                    </p>
                  </div>


                  <small>
                    {login.login_time
                      ? new Date(
                          login.login_time
                        ).toLocaleString()
                      : "Unknown time"}
                  </small>

                </article>
              )
            )}

          </div>
        )}

      </section>

    </div>
  );
}


export default UserDetail;