import { useNavigate } from "react-router-dom";

function IncidentTable({
  incidents = [],
}) {

  const navigate = useNavigate();


  if (!incidents.length) {

    return (

      <section className="dashboard-panel">

        <h3>
          Recent Incidents
        </h3>

        <p>
          No active incidents.
        </p>

      </section>

    );
  }



  return (

    <section className="dashboard-panel">


      <div className="panel-header">

        <h3>
          Recent Incidents
        </h3>

        <span>
          {incidents.length} items
        </span>

      </div>



      <div className="incident-table">


        {incidents.map(
          (incident) => (

            <div
              className="incident-row"
              key={incident.id}
            >


              <div className="incident-info">

                <strong>

                  #{incident.id}
                  {" "}
                  {incident.title}

                </strong>


                <p>

                  User:
                  {" "}
                  {incident.username}

                </p>


              </div>



              <div className="incident-meta">


                <span
                  className={
                    `severity-${incident.severity?.toLowerCase()}`
                  }
                >

                  {incident.severity}

                </span>



                <span
                  className={
                    `status-${incident.status?.toLowerCase()}`
                  }
                >

                  {incident.status}

                </span>



              </div>



              <button

                type="button"

                className="review-button"

                onClick={() =>
                  navigate(
                    `/incidents/${incident.id}`
                  )
                }

              >

                Review

              </button>


            </div>

          )

        )}


      </div>


    </section>

  );
}


export default IncidentTable;