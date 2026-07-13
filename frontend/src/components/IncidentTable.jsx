import { useNavigate } from "react-router-dom";


function IncidentTable({ incidents }) {

  const navigate = useNavigate();


  return (
    <section className="panel">

      <div className="panel-header">
        <div>
          <h2>
            Open Incidents
          </h2>

          <p>
            Incidents requiring investigation
          </p>
        </div>
      </div>


      <div className="table-wrapper">

        <table>

          <thead>

            <tr>
              <th>ID</th>
              <th>User</th>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Created</th>
            </tr>

          </thead>


          <tbody>

            {
              incidents.length === 0 ? (

                <tr>

                  <td 
                    colSpan="6"
                    className="empty-state"
                  >
                    No open incidents.
                  </td>

                </tr>

              ) : (

                incidents.map((incident) => (

                  <tr
                    key={incident.id}
                  >


                    <td>

                      <button

                        className="incident-link"

                        onClick={() =>
                          navigate(
                            `/investigation/${incident.id}`
                          )
                        }

                      >

                        #{incident.id}

                      </button>

                    </td>



                    <td>
                      {incident.username}
                    </td>



                    <td>
                      {incident.title}
                    </td>



                    <td>

                      <span
                        className={
                          `badge badge-${
                            incident.severity?.toLowerCase()
                          }`
                        }
                      >

                        {incident.severity}

                      </span>

                    </td>



                    <td>

                      <span
                        className="badge badge-open"
                      >

                        {incident.status}

                      </span>

                    </td>



                    <td>

                      {
                        new Date(
                          incident.created_at
                        ).toLocaleString()
                      }

                    </td>


                  </tr>

                ))

              )
            }


          </tbody>

        </table>


      </div>


    </section>
  );
}


export default IncidentTable;