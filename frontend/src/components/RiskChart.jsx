import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";


function RiskChart({ data }) {

  return (

    <section className="panel">

      <div className="panel-header">

        <div>
          <h2>
            Risk Timeline
          </h2>

          <p>
            UEBA risk score monitoring
          </p>
        </div>

      </div>


      <div
        style={{
          width: "100%",
          height: 320
        }}
      >

        <ResponsiveContainer>

          <LineChart
            data={data}
          >

            <CartesianGrid
              strokeDasharray="3 3"
            />


            <XAxis
              dataKey="username"
            />


            <YAxis
              domain={[0,100]}
            />


            <Tooltip />


            <Line
              type="monotone"
              dataKey="risk_score"
              stroke="#38bdf8"
              strokeWidth={3}
            />


          </LineChart>


        </ResponsiveContainer>


      </div>


    </section>

  );

}


export default RiskChart;