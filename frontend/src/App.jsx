import {
  BrowserRouter,
  Route,
  Routes,
} from "react-router-dom";

import AppLayout from "./components/AppLayout";

import Dashboard from "./pages/Dashboard";
import EventDetail from "./pages/EventDetail";
import Events from "./pages/Events";
import EvidenceDetail from "./pages/EvidenceDetail";
import Evidences from "./pages/Evidences";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import Investigation from "./pages/Investigation";


function App() {
  return (
    <BrowserRouter>

      <Routes>

        <Route element={<AppLayout />}>

          <Route
            path="/"
            element={<Dashboard />}
          />

          <Route
            path="/events"
            element={<Events />}
          />

          <Route
            path="/events/:id"
            element={<EventDetail />}
          />

          <Route
            path="/incidents"
            element={<Incidents />}
          />

          <Route
            path="/incidents/:id"
            element={<IncidentDetail />}
          />

          <Route
            path="/evidences"
            element={<Evidences />}
          />

          <Route
            path="/evidences/:id"
            element={<EvidenceDetail />}
          />

          <Route
            path="/investigation/:id"
            element={<Investigation />}
          />

        </Route>

      </Routes>

    </BrowserRouter>
  );
}


export default App;