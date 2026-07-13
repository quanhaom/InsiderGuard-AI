import {
  Outlet,
} from "react-router-dom";

import Sidebar from "./Sidebar";

import "../styles/layout.css";


function AppLayout() {
  return (
    <div className="application-layout">

      <Sidebar />

      <div className="application-content">
        <Outlet />
      </div>

    </div>
  );
}


export default AppLayout;