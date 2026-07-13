import {
  NavLink,
} from "react-router-dom";


const navigationItems = [
  {
    label: "Dashboard",
    path: "/",
  },
  {
    label: "Events",
    path: "/events",
  },
  {
    label: "Incidents",
    path: "/incidents",
  },
  {
    label: "Evidence",
    path: "/evidences",
  },
];


function Sidebar() {
  return (
    <aside className="sidebar">

      <div className="sidebar-brand">
        <h1>InsiderGuard AI</h1>
        <p>SOC & DFIR Platform</p>
      </div>


      <nav className="sidebar-nav">

        {navigationItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/"}
            className={({ isActive }) =>
              isActive
                ? "sidebar-link active"
                : "sidebar-link"
            }
          >
            {item.label}
          </NavLink>
        ))}

      </nav>


      <div className="sidebar-footer">

        <div className="sidebar-status">
          <span className="sidebar-status-dot" />

          <div>
            <strong>System Online</strong>
            <small>Collector connected</small>
          </div>
        </div>

      </div>

    </aside>
  );
}


export default Sidebar;