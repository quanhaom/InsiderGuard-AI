function Navbar() {
  return (
    <header className="navbar">
      <div>
        <h1>InsiderGuard AI</h1>
        <p>Security Operations Center</p>
      </div>

      <div className="system-status">
        <span className="status-dot" />
        System Online
      </div>
    </header>
  );
}

export default Navbar;