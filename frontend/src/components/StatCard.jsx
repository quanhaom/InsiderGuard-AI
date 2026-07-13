function StatCard({
  title,
  value,
  description,
  variant = "default",
  onClick,
}) {
  return (
    <article
      className={`stat-card stat-card-${variant} ${
        onClick ? "stat-card-clickable" : ""
      }`}
      onClick={onClick}
      onKeyDown={(event) => {
        if (
          onClick &&
          (event.key === "Enter" ||
            event.key === " ")
        ) {
          onClick();
        }
      }}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      <div className="stat-card-header">
        <span>{title}</span>
      </div>

      <strong className="stat-card-value">
        {value ?? 0}
      </strong>

      <p className="stat-card-description">
        {description}
      </p>
    </article>
  );
}

export default StatCard;