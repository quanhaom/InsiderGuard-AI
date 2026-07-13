import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import api from "../api/client";

import "../styles/events.css";


const INITIAL_FILTERS = {
  event_id: "",
  record_id: "",
  computer: "",
  provider: "",
  start_time: "",
  end_time: "",
};


function Events() {
  const navigate = useNavigate();

  const [filters, setFilters] = useState(
    INITIAL_FILTERS
  );

  const [appliedFilters, setAppliedFilters] =
    useState(INITIAL_FILTERS);

  const [events, setEvents] = useState([]);

  const [page, setPage] = useState(1);

  const [pageSize, setPageSize] = useState(25);

  const [total, setTotal] = useState(0);

  const [totalPages, setTotalPages] =
    useState(0);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  const queryParams = useMemo(() => {
    const params = {
      page,
      page_size: pageSize,
    };

    if (appliedFilters.event_id) {
      params.event_id =
        Number(appliedFilters.event_id);
    }

    if (appliedFilters.record_id) {
      params.record_id =
        Number(appliedFilters.record_id);
    }

    if (appliedFilters.computer.trim()) {
      params.computer =
        appliedFilters.computer.trim();
    }

    if (appliedFilters.provider.trim()) {
      params.provider =
        appliedFilters.provider.trim();
    }

    if (appliedFilters.start_time) {
      params.start_time =
        new Date(
          appliedFilters.start_time
        ).toISOString();
    }

    if (appliedFilters.end_time) {
      params.end_time =
        new Date(
          appliedFilters.end_time
        ).toISOString();
    }

    return params;
  }, [
    appliedFilters,
    page,
    pageSize,
  ]);


  const loadEvents = useCallback(
    async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get(
          "/event-explorer/events",
          {
            params: queryParams,
          }
        );

        setEvents(
          response.data.items || []
        );

        setTotal(
          response.data.total || 0
        );

        setTotalPages(
          response.data.total_pages || 0
        );
      } catch (requestError) {
        console.error(requestError);

        setError(
          "Could not load Windows events."
        );
      } finally {
        setLoading(false);
      }
    },
    [queryParams]
  );


  useEffect(() => {
    loadEvents();
  }, [loadEvents]);


  function handleInputChange(event) {
    const {
      name,
      value,
    } = event.target;

    setFilters((current) => ({
      ...current,
      [name]: value,
    }));
  }


  function handleSubmit(event) {
    event.preventDefault();

    setPage(1);

    setAppliedFilters({
      ...filters,
    });
  }


  function handleReset() {
    setFilters(
      INITIAL_FILTERS
    );

    setAppliedFilters(
      INITIAL_FILTERS
    );

    setPage(1);
  }


  function goToPreviousPage() {
    setPage((current) =>
      Math.max(1, current - 1)
    );
  }


  function goToNextPage() {
    setPage((current) =>
      Math.min(
        totalPages || 1,
        current + 1
      )
    );
  }


  return (
    <div className="events-page">

      <header className="events-header">

        <div>
          <h1>
            Windows Event Explorer
          </h1>

          <p>
            Search, filter and inspect raw
            Windows security telemetry.
          </p>
        </div>

        <button
          type="button"
          className="secondary-button"
          onClick={() =>
            navigate("/")
          }
        >
          Back to Dashboard
        </button>

      </header>


      <section className="events-filter-panel">

        <form
          className="events-filter-form"
          onSubmit={handleSubmit}
        >

          <div className="filter-field">
            <label htmlFor="event_id">
              Event ID
            </label>

            <input
              id="event_id"
              name="event_id"
              type="number"
              placeholder="4624"
              value={filters.event_id}
              onChange={
                handleInputChange
              }
            />
          </div>


          <div className="filter-field">
            <label htmlFor="record_id">
              Record ID
            </label>

            <input
              id="record_id"
              name="record_id"
              type="number"
              placeholder="5276"
              value={filters.record_id}
              onChange={
                handleInputChange
              }
            />
          </div>


          <div className="filter-field">
            <label htmlFor="computer">
              Computer
            </label>

            <input
              id="computer"
              name="computer"
              type="text"
              placeholder="T-01"
              value={filters.computer}
              onChange={
                handleInputChange
              }
            />
          </div>


          <div className="filter-field">
            <label htmlFor="provider">
              Provider
            </label>

            <input
              id="provider"
              name="provider"
              type="text"
              placeholder="Security-Auditing"
              value={filters.provider}
              onChange={
                handleInputChange
              }
            />
          </div>


          <div className="filter-field">
            <label htmlFor="start_time">
              Start Time
            </label>

            <input
              id="start_time"
              name="start_time"
              type="datetime-local"
              value={filters.start_time}
              onChange={
                handleInputChange
              }
            />
          </div>


          <div className="filter-field">
            <label htmlFor="end_time">
              End Time
            </label>

            <input
              id="end_time"
              name="end_time"
              type="datetime-local"
              value={filters.end_time}
              onChange={
                handleInputChange
              }
            />
          </div>


          <div className="filter-actions">

            <button
              type="submit"
              className="primary-button"
            >
              Apply Filters
            </button>

            <button
              type="button"
              className="secondary-button"
              onClick={handleReset}
            >
              Reset
            </button>

          </div>

        </form>

      </section>


      <section className="events-table-panel">

        <div className="events-table-header">

          <div>
            <h2>
              Raw Windows Events
            </h2>

            <p>
              {total} event
              {total === 1 ? "" : "s"} found
            </p>
          </div>


          <div className="page-size-control">

            <label htmlFor="page-size">
              Rows
            </label>

            <select
              id="page-size"
              value={pageSize}
              onChange={(event) => {
                setPageSize(
                  Number(event.target.value)
                );

                setPage(1);
              }}
            >
              <option value="10">
                10
              </option>

              <option value="25">
                25
              </option>

              <option value="50">
                50
              </option>

              <option value="100">
                100
              </option>
            </select>

          </div>

        </div>


        {error && (
          <div className="events-error">
            {error}
          </div>
        )}


        {loading ? (
          <div className="events-loading">
            Loading events...
          </div>
        ) : (
          <div className="events-table-wrapper">

            <table className="events-table">

              <thead>
                <tr>
                  <th>ID</th>
                  <th>Record ID</th>
                  <th>Event ID</th>
                  <th>Computer</th>
                  <th>Provider</th>
                  <th>Received At</th>
                  <th>Action</th>
                </tr>
              </thead>


              <tbody>

                {events.length === 0 ? (
                  <tr>
                    <td
                      colSpan="7"
                      className="events-empty"
                    >
                      No Windows events found.
                    </td>
                  </tr>
                ) : (
                  events.map((item) => (
                    <tr key={item.id}>

                      <td>
                        #{item.id}
                      </td>

                      <td>
                        {item.record_id}
                      </td>

                      <td>
                        <span className="event-id-badge">
                          {item.event_id}
                        </span>
                      </td>

                      <td>
                        {item.computer ||
                          "Unknown"}
                      </td>

                      <td>
                        {item.provider ||
                          "Unknown"}
                      </td>

                      <td>
                        {item.received_at
                          ? new Date(
                              item.received_at
                            ).toLocaleString()
                          : "Unknown"}
                      </td>

                      <td>
                        <button
                          type="button"
                          className="view-event-button"
                          onClick={() =>
                            navigate(
                              `/events/${item.id}`
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


        <div className="events-pagination">

          <button
            type="button"
            className="secondary-button"
            disabled={
              page <= 1 || loading
            }
            onClick={
              goToPreviousPage
            }
          >
            Previous
          </button>


          <span>
            Page {page} of{" "}
            {totalPages || 1}
          </span>


          <button
            type="button"
            className="secondary-button"
            disabled={
              page >= totalPages ||
              totalPages === 0 ||
              loading
            }
            onClick={
              goToNextPage
            }
          >
            Next
          </button>

        </div>

      </section>

    </div>
  );
}


export default Events;