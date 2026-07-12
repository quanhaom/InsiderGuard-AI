                  Windows Endpoint
                         │
                Windows Event Log
                         │
                         ▼
                Windows Collector
                         │
                 Offline Queue
                         │
                         ▼
────────────────────────────────────────────────────

                    FastAPI Backend

        Collector API (/collector/events)
                         │
                         ▼
                Raw Event Storage
                         │
                         ▼
                 Parser Engine
                         │
                         ▼
              Normalized Event Model
                         │
                         ▼
                  Rule Engine
                         │
             ┌───────────┴────────────┐
             ▼                        ▼
       Risk Hint              Detection Alert
             │
             ▼
              Event Dispatcher
                         │
     ┌───────────┬───────────┬───────────┐
     ▼           ▼           ▼
 Login      Process      File Access
 Service      Service        Service
     │
     ▼
 Behavior Twin
     │
     ▼
 UEBA Engine
     │
     ▼
 Incident Engine
     │
     ▼
 Evidence Engine
     │
     ▼
 Blockchain Integrity
     │
     ▼
 AI Investigation