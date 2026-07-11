               Windows
                   │
                Linux
                   │
                Sysmon
                   │
              Azure AD
                   │
            Microsoft 365
                   │
            ┌──────────────┐
            │ Collector API│
            └──────┬───────┘
                   │
             Event Dispatcher
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
     Behavior Twin        UEBA Engine
         │                   │
         └─────────┬─────────┘
                   ▼
              Risk Engine
                   │
                   ▼
          Incident Management
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
      Evidence          Blockchain
                   │
                   ▼
            AI Investigator