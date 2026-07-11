        Windows Agent
                   Linux Agent
                     Sysmon
                  File Monitor
                    USB Monitor
                     Email Logs
                         │
                         │
                Event Collector API
                         │
                         ▼
                PostgreSQL (Raw Events)
                         │
      ┌──────────────────┼──────────────────┐
      ▼                  ▼                  ▼
 Behavior Twin      UEBA Engine       Event Correlation
      │                  │                  │
      └──────────────┬───┘                  │
                     ▼                      │
               Risk Assessment             │
                     │                      │
                     ▼                      │
                 Incident Engine────────────┘
                     │
                     ▼
               Evidence Vault
                     │
                     ▼
               SHA256 Generator
                     │
                     ▼
            Blockchain Audit Chain
                     │
                     ▼
             AI Investigation Report
                     │
                     ▼
                SOC Dashboard