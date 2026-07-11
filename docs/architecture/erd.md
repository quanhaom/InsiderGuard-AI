erDiagram
    USERS {
        UUID id PK
        VARCHAR username
        VARCHAR department
        VARCHAR role
    }

    LOGIN_EVENTS {
        UUID id PK
        UUID user_id FK
        TIMESTAMP login_time
        VARCHAR source_ip
    }

    FILE_EVENTS {
        UUID id PK
        UUID user_id FK
        TEXT filename
        VARCHAR action
        TIMESTAMP timestamp
    }

    USB_EVENTS {
        UUID id PK
        UUID user_id FK
        VARCHAR device_id
        VARCHAR action
        TIMESTAMP timestamp
    }

    EMAIL_EVENTS {
        UUID id PK
        VARCHAR sender "Matches users.username or email"
        VARCHAR receiver
        TEXT attachment
    }

    BEHAVIOR_PROFILES {
        UUID id PK
        UUID user_id FK
        VARCHAR risk_score
        TIMESTAMP last_updated
    }

    INCIDENTS {
        UUID id PK
        UUID user_id FK
        VARCHAR title
        VARCHAR severity
        TIMESTAMP detected_at
    }

    EVIDENCES {
        UUID id PK
        UUID incident_id FK
        VARCHAR event_type "e.g., File, USB, Email"
        UUID event_id "Generic FK to specific event"
        TEXT file_hash
    }

    BLOCKCHAIN_BLOCKS {
        UUID id PK
        UUID evidence_id FK
        VARCHAR block_hash
        VARCHAR previous_hash
        TIMESTAMP timestamp
    }

    USERS ||--o{ LOGIN_EVENTS : "generates"
    USERS ||--o{ FILE_EVENTS : "performs"
    USERS ||--o{ USB_EVENTS : "triggers"
    USERS ||--o{ EMAIL_EVENTS : "sends (via sender)"
    USERS ||--oX BEHAVIOR_PROFILES : "has"
    USERS ||--o{ INCIDENTS : "involved_in"

    INCIDENTS ||--o{ EVIDENCES : "contains"
    EVIDENCES ||--oX BLOCKCHAIN_BLOCKS : "secured_by"