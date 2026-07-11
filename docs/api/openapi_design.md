User APIs
GET /api/v1/users

GET /api/v1/users/{id}

POST /api/v1/users

PUT /api/v1/users/{id}

DELETE /api/v1/users/{id}


Events APIs
GET /api/v1/events

GET /api/v1/events/login

GET /api/v1/events/file

GET /api/v1/events/usb

GET /api/v1/events/email


Behavior Twin APIs
GET /api/v1/behavior-twins

GET /api/v1/behavior-twins/{user_id}

POST /api/v1/behavior-twins/rebuild


UEBA APIs
GET /api/v1/risk-scores

GET /api/v1/risk-scores/{user_id}


Incident APIs
GET /api/v1/incidents

GET /api/v1/incidents/{id}

POST /api/v1/incidents


Evidence APIs
GET /api/v1/evidences

GET /api/v1/evidences/{id}


Blockchain APIs
GET /api/v1/blockchain/verify/{incident_id}

GET /api/v1/blockchain/blocks


AI Investigator APIs
POST /api/v1/investigator/analyze/{incident_id}

GET /api/v1/investigator/report/{incident_id}