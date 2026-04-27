```mermaid
flowchart LR
    A[Attacker] --> B[Cowrie Honeypot (VPS)]
    B --> C[Elastic Agent]
    C --> D[Elasticsearch]

    D --> E[Detection Rules]
    E --> F[Alerts (Elastic Security)]

    F --> G[Analyst Investigation (Kibana Discover)]

    subgraph Detection Types
        E1[Threshold Rules<br>Brute Force]
        E2[Correlation Rules<br>Brute Force → Success]
        E3[Custom Query<br>Suspicious Commands]
        E4[Behavioral Detection<br>Interactive Sessions]
    end

    E --> E1
    E --> E2
    E --> E3
    E --> E4

    G --> H[Pivot on source.ip]
    H --> I[Reconstruct Attack Timeline]
