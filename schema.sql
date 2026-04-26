CREATE TABLE vulnerability (
    id TEXT PRIMARY KEY,
    vendor_release_date DATE,
    vendor_release_url TEXT,
    url TEXT,
    published_date TIMESTAMP,
    updated_date TIMESTAMP,
    description TEXT
);

CREATE TABLE cvss (
    id SERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES vulnerability(id) ON DELETE CASCADE,
    version TEXT,
    score FLOAT,
    vector TEXT,
    severity TEXT
);

CREATE TABLE cpe (
    id SERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES vulnerability(id) ON DELETE CASCADE,
    cpe_string TEXT
);

CREATE TABLE cwe (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT
);

CREATE TABLE vulnerability_cwe (
    cve_id TEXT REFERENCES vulnerability(id) ON DELETE CASCADE,
    cwe_id TEXT REFERENCES cwe(id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, cwe_id)
);