CREATE TABLE installer_fetches (
    day TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('unix', 'windows')),
    fetches INTEGER NOT NULL CHECK (fetches > 0),
    PRIMARY KEY (day, platform)
) WITHOUT ROWID;

CREATE TABLE metric_snapshots (
    measured_at TEXT NOT NULL,
    source TEXT NOT NULL,
    metric TEXT NOT NULL,
    value INTEGER NOT NULL CHECK (value >= 0),
    window_start TEXT,
    window_end TEXT,
    PRIMARY KEY (measured_at, source, metric)
) WITHOUT ROWID;

-- These measurements have different meanings and must not be added together.
INSERT INTO metric_snapshots
    (measured_at, source, metric, value, window_start, window_end)
VALUES
    ('2026-09-09T19:30:32Z', 'cloudflare', 'retained_installer_endpoint_requests', 15,
     '2026-09-01T20:30:32Z', '2026-09-09T19:30:32Z'),
    ('2026-09-09T21:24:41Z', 'github', 'release_archive_downloads', 134, NULL, NULL),
    ('2026-09-09T21:24:41Z', 'github', 'checksum_file_downloads', 55, NULL, NULL);
