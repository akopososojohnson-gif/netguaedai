-- NetGuard AI Database Initialization

CREATE TABLE IF NOT EXISTS connections (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    id BIGSERIAL PRIMARY KEY,
    src_ip INET,
    src_port INTEGER,
    dst_ip INET,
    dst_port INTEGER,
    domain TEXT DEFAULT '-',
    protocol TEXT,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    duration DOUBLE PRECISION,
    threat_score DOUBLE PRECISION DEFAULT 0.0,
    threat_type TEXT DEFAULT 'normal',
    threat_level TEXT DEFAULT 'LOW',
    src_country TEXT DEFAULT 'Unknown',
    src_city TEXT DEFAULT 'Unknown',
    dst_country TEXT DEFAULT 'Unknown',
    raw_packet JSONB
);

CREATE INDEX idx_connections_time ON connections (time DESC);
CREATE INDEX idx_connections_threat ON connections (threat_score) WHERE threat_score > 0.5;
CREATE INDEX idx_connections_threat_level ON connections (threat_level);
CREATE INDEX idx_connections_src_ip ON connections (src_ip);
CREATE INDEX idx_connections_dst_ip ON connections (dst_ip);
CREATE INDEX idx_connections_src_country ON connections (src_country);

CREATE TABLE IF NOT EXISTS alerts (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    id BIGSERIAL PRIMARY KEY,
    alert_type TEXT,
    severity TEXT,
    threat_level TEXT DEFAULT 'LOW',
    message TEXT,
    src_ip INET,
    dst_ip INET,
    acknowledged BOOLEAN DEFAULT FALSE
);

-- Migration: add GeoIP and threat_level columns if upgrading from older version
ALTER TABLE connections ADD COLUMN IF NOT EXISTS threat_level TEXT DEFAULT 'LOW';
ALTER TABLE connections ADD COLUMN IF NOT EXISTS src_country TEXT DEFAULT 'Unknown';
ALTER TABLE connections ADD COLUMN IF NOT EXISTS src_city TEXT DEFAULT 'Unknown';
ALTER TABLE connections ADD COLUMN IF NOT EXISTS dst_country TEXT DEFAULT 'Unknown';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_level TEXT DEFAULT 'LOW';

CREATE INDEX IF NOT EXISTS idx_connections_threat_level ON connections (threat_level);
CREATE INDEX IF NOT EXISTS idx_connections_src_country ON connections (src_country);

CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS $$
BEGIN
    DELETE FROM connections WHERE time < NOW() - INTERVAL '30 days';
    DELETE FROM alerts WHERE time < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;
