-- ============================================================================
-- LEXVAULT: FORENSIC EVIDENCE CUSTODY & ANTI-TAMPER ARCHIVAL SYSTEM
-- Database Schema (Compatible with PostgreSQL / Supabase & SQLite3)
-- Standard Compliance: ISO/IEC 27037 Digital Chain of Custody
-- ============================================================================

-- 1. Authorized Hardware Security Dongles & 3-Pose Neural Biometric Credentials
CREATE TABLE IF NOT EXISTS authorized_dongles (
    serial_number VARCHAR(128) PRIMARY KEY,
    operator_name VARCHAR(128) NOT NULL,
    badge_id VARCHAR(64) NOT NULL,
    token_signature VARCHAR(128) NOT NULL,
    password_salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    face_profile_hash TEXT,
    face_embedding_front TEXT,
    face_embedding_left TEXT,
    face_embedding_right TEXT,
    biometric_model VARCHAR(64) DEFAULT 'YuNet+SFace-128D-3Pose',
    biometric_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- MIGRATION SCRIPT UNTUK SUPABASE SQL EDITOR (Jika tabel sudah dibuat sebelumnya):
-- Copy & Run perintah di bawah ini pada menu SQL Editor di Dashboard Supabase:
--
-- ALTER TABLE authorized_dongles ALTER COLUMN face_profile_hash TYPE TEXT;
-- ALTER TABLE authorized_dongles ADD COLUMN IF NOT EXISTS face_embedding_front TEXT;
-- ALTER TABLE authorized_dongles ADD COLUMN IF NOT EXISTS face_embedding_left TEXT;
-- ALTER TABLE authorized_dongles ADD COLUMN IF NOT EXISTS face_embedding_right TEXT;
-- ALTER TABLE authorized_dongles ADD COLUMN IF NOT EXISTS biometric_model VARCHAR(64) DEFAULT 'YuNet+SFace-128D-3Pose';
-- ALTER TABLE authorized_dongles ADD COLUMN IF NOT EXISTS biometric_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
-- ============================================================================

-- 2. Forensic Evidence Custody Records
-- Stores ONLY cryptographic metadata, hashes, IV/Nonce, and ciphertext/paths
-- Plaintext and raw keys are NEVER stored in the database.
CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id VARCHAR(64) PRIMARY KEY,
    evidence_type VARCHAR(32) NOT NULL, -- 'TEXT_SUPER_CRYPTO', 'FILE_CHACHA20', 'STEGO_LSB_PNG'
    ciphertext_or_asset_path TEXT NOT NULL,
    iv_nonce VARCHAR(128) NOT NULL,
    data_hash VARCHAR(64) NOT NULL,     -- SHA-256 of sealed payload
    layer1_block_hash VARCHAR(64) NOT NULL,
    layer2_tx_hash VARCHAR(128),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Layer 1 Local Proof-of-Work Blockchain Audit Ledger
CREATE TABLE IF NOT EXISTS audit_blocks (
    block_index INTEGER PRIMARY KEY,
    timestamp VARCHAR(64) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    evidence_hash VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    nonce INTEGER NOT NULL,
    block_hash VARCHAR(64) NOT NULL,
    layer2_tx_hash VARCHAR(128),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_evidence_records_hash ON evidence_records(data_hash);
CREATE INDEX IF NOT EXISTS idx_audit_blocks_evidence_id ON audit_blocks(evidence_id);

