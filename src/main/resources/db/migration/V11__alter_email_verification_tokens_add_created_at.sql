ALTER TABLE email_verification_tokens
    ADD COLUMN issued_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX idx_evt_user_issued
    ON email_verification_tokens (user_id, issued_at);