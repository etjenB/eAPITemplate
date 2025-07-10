CREATE TABLE email_verification_tokens (
    id          BIGSERIAL PRIMARY KEY,
    token       VARCHAR(64)  NOT NULL UNIQUE, -- UUIDv4 (36) + slack
    expires_at  TIMESTAMPTZ  NOT NULL,
    used        BOOLEAN      NOT NULL DEFAULT FALSE,
    user_id     BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE
);