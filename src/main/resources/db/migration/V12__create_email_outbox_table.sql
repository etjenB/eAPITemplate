CREATE TABLE email_outbox (
    id           BIGSERIAL PRIMARY KEY,
    aggregate_id BIGINT      NOT NULL,      -- user.id
    to_address   VARCHAR(320) NOT NULL,
    subject      TEXT         NOT NULL,
    body         TEXT         NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    sent         BOOLEAN      NOT NULL DEFAULT FALSE,
    sent_at      TIMESTAMPTZ
);

CREATE INDEX idx_email_outbox_unsent ON email_outbox(sent) WHERE sent = FALSE;