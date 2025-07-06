CREATE TABLE refresh_tokens (
    id          BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    token_id    VARCHAR(36)  NOT NULL,
    expires_at  TIMESTAMP NOT NULL,
    revoked     BOOLEAN   NOT NULL DEFAULT FALSE,
    issued_at   TIMESTAMP NOT NULL,
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    user_id     BIGINT    NOT NULL,
    CONSTRAINT uq_rt_token_id UNIQUE (token_id)
);

ALTER TABLE refresh_tokens
    ADD CONSTRAINT fk_rt_user
    FOREIGN KEY (user_id) REFERENCES users(id);

CREATE UNIQUE INDEX idx_rt_token_id ON refresh_tokens (token_id);
CREATE INDEX idx_rt_user_id  ON refresh_tokens (user_id);