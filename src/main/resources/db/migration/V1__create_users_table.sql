CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  email    VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  account_non_expired    BOOLEAN NOT NULL DEFAULT TRUE,
  account_non_locked     BOOLEAN NOT NULL DEFAULT TRUE,
  credentials_non_expired BOOLEAN NOT NULL DEFAULT TRUE,
  enabled                BOOLEAN NOT NULL DEFAULT TRUE
);
