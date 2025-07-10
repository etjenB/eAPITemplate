-- because we already have users we will set status to active and email is verified for each existing user
ALTER TABLE users
    ADD COLUMN status          VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN email_verified  BOOLEAN     NOT NULL DEFAULT TRUE;

UPDATE users
   SET status = 'ACTIVE',
       email_verified = TRUE
 WHERE status = 'ACTIVE';

-- we drop the column defaults because when new user needs to be added it needs to have status and email_verified set and not relly on default values
ALTER TABLE users
    ALTER COLUMN status DROP DEFAULT,
    ALTER COLUMN email_verified DROP DEFAULT;