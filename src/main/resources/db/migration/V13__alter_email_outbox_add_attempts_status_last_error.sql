ALTER TABLE email_outbox
    ADD COLUMN attempts       INT    NOT NULL DEFAULT 0,
    ADD COLUMN last_error     TEXT,
    ADD COLUMN status         VARCHAR(20) NOT NULL DEFAULT 'PENDING';

UPDATE email_outbox
   SET status = CASE
      WHEN sent THEN 'SENT'
      ELSE 'PENDING'
    END;

ALTER TABLE email_outbox
    DROP COLUMN sent;

DROP INDEX IF EXISTS idx_email_outbox_unsent;