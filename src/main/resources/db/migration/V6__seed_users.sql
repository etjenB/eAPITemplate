INSERT INTO users (username, email, password) VALUES
  ('user', 'user@gmail.com', '$2a$12$QNb7pjImmoX40d6quaYOKuA1LpYqIBTnLmVDMS4tUKD5/peiNY7d2')
ON CONFLICT (username) DO NOTHING;

INSERT INTO users_roles (user_id, role_id) VALUES
  (1, 1);
