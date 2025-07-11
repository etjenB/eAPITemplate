INSERT INTO users (username, email, password) VALUES
  ('mainuser', 'mainuser@gmail.com', '{bcrypt}$2a$10$mAuDLFCHlz5wycTtMhUnPOFeg2VwFvgH6dDjLkwlY9TNSsnOfv8Qy') --pass: Corners8829%
ON CONFLICT (username) DO NOTHING;

INSERT INTO users_roles (user_id, role_id) VALUES
  (1, 1);
