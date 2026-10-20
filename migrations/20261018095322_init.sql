-- MariaDB has no gen_random_uuid(): the app generates every UUID and stores it as BINARY(16).

CREATE TABLE users (
  id            BINARY(16) PRIMARY KEY,
  email         VARCHAR(255) NOT NULL UNIQUE,  -- store lowercased
  password_hash VARCHAR(255) NOT NULL,
  full_name     VARCHAR(100) NOT NULL,
  role          ENUM('admin', 'manager', 'member') NOT NULL DEFAULT 'member',
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  -- shortcut: TIMESTAMP stops at 2038, switch to DATETIME(6) before then
  created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;

CREATE TABLE projects (
  id          BINARY(16) PRIMARY KEY,
  name        VARCHAR(255) NOT NULL,
  description TEXT,
  owner_id    BINARY(16) NOT NULL,
  created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  FOREIGN KEY (owner_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE project_members (
  project_id BINARY(16) NOT NULL,
  user_id    BINARY(16) NOT NULL,
  PRIMARY KEY (project_id, user_id),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE tasks (
  id          BINARY(16) PRIMARY KEY,
  project_id  BINARY(16) NOT NULL,
  title       VARCHAR(255) NOT NULL,
  description TEXT,
  status      ENUM('todo', 'in_progress', 'done') NOT NULL DEFAULT 'todo',
  assignee_id BINARY(16),
  created_by  BINARY(16) NOT NULL,
  created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id),
  INDEX (project_id),
  INDEX (assignee_id)
) ENGINE=InnoDB;

-- The token hash is the primary key, so no separate id is needed.
CREATE TABLE refresh_tokens (
  token_hash  CHAR(43) PRIMARY KEY,  -- SHA-256 in URL-safe base64, always 43 chars
  user_id     BINARY(16) NOT NULL,
  expires_at  TIMESTAMP(6) NOT NULL,
  revoked_at  TIMESTAMP(6) NULL,
  created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX (user_id)
) ENGINE=InnoDB;
