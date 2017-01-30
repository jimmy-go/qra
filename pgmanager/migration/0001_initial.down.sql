/*
    PostgreSQL default migration for QRA manager.
*/
DROP TABLE IF EXISTS session;
DROP TABLE IF EXISTS trail;
DROP TABLE IF EXISTS designation;
DROP TABLE IF EXISTS identity;
DROP TYPE IF EXISTS perm;
DROP TYPE IF EXISTS status;
--DROP FUNCTION update_modified_column();
--DROP EXTENSION IF EXISTS "uuid-ossp";
