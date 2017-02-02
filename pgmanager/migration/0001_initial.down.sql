/*
    PostgreSQL default migration for QRA manager.
*/
DROP TABLE IF EXISTS qra_session;
DROP TABLE IF EXISTS qra_trail;
DROP TABLE IF EXISTS qra_designation;
DROP TABLE IF EXISTS qra_identity;
DROP TYPE IF EXISTS perm;
DROP TYPE IF EXISTS status;
--DROP FUNCTION update_modified_column();
--DROP EXTENSION IF EXISTS "uuid-ossp";
