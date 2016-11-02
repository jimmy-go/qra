/*
    PostgreSQL default migration for QRA manager.
*/
DROP TABLE session;
DROP TABLE trail;
DROP TABLE designation;
DROP TABLE identity;
DROP TYPE IF EXISTS perm;
DROP FUNCTION update_modified_column();
DROP EXTENSION IF EXISTS "uuid-ossp";
