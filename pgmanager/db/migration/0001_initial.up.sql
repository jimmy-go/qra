-- contains identity, session, designation, trail
/*
    PostgreSQL default migration for QRA manager.
*/

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS trigger AS
$BODY$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$BODY$
LANGUAGE plpgsql VOLATILE
COST 100;
ALTER FUNCTION update_modified_column()
OWNER TO postgres;

CREATE TABLE identity (
    id uuid NOT NULL DEFAULT uuid_generate_v1mc(),
    name text,
    password bytea,
    private_key bytea,
    public_key bytea,
    created_at timestamp DEFAULT now(),
    updated_at timestamp DEFAULT now(),
    CONSTRAINT identity_pkey PRIMARY KEY (id)
)
WITH (
    OIDS=FALSE
);

CREATE UNIQUE INDEX identity_name_idx ON identity (name);

CREATE TRIGGER update_identity_updated_at
BEFORE UPDATE
ON identity
FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TABLE session (
    id uuid NOT NULL DEFAULT uuid_generate_v1mc(),
    identity_id uuid REFERENCES identity (id) ON DELETE RESTRICT,
    token text,
    active bool,
    expires_at timestamp,
    created_at timestamp DEFAULT now(),
    CONSTRAINT session_pkey PRIMARY KEY (id)
)
WITH (
    OIDS=FALSE
);

DROP TYPE IF EXISTS PERM;

-- permission catalog.
-- TODO; add more common permissions
CREATE TYPE PERM AS ENUM(
'session-on','identity-create','identity-edit','identity-delete','read','write',
'delete'
);

CREATE TABLE designation (
    id uuid NOT NULL DEFAULT uuid_generate_v1mc(),
    issuer_id uuid REFERENCES identity (id) ON DELETE RESTRICT,
    issuer_signature bytea,
    identity text,
    permission PERM,
    resource text,
    expires_at timestamp,
    created_at timestamp DEFAULT now(),
    CONSTRAINT designation_pkey PRIMARY KEY (id)
)
WITH (
    OIDS=FALSE
);

CREATE INDEX designation_issuer_signature_idx ON designation (issuer_signature);
CREATE INDEX designation_permission_idx ON designation (permission);
CREATE INDEX designation_resource_idx ON designation (resource);

CREATE TABLE trail (
    id uuid NOT NULL DEFAULT uuid_generate_v1mc(),
    designation_id uuid REFERENCES designation (id) ON DELETE RESTRICT,
    created_at timestamp DEFAULT now(),
    CONSTRAINT trail_pkey PRIMARY KEY (id)
)
WITH (
    OIDS=FALSE
);
