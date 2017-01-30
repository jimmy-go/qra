-- contains identity, session, designation, trail
/*
    QRA Manager PostgreSQL database.
    see: https://github.com/jimmy-go/qra
*/

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TYPE IF EXISTS STATUS;
CREATE TYPE STATUS AS ENUM('active','inactive');

DROP TYPE IF EXISTS PERM;
CREATE TYPE PERM AS ENUM(
'session-on','identity-create','identity-edit','identity-delete','read','write',
'delete'
);


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
    created_at timestamp without time zone DEFAULT (now() at time zone 'utc'),
    updated_at timestamp without time zone DEFAULT (now() at time zone 'utc'),
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
    status STATUS DEFAULT 'inactive',
    expires_at timestamp without time zone DEFAULT (now() at time zone 'utc'),
    created_at timestamp without time zone DEFAULT (now() at time zone 'utc'),
    CONSTRAINT session_pkey PRIMARY KEY (id)
)
WITH (
    OIDS=FALSE
);

CREATE TABLE designation (
    id uuid NOT NULL DEFAULT uuid_generate_v1mc(),
    issuer_id uuid REFERENCES identity (id) ON DELETE RESTRICT,
    issuer_signature bytea,
    identity_id uuid REFERENCES identity (id) ON DELETE RESTRICT,
    permission PERM,
    resource text,
    expires_at timestamp without time zone DEFAULT (now() at time zone 'utc'),
    created_at timestamp without time zone DEFAULT (now() at time zone 'utc'),
    CONSTRAINT designation_pkey PRIMARY KEY (id)
)
WITH (
    OIDS=FALSE
);

-- TODO; make fast index for query at the same time issuer_id,issuer_signature,
-- identity_id, permission and resource
CREATE INDEX designation_issuer_signature_idx ON designation (issuer_signature);
--CREATE INDEX designation_permission_idx ON designation (permission);
--CREATE INDEX designation_resource_idx ON designation (resource);

CREATE TABLE trail (
    id uuid NOT NULL DEFAULT uuid_generate_v1mc(),
    designation_id uuid REFERENCES designation (id) ON DELETE RESTRICT,
    created_at timestamp without time zone DEFAULT (now() at time zone 'utc'),
    CONSTRAINT trail_pkey PRIMARY KEY (id)
)
WITH (
    OIDS=FALSE
);
