-- OPERATOR REVIEW ONLY. Do not run on product DB or on an existing lab.
-- Connect as synthetic DB administrator via the exact Neon lab branch.
-- Deliberately no DROP, reset, ON CONFLICT or runtime DDL.
BEGIN;
DO $$ BEGIN
 IF current_database() <> 'iamina925_empty' OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
 THEN RAISE EXCEPTION 'wrong database'; END IF;
 IF current_user = 'd1_safari_runtime' THEN RAISE EXCEPTION 'runtime role cannot initialize'; END IF;
END $$;
CREATE TABLE d1_physical_lab_session_candidate (
 owner bigint PRIMARY KEY CHECK(owner=900001),
 context text NOT NULL, pending text, session text,
 sign_count bigint NOT NULL DEFAULT 0 CHECK(sign_count BETWEEN 0 AND 4294967295)
);
CREATE TABLE d1_prf_authority_candidate (
 owner bigint PRIMARY KEY CHECK(owner=900001),
 state text NOT NULL CHECK(state IN ('fresh','unknown','reserved','redeemed')),
 binding text NOT NULL, ticket text, signature bytea,
 CHECK ((state IN ('reserved','redeemed') AND ticket IS NOT NULL AND signature IS NOT NULL AND octet_length(signature)=64)
 OR (state NOT IN ('reserved','redeemed') AND ticket IS NULL AND signature IS NULL))
);
INSERT INTO d1_physical_lab_session_candidate(owner,context) VALUES(900001,'');
INSERT INTO d1_prf_authority_candidate(owner,state,binding) VALUES(900001,'unknown','');
REVOKE ALL ON d1_physical_lab_session_candidate,d1_prf_authority_candidate FROM PUBLIC;
GRANT SELECT ON d1_physical_lab_session_candidate,d1_prf_authority_candidate TO d1_safari_runtime;
GRANT UPDATE(context,pending,session,sign_count) ON d1_physical_lab_session_candidate TO d1_safari_runtime;
GRANT UPDATE(state,binding,ticket,signature) ON d1_prf_authority_candidate TO d1_safari_runtime;
COMMIT;
