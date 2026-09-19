-- Existing grants were derived from installation-wide access and are not proof
-- of a user's repository permissions. Users must sync once after this migration.
-- Repository activation, analysis history and settings are intentionally retained.
DELETE FROM repository_access;

CREATE OR REPLACE FUNCTION revoke_installation_membership_access()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM repository_access ra USING repositories r
  WHERE ra.repository_id = r.id
    AND ra.user_id = OLD.user_id
    AND r.installation_id = OLD.installation_id;
  RETURN OLD;
END;
$$;
CREATE TRIGGER revoke_installation_membership_access
AFTER DELETE ON user_installations
FOR EACH ROW EXECUTE FUNCTION revoke_installation_membership_access();

CREATE OR REPLACE FUNCTION revoke_inactive_installation_access()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status <> 'active' THEN
    DELETE FROM repository_access ra USING repositories r
    WHERE ra.repository_id = r.id AND r.installation_id = NEW.id;
    DELETE FROM user_installations WHERE installation_id = NEW.id;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER revoke_inactive_installation_access
AFTER UPDATE OF status ON installations
FOR EACH ROW EXECUTE FUNCTION revoke_inactive_installation_access();
