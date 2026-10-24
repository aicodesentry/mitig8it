-- A repository can move to another installation: the App is uninstalled and installed
-- again (GitHub issues a new installation id), or the repository is transferred to an
-- account that has the App. The pull_request and installation_repositories webhooks
-- move it by rewriting repositories.installation_id.
--
-- finding_outcomes ties each row to its repository's tenant with a composite foreign
-- key on (repository_id, installation_id). With the default NO ACTION, that rewrite
-- failed with 23503 once the repository had a single outcome row, every delivery for
-- the repository returned 500, and the repository was never analysed again.
--
-- ON UPDATE CASCADE carries the outcome rows to the new installation with their
-- repository. The rows describe that repository's findings, so they belong to whoever
-- holds the repository now; leaving them on the old tenant would orphan them from the
-- repository they describe and from the new tenant's quality numbers. Deletes keep NO
-- ACTION: the purge removes outcome rows explicitly before their repository.
ALTER TABLE finding_outcomes DROP CONSTRAINT finding_outcomes_tenant_repo_fkey;
ALTER TABLE finding_outcomes ADD CONSTRAINT finding_outcomes_tenant_repo_fkey
  FOREIGN KEY (repository_id, installation_id) REFERENCES repositories (id, installation_id)
  ON UPDATE CASCADE;
