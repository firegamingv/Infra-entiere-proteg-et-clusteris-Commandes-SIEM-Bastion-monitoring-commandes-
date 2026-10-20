-- =============================================================================
-- OSTRAL — lot D — comptes, connexions et autorisations du bastion Guacamole
-- Chargé par services/guacamole/initdb/010-ostral-guacamole.sh APRÈS le schéma officiel.
--
-- Variables psql attendues (-v) :
--   admin1_password, admin2_password, agence_web_password  mots de passe INITIAUX (à changer dans les préférences
--                                                          après le 1er login ; voir ostral_creer_utilisateur)
--   agence_web_valid_until    date de fin du compte prestataire (AAAA-MM-JJ, E07)
--   agence_web_access_start   début de la fenêtre horaire (HH:MM)
--   agence_web_access_end     fin de la fenêtre horaire (HH:MM)
--   fuseau                    fuseau horaire des fenêtres (ex. Europe/Paris)
--   ssh_private_key           clé privée du bastion vers admin-target
--   ssh_host_key              entrée known_hosts épinglée d'admin-target
--
-- Traçabilité :
--   E06  administration uniquement par le bastion, MFA (TOTP, enrôlement imposé au 1er login),
--        sessions enregistrées (recording-path / typescript-path -> volume guac_recordings)
--   E07  comptes prestataires nominatifs ET limités dans le temps (valid_until + fenêtre horaire)
--   F10  bastion -> serveurs en TCP 22 (connexion SSH vers admin-target 10.10.3.30)
--   SS5  abus de droits : moindre privilège, comptes nominatifs, plus de compte guacadmin partagé
--   R3   vol d'un compte administrateur : MFA obligatoire, mots de passe à durée de vie limitée (90 j), alertes SIEM
-- =============================================================================
\set ON_ERROR_STOP on

BEGIN;

-- Hachage Guacamole : SHA-256( mot_de_passe || HEX_MAJUSCULE(sel) )
CREATE FUNCTION pg_temp.ostral_hash(p_mdp text, p_sel bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE AS $$
  SELECT sha256(convert_to(p_mdp || upper(encode(p_sel, 'hex')), 'UTF8'))
$$;

CREATE FUNCTION pg_temp.ostral_sel() RETURNS bytea
LANGUAGE sql VOLATILE AS $$
  SELECT sha256(convert_to(gen_random_uuid()::text || clock_timestamp()::text || random()::text, 'UTF8'))
$$;

CREATE FUNCTION pg_temp.ostral_erreur(p_message text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '%', p_message;
END
$$;

-- Crée un utilisateur nominatif avec mot de passe initial EXPIRÉ (changement au 1er login).
CREATE FUNCTION pg_temp.ostral_creer_utilisateur(
  p_nom text, p_mdp text, p_nom_complet text, p_organisation text, p_role text, p_fuseau text)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_entity integer;
  v_user   integer;
  v_sel    bytea := pg_temp.ostral_sel();
BEGIN
  IF p_mdp IS NULL OR length(p_mdp) < 12 THEN
    RAISE EXCEPTION 'Mot de passe initial de % trop court (12 caractères minimum)', p_nom;
  END IF;

  INSERT INTO guacamole_entity (name, type)
  VALUES (p_nom, 'USER')
  RETURNING entity_id INTO v_entity;

  INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date,
                              disabled, expired, timezone,
                              full_name, organization, organizational_role)
  -- expired = false : Guacamole 1.6 renvoie l'ANCIEN mot de passe à l'étape TOTP quand un
  -- changement imposé et un enrôlement TOTP ont lieu dans la même connexion (refus « Invalid
  -- login »). Le mot de passe initial est donc changé dans Paramètres > Préférences après le
  -- 1er login ; la durée de vie maximale (90 j) impose ensuite les renouvellements.
  VALUES (v_entity, pg_temp.ostral_hash(p_mdp, v_sel), v_sel, now(),
          false, false, p_fuseau,
          p_nom_complet, p_organisation, p_role)
  RETURNING user_id INTO v_user;

  -- Lecture de son propre profil (nécessaire à l'interface ; pas de droit UPDATE).
  INSERT INTO guacamole_user_permission (entity_id, affected_user_id, permission)
  VALUES (v_entity, v_user, 'READ');

  RETURN v_entity;
END
$$;

-- -----------------------------------------------------------------------------
-- 0. Contrôles des paramètres du compte prestataire (E07)
-- -----------------------------------------------------------------------------
SELECT pg_temp.ostral_erreur('AGENCE_WEB_VALID_UNTIL doit être une date future')
WHERE :'agence_web_valid_until'::date <= current_date;

SELECT pg_temp.ostral_erreur('AGENCE_WEB_VALID_UNTIL : 90 jours maximum (accès prestataire temporaire, E07)')
WHERE :'agence_web_valid_until'::date > current_date + 90;

SELECT pg_temp.ostral_erreur('Fenêtre horaire prestataire invalide (début >= fin)')
WHERE :'agence_web_access_start'::time >= :'agence_web_access_end'::time;

-- -----------------------------------------------------------------------------
-- 1. Neutralisation du compte par défaut guacadmin (SS5 : pas de compte partagé)
--    Désactivé, mot de passe remplacé par un aléa inconnu, droits retirés.
-- -----------------------------------------------------------------------------
UPDATE guacamole_user u
SET disabled      = true,
    password_salt = s.sel,
    password_hash = pg_temp.ostral_hash(gen_random_uuid()::text || random()::text, s.sel),
    password_date = now()
FROM (SELECT pg_temp.ostral_sel() AS sel) s
WHERE u.entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin' AND type = 'USER');

DELETE FROM guacamole_system_permission
WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin' AND type = 'USER');

DELETE FROM guacamole_user_permission
WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin' AND type = 'USER');

-- -----------------------------------------------------------------------------
-- 2. Comptes nominatifs (E06, E07)
-- -----------------------------------------------------------------------------
SELECT pg_temp.ostral_creer_utilisateur('admin1', :'admin1_password',
       'Administrateur 1', 'OSTRAL - DSI', 'Administrateur du bastion et des serveurs', :'fuseau');

SELECT pg_temp.ostral_creer_utilisateur('admin2', :'admin2_password',
       'Administrateur 2', 'OSTRAL - DSI', 'Administrateur des serveurs', :'fuseau');

SELECT pg_temp.ostral_creer_utilisateur('agence-web', :'agence_web_password',
       'Prestataire agence web', 'Agence web (prestataire externe)', 'Prestataire - accès temporaire', :'fuseau');

-- Compte prestataire : validité limitée + fenêtre horaire (E07, SS3, SS5).
UPDATE guacamole_user
SET valid_from          = current_date,
    valid_until         = :'agence_web_valid_until'::date,
    access_window_start = :'agence_web_access_start'::time,
    access_window_end   = :'agence_web_access_end'::time,
    timezone            = :'fuseau'
WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = 'agence-web' AND type = 'USER');

-- admin1 administre le bastion (création de comptes prestataires, révocation, audit).
-- admin2 et agence-web n'ont AUCUN droit système (moindre privilège, SS5).
INSERT INTO guacamole_system_permission (entity_id, permission)
SELECT entity_id, 'ADMINISTER'::guacamole_system_permission_type
FROM guacamole_entity WHERE name = 'admin1' AND type = 'USER';

-- -----------------------------------------------------------------------------
-- 3. Connexion SSH vers admin-target (Z3, 10.10.3.30:22) — F10, sessions enregistrées (E06)
--    guacd (10.10.3.11 sur z3_servers) est la seule source SSH acceptée par admin-target.
-- -----------------------------------------------------------------------------
INSERT INTO guacamole_connection (connection_name, protocol, max_connections, max_connections_per_user)
VALUES ('admin-target (Z3) - SSH', 'ssh', 4, 1)
RETURNING connection_id AS conn_id
\gset

INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES
  (:conn_id, 'hostname',               '10.10.3.30'),
  (:conn_id, 'port',                   '22'),
  (:conn_id, 'username',               'ostral-admin'),
  (:conn_id, 'private-key',            :'ssh_private_key'),
  -- Clé d'hôte épinglée : refus si l'identité du serveur change (anti-MITM).
  (:conn_id, 'host-key',               :'ssh_host_key'),
  -- Enregistrement graphique de la session, consultable depuis l'historique (E06, SS5).
  (:conn_id, 'recording-path',         '${HISTORY_PATH}/${HISTORY_UUID}'),
  (:conn_id, 'create-recording-path',  'true'),
  -- Transcription texte (typescript) de la session : exploitable par recherche / SIEM.
  (:conn_id, 'typescript-path',        '${HISTORY_PATH}/${HISTORY_UUID}'),
  (:conn_id, 'create-typescript-path', 'true'),
  -- Pas de transfert de fichiers par le bastion (SFTP désactivé), pas de presse-papiers sortant.
  (:conn_id, 'enable-sftp',            'false'),
  (:conn_id, 'disable-copy',           'true'),
  (:conn_id, 'server-alive-interval',  '60');

-- Autorisations minimales : lecture (= utilisation) de la connexion uniquement.
INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT entity_id, :conn_id, 'READ'::guacamole_object_permission_type
FROM guacamole_entity
WHERE type = 'USER' AND name IN ('admin1', 'admin2', 'agence-web');

-- admin1 peut aussi modifier/supprimer la connexion (gestion du bastion).
INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT e.entity_id, :conn_id, p.perm::guacamole_object_permission_type
FROM guacamole_entity e
CROSS JOIN (VALUES ('UPDATE'), ('DELETE'), ('ADMINISTER')) AS p(perm)
WHERE e.type = 'USER' AND e.name = 'admin1';

COMMIT;

-- Récapitulatif (journal d'initialisation du conteneur guac-db).
SELECT e.name AS compte, u.disabled AS desactive, u.expired AS mdp_a_changer,
       u.valid_until AS valide_jusqu_au, u.access_window_start AS debut, u.access_window_end AS fin
FROM guacamole_user u JOIN guacamole_entity e USING (entity_id)
ORDER BY e.name;
