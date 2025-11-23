PRAGMA user_version=4;
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `users` (`is_admin` numeric,`is_locked` numeric,`uuid` text,`username` text NOT NULL UNIQUE,`password_salt` blob,`password_hash` blob,`browser_token` text,`minecraft_token` text,`api_token` text,`preferred_language` text,`max_player_count` integer,PRIMARY KEY (`uuid`));
INSERT INTO users VALUES(1,0,'3203a466-e087-4722-bcb2-a58094d44e30','foo',X'15175e011c3e1083717a428fa2ec9834',X'124b73815d2faf962ceeb5912f8d1eddcbab1732046c3f8e207ec4e2ba2c1861',NULL,'MC_QNWeHw5gbBEQ5vZ66lvvbD','99vtgWUFYhpppynaO3xsLB','en',-2);
INSERT INTO users VALUES(0,0,'02a38a6a-0128-4128-94dc-6c4a87c62b54','bar',X'49f3bfc68fe0f83ae5aa56a4e8691c9b',X'28fc38decfc8968d3b45cb799e22708c928bd10ba91548119ab6827eb52f337b',NULL,'MC_fA8P0NOHbEIcVqiNZtic1A','WYU257wONQKYJfgSLAH2tA','en',-2);
CREATE TABLE `players` (`uuid` text,`name` text collate nocase NOT NULL UNIQUE,`offline_uuid` text NOT NULL,`created_at` datetime,`name_last_changed_at` datetime,`skin_hash` text,`skin_model` text,`cape_hash` text,`server_id` text,`fallback_player` text,`user_uuid` text NOT NULL,PRIMARY KEY (`uuid`),CONSTRAINT `fk_users_players` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`));
INSERT INTO players VALUES('191ead5e-96f2-433c-a83f-ef5fc1c20177','foo','ab980ae0-02d3-3064-adcf-22d6ca24b404','2025-11-17 00:19:27.687405612-05:00','2025-11-17 00:19:27.687405645-05:00',NULL,'classic',NULL,NULL,'191ead5e-96f2-433c-a83f-ef5fc1c20177','3203a466-e087-4722-bcb2-a58094d44e30');
INSERT INTO players VALUES('81a0cad3-ee6c-4955-9265-62f86b1668b0','bar','4f9d5bad-fe3d-372c-bd1e-6517bc0e6b3e','2025-11-17 00:21:25.982752056-05:00','2025-11-17 00:21:25.982752093-05:00',NULL,'classic',NULL,NULL,'81a0cad3-ee6c-4955-9265-62f86b1668b0','02a38a6a-0128-4128-94dc-6c4a87c62b54');
CREATE TABLE `clients` (`uuid` text,`client_token` text,`version` integer,`user_uuid` text NOT NULL,`player_uuid` text,PRIMARY KEY (`uuid`),CONSTRAINT `fk_players_clients` FOREIGN KEY (`player_uuid`) REFERENCES `players`(`uuid`) ON DELETE CASCADE,CONSTRAINT `fk_users_clients` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`));
INSERT INTO clients VALUES('182d6a41-d385-406d-9e15-ff16acc860a5','e80247d30b904d3b8fcc891d6461aae7',0,'3203a466-e087-4722-bcb2-a58094d44e30','191ead5e-96f2-433c-a83f-ef5fc1c20177');
CREATE TABLE `invites` (`code` text,`created_at` datetime,PRIMARY KEY (`code`));
INSERT INTO invites VALUES('T2TKoCjKNgA','2025-11-17 00:20:59.740859001-05:00');
CREATE TABLE `user_oidc_identities` (`id` integer,`user_uuid` text NOT NULL,`subject` text NOT NULL,`issuer` text NOT NULL,PRIMARY KEY (`id`),CONSTRAINT `fk_users_o_id_c_identities` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`));
INSERT INTO user_oidc_identities VALUES(1,'3203a466-e087-4722-bcb2-a58094d44e30','8194612f-f244-45d5-a5f9-313d9c538f83','https://idm.example.com/oauth2/openid/drasl');
CREATE TRIGGER v4_insert_unique_username
			BEFORE INSERT ON users
			FOR EACH ROW
			BEGIN
				-- We have to reimplement the regular "UNIQUE constraint
				-- failed" errors here too since we want them to take priority
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: users.username')
				WHERE EXISTS(
					SELECT 1 FROM users WHERE username = NEW.username AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, 'USERNAME_TAKEN_BY_PLAYER_NAME')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.username AND user_uuid != NEW.uuid
				);
			END
;
CREATE TRIGGER v4_update_unique_username
			BEFORE UPDATE ON users
			FOR EACH ROW
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: users.username')
				WHERE EXISTS(
					SELECT 1 FROM users WHERE username = NEW.username AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, 'USERNAME_TAKEN_BY_PLAYER_NAME')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.username AND user_uuid != NEW.uuid
				);
			END;
CREATE TRIGGER v4_insert_unique_player_name
			BEFORE INSERT ON players
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: players.name')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.name AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, 'PLAYER_NAME_TAKEN_BY_USERNAME')
				WHERE EXISTS(
					SELECT 1 from users WHERE username == NEW.name AND uuid != NEW.user_uuid
				);
			END;
CREATE TRIGGER v4_update_unique_player_name
			BEFORE UPDATE ON players
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: players.name')
				WHERE EXISTS(
					SELECT 1 from players WHERE name == NEW.name AND uuid != NEW.uuid
				);

				SELECT RAISE(ABORT, 'PLAYER_NAME_TAKEN_BY_USERNAME')
				WHERE EXISTS(
					SELECT 1 from users WHERE username == NEW.name AND uuid != NEW.user_uuid
				);
			END;
CREATE TRIGGER v4_insert_unique_user_oidc_identities
			BEFORE INSERT ON user_oidc_identities
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer, user_oidc_identities.subject')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND issuer == NEW.issuer AND subject == NEW.subject
				);

				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND user_uuid == NEW.user_uuid AND issuer == NEW.issuer
				);
			END;
CREATE TRIGGER v4_update_unique_user_oidc_identities
			BEFORE UPDATE ON user_oidc_identities
			BEGIN
				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer, user_oidc_identities.subject')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND issuer == NEW.issuer AND subject == NEW.subject
				);

				SELECT RAISE(ABORT, 'UNIQUE constraint failed: user_oidc_identities.issuer')
				WHERE EXISTS(
					SELECT 1 from user_oidc_identities WHERE id != NEW.id AND user_uuid == NEW.user_uuid AND issuer == NEW.issuer
				);
			END;
CREATE INDEX `idx_users_browser_token` ON `users`(`browser_token`);
CREATE INDEX `idx_players_cape_hash` ON `players`(`cape_hash`);
CREATE INDEX `idx_players_skin_hash` ON `players`(`skin_hash`);
CREATE INDEX `idx_clients_player_uuid` ON `clients`(`player_uuid`);
CREATE UNIQUE INDEX `subject_issuer_unique_index` ON `user_oidc_identities`(`subject`,`issuer`);
CREATE INDEX `idx_user_oidc_identities_user_uuid` ON `user_oidc_identities`(`user_uuid`);
COMMIT;
