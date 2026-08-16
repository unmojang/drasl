PRAGMA foreign_keys=OFF;
PRAGMA user_version=5;
BEGIN TRANSACTION;
CREATE TABLE `users` (`is_admin` numeric,`is_locked` numeric,`uuid` text,`username` text NOT NULL,`password_salt` blob,`password_hash` blob,`browser_token` text,`minecraft_token` text,`api_token` text,`preferred_language` text,`max_player_count` integer,PRIMARY KEY (`uuid`),CONSTRAINT `uni_users_username` UNIQUE (`username`));
INSERT INTO users VALUES(1,0,'8cc19371-580e-49a4-88ab-77707b96ff28','foo',X'78fb4bb415ad07c204d24488f880848e',X'f5af2fa68e39755a87ce34c74866f78542b3fbd9918c330fdcd8d881e644332a','d6e1202a738eb20551953e236a257f14933e6a7b2c90449d161436d12c57cd81','MC_G8CGX1QdiYkBsT7Ai47beE','BKh2QKDLN2aqkqPARd4YWB','en',-2);
CREATE TABLE `players` (`uuid` text,`name` text collate nocase NOT NULL,`offline_uuid` text NOT NULL,`created_at` datetime,`name_last_changed_at` datetime,`skin_hash` text,`skin_model` text,`cape_hash` text,`server_id` text,`fallback_player` text,`user_uuid` text NOT NULL,PRIMARY KEY (`uuid`),CONSTRAINT `fk_users_players` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`),CONSTRAINT `uni_players_name` UNIQUE (`name`));
INSERT INTO players VALUES('ffdfc136-95b3-44f5-a11c-71ab7ee2259f','foo','ab980ae0-02d3-3064-adcf-22d6ca24b404','2026-08-16 16:04:30.414106488-04:00','2026-08-16 16:04:30.414106524-04:00','27818f0eadf68945ad0880c6c63c2baa0f466ac41960b3b6cc00c51e5dd23125','classic','d69e2c4c5dac0575f1c95805778d66e11e31996199a8f32381062d0ac00b240d',NULL,'ffdfc136-95b3-44f5-a11c-71ab7ee2259f','8cc19371-580e-49a4-88ab-77707b96ff28');
CREATE TABLE `clients` (`uuid` text,`client_token` text,`version` integer,`user_uuid` text NOT NULL,`player_uuid` text,`last_used_at` datetime,PRIMARY KEY (`uuid`),CONSTRAINT `fk_players_clients` FOREIGN KEY (`player_uuid`) REFERENCES `players`(`uuid`) ON DELETE CASCADE,CONSTRAINT `fk_users_clients` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`));
CREATE TABLE `invites` (`code` text,`created_at` datetime,PRIMARY KEY (`code`));
CREATE TABLE `user_oidc_identities` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_uuid` text NOT NULL,`subject` text NOT NULL,`issuer` text NOT NULL,CONSTRAINT `fk_users_o_id_c_identities` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`));
CREATE TRIGGER v5_insert_unique_username
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
CREATE TRIGGER v5_update_unique_username
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
CREATE TRIGGER v5_insert_unique_player_name
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
CREATE TRIGGER v5_update_unique_player_name
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
CREATE TRIGGER v5_insert_unique_user_oidc_identities
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
CREATE TRIGGER v5_update_unique_user_oidc_identities
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
CREATE TRIGGER v5_insert_clients_max_count
			AFTER INSERT ON clients
			BEGIN
				DELETE FROM clients
				WHERE user_uuid = NEW.user_uuid
				AND uuid NOT IN (
					SELECT uuid
					FROM clients
					WHERE user_uuid = NEW.user_uuid
					ORDER BY last_used_at DESC
					LIMIT 256
				);
			END;
CREATE INDEX `idx_users_browser_token` ON `users`(`browser_token`);
CREATE INDEX `idx_players_cape_hash` ON `players`(`cape_hash`);
CREATE INDEX `idx_players_skin_hash` ON `players`(`skin_hash`);
CREATE INDEX `idx_clients_player_uuid` ON `clients`(`player_uuid`);
CREATE UNIQUE INDEX `subject_issuer_unique_index` ON `user_oidc_identities`(`subject`,`issuer`);
CREATE INDEX `idx_user_oidc_identities_user_uuid` ON `user_oidc_identities`(`user_uuid`);
COMMIT;
