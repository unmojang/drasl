PRAGMA user_version=3;
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `users` (`is_admin` numeric,`is_locked` numeric,`uuid` text,`username` text NOT NULL UNIQUE,`password_salt` blob NOT NULL,`password_hash` blob NOT NULL,`server_id` text,`player_name` text collate nocase NOT NULL UNIQUE,`offline_uuid` text NOT NULL,`fallback_player` text,`preferred_language` text,`browser_token` text,`api_token` text,`skin_hash` text,`skin_model` text,`cape_hash` text,`created_at` datetime,`name_last_changed_at` datetime,PRIMARY KEY (`uuid`));
INSERT INTO users VALUES(1,0,'8a94719d-94b5-49f6-93c1-bff20aeb9d70','foo',X'a5c1419d67c0ae15e9894e1d505e215e',X'7e5b0222eb21362cea20609501dbe7c69bfcdebca05e66341fe5ad85593ea922',NULL,'foo','ab980ae0-02d3-3064-adcf-22d6ca24b404','8a94719d-94b5-49f6-93c1-bff20aeb9d70','en','8e1da35a9e20f1651404c3315bfebb438028fb6495b1407622d8546749c4998b','qVefdhlf90THN49ceNLc1T','27818f0eadf68945ad0880c6c63c2baa0f466ac41960b3b6cc00c51e5dd23125','classic','5630e530c3853fde80d99c60eb91ac8d11061d18f0404a189f73503940473187','2024-11-28 11:41:24.273481686-05:00','2024-11-28 11:41:24.273481896-05:00');
CREATE TABLE `clients` (`uuid` text,`client_token` text,`version` integer,`user_uuid` text,PRIMARY KEY (`uuid`),CONSTRAINT `fk_users_clients` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`));
INSERT INTO clients VALUES('1e654965-89f5-4ab5-8b21-9c9087652ce4','951b701320a84d34b6d873c68db58de4',1,'8a94719d-94b5-49f6-93c1-bff20aeb9d70');
CREATE TABLE `invites` (`code` text,`created_at` datetime,PRIMARY KEY (`code`));
CREATE INDEX `idx_users_cape_hash` ON `users`(`cape_hash`);
CREATE INDEX `idx_users_skin_hash` ON `users`(`skin_hash`);
CREATE INDEX `idx_users_browser_token` ON `users`(`browser_token`);
COMMIT;