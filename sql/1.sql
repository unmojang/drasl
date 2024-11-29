PRAGMA user_version=1;
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `users` (`is_admin` numeric,`is_locked` numeric,`uuid` text,`username` text NOT NULL UNIQUE,`password_salt` blob NOT NULL,`password_hash` blob NOT NULL,`server_id` text,`player_name` text collate nocase NOT NULL UNIQUE,`offline_uuid` text,`fallback_player` text,`preferred_language` text,`browser_token` text,`skin_hash` text,`skin_model` text,`cape_hash` text,`created_at` datetime,`name_last_changed_at` datetime,PRIMARY KEY (`uuid`));
INSERT INTO users VALUES(1,0,'dc500452-7745-4939-a187-a8ce37beca28','foo',X'cdae655061130b4594991676095739d6',X'76f1040e8fa5c96f6d94b3b088d8079bfbc46efcb94d270a750a5673c88e757d',NULL,'foo','ab980ae0-02d3-3064-adcf-22d6ca24b404','dc500452-7745-4939-a187-a8ce37beca28','en','23313163410b65f0fcb4bc1beea75a3a8bfbbc25af626c3e1d34b61f9f8c050b',NULL,'classic',NULL,'2024-11-27 17:21:50.994337304-05:00','2024-11-27 17:21:50.994337485-05:00');
CREATE TABLE `clients` (`client_token` text,`version` integer,`user_uuid` text,PRIMARY KEY (`client_token`),CONSTRAINT `fk_users_clients` FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`));
INSERT INTO clients VALUES('e7926dc1e9b74b598251dd16277d0bba',0,'dc500452-7745-4939-a187-a8ce37beca28');
CREATE TABLE `invites` (`code` text,`created_at` datetime,PRIMARY KEY (`code`));
INSERT INTO invites VALUES('cwB03PjPqSJ','2024-11-27 17:22:00.218111184-05:00');
CREATE INDEX `idx_users_cape_hash` ON `users`(`cape_hash`);
CREATE INDEX `idx_users_skin_hash` ON `users`(`skin_hash`);
CREATE INDEX `idx_users_browser_token` ON `users`(`browser_token`);
COMMIT;