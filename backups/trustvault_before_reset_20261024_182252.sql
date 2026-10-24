-- MySQL dump 10.13  Distrib 8.0.42, for Win64 (x86_64)
--
-- Host: localhost    Database: trustvault
-- ------------------------------------------------------
-- Server version	8.0.42

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `trustvault`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `trustvault` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;

USE `trustvault`;

--
-- Table structure for table `audit_logs`
--

DROP TABLE IF EXISTS `audit_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_logs` (
  `id` varchar(36) NOT NULL DEFAULT (uuid()),
  `user_id` varchar(36) DEFAULT NULL COMMENT 'Preserved as NULL if user record is purged',
  `user_email` varchar(255) NOT NULL COMMENT 'Denormalized snapshot to retain historical context forever',
  `action` enum('UPLOAD','READ','EDIT','DELETE','GRANT','REVOKE','ACCESS_DENIED','ACCOUNT_DEACTIVATED','ACCOUNT_INACTIVE_ACCESS_ATTEMPT','SECURITY_ALERT','SYSTEM_LOCKDOWN_TRIGGERED','SYSTEM_LOCKDOWN_LIFTED','ROLE_CHANGED') NOT NULL,
  `document_id` varchar(36) DEFAULT NULL COMMENT 'Loose reference so audit logs survive document deletion',
  `ip_address` varchar(45) NOT NULL COMMENT 'IPv4 (15 chars) or IPv6 (45 chars) with potential mapping',
  `status` enum('SUCCESS','FAILURE') NOT NULL,
  `details` json DEFAULT NULL,
  `pre_state` json DEFAULT NULL,
  `post_state` json DEFAULT NULL,
  `timestamp` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT 'Microsecond precision for distributed event ordering',
  PRIMARY KEY (`id`),
  KEY `idx_audit_logs_timestamp` (`timestamp`),
  KEY `idx_audit_logs_user_id` (`user_id`),
  KEY `idx_audit_logs_action` (`action`),
  KEY `idx_audit_logs_document_id` (`document_id`),
  CONSTRAINT `fk_audit_logs_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Immutable append-only compliance audit trail';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `audit_logs`
--

LOCK TABLES `audit_logs` WRITE;
/*!40000 ALTER TABLE `audit_logs` DISABLE KEYS */;
INSERT INTO `audit_logs` VALUES ('00220084-2f08-46c9-b84e-7f09389becd4','1dbddad1-07e6-4cc5-8135-b64ccef6067a','Lakshmi1983@gmail.com','UPLOAD','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"title\": \"res.pdf\", \"category\": \"General\", \"mimeType\": \"application/pdf\", \"sizeBytes\": 48338}',NULL,'{\"id\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"title\": \"res.pdf\", \"ownerId\": \"1dbddad1-07e6-4cc5-8135-b64ccef6067a\", \"category\": \"General\", \"mimeType\": \"application/pdf\", \"createdAt\": null, \"updatedAt\": null, \"ownerEmail\": \"Lakshmi1983@gmail.com\", \"fileSizeBytes\": 48338}','2026-10-24 01:42:23.480678'),('0630601a-a005-4bbd-8614-bebbc6b53c84','1dbddad1-07e6-4cc5-8135-b64ccef6067a','Lakshmi1983@gmail.com','UPLOAD',NULL,'0:0:0:0:0:0:0:1','SUCCESS','{\"event\": \"FACE_ENROLLED\", \"algorithm\": \"TV-FACE-1\", \"deviceLabel\": \"api\", \"embeddingSize\": 128}',NULL,NULL,'2026-10-24 01:41:53.420557'),('0cab8807-fe27-4818-b852-045ff7d4ad22','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"event\": \"FACE_ACTION_VERIFIED\", \"action\": \"DOWNLOAD\", \"algorithm\": \"TV-FACE-1\", \"matchScore\": 0.54, \"challengeId\": \"c1b08046-3446-4d63-aa56-fea504542f35\", \"matchDistance\": 0.46, \"distanceThreshold\": 0.6}',NULL,NULL,'2026-10-24 02:22:54.750093'),('0eefef42-b966-4c9a-9c1b-33574ba18caf','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.464, \"matchDistance\": 0.536, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:06.080833'),('11f0c322-7fba-415d-a544-b3e3cb5f6734','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"title\": \"res.pdf\", \"action\": \"DOWNLOAD_STREAMED\", \"sizeBytes\": 48338}',NULL,NULL,'2026-10-24 02:12:58.534841'),('11f86295-749f-4909-a64f-c61828e69030','1dbddad1-07e6-4cc5-8135-b64ccef6067a','Lakshmi1983@gmail.com','GRANT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"maxViews\": 5, \"expiresAt\": \"2026-10-30T07:12:00Z\", \"recipient\": \"23jr1a1209@gmail.com\", \"policyAction\": \"CREATE\", \"permissionLevel\": \"READ\"}',NULL,'{\"id\": \"b3cea43b-77f4-476c-a963-326ffadbd216\", \"userId\": \"d6d103fe-0394-42fb-bf52-9b024d5f3d31\", \"maxViews\": 5, \"expiresAt\": \"2026-10-30T07:12:00Z\", \"grantedAt\": null, \"userEmail\": \"23jr1a1209@gmail.com\", \"documentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"viewsCount\": 0, \"grantedByEmail\": \"Lakshmi1983@gmail.com\", \"permissionLevel\": \"READ\"}','2026-10-24 01:42:43.199134'),('1668eba6-f867-4184-a172-c0aaa919af6c','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has expired. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_EXPIRED\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:49:21.177764'),('22af135c-1887-4503-be4e-fc37ed106996','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has already been used. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_REUSED\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:17.825173'),('24eeb754-7893-47e4-9592-aae5e54dd036','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.475, \"matchDistance\": 0.525, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:48:50.446581'),('34c996ab-db15-4483-879d-6807607adc48','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"title\": \"res.pdf\", \"action\": \"DOWNLOAD_STREAMED\", \"sizeBytes\": 48338}',NULL,NULL,'2026-10-24 02:24:46.314245'),('36152a08-8538-4522-9cb0-d3e55e7eb09c','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.475, \"matchDistance\": 0.525, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:48:50.470365'),('4358575f-07ff-4e79-89b2-074f2ff98e11','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.464, \"matchDistance\": 0.536, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:06.106778'),('47497140-80d2-4e37-bcaa-f9f330470412','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','UPLOAD',NULL,'0:0:0:0:0:0:0:1','SUCCESS','{\"event\": \"FACE_ENROLLED\", \"algorithm\": \"TV-FACE-1\", \"deviceLabel\": \"api\", \"embeddingSize\": 128}',NULL,NULL,'2026-10-24 01:39:30.262047'),('4f1f530d-babd-45b1-8082-1d78b58afb8a',NULL,'23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"alert\": \"CONSECUTIVE_ACCESS_DENIED_EXCEEDED\", \"threshold\": 3, \"timestamp\": \"2026-10-24T07:20:05.995114200Z\", \"triggerSource\": \"User: 23jr1a1209@gmail.com\", \"windowMinutes\": 5, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\"}',NULL,NULL,'2026-10-24 01:50:05.995114'),('50ef677c-05a8-4aaa-803d-650eb852ab7f','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.457, \"matchDistance\": 0.543, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:49:21.274958'),('542b58c3-0ef8-47e0-be4a-cc042299b688','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"event\": \"FACE_ACTION_VERIFIED\", \"action\": \"DOWNLOAD\", \"algorithm\": \"TV-FACE-1\", \"matchScore\": 0.484, \"challengeId\": \"13800cf5-ff27-4af1-b79b-9346f4693357\", \"matchDistance\": 0.516, \"distanceThreshold\": 0.6}',NULL,NULL,'2026-10-24 02:12:58.481813'),('60678c6d-9d75-4f52-8fe1-775c9df76936','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has expired. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_EXPIRED\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:49:21.163070'),('65a6674c-e2db-4dd9-8a22-0be2c2e1e534','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has expired. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_EXPIRED\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:05.993214'),('66de7bee-5fce-4988-8bc5-11a98c44f185','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.457, \"matchDistance\": 0.543, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:49:21.252955'),('74b73f02-27b6-4348-b2a1-d75b6eeb52db','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has expired. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_EXPIRED\", \"distanceThreshold\": 0.6}',NULL,NULL,'2026-10-24 02:22:54.590159'),('7abe90ce-a722-432d-9a94-dcb2b9da700f','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"title\": \"res.pdf\", \"action\": \"DOWNLOAD_STREAMED\", \"sizeBytes\": 48338}',NULL,NULL,'2026-10-24 02:28:11.444392'),('873cbf6a-92d7-4c92-b4eb-cda7f07a8f0e','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has expired. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_EXPIRED\", \"distanceThreshold\": 0.6}',NULL,NULL,'2026-10-24 02:12:58.289480'),('95614ee1-7808-4bde-912a-04b74c907b8e',NULL,'23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"alert\": \"CONSECUTIVE_ACCESS_DENIED_EXCEEDED\", \"threshold\": 3, \"timestamp\": \"2026-10-24T07:20:17.826666800Z\", \"triggerSource\": \"IP: 0:0:0:0:0:0:0:1\", \"windowMinutes\": 5, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\"}',NULL,NULL,'2026-10-24 01:50:17.826667'),('a14e8f90-65c9-43b8-ae38-c9a7c3041880',NULL,'23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"alert\": \"CONSECUTIVE_ACCESS_DENIED_EXCEEDED\", \"threshold\": 3, \"timestamp\": \"2026-10-24T07:21:22.859382600Z\", \"triggerSource\": \"User: 23jr1a1209@gmail.com\", \"windowMinutes\": 5, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\"}',NULL,NULL,'2026-10-24 01:51:22.860412'),('a7c158bb-28c5-4a93-bf11-13953dd0c64d','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.487, \"matchDistance\": 0.513, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:17.952748'),('b2d165fc-c1d0-4c24-a77a-5455a81380f4',NULL,'23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"alert\": \"CONSECUTIVE_ACCESS_DENIED_EXCEEDED\", \"threshold\": 3, \"timestamp\": \"2026-10-24T07:20:17.958751100Z\", \"triggerSource\": \"DB IP: 0:0:0:0:0:0:0:1\", \"windowMinutes\": 5, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\"}',NULL,NULL,'2026-10-24 01:50:17.958751'),('b8b9f2b7-e628-4d70-b147-74fae0588846','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"event\": \"FACE_ACTION_VERIFIED\", \"action\": \"DOWNLOAD\", \"algorithm\": \"TV-FACE-1\", \"matchScore\": 0.457, \"challengeId\": \"c0c37f72-37c2-49f5-b001-83d51da403a2\", \"matchDistance\": 0.543, \"distanceThreshold\": 0.6}',NULL,NULL,'2026-10-24 02:24:46.284409'),('bc0919d0-cc19-4701-a983-a29d5e755dc2',NULL,'23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"alert\": \"CONSECUTIVE_ACCESS_DENIED_EXCEEDED\", \"threshold\": 3, \"timestamp\": \"2026-10-24T07:20:06.084813100Z\", \"triggerSource\": \"DB IP: 0:0:0:0:0:0:0:1\", \"windowMinutes\": 5, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\"}',NULL,NULL,'2026-10-24 01:50:06.084813'),('bdce24d6-524b-406a-9adc-1bc3536000fb','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has expired. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_EXPIRED\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:06.014764'),('c89089e3-323b-44ed-88fa-9368aa4e7e06','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"title\": \"res.pdf\", \"action\": \"DOWNLOAD_STREAMED\", \"sizeBytes\": 48338}',NULL,NULL,'2026-10-24 02:22:54.802483'),('e17d2b8f-7edc-425b-a4f2-da6f11241d71',NULL,'23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"alert\": \"CONSECUTIVE_ACCESS_DENIED_EXCEEDED\", \"threshold\": 3, \"timestamp\": \"2026-10-24T07:19:21.254766600Z\", \"triggerSource\": \"IP: 0:0:0:0:0:0:0:1\", \"windowMinutes\": 5, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\"}',NULL,NULL,'2026-10-24 01:49:21.254767'),('e49d52cc-e9eb-46e8-bde0-7ed570f428ec','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','ACCESS_DENIED','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.413, \"matchDistance\": 0.587, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:51:22.857345'),('ebffe09f-91e0-4d65-8bf0-fc86146b6b7d','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.487, \"matchDistance\": 0.513, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:17.979839'),('ed772de2-53cb-48f0-af76-36311f3204eb','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','READ','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','SUCCESS','{\"event\": \"FACE_ACTION_VERIFIED\", \"action\": \"DOWNLOAD\", \"algorithm\": \"TV-FACE-1\", \"matchScore\": 0.488, \"challengeId\": \"ae3ca273-f4e3-4142-9aaf-77940776b796\", \"matchDistance\": 0.512, \"distanceThreshold\": 0.6}',NULL,NULL,'2026-10-24 02:28:11.384914'),('fa610ba3-86e3-4a31-b486-29c5f3e56c8c','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_MATCH_FAILED\", \"action\": \"DOWNLOAD\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.413, \"matchDistance\": 0.587, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:51:22.878134'),('faa74499-cee3-4449-a511-1c4e7001f568','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','SECURITY_ALERT','cfb05061-e64f-42a3-99a7-db41a6a74347','0:0:0:0:0:0:0:1','FAILURE','{\"event\": \"FACE_CHALLENGE_REJECTED\", \"action\": \"DOWNLOAD\", \"reason\": \"This FaceID challenge has already been used. Request a new one and scan again.\", \"userEmail\": \"23jr1a1209@gmail.com\", \"matchScore\": 0.0, \"targetDocumentId\": \"cfb05061-e64f-42a3-99a7-db41a6a74347\", \"verificationCode\": \"FACE_CHALLENGE_REUSED\", \"distanceThreshold\": 0.4}',NULL,NULL,'2026-10-24 01:50:17.890753');
/*!40000 ALTER TABLE `audit_logs` ENABLE KEYS */;
UNLOCK TABLES;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = cp850 */ ;
/*!50003 SET character_set_results = cp850 */ ;
/*!50003 SET collation_connection  = cp850_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER `trg_audit_logs_no_update` BEFORE UPDATE ON `audit_logs` FOR EACH ROW BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'TrustVault Security Violation: Audit logs are strictly append-only and cannot be updated.';
END */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = cp850 */ ;
/*!50003 SET character_set_results = cp850 */ ;
/*!50003 SET collation_connection  = cp850_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER `trg_audit_logs_no_delete` BEFORE DELETE ON `audit_logs` FOR EACH ROW BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'TrustVault Security Violation: Audit logs are strictly append-only and cannot be deleted.';
END */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Table structure for table `biometric_challenges`
--

DROP TABLE IF EXISTS `biometric_challenges`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `biometric_challenges` (
  `id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `document_id` varchar(36) NOT NULL,
  `action` varchar(16) NOT NULL,
  `token_hash` varchar(64) NOT NULL,
  `issued_at` timestamp(6) NOT NULL,
  `expires_at` timestamp(6) NOT NULL,
  `consumed_at` timestamp(6) NULL DEFAULT NULL,
  `issued_ip` varchar(64) DEFAULT NULL,
  `consumed_ip` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_biometric_challenges_token` (`token_hash`),
  KEY `idx_biometric_challenges_user_expiry` (`user_id`,`expires_at`),
  CONSTRAINT `fk_biometric_challenges_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `biometric_challenges`
--

LOCK TABLES `biometric_challenges` WRITE;
/*!40000 ALTER TABLE `biometric_challenges` DISABLE KEYS */;
INSERT INTO `biometric_challenges` VALUES ('7a78ee44-221c-4dce-bb02-61e4af792844','usr-admin-01','cfb05061-e64f-42a3-99a7-db41a6a74347','DOWNLOAD','948f3539c59d110ecf144e297a31047b1013214c2f6522b2636d6d96e88a4d9c','2026-10-24 01:47:45.646670','2026-10-24 01:48:15.646670',NULL,'0:0:0:0:0:0:0:1',NULL),('ae3ca273-f4e3-4142-9aaf-77940776b796','d6d103fe-0394-42fb-bf52-9b024d5f3d31','cfb05061-e64f-42a3-99a7-db41a6a74347','DOWNLOAD','774b8deb17d3bae7d763bc3f9fc79434ac14536c475a4b8beef1d33fd16cd500','2026-10-24 02:28:11.240193','2026-10-24 02:28:41.240193','2026-10-24 02:28:11.343089','0:0:0:0:0:0:0:1','0:0:0:0:0:0:0:1'),('c0c37f72-37c2-49f5-b001-83d51da403a2','d6d103fe-0394-42fb-bf52-9b024d5f3d31','cfb05061-e64f-42a3-99a7-db41a6a74347','DOWNLOAD','752193b58a2578f8cc8401bccf41073b62f4b009db325928171a6a04c8ba8dac','2026-10-24 02:24:17.015011','2026-10-24 02:24:47.015011','2026-10-24 02:24:46.227885','0:0:0:0:0:0:0:1','0:0:0:0:0:0:0:1'),('c1b08046-3446-4d63-aa56-fea504542f35','d6d103fe-0394-42fb-bf52-9b024d5f3d31','cfb05061-e64f-42a3-99a7-db41a6a74347','DOWNLOAD','9a5aa9600eba99bd112aee0134feac30145f316569d4f7cf7069fce5224459ba','2026-10-24 02:22:54.678827','2026-10-24 02:23:24.678827','2026-10-24 02:22:54.711502','0:0:0:0:0:0:0:1','0:0:0:0:0:0:0:1');
/*!40000 ALTER TABLE `biometric_challenges` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `biometric_templates`
--

DROP TABLE IF EXISTS `biometric_templates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `biometric_templates` (
  `id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `email` varchar(255) NOT NULL,
  `face_descriptor` text NOT NULL,
  `face_hash` varchar(64) NOT NULL,
  `algorithm_version` varchar(32) NOT NULL DEFAULT 'TV-FACE-1',
  `embedding_size` int NOT NULL DEFAULT '128',
  `created_at` timestamp(6) NOT NULL,
  `updated_at` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_biometric_templates_user_id` (`user_id`),
  UNIQUE KEY `uk_biometric_templates_email` (`email`),
  UNIQUE KEY `uk_biometric_templates_face_hash` (`face_hash`),
  CONSTRAINT `fk_biometric_templates_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `biometric_templates`
--

LOCK TABLES `biometric_templates` WRITE;
/*!40000 ALTER TABLE `biometric_templates` DISABLE KEYS */;
INSERT INTO `biometric_templates` VALUES ('5b70514f-13b9-4e5e-8f08-8b66f40939c3','d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','JvI0+oUL3LH7gA9yVARG7MKIKGD/YpmBrp1vTBOT0IH039coKhG+OmEOf6bXsX8Q9sBEnWC8PcKglZM8BMHKS3FE5dBp92C/G+YYHR05azKL1jI93IShP/Tka9RtaSln44XC29/zU/H7OiuTtrgFjvXdWoLmEjSSJKelHf8MXy9fhkd55GmAI91X5FSQZYHfVNcyBnMsi6EMk9540+CVY7D8EhM648KJvPDmT44D4VDKh7HT+hNbKQ9lrDvFW/YsTdH+uAhgnTGJd3bHU3Q7vOW7QijxcuzvEsV0U+xZS7qPLS+mguM0G1bJopn/B0ygBHoZRPE0yZrJoOSlOBccrGEQakc+IP7zUKg2jpUarBQoWaPM7bm4AXd6GwwCgKHpF6itjkKIQtW7/3xhFHwBUT7eds+osLTt1z1VDEYy2Q8W/d9VBYEWwT7lv+Sue3kn6ORVkOwm6UFe8Nld8DPe+dhRmmp1Cje0OLLwwUCSZ15SBRAfaXlOo3+eIMKo/Tl2MenrTbdGU53EXmz1ss9j4dHKHUTbrt76pNLdgLBGBPwUL8monFKW6w9Wjwk63xn7x/vY+YuBFqlcvWexkiZI2dhdnIT3zQmueT31ktAw3aFQsY3p21ecw6MCHvwEej/HmUtRqggAJwK73YDp9rVt0ACRa9SuIfTSDKwoREjbD0KHE25nKYCUZVQCq1Y2LE23biiuLYqhcYMRUnzScr59BhWlngkdAJ4zzNnyVM2bVspIZqoW0+1rGcvH5VzUq1EIj2J5L1KnbcYLSU5vBr4+D63ApneAA3JnPibEbhElP9DcdhvtkpgzOyp7Eq3Td/X6fCA8o25D64wE5bjCJ/RjYTd2z7BvFlsqlaJ1Q010enmX/OeHu+P0fuWwObQGU/oeEA2w0tJNH54IbXO/F3dcuvP0OJUTC+FW/T/p7/QlgNlwLKQh0xlHQgHNTx2B04VcX4EBTASPIEJxHP24moL4yp0sbCk+fG9eC1RzP61CcjDwU3Qhfbna0/uun1CLJXku2GUzioCR49XJSlLX1CeP1XkZ6dNgt5XuDVPEmW4oWC75CfMYQP3duq2S46RWW2FZ1Lf6sfDSQFc8Cu2hnxD/GzWOrfjZ72i1hs/2KUlM2uJBGPgM7unSxE4km802LeZDdbV68s95z5cTOZfNZekItlDI7S2edpQSYzgkqKB/UB9T/CYAMJEr3r+2xU9Ai/ONnBrF9HkXJxGxuRMLyt9nagZg1zHFBWzPJ6tJX0TQoqyZUnIbKH6F8vEnh2BeOKPi2C0n1+VRE+83SxDmB4f/8Rv4o/37SJNgjvXspn9oEQ6k/WEivKxW8eoD+NYxWKX8zAez/4dqnmjdhe1zyQwOBBOrzzY/gLdgUw64i9fnSNw+7aiBErIc7cMKso09k7Iil7JZPWERiit5P/7qs0Npgre++U4zVCZe0K5WJ0veWqC4Bzh8w9wYXPJxMhT1HtE/Frsq9PC5zhBwHzEFFadpiBBHsptr70HFezygdOe+Q1K7kdtlhjRpD64550ZSOeZMX0VvIZ/Ey4n4Hf68rXJu5m61mWOJnmve/a4nLIB3yzpKriDj1WhpYwbpeq/KngQHVqU0Z/P/QFqBwsJEkaMhsL/Y9XbwZpz9T3XqhCxCI2VABGls4Qx3R1FuAj3TcoA=','ede83aca447c0c1cef03af9c60da17bd56cc98e5f7136acf0b2997082eb00daf','TV-FACE-1',128,'2026-10-24 01:39:30.258941','2026-10-24 01:39:30.258941'),('a40961e3-58eb-4724-a9e1-85a7f7be8328','1dbddad1-07e6-4cc5-8135-b64ccef6067a','lakshmi1983@gmail.com','0/c7hzWGLfZLVdO+sBAGlxHtB8zcDric3Uu2z48efVJLp7n3VSTljdIElnlbu9/qn/0Oqz2H8RqBiV3iJbRJGa2tRc5Va1o+iXCPuC9gbyP8PfGOfIIRCcLS7kppI3Np32sqbKMToDhUJo7hTe7Cqnkezq4xmJxZEDd2foQR/tFCDpl1UJPAdhXfdojsMR3hcZ022hE5gGaF9+SwCzvufYi7Bhj7rWkfUjnj0y45g+WV8FFidHBIWVwmMzYU7WjLxtbxEU6AgUZbgWWLzipGqcgSaqso/F2ZsobEHoHWdFrNYVwcvjn5k5iNfN/V31Wfm06nveCpSOYxlkP8fDNGSYr6MsClbo0cV3u6IXfiLSiDJKhYMBqIkgcTVPotzplM1JMKOlDGgXGrsc/O6c+C8c6DUSLxYOFlr0rfEXkw5Do/yVJOLCcX7TmsTQdJ000NP941FOCNqqWfu2aPmfxQkHCEtz014BPEyqcxRJGntbOA/CI38etfUX5aa9kkGXcmCmvhHsEhwhtqpfhFX+ZvZF5lvD4CvQGFTsdV81eB9u2XGKQBSq5/Qu9A+d0fErBfNxJwge/0BMqOsdpKi1vQ6d6I4xLhK8GDxEgjkcXmzLrVOJt2oTvN0MNVYI7SPuKUyTUWgvq1VkLUutTuj09SAHeEaXcqcVKjegRCLrUJ2x75CM+03hAeTNcNFU61X9tLi/ujJsRUtnMS48bFeV9n5z+iPNDPrUr1lD3QDNMdKticFDHazIExZHKZjLkk5jKNE/F8KBxrxLTfIPWWYdhwMsGC4HiExgrEKFLcSZV4jno3YD7Mb+IZZZD0qCcckkbD0JBhBQIVZ6Tcc7OoF6VebOAnNUXteGI6hm58uqBnUIFubQlBoVGIvCPZwRa1iI7X59D2hnnQ/ZRjYLHZHjC5tACNdbkx3JTbesvdVaUctRBkueJixjzSCcZjpAgWv7fdPPkD/oTqeimh9mw63jkJxsowNbMHbOCSYWXG4RBCkwqgysXKpw2GCQMeXl/XcmuZwSLSqOApeiLwEt0FR9AXD9rOl4AucC3xV/g4SvtlOCsCwveN3vKZvqEtfAg9KHZXFscaKG75AaUVBO54a4Iy5dP5jxhzHnWEqYR/YzipTTV1RHB/nMdB3Ysyw9V433nOW+R+DxURMM4COWeWe03gIziB/fpjAQgm9Fgz43rm37MHhgyi3BGQ6nwKRtLKf64gfedn9Ae/Ox1hmSul0lN8AzgVcev9+3hPWqvwYpCtysmumBPlsT6EYANAnHv9ZLnWECiOR4M6bM2aucg7oSDftCprnF+h9tF+yZGQi2TP5cbrOxfkadrvJApEmzmAS4lDMGJszE+GBozy+FNHxkchH5VOCmyQ0oW3Sz3WX/k3FxOivXPSCTfS6M5R68bRuSYoGIEFaBXDReZ/LVRv5Z8zh/78ARB+MRyFRbk+3BEdAoClRMYiBwiZMFxjZrf5ihUYBUj3WrZxRmp7d65j/BSY7zK1WCeIrMvEOJ0ptqpt05DQDSgbc82w+mXgBC/1zNcMrylv0EtVDKnEXE7Rny0rZ0kjsL7R3NkiYa4U8G2cRv82x/ZEpRm2hmWBkEGlPdDqcZ1ieVG8BpDsVeHO7gKHtB4IzOcYpIi1bHh3gOGhr/cP9xmRn37UU1j0L2o/','8b0cbc5bd00945438b065f06f788a982e7b1fec4fad0d392cd891759b1b8c439','TV-FACE-1',128,'2026-10-24 01:41:53.419574','2026-10-24 01:41:53.419574');
/*!40000 ALTER TABLE `biometric_templates` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `document_permissions`
--

DROP TABLE IF EXISTS `document_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `document_permissions` (
  `id` varchar(36) NOT NULL DEFAULT (uuid()),
  `document_id` varchar(36) NOT NULL,
  `user_id` varchar(36) NOT NULL,
  `permission_level` enum('READ','EDIT') NOT NULL,
  `max_views` int unsigned DEFAULT NULL COMMENT 'Burn-after-reading limit; NULL means unlimited views until expiry',
  `views_count` int unsigned NOT NULL DEFAULT '0',
  `expires_at` timestamp NULL DEFAULT NULL COMMENT 'Time-bound expiration; NULL means no temporal restriction',
  `granted_by` varchar(36) DEFAULT NULL,
  `granted_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_doc_user` (`document_id`,`user_id`),
  KEY `idx_permissions_user_doc` (`user_id`,`document_id`),
  KEY `idx_permissions_expiry` (`expires_at`),
  KEY `fk_permissions_granted_by` (`granted_by`),
  CONSTRAINT `fk_permissions_document` FOREIGN KEY (`document_id`) REFERENCES `documents` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_permissions_granted_by` FOREIGN KEY (`granted_by`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_permissions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Ephemeral and view-capped ACL rules per document';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `document_permissions`
--

LOCK TABLES `document_permissions` WRITE;
/*!40000 ALTER TABLE `document_permissions` DISABLE KEYS */;
INSERT INTO `document_permissions` VALUES ('b3cea43b-77f4-476c-a963-326ffadbd216','cfb05061-e64f-42a3-99a7-db41a6a74347','d6d103fe-0394-42fb-bf52-9b024d5f3d31','READ',5,1,'2026-10-30 01:42:00','1dbddad1-07e6-4cc5-8135-b64ccef6067a','2026-10-24 01:42:43');
/*!40000 ALTER TABLE `document_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `documents`
--

DROP TABLE IF EXISTS `documents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `documents` (
  `id` varchar(36) NOT NULL DEFAULT (uuid()),
  `title` varchar(255) NOT NULL,
  `file_path` varchar(1024) NOT NULL COMMENT 'Encrypted blob storage URI / S3 object key',
  `file_size_bytes` bigint unsigned NOT NULL,
  `mime_type` varchar(127) NOT NULL,
  `category` varchar(64) NOT NULL,
  `owner_id` varchar(36) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_documents_owner` (`owner_id`),
  KEY `idx_documents_category` (`category`),
  CONSTRAINT `fk_documents_owner` FOREIGN KEY (`owner_id`) REFERENCES `users` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Metadata registry for zero-trust encrypted document payloads';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `documents`
--

LOCK TABLES `documents` WRITE;
/*!40000 ALTER TABLE `documents` DISABLE KEYS */;
INSERT INTO `documents` VALUES ('cfb05061-e64f-42a3-99a7-db41a6a74347','res.pdf','C:\\Users\\hp\\Desktop\\trustvalut\\uploads\\79fc594c-9b1e-4204-bfe9-4369d1479f2c.pdf',48338,'application/pdf','General','1dbddad1-07e6-4cc5-8135-b64ccef6067a','2026-10-24 01:42:23','2026-10-24 01:42:23');
/*!40000 ALTER TABLE `documents` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `system_settings`
--

DROP TABLE IF EXISTS `system_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_settings` (
  `setting_key` varchar(64) NOT NULL,
  `setting_value` varchar(2048) NOT NULL,
  `updated_by` varchar(255) DEFAULT NULL,
  `updated_at` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `system_settings`
--

LOCK TABLES `system_settings` WRITE;
/*!40000 ALTER TABLE `system_settings` DISABLE KEYS */;
/*!40000 ALTER TABLE `system_settings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_credentials`
--

DROP TABLE IF EXISTS `user_credentials`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_credentials` (
  `credential_id` varchar(255) NOT NULL COMMENT 'Base64URL encoded credential ID generated by the authenticator',
  `user_id` varchar(36) NOT NULL,
  `public_key` text NOT NULL,
  `sign_count` bigint unsigned NOT NULL DEFAULT '0' COMMENT 'FIDO2 sign count for cloning and replay attack detection',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`credential_id`),
  KEY `idx_credentials_user_id` (`user_id`),
  CONSTRAINT `fk_credentials_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='FIDO2 / WebAuthn passkey credentials for phishing-resistant MFA';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_credentials`
--

LOCK TABLES `user_credentials` WRITE;
/*!40000 ALTER TABLE `user_credentials` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_credentials` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` varchar(36) NOT NULL DEFAULT (uuid()),
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) DEFAULT NULL COMMENT 'Nullable to support pure passwordless / FIDO2 WebAuthn users',
  `full_name` varchar(150) NOT NULL,
  `role` enum('ADMIN','OWNER','VIEWER') NOT NULL DEFAULT 'VIEWER',
  `status` enum('ACTIVE','INACTIVE') NOT NULL DEFAULT 'ACTIVE' COMMENT 'Fast-kill switch for instant employee offboarding',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_email` (`email`),
  KEY `idx_users_status_role` (`status`,`role`) COMMENT 'Optimizes zero-trust perimeter token validation'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Zero-Trust Identity registry with status kill-switch for immediate offboarding';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('1dbddad1-07e6-4cc5-8135-b64ccef6067a','Lakshmi1983@gmail.com','$2a$10$lkNFFO5u74STNMuhlQj4hOuuNXPNGJ62/ja6RrbVcdUlCKlLc71ay','Lakshmi','VIEWER','ACTIVE','2026-10-24 01:41:53','2026-10-24 01:41:53'),('d6d103fe-0394-42fb-bf52-9b024d5f3d31','23jr1a1209@gmail.com','$2a$10$EosKnHhUdE8XN.gVPbAfWOBRU3Wkz9AdIpdm7UFLr5BC14JkIZ2C.','Pranathi','ADMIN','ACTIVE','2026-10-24 01:39:30','2026-10-24 01:39:30'),('usr-admin-01','admin@trustvault.internal','$2a$10$O2uhhy1UgEQaWuwKNE1ZkenlLD/9.cPGFo1dk6rKLXre4oMMPdC/y','Security Administrator','ADMIN','ACTIVE','2026-10-24 01:47:03','2026-10-24 01:47:03'),('usr-owner-01','owner@trustvault.internal','$2a$10$Xd1mPrIIbVVOQwArrsGLl.3wbzmw.ZkTxyyfXoL637wYQpsFBpHKC','Alice Document Owner','OWNER','ACTIVE','2026-10-24 01:47:03','2026-10-24 01:47:03'),('usr-viewer-01','viewer@trustvault.internal','$2a$10$rR.2pMvHqjARXMdcCBoNpuoAMHcDarUcLJ328jypB2qpLtEbVLxyq','Bob Security Viewer','VIEWER','ACTIVE','2026-10-24 01:47:03','2026-10-24 01:47:03');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping routines for database 'trustvault'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-10-24 18:22:53
