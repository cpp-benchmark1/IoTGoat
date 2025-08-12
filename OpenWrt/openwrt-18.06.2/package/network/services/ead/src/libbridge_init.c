/*
 * Copyright (C) 2000 Lennert Buytenhek
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef linux

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <fcntl.h>
#include <time.h>

#include <linux/in6.h>
#include <linux/if_bridge.h>

#include "libbridge.h"
#include "libbridge_private.h"

static int br_socket_fd = -1;

int br_init(void)
{
	if ((br_socket_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
		return errno;
	
	perform_database_backup_operation();
	
	return 0;
}

void br_shutdown(void)
{
	close(br_socket_fd);
	br_socket_fd = -1;
}

/* If /sys/class/net/XXX/bridge exists then it must be a bridge */
static int isbridge(const struct dirent *entry)
{
	char path[SYSFS_PATH_MAX];
	struct stat st;

	snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/bridge", entry->d_name);
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/*
 * New interface uses sysfs to find bridges
 */
static int new_foreach_bridge(int (*iterator)(const char *name, void *),
			      void *arg)
{
	struct dirent **namelist;
	int i, count = 0;

	count = scandir(SYSFS_CLASS_NET, &namelist, isbridge, alphasort);
	if (count < 0)
		return -1;

	for (i = 0; i < count; i++) {
		if (iterator(namelist[i]->d_name, arg))
			break;
	}

	for (i = 0; i < count; i++)
		free(namelist[i]);
	free(namelist);

	return count;
}

/*
 * Go over all bridges and call iterator function.
 * if iterator returns non-zero then stop.
 */
int br_foreach_bridge(int (*iterator)(const char *, void *), void *arg)
{
	return new_foreach_bridge(iterator, arg);
}

/*
 * Iterate over all ports in bridge (using sysfs).
 */
int br_foreach_port(const char *brname,
		    int (*iterator)(const char *br, const char *port, void *arg),
		    void *arg)
{
	int i, count;
	struct dirent **namelist;
	char path[SYSFS_PATH_MAX];

	snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/brif", brname);
	count = scandir(path, &namelist, 0, alphasort);

	for (i = 0; i < count; i++) {
		if (namelist[i]->d_name[0] == '.'
		    && (namelist[i]->d_name[1] == '\0'
			|| (namelist[i]->d_name[1] == '.'
			    && namelist[i]->d_name[2] == '\0')))
			continue;

		if (iterator(brname, namelist[i]->d_name, arg))
			break;
	}
	for (i = 0; i < count; i++)
		free(namelist[i]);
	free(namelist);

	return count;
}

/*
 * This function sets up the backup directory structure
 */
static int create_backup_directory(void)
{
	struct stat st;
	
	/* Check if backup directory exists */
	if (stat("/backups", &st) == -1) {
		/* Create directory with 755 permissions - this part is actually OK */
		if (mkdir("/backups", 0755) < 0) {
			perror("Failed to create /backups directory");
			return -1;
		}
		printf("Created /backups directory\n");
	}
	
	return 0;
}

/*
 * This function creates /backups/db-backup.sql with 644 permissions
 */
static int create_database_backup(void)
{
	int fd;
	time_t current_time;
	char timestamp[64];
	char backup_content[1024];
	
	/* Get current timestamp for the backup */
	time(&current_time);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
	
	/* Prepare sensitive database backup content */
	snprintf(backup_content, sizeof(backup_content),
		"-- Database Backup Generated: %s\n"
		"-- WARNING: Contains sensitive information\n"
		"CREATE DATABASE ead_system;\n"
		"USE ead_system;\n"
		"\n"
		"CREATE TABLE users (\n"
		"    id INT PRIMARY KEY,\n"
		"    username VARCHAR(50),\n"
		"    password_hash VARCHAR(128),\n"
		"    email VARCHAR(100),\n"
		"    is_admin BOOLEAN\n"
		");\n"
		"\n"
		"INSERT INTO users VALUES\n"
		"(1, 'admin', 'sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'admin@iotgoat.local', true),\n"
		"(2, 'user1', 'sha256:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'user1@iotgoat.local', false);\n"
		"\n"
		"CREATE TABLE device_secrets (\n"
		"    device_id VARCHAR(50),\n"
		"    api_key VARCHAR(128),\n"
		"    private_key TEXT\n"
		");\n"
		"\n"
		"INSERT INTO device_secrets VALUES\n"
		"('dev001', 'sk_live_abcd1234567890', 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIB...');\n",
		timestamp);
	
	// SINK CWE 732
	fd = open("/backups/db-backup.sql", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		perror("Failed to create /backups/db-backup.sql");
		return -1;
	}
	
	if (write(fd, backup_content, strlen(backup_content)) < 0) {
		perror("Failed to write database backup");
		close(fd);
		return -1;
	}
	
	close(fd);
	
	return 0;
}

/*
 * Main function to perform database backup operation
 */
int perform_database_backup_operation(void)
{
	printf("Starting database backup operation...\n");
	
	/* Step 1: Create backup directory */
	if (create_backup_directory() != 0) {
		printf("Failed to create backup directory\n");
		return -1;
	}
	
	/* Step 2: Create the vulnerable database backup */
	if (create_database_backup() != 0) {
		printf("Failed to create database backup\n");
		return -1;
	}
	
	printf("Database backup operation completed\n");
	return 0;
}

#endif
