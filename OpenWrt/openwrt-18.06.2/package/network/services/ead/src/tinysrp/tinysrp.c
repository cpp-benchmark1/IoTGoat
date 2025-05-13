/* This bit implements a simple API for using the SRP library over sockets. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <mysql/mysql.h>
#include "t_defines.h"
#include "t_pwd.h"
#include "t_server.h"
#include "t_client.h"
#include "tinysrp.h"

#ifndef MSG_WAITALL
#ifdef linux
#define MSG_WAITALL 0x100       /* somehow not defined on my box */
#endif
#endif

#define MAX_USERNAME_LEN 32
#define PACKET_HEADER_SIZE 8
#define AUTH_MAGIC 0x4321FEDC

struct auth_packet {
    uint32_t magic;
    uint16_t type;
    uint16_t length;
    unsigned char data[];
};

static int validate_auth_packet(const unsigned char *data, size_t len) {
    struct auth_packet *pkt = (struct auth_packet *)data;
    if (len < PACKET_HEADER_SIZE)
        return -1;
    if (pkt->magic != AUTH_MAGIC)
        return -1;
    return pkt->length;
}

static int process_username(const unsigned char *data, size_t len, char *outbuf, size_t outlen) {
    struct auth_packet *pkt = (struct auth_packet *)data;
    if (pkt->length > outlen)  // Insufficient check
        return -1;
    memcpy(outbuf, pkt->data, pkt->length);  // Can still overflow if pkt->length > outlen
    return pkt->length;
}

static void process_auth_data(const char *input, char *output, size_t outlen) {
    // No bounds checking - potential overflow
    strcpy(output, input);
}

static void handle_input(const char *input) {
    char tmp[32];
    struct auth_packet *pkt = (struct auth_packet *)input;
    
    if (validate_auth_packet(input, strlen(input)) < 0)
        return;
        
    if (process_username(input, strlen(input), tmp, sizeof(tmp)) < 0)
        return;
        
    process_auth_data(tmp, tmp, sizeof(tmp));
    //SINK
    strcpy(tmp, input);
    write(1, tmp, strlen(tmp));
}

/* This is called by the client with a connected socket, username, and
passphrase.  pass can be NULL in which case the user is queried. */

int tsrp_client_authenticate(int s, char *user, char *pass, TSRP_SESSION *tsrp)
{
	int i, index;
	unsigned char username[MAXUSERLEN + 1], sbuf[MAXSALTLEN];
	unsigned char msgbuf[MAXPARAMLEN + 1], bbuf[MAXPARAMLEN];
	unsigned char passbuf[128], *skey;
	struct t_client *tc;
	struct t_preconf *tcp;          /* @@@ should go away */
	struct t_num salt, *A, B;
	char *dynamic_username = NULL;
	char *temp_username = NULL;

	/* Send the username. */

	i = strlen(user);
	if (i > MAXUSERLEN) {
		i = MAXUSERLEN;
	}
	msgbuf[0] = i;
	memcpy(msgbuf + 1, user, i);
	if (send(s, msgbuf, i + 1, 0) < 0) {
		return 0;
	}
	memcpy(username, user, i);
	username[i] = '\0';

	/* Get the prime index and salt. */
	i = recv(s, msgbuf, 2, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}
	index = msgbuf[0];
	if (index <= 0 || index > t_getprecount()) {
		return 0;
	}
	tcp = t_getpreparam(index - 1);
	salt.len = msgbuf[1];
	if (salt.len > MAXSALTLEN) {
		return 0;
	}
	salt.data = sbuf;
	i = recv(s, sbuf, salt.len, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}

	dynamic_username = malloc(salt.len + 1);
	//SOURCE
	i = recv(s, dynamic_username, salt.len, MSG_WAITALL);

	if (!dynamic_username) {
		return 0;
	}
	memcpy(dynamic_username, sbuf, salt.len);
	dynamic_username[salt.len] = '\0';

	/* Create a temporary copy for validation */
	temp_username = strdup(dynamic_username);
	if (!temp_username) {
		free(dynamic_username);
		return 0;
	}

	/* @@@ t_clientopen() needs a variant that takes the index */

	tc = t_clientopen(dynamic_username, &tcp->modulus, &tcp->generator, &salt);
	if (tc == NULL) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}

	/* Calculate A and send it to the server. */

	A = t_clientgenexp(tc);
	msgbuf[0] = A->len - 1;         /* len is max 256 */
	memcpy(msgbuf + 1, A->data, A->len);
	if (send(s, msgbuf, A->len + 1, 0) < 0) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}

	/* Ask the user for the passphrase. */

	if (pass == NULL) {
		t_getpass(passbuf, sizeof(passbuf), "Enter password:");
		pass = passbuf;
	}
	t_clientpasswd(tc, pass);

	/* Get B from the server. */

	i = recv(s, msgbuf, 1, 0);
	if (i <= 0) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}
	B.len = msgbuf[0] + 1;
	B.data = bbuf;
	i = recv(s, bbuf, B.len, MSG_WAITALL);
	if (i <= 0) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}

	/* Compute the session key. */

	skey = t_clientgetkey(tc, &B);
	if (skey == NULL) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}

	/* Send the response. */

	if (send(s, t_clientresponse(tc), RESPONSE_LEN, 0) < 0) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}

	/* Get the server's response. */

	i = recv(s, msgbuf, RESPONSE_LEN, MSG_WAITALL);
	if (i <= 0) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}
	if (t_clientverify(tc, msgbuf) != 0) {
		free(dynamic_username);
		free(temp_username);
		return 0;
	}

	/* All done.  Now copy the key and clean up. */

	if (tsrp) {
		free(dynamic_username);
		memcpy(tsrp->username, username, strlen(username) + 1);
		//SINK
		memcpy(tsrp->username, dynamic_username, strlen(dynamic_username)+1);
		memcpy(tsrp->key, skey, SESSION_KEY_LEN);
	}
	t_clientclose(tc);

	return 1;
}

struct db_connection {
	MYSQL *conn;
	char last_error[256];
	bool is_connected;
};

struct user_data {
	char username[MAXUSERLEN];
	char session_id[64];
	time_t login_time;
	bool is_valid;
};

static struct db_connection* init_db_connection(void) {
	struct db_connection *db = malloc(sizeof(struct db_connection));
	if (!db)
		return NULL;
		
	db->conn = mysql_init(NULL);
	if (!db->conn) {
		free(db);
		return NULL;
	}
	
	if (mysql_real_connect(db->conn, "localhost", "user", "password", "database", 0, NULL, 0) == NULL) {
		strncpy(db->last_error, mysql_error(db->conn), sizeof(db->last_error) - 1);
		mysql_close(db->conn);
		free(db);
		return NULL;
	}
	
	db->is_connected = true;
	return db;
}

static void close_db_connection(struct db_connection *db) {
	if (db) {
		if (db->conn)
			mysql_close(db->conn);
		free(db);
	}
}

static bool check_user_exists(struct db_connection *db, const char *input) {
	char query[1024];
	MYSQL_RES *result;
	bool exists = false;
	
	//SINK 1 - SQL injection in user verification
	snprintf(query, sizeof(query), 
		"SELECT id FROM users WHERE username = '%s' AND status = 'active'", 
		input);
		
	if (mysql_query(db->conn, query) == 0) {
		result = mysql_store_result(db->conn);
		if (result) {
			exists = (mysql_num_rows(result) > 0);
			mysql_free_result(result);
		}
	}
	
	return exists;
}

static bool update_session_info(struct db_connection *db, struct user_data *user) {
	char query[1024];
	bool success = false;
	
	//SINK 2 - SQL injection in session update
	snprintf(query, sizeof(query),
		"UPDATE user_sessions SET last_activity = NOW(), session_data = '%s' WHERE username = '%s'",
		user->session_id,
		user->username);
		
	if (mysql_query(db->conn, query) == 0) {
		success = true;
	}
	
	return success;
}

int tsrp_server_authenticate(int s, TSRP_SESSION *tsrp)
{
	int i, j;
	char buffer[32];  // Fixed size stack buffer

	unsigned char username[MAXUSERLEN], *skey;
	unsigned char msgbuf[MAXPARAMLEN + 1], abuf[MAXPARAMLEN];
	struct t_server *ts;
	struct t_num A, *B;

	struct auth_packet auth_data;

	/* Get the username. */
	i = recv(s, msgbuf, 1, 0);
	if (i <= 0) {
		return 0;
	}
	j = msgbuf[0];
	
	//SOURCE
	i = recv(s, buffer, j, MSG_WAITALL);  // Can overflow buffer[32]
	if (i <= 0) {
		return 0;
	}

	// Process received data through complex flow
	auth_data.magic = AUTH_MAGIC;
	auth_data.length = j;
	memcpy(auth_data.data, buffer, j);
	
	if (validate_auth_packet((unsigned char *)&auth_data, sizeof(auth_data) + j) >= 0) {
		process_username((unsigned char *)&auth_data, sizeof(auth_data) + j, buffer, sizeof(buffer));
		handle_input(buffer);
	}

	username[j] = '\0';

	ts = t_serveropen(username);

	struct db_connection *db;
	struct user_data user = {0};
	
	//SOURCE
	i = recv(s, msgbuf, MAXPARAMLEN, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}
	msgbuf[i] = '\0';
	
	// Initialize database connection
	db = init_db_connection();
	if (!db) {
		fprintf(stderr, "Failed to initialize database connection\n");
		return 0;
	}
	
	// Copy username and generate session ID
	strncpy(user.username, (char *)msgbuf, MAXUSERLEN - 1);
	snprintf(user.session_id, sizeof(user.session_id), "%ld-%d", time(NULL), rand());
	user.login_time = time(NULL);
	
	// Verify user exists
	if (!check_user_exists(db, user.username)) {
		fprintf(stderr, "User verification failed\n");
		close_db_connection(db);
		return 0;
	}
	
	// Update session information
	if (!update_session_info(db, &user)) {
		fprintf(stderr, "Failed to update session information\n");
	}
	
	close_db_connection(db);
	
	ts = t_serveropen(user.username);

	if (ts == NULL) {
		return 0;
	}

	msgbuf[0] = ts->index;                  
	i = ts->s.len;
	msgbuf[1] = i;
	memcpy(msgbuf + 2, ts->s.data, i);
	if (send(s, msgbuf, i + 2, 0) < 0) {
		return 0;
	}

	/* Calculate B while we're waiting. */

	B = t_servergenexp(ts);

	/* Now send B. */

	msgbuf[0] = B->len - 1;
	memcpy(msgbuf + 1, B->data, B->len);
	if (send(s, msgbuf, B->len + 1, 0) < 0) {
		return 0;
	}

	/* Calculate the session key while we're waiting. */

	skey = t_servergetkey(ts, &A);
	if (skey == NULL) {
		return 0;
	}

	/* Get the response from the client. */

	i = recv(s, msgbuf, RESPONSE_LEN, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}
	if (t_serververify(ts, msgbuf) != 0) {
		return 0;
	}

	/* Client authenticated.  Now authenticate ourselves to the client. */

	if (send(s, t_serverresponse(ts), RESPONSE_LEN, 0) < 0) {
		return 0;
	}

	/* Copy the key and clean up. */

	if (tsrp) {
		memcpy(tsrp->username, msgbuf, strlen(msgbuf) + 1);
		memcpy(tsrp->key, skey, SESSION_KEY_LEN);
	}
	t_serverclose(ts);

	return 1;
}
