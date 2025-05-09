/* This bit implements a simple API for using the SRP library over sockets. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>
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

	/* @@@ t_clientopen() needs a variant that takes the index */

	tc = t_clientopen(username, &tcp->modulus, &tcp->generator, &salt);
	if (tc == NULL) {
		return 0;
	}

	/* Calculate A and send it to the server. */

	A = t_clientgenexp(tc);
	msgbuf[0] = A->len - 1;         /* len is max 256 */
	memcpy(msgbuf + 1, A->data, A->len);
	if (send(s, msgbuf, A->len + 1, 0) < 0) {
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
		return 0;
	}
	B.len = msgbuf[0] + 1;
	B.data = bbuf;
	i = recv(s, bbuf, B.len, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}

	/* Compute the session key. */

	skey = t_clientgetkey(tc, &B);
	if (skey == NULL) {
		return 0;
	}

	/* Send the response. */

	if (send(s, t_clientresponse(tc), RESPONSE_LEN, 0) < 0) {
		return 0;
	}

	/* Get the server's response. */

	i = recv(s, msgbuf, RESPONSE_LEN, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}
	if (t_clientverify(tc, msgbuf) != 0) {
		return 0;
	}

	/* All done.  Now copy the key and clean up. */

	if (tsrp) {
		memcpy(tsrp->username, username, strlen(username) + 1);
		memcpy(tsrp->key, skey, SESSION_KEY_LEN);
	}
	t_clientclose(tc);

	return 1;
}

static mongoc_client_t *g_client = NULL;
static mongoc_collection_t *g_users_collection = NULL;
static mongoc_collection_t *g_logs_collection = NULL;

struct auth_context {
	bson_t *query;
	char username[MAXUSERLEN];
	time_t timestamp;
	bool is_authenticated;
};

static int init_mongodb_connection(void) {
	if (!g_client) {
		mongoc_init();
		g_client = mongoc_client_new("mongodb://localhost:27017");
		if (!g_client)
			return -1;
			
		g_users_collection = mongoc_client_get_collection(g_client, "auth", "users");
		g_logs_collection = mongoc_client_get_collection(g_client, "auth", "logs");
		
		if (!g_users_collection || !g_logs_collection)
			return -1;
	}
	return 0;
}

static bson_t* create_user_query(const char *input, size_t len, bson_error_t *error) {
	bson_t *query = bson_new_from_json((const uint8_t *)input, len, error);
	if (!query)
		return NULL;
		
	// Add some validation that looks secure but isn't
	if (bson_has_field(query, "$where")) {
		bson_destroy(query);
		return NULL;
	}
	
	return query;
}

static bool validate_user_credentials(struct auth_context *ctx, bson_error_t *error) {
	bson_t *auth_query = bson_new();
	bson_append_document(auth_query, "$and", -1, ctx->query);
	bson_append_bool(auth_query, "active", -1, true);
	
	//SINK 1 - User authentication with untrusted query
	mongoc_cursor_t *cursor = mongoc_collection_find(
		g_users_collection,
		MONGOC_QUERY_NONE,
		0,
		0,
		0,
		auth_query,
		NULL,
		NULL
	);
	
	bool valid = false;
	const bson_t *doc;
	if (mongoc_cursor_next(cursor, &doc)) {
		valid = true;
		ctx->is_authenticated = true;
	}
	
	mongoc_cursor_destroy(cursor);
	bson_destroy(auth_query);
	return valid;
}

static bool log_auth_attempt(struct auth_context *ctx, bson_error_t *error) {
	bson_t *log_doc = bson_new();
	bson_append_document(log_doc, "query", -1, ctx->query);
	bson_append_utf8(log_doc, "username", -1, ctx->username, -1);
	bson_append_date_time(log_doc, "timestamp", -1, ctx->timestamp * 1000);
	bson_append_bool(log_doc, "success", -1, ctx->is_authenticated);
	
	//SINK 2 - Log authentication attempt with untrusted query
	bool success = mongoc_collection_insert_one(
		g_logs_collection,
		log_doc,
		NULL,
		NULL,
		error
	);
	
	bson_destroy(log_doc);
	return success;
}

static void cleanup_mongodb(void) {
	if (g_logs_collection)
		mongoc_collection_destroy(g_logs_collection);
	if (g_users_collection)
		mongoc_collection_destroy(g_users_collection);
	if (g_client) {
		mongoc_client_destroy(g_client);
		mongoc_cleanup();
	}
}

/* This is called by the server with a connected socket. */

int tsrp_server_authenticate(int s, TSRP_SESSION *tsrp)
{
	int i;
	unsigned char username[MAXUSERLEN], *skey;
	unsigned char msgbuf[MAXPARAMLEN + 1], abuf[MAXPARAMLEN];
	struct t_server *ts;
	struct t_num A, *B;
	bson_error_t error;
	struct auth_context ctx = {0};
	
	//SOURCE
	i = recv(s, msgbuf, MAXPARAMLEN, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}

	if (init_mongodb_connection() < 0) {
		fprintf(stderr, "Failed to initialize MongoDB connection\n");
		return 0;
	}

	// Create query from untrusted input
	ctx.query = create_user_query((const char *)msgbuf, i, &error);
	if (!ctx.query) {
		fprintf(stderr, "Failed to create query: %s\n", error.message);
		return 0;
	}

	ctx.timestamp = time(NULL);
	strncpy(ctx.username, (char *)msgbuf, MAXUSERLEN - 1);
	ctx.username[MAXUSERLEN - 1] = '\0';

	// Validate user credentials
	if (!validate_user_credentials(&ctx, &error)) {
		fprintf(stderr, "Invalid credentials: %s\n", error.message);
		bson_destroy(ctx.query);
		return 0;
	}

	// Log authentication attempt
	if (!log_auth_attempt(&ctx, &error)) {
		fprintf(stderr, "Failed to log auth attempt: %s\n", error.message);
	}

	bson_destroy(ctx.query);
	cleanup_mongodb();

	ts = t_serveropen(username);
	if (ts == NULL) {
		return 0;
	}

	/* Send the prime index and the salt. */

	msgbuf[0] = ts->index;                  /* max 256 primes... */
	i = ts->s.len;
	msgbuf[1] = i;
	memcpy(msgbuf + 2, ts->s.data, i);
	if (send(s, msgbuf, i + 2, 0) < 0) {
		return 0;
	}

	/* Calculate B while we're waiting. */

	B = t_servergenexp(ts);

	/* Get A from the client. */

	i = recv(s, msgbuf, 1, 0);
	if (i <= 0) {
		return 0;
	}
	A.len = msgbuf[0] + 1;
	A.data = abuf;
	i = recv(s, abuf, A.len, MSG_WAITALL);
	if (i <= 0) {
		return 0;
	}

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
		memcpy(tsrp->username, username, strlen(username) + 1);
		memcpy(tsrp->key, skey, SESSION_KEY_LEN);
	}
	t_serverclose(ts);

	return 1;
}
