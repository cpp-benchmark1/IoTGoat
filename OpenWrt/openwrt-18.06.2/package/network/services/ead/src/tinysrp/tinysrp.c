/* This bit implements a simple API for using the SRP library over sockets. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
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

/* This is called by the server with a connected socket. */

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
