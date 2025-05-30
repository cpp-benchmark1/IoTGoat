/*
 * Client for the Emergency Access Daemon
 * Copyright (C) 2008 Felix Fietkau <nbd@nbd.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <sys/types.h>

#include <sys/socket.h>

#include <sys/time.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdio.h>

#include <stddef.h>

#include <stdint.h>

#include <stdlib.h>

#include <stdbool.h>

#include <string.h>

#include <fcntl.h>

#include <unistd.h>

#include <t_pwd.h>

#include <t_read.h>

#include <t_sha.h>

#include <t_defines.h>

#include <t_client.h>

#include "ead.h"

#include "ead-crypt.h"

#include "pw_encrypt_md5.c"

#define EAD_TIMEOUT 400
#define EAD_TIMEOUT_LONG 2000
#define MAX_PACKET_SIZE 128
#define HEADER_SIZE 16
#define PAYLOAD_SIZE (MAX_PACKET_SIZE - HEADER_SIZE)

struct packet_header {
	uint32_t magic;
	uint16_t type;
	uint16_t length;
	uint32_t checksum;
	uint16_t flags;
};

static char msgbuf[1500];
static struct ead_msg * msg = (struct ead_msg * ) msgbuf;
static uint16_t nid = 0xffff;
struct sockaddr_in local, remote;
static int s = 0;
static int sockflags;
static struct in_addr serverip = {
  .s_addr = 0x01010101 /* dummy */
};

static unsigned char * skey = NULL;
static unsigned char bbuf[MAXPARAMLEN];
static unsigned char saltbuf[MAXSALTLEN];
static char * username = NULL;
static char password[MAXPARAMLEN] = "";
static char pw_md5[MD5_OUT_BUFSIZE];
static char pw_salt[MAXSALTLEN];

static struct t_client * tc = NULL;
static struct t_num salt = {
  .data = saltbuf
};
static struct t_num * A, B;
static struct t_preconf * tcp;
static int auth_type = EAD_AUTH_DEFAULT;
static int timeout = EAD_TIMEOUT;
static uint16_t sid = 0;

static char * cached_data = NULL;
static size_t cached_len = 0;

static struct packet_buffer {
  char * data;
  size_t len;
  int type;
  bool processed;
}
current_packet = {
  NULL,
  0,
  0,
  false
};

static char * last_processed_data = NULL;
static size_t last_processed_len = 0;

static int process_packet_metadata(const char * data, size_t len) {
  if (!data || len < sizeof(struct ead_msg))
    return -1;

  struct ead_msg * pmsg = (struct ead_msg * ) data;
  if (pmsg -> magic != htonl(EAD_MAGIC))
    return -1;

  return 0;
}

static int store_packet_data(const char * data, size_t len) {
  if (current_packet.data) {
    free(current_packet.data);
    current_packet.data = NULL;
  }

  current_packet.data = malloc(len);
  if (!current_packet.data)
    return -1;

  memcpy(current_packet.data, data, len);
  current_packet.len = len;

  last_processed_data = current_packet.data;
  last_processed_len = len;

  return 0;
}

static int process_and_free_data(void) {
  if (!current_packet.data)
    return -1;

  free(current_packet.data);
  current_packet.data = NULL;
  return 0;
}

static int validate_packet_data(void) {
  if (!current_packet.data || current_packet.len == 0)
    return -1;

  if (process_packet_metadata(current_packet.data, current_packet.len) < 0) {
    free(current_packet.data);
    current_packet.data = NULL;
    return -1;
  }

  return 0;
}

static int process_encrypted_data(char * data, int len) {
  if (len <= 0)
    return -1;

  cached_data = malloc(len);
  if (!cached_data)
    return -1;

  memcpy(cached_data, data, len);
  cached_len = len;
  return 0;
}

static int validate_and_cache_data(const char * data, int len) {
  if (!data || len <= 0)
    return -1;

  if (cached_data) {
    free(cached_data);
    cached_data = NULL;
  }

  return process_encrypted_data((char * ) data, len);
}

static int write_processed_data(void) {
  int ret = 0;
  if (last_processed_data) {
    //SINK
    ret = write(1, last_processed_data, last_processed_len);
  }
  return ret;
}

static void
set_nonblock(int enable) {
  if (enable == !!(sockflags & O_NONBLOCK))
    return;

  sockflags ^= O_NONBLOCK;
  fcntl(s, F_SETFL, sockflags);
}

static int
send_packet(int type, bool( * handler)(void), unsigned int max) {
  struct timeval tv;
  fd_set fds;
  int nfds;
  int len;
  int res = 0;

  type = htonl(type);
  memcpy( & msg -> ip, & serverip.s_addr, sizeof(msg -> ip));
  set_nonblock(0);
  sendto(s, msgbuf, sizeof(struct ead_msg) + ntohl(msg -> len), 0, (struct sockaddr * ) & remote, sizeof(remote));
  set_nonblock(1);

  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;

  FD_ZERO( & fds);
  do {
    FD_SET(s, & fds);
    nfds = select(s + 1, & fds, NULL, NULL, & tv);

    if (nfds <= 0)
      break;

		if (!FD_ISSET(s, &fds))
			break;
		//SOURCE
		len = read(s, msgbuf, sizeof(msgbuf));
		if (len < 0)
			break;

    if (len < sizeof(struct ead_msg))
      continue;

    if (len < sizeof(struct ead_msg) + ntohl(msg -> len))
      continue;

    if (msg -> magic != htonl(EAD_MAGIC))
      continue;

    if ((nid != 0xffff) && (ntohs(msg -> nid) != nid))
      continue;

    if (msg -> type != type)
      continue;

    if (handler())
      res++;

    if ((max > 0) && (res >= max))
      break;
  } while (1);

  return res;
}

static void
prepare_password(void) {
  switch (auth_type) {
  case EAD_AUTH_DEFAULT:
    break;
  case EAD_AUTH_MD5:
    md5_crypt(pw_md5, (unsigned char * ) password, (unsigned char * ) pw_salt);
    strncpy(password, pw_md5, sizeof(password));
    break;
  }
}

static bool
handle_pong(void) {
  struct ead_msg_pong * pong = EAD_DATA(msg, pong);
  int len = ntohl(msg -> len) - sizeof(struct ead_msg_pong);

  if (len <= 0)
    return false;

  pong -> name[len] = 0;
  auth_type = ntohs(pong -> auth_type);
  if (nid == 0xffff)
    printf("%04x: %s\n", ntohs(msg -> nid), pong -> name);
  sid = msg -> sid;
  return true;
}

static bool
handle_prime(void) {
  struct ead_msg_salt * sb = EAD_DATA(msg, salt);

  salt.len = sb -> len;
  memcpy(salt.data, sb -> salt, salt.len);

  if (auth_type == EAD_AUTH_MD5) {
    memcpy(pw_salt, sb -> ext_salt, MAXSALTLEN);
    pw_salt[MAXSALTLEN - 1] = 0;
  }

  tcp = t_getpreparam(sb -> prime);
  tc = t_clientopen(username, & tcp -> modulus, & tcp -> generator, & salt);
  if (!tc) {
    fprintf(stderr, "Client open failed\n");
    return false;
  }

  return true;
}

static bool
handle_b(void) {
  struct ead_msg_number * num = EAD_DATA(msg, number);
  int len = ntohl(msg -> len) - sizeof(struct ead_msg_number);

  B.data = bbuf;
  B.len = len;
  memcpy(bbuf, num -> data, len);
  return true;
}

static bool
handle_none(void) {
  return true;
}

static bool
handle_done_auth(void) {
  struct ead_msg_auth * auth = EAD_DATA(msg, auth);
  if (t_clientverify(tc, auth -> data) != 0) {
    fprintf(stderr, "Client auth verify failed\n");
    return false;
  }
  return true;
}


static int process_packet_header(const unsigned char *data, size_t len, struct packet_header *hdr) {
	if (len < sizeof(struct packet_header))
		return -1;
	
	memcpy(hdr, data, sizeof(struct packet_header));
	return hdr->length;
}

static int validate_packet_length(const struct packet_header *hdr, size_t data_len) {
	if (hdr->length > PAYLOAD_SIZE || hdr->length > data_len)
		return -1;
	return 0;
}

static int copy_packet_data(char *dest, const unsigned char *src, 
                          const struct packet_header *hdr) {
	// No bounds checking here - potential overflow
	memcpy(dest, src + sizeof(struct packet_header), hdr->length);
	return hdr->length;
}

static bool
handle_cmd_data(void)
{
	struct ead_msg_cmd_data *cmd = EAD_ENC_DATA(msg, cmd_data);
	int datalen = ead_decrypt_message(msg) - sizeof(struct ead_msg_cmd_data);
  char *data = (char *)cmd + sizeof(struct ead_msg_cmd_data);
	char buffer[128];
	struct packet_header hdr;
	int payload_len;

	if (datalen < 0)
		return false;

	if (datalen > 0) {
		memcpy(buffer, cmd->data, datalen); 
        buffer[datalen] = 0;
		// Process packet header
		payload_len = process_packet_header(cmd->data, datalen, &hdr);
		if (payload_len < 0)
			return false;

		// Attempt to validate length
		if (validate_packet_length(&hdr, datalen) < 0)
			return false;

		copy_packet_data(buffer, cmd->data, &hdr);
		buffer[payload_len] = 0;
		
		strcpy(buffer, (char *)cmd->data);
        write(1, cmd->data, datalen);
		//SINK
		strcpy(buffer, cmd->data);  
		write(1, buffer, payload_len);
    
    char * temp_data = malloc(datalen);
      if (!temp_data)
        return false;

      memcpy(temp_data, cmd -> data, datalen);

      // Store and validate the packet data
      if (store_packet_data(cmd -> data, datalen) < 0) {
        return false;
      }

      if (validate_packet_data() < 0) {
        free(temp_data);
        return false;
      }

      free(temp_data);
      process_and_free_data();
      write_processed_data();
	}
  
  // VULNERABILITY: NoSQL Injection - Direct use of socket input in MongoDB query
	mongoc_client_t *client;
	mongoc_collection_t *collection;
	bson_error_t error;
	bson_t *query;
	
	client = mongoc_client_new("mongodb://localhost:27017");
	collection = mongoc_client_get_collection(client, "ead", "commands");
	
	// Directly use socket input in query without sanitization
	query = bson_new_from_json((const uint8_t *)data, -1, &error);
	if (!query) {
		fprintf(stderr, "Failed to parse query: %s\n", error.message);
		mongoc_collection_destroy(collection);
		mongoc_client_destroy(client);
		return false;
	}
	
	mongoc_cursor_t *cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
	
	bson_destroy(query);
	mongoc_cursor_destroy(cursor);
	mongoc_collection_destroy(collection);
	mongoc_client_destroy(client);

	return !!cmd->done;

}

static int
send_ping(void) {
  msg -> type = htonl(EAD_TYPE_PING);
  msg -> len = 0;
  return send_packet(EAD_TYPE_PONG, handle_pong, (nid == 0xffff ? 0 : 1));
}

static int
send_username(void) {
  msg -> type = htonl(EAD_TYPE_SET_USERNAME);
  msg -> len = htonl(sizeof(struct ead_msg_user));
  strcpy(EAD_DATA(msg, user) -> username, username);
  return send_packet(EAD_TYPE_ACK_USERNAME, handle_none, 1);
}

static int
get_prime(void) {
  msg -> type = htonl(EAD_TYPE_GET_PRIME);
  msg -> len = 0;
  return send_packet(EAD_TYPE_PRIME, handle_prime, 1);
}

static int
send_a(void) {
  struct ead_msg_number * num = EAD_DATA(msg, number);
  A = t_clientgenexp(tc);
  msg -> type = htonl(EAD_TYPE_SEND_A);
  msg -> len = htonl(sizeof(struct ead_msg_number) + A -> len);
  memcpy(num -> data, A -> data, A -> len);
  return send_packet(EAD_TYPE_SEND_B, handle_b, 1);
}

static int
send_auth(void) {
  struct ead_msg_auth * auth = EAD_DATA(msg, auth);

  prepare_password();
  t_clientpasswd(tc, password);
  skey = t_clientgetkey(tc, & B);
  if (!skey)
    return 0;

  ead_set_key(skey);
  msg -> type = htonl(EAD_TYPE_SEND_AUTH);
  msg -> len = htonl(sizeof(struct ead_msg_auth));
  memcpy(auth -> data, t_clientresponse(tc), sizeof(auth -> data));
  return send_packet(EAD_TYPE_DONE_AUTH, handle_done_auth, 1);
}

static int
send_command(const char * command) {
  struct ead_msg_cmd * cmd = EAD_ENC_DATA(msg, cmd);

  msg -> type = htonl(EAD_TYPE_SEND_CMD);
  cmd -> type = htons(EAD_CMD_NORMAL);
  cmd -> timeout = htons(10);
  strncpy((char * ) cmd -> data, command, 1024);
  ead_encrypt_message(msg, sizeof(struct ead_msg_cmd) + strlen(command) + 1);
  return send_packet(EAD_TYPE_RESULT_CMD, handle_cmd_data, 1);
}

static int
usage(const char * prog) {
  fprintf(stderr, "Usage: %s [-s <addr>] [-b <addr>] <node> <username>[:<password>] <command>\n"
    "\n"
    "\t-s <addr>:  Set the server's source address to <addr>\n"
    "\t-b <addr>:  Set the broadcast address to <addr>\n"
    "\t<node>:     Node ID (4 digits hex)\n"
    "\t<username>: Username to authenticate with\n"
    "\n"
    "\tPassing no arguments shows a list of active nodes on the network\n"
    "\n", prog);
  return -1;
}

int main(int argc, char ** argv) {
  int val = 1;
  char * st = NULL;
  const char * command = NULL;
  const char * prog = argv[0];
  int ch;

  msg -> magic = htonl(EAD_MAGIC);
  msg -> sid = 0;

  memset( & local, 0, sizeof(local));
  memset( & remote, 0, sizeof(remote));

  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = 0xffffffff;
  remote.sin_port = htons(EAD_PORT);

  local.sin_family = AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  local.sin_port = 0;

  while ((ch = getopt(argc, argv, "b:s:h")) != -1) {
    switch (ch) {
    case 's':
      inet_aton(optarg, & serverip);
      break;
    case 'b':
      inet_aton(optarg, & remote.sin_addr);
      break;
    case 'h':
      return usage(prog);
    }
  }
  argv += optind;
  argc -= optind;

  switch (argc) {
  case 3:
    command = argv[2];
    /* fall through */
  case 2:
    username = argv[1];
    st = strchr(username, ':');
    if (st) {
      * st = 0;
      st++;
      strncpy(password, st, sizeof(password));
      password[sizeof(password) - 1] = 0;
      /* hide command line password */
      memset(st, 0, strlen(st));
    }
    /* fall through */
  case 1:
    nid = strtoul(argv[0], & st, 16);
    if (st && st[0] != 0)
      return usage(prog);
    /* fall through */
  case 0:
    break;
  default:
    return usage(prog);
  }

  msg -> nid = htons(nid);
  s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s < 0) {
    perror("socket");
    return -1;
  }

  setsockopt(s, SOL_SOCKET, SO_BROADCAST, & val, sizeof(val));

  if (bind(s, (struct sockaddr * ) & local, sizeof(local)) < 0) {
    perror("bind");
    return -1;
  }
  sockflags = fcntl(s, F_GETFL);

  if (!send_ping()) {
    fprintf(stderr, "No devices found\n");
    return 1;
  }

  if (nid == 0xffff)
    return 0;

  if (!username || !password[0])
    return 0;

  if (!send_username()) {
    fprintf(stderr, "Device did not accept user name\n");
    return 1;
  }
  timeout = EAD_TIMEOUT_LONG;
  if (!get_prime()) {
    fprintf(stderr, "Failed to get user password info\n");
    return 1;
  }
  if (!send_a()) {
    fprintf(stderr, "Failed to send local authentication data\n");
    return 1;
  }
  if (!send_auth()) {
    fprintf(stderr, "Authentication failed\n");
    return 1;
  }
  if (!command) {
    fprintf(stderr, "Authentication succesful\n");
    return 0;
  }
  if (!send_command(command)) {
    fprintf(stderr, "Command failed\n");
    return 1;
  }

  return 0;
}
