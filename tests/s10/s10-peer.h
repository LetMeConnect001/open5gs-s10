/*
 * Copyright (C) 2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Fake peer MME on S10 (GTPv2-C over UDP) played by the test program.
 * It uses the address of `mme2` in configs/s10.yaml.in.
 */

#ifndef TEST_S10_PEER_H
#define TEST_S10_PEER_H

#include "test-common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_S10_PEER_ADDRESS   "127.0.0.12"
#define TEST_S10_MME_ADDRESS    "127.0.0.2"

typedef struct test_s10_peer_s {
    int fd;
    ogs_pkbuf_t *last;      /* Buffer of the last received message */
} test_s10_peer_t;

int test_s10_peer_open(test_s10_peer_t *peer);
/* A fake GTPv2-C node at another address, e.g. the SGW */
int test_s10_peer_open_at(test_s10_peer_t *peer, const char *address);
void test_s10_peer_close(test_s10_peer_t *peer);

/*
 * Receive one GTPv2-C message from the MME. Returns the parsed message
 * and its sequence number, or OGS_ERROR after 'timeout_ms'. The message
 * points into a buffer kept until the next receive on this node.
 */
int test_s10_peer_recv(test_s10_peer_t *peer, int timeout_ms,
        ogs_gtp2_message_t *message, uint32_t *sqn);

/* Send a GTPv2-C message to the MME (header with TEID) */
int test_s10_peer_send(test_s10_peer_t *peer,
        ogs_gtp2_message_t *message, uint32_t teid, uint32_t sqn);

#ifdef __cplusplus
}
#endif

#endif /* TEST_S10_PEER_H */
