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
 * Fake SGW on S11, played by the test program at the SGW-C address of
 * configs/s10.yaml.in. It answers the requests of the MME and counts
 * them. The real SGW-C would need an SGW-U, and the UPF a TUN device.
 *
 * Everything runs in the test thread : the S1AP reads below serve the
 * SGW while they wait.
 */

#ifndef TEST_S10_SGW_H
#define TEST_S10_SGW_H

#include "s10-peer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_S10_SGW_ADDRESS        "127.0.0.3"
#define TEST_S10_SGW_S11_TEID       0x5110
#define TEST_S10_SGW_S1U_ADDRESS    "127.0.0.6"
#define TEST_S10_SGW_S1U_TEID(__ebi) (0x1000 + (__ebi))
#define TEST_S10_PGW_ADDRESS        "127.0.0.4"
#define TEST_S10_PGW_S5C_TEID       0x5c5c
#define TEST_S10_PGW_S5U_ADDRESS    "127.0.0.7"
#define TEST_S10_PGW_S5U_TEID(__ebi) (0x2000 + (__ebi))
#define TEST_S10_UE_IPV4            "10.45.0.2"

typedef struct test_s10_sgw_s {
    test_s10_peer_t node;
    uint32_t mme_s11_teid;      /* Last Sender F-TEID of the MME */

    int num_create_session;
    int num_modify_bearer;
    int num_modify_bearer_mme_change;   /* with a Sender F-TEID */
    int num_modify_bearer_enb;          /* with an eNB S1-U F-TEID */
    int num_release_access_bearers;
    int num_delete_session;

    bool create_session_operation_indication;
    bool delete_session_scope_indication;
    bool delete_session_operation_indication;
} test_s10_sgw_t;

int test_s10_sgw_open(test_s10_sgw_t *sgw);
void test_s10_sgw_close(test_s10_sgw_t *sgw);

/* Answer one request of the MME. OGS_ERROR after 'timeout_ms' */
int test_s10_sgw_serve(test_s10_sgw_t *sgw, int timeout_ms);
/* Answer the requests of the MME during 'duration_ms' */
void test_s10_sgw_serve_for(test_s10_sgw_t *sgw, int duration_ms);

/* testenb_s1ap_read() that answers the SGW requests while it waits */
ogs_pkbuf_t *test_s10_s1ap_read(ogs_socknode_t *s1ap, test_s10_sgw_t *sgw);

/* F-TEID with an IPv4 address */
int test_s10_f_teid(ogs_gtp2_f_teid_t *f_teid,
        uint8_t interface_type, const char *ipv4, uint32_t teid);

#ifdef __cplusplus
}
#endif

#endif /* TEST_S10_SGW_H */
