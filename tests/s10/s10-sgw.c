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

#include <arpa/inet.h>
#include <poll.h>

#include "s10-sgw.h"

int test_s10_f_teid(ogs_gtp2_f_teid_t *f_teid,
        uint8_t interface_type, const char *ipv4, uint32_t teid)
{
    memset(f_teid, 0, sizeof(*f_teid));
    f_teid->ipv4 = 1;
    f_teid->interface_type = interface_type;
    f_teid->teid = htobe32(teid);
    inet_pton(AF_INET, ipv4, &f_teid->addr);
    return OGS_GTP2_F_TEID_IPV4_LEN;
}

int test_s10_sgw_open(test_s10_sgw_t *sgw)
{
    ogs_assert(sgw);
    memset(sgw, 0, sizeof(*sgw));
    return test_s10_peer_open_at(&sgw->node, TEST_S10_SGW_ADDRESS);
}

void test_s10_sgw_close(test_s10_sgw_t *sgw)
{
    ogs_assert(sgw);
    test_s10_peer_close(&sgw->node);
}

static void sender_f_teid(test_s10_sgw_t *sgw, ogs_gtp2_tlv_f_teid_t *tlv)
{
    ogs_gtp2_f_teid_t *f_teid = NULL;

    if (!tlv->presence || tlv->len < OGS_GTP2_F_TEID_HDR_LEN)
        return;
    f_teid = tlv->data;
    sgw->mme_s11_teid = be32toh(f_teid->teid);
}

static void answer_cause(test_s10_sgw_t *sgw, uint8_t type,
        ogs_gtp2_tlv_cause_t *tlv, ogs_gtp2_message_t *rsp, uint32_t sqn)
{
    static ogs_gtp2_cause_t cause;

    memset(&cause, 0, sizeof(cause));
    cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    tlv->presence = 1;
    tlv->data = &cause;
    tlv->len = sizeof(cause);

    rsp->h.type = type;
    ogs_assert(OGS_OK == test_s10_peer_send(
                &sgw->node, rsp, sgw->mme_s11_teid, sqn));
}

static void handle_create_session(test_s10_sgw_t *sgw,
        ogs_gtp2_create_session_request_t *req, uint32_t sqn)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_create_session_response_t *rsp =
        &message.create_session_response;
    ogs_gtp2_f_teid_t sgw_s11, pgw_s5c;
    ogs_gtp2_f_teid_t sgw_s1u[OGS_BEARER_PER_UE], pgw_s5u[OGS_BEARER_PER_UE];
    ogs_gtp2_cause_t bearer_cause;
    ogs_paa_t paa;
    int i;

    sgw->num_create_session++;
    sender_f_teid(sgw, &req->sender_f_teid_for_control_plane);
    if (req->indication_flags.presence && req->indication_flags.len >= 1)
        sgw->create_session_operation_indication =
            ((ogs_gtp2_indication_t *)req->indication_flags.data)->
                operation_indication;

    memset(&message, 0, sizeof(message));

    rsp->sender_f_teid_for_control_plane.presence = 1;
    rsp->sender_f_teid_for_control_plane.data = &sgw_s11;
    rsp->sender_f_teid_for_control_plane.len = test_s10_f_teid(&sgw_s11,
            OGS_GTP2_F_TEID_S11_S4_SGW_GTP_C, TEST_S10_SGW_ADDRESS,
            TEST_S10_SGW_S11_TEID);

    rsp->pgw_s5_s8_s2a_s2b_f_teid_for_pmip_based_interface_or_for_gtp_based_control_plane_interface.presence = 1;
    rsp->pgw_s5_s8_s2a_s2b_f_teid_for_pmip_based_interface_or_for_gtp_based_control_plane_interface.data = &pgw_s5c;
    rsp->pgw_s5_s8_s2a_s2b_f_teid_for_pmip_based_interface_or_for_gtp_based_control_plane_interface.len =
        test_s10_f_teid(&pgw_s5c, OGS_GTP2_F_TEID_S5_S8_PGW_GTP_C,
                TEST_S10_PGW_ADDRESS, TEST_S10_PGW_S5C_TEID);

    /* The PGW allocates the IPv4 address of the UE */
    memset(&paa, 0, sizeof(paa));
    if (req->pdn_address_allocation.presence &&
        req->pdn_address_allocation.len <= sizeof(paa))
        memcpy(&paa, req->pdn_address_allocation.data,
                req->pdn_address_allocation.len);
    if (paa.session_type == OGS_PDU_SESSION_TYPE_IPV4V6)
        inet_pton(AF_INET, TEST_S10_UE_IPV4, &paa.both.addr);
    else {
        paa.session_type = OGS_PDU_SESSION_TYPE_IPV4;
        inet_pton(AF_INET, TEST_S10_UE_IPV4, &paa.addr);
    }
    rsp->pdn_address_allocation.presence = 1;
    rsp->pdn_address_allocation.data = &paa;
    rsp->pdn_address_allocation.len =
        paa.session_type == OGS_PDU_SESSION_TYPE_IPV4V6 ?
            OGS_PAA_IPV4V6_LEN : OGS_PAA_IPV4_LEN;

    memset(&bearer_cause, 0, sizeof(bearer_cause));
    bearer_cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    for (i = 0; i < OGS_BEARER_PER_UE &&
            req->bearer_contexts_to_be_created[i].presence; i++) {
        ogs_gtp2_tlv_bearer_context_t *ctx = &rsp->bearer_contexts_created[i];
        uint8_t ebi = req->bearer_contexts_to_be_created[i].eps_bearer_id.u8;

        ctx->presence = 1;
        ctx->eps_bearer_id.presence = 1;
        ctx->eps_bearer_id.u8 = ebi;
        ctx->cause.presence = 1;
        ctx->cause.data = &bearer_cause;
        ctx->cause.len = sizeof(bearer_cause);
        /* Create Session Response : instance 0 is the SGW S1-U F-TEID
         * and instance 2 the PGW S5/S8-U F-TEID */
        ctx->s1_u_enodeb_f_teid.presence = 1;
        ctx->s1_u_enodeb_f_teid.data = &sgw_s1u[i];
        ctx->s1_u_enodeb_f_teid.len = test_s10_f_teid(&sgw_s1u[i],
                OGS_GTP2_F_TEID_S1_U_SGW_GTP_U, TEST_S10_SGW_S1U_ADDRESS,
                TEST_S10_SGW_S1U_TEID(ebi));
        ctx->s5_s8_u_sgw_f_teid.presence = 1;
        ctx->s5_s8_u_sgw_f_teid.data = &pgw_s5u[i];
        ctx->s5_s8_u_sgw_f_teid.len = test_s10_f_teid(&pgw_s5u[i],
                OGS_GTP2_F_TEID_S5_S8_PGW_GTP_U, TEST_S10_PGW_S5U_ADDRESS,
                TEST_S10_PGW_S5U_TEID(ebi));
    }

    answer_cause(sgw, OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
            &rsp->cause, &message, sqn);
}

static void handle_modify_bearer(test_s10_sgw_t *sgw,
        ogs_gtp2_modify_bearer_request_t *req, uint32_t sqn)
{
    static ogs_gtp2_message_t message;
    int i;

    sgw->num_modify_bearer++;
    if (req->sender_f_teid_for_control_plane.presence) {
        sgw->num_modify_bearer_mme_change++;
        sender_f_teid(sgw, &req->sender_f_teid_for_control_plane);
    }
    for (i = 0; i < OGS_BEARER_PER_UE &&
            req->bearer_contexts_to_be_modified[i].presence; i++) {
        if (req->bearer_contexts_to_be_modified[i].
                s1_u_enodeb_f_teid.presence) {
            sgw->num_modify_bearer_enb++;
            break;
        }
    }

    memset(&message, 0, sizeof(message));
    answer_cause(sgw, OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE,
            &message.modify_bearer_response.cause, &message, sqn);
}

static void handle_release_access_bearers(test_s10_sgw_t *sgw, uint32_t sqn)
{
    static ogs_gtp2_message_t message;

    sgw->num_release_access_bearers++;
    memset(&message, 0, sizeof(message));
    answer_cause(sgw, OGS_GTP2_RELEASE_ACCESS_BEARERS_RESPONSE_TYPE,
            &message.release_access_bearers_response.cause, &message, sqn);
}

static void handle_delete_session(test_s10_sgw_t *sgw,
        ogs_gtp2_delete_session_request_t *req, uint32_t sqn)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_indication_t *indication = NULL;

    sgw->num_delete_session++;
    if (req->indication_flags.presence && req->indication_flags.len >= 2) {
        indication = req->indication_flags.data;
        sgw->delete_session_scope_indication = indication->scope_indication;
        sgw->delete_session_operation_indication =
            indication->operation_indication;
    }

    memset(&message, 0, sizeof(message));
    answer_cause(sgw, OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE,
            &message.delete_session_response.cause, &message, sqn);
}

int test_s10_sgw_serve(test_s10_sgw_t *sgw, int timeout_ms)
{
    static ogs_gtp2_message_t message;
    uint32_t sqn = 0;

    ogs_assert(sgw);

    if (test_s10_peer_recv(&sgw->node, timeout_ms, &message, &sqn) !=
            OGS_OK)
        return OGS_ERROR;

    switch (message.h.type) {
    case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE:
        handle_create_session(sgw, &message.create_session_request, sqn);
        break;
    case OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE:
        handle_modify_bearer(sgw, &message.modify_bearer_request, sqn);
        break;
    case OGS_GTP2_RELEASE_ACCESS_BEARERS_REQUEST_TYPE:
        handle_release_access_bearers(sgw, sqn);
        break;
    case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
        handle_delete_session(sgw, &message.delete_session_request, sqn);
        break;
    default:
        ogs_error("Fake SGW : unexpected message type %d", message.h.type);
        break;
    }

    return OGS_OK;
}

void test_s10_sgw_serve_for(test_s10_sgw_t *sgw, int duration_ms)
{
    ogs_time_t end = ogs_get_monotonic_time() + ogs_time_from_msec(duration_ms);

    while (ogs_get_monotonic_time() < end) {
        int left = (int)ogs_time_to_msec(end - ogs_get_monotonic_time());
        if (left <= 0)
            break;
        test_s10_sgw_serve(sgw, left);
    }
}

ogs_pkbuf_t *test_s10_s1ap_read(ogs_socknode_t *s1ap, test_s10_sgw_t *sgw)
{
    struct pollfd pfd[2];

    ogs_assert(s1ap);
    ogs_assert(s1ap->sock);
    ogs_assert(sgw);

    pfd[0].fd = s1ap->sock->fd;
    pfd[0].events = POLLIN;
    pfd[1].fd = sgw->node.fd;
    pfd[1].events = POLLIN;

    while (1) {
        pfd[0].revents = pfd[1].revents = 0;
        if (poll(pfd, 2, 30000) <= 0) {
            ogs_error("No S1AP message from the MME");
            return NULL;
        }
        if (pfd[1].revents & POLLIN)
            test_s10_sgw_serve(sgw, 0);
        if (pfd[0].revents & POLLIN)
            return testenb_s1ap_read(s1ap);
    }
}
