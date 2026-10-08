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
 * S10 Tracking Area Update with MME change
 * (TS 23.401 5.3.3.1 and 5.3.3.2, TS 29.274 7.3.5 to 7.3.7).
 *
 * The MME under test is `mme1`. The test program plays the eNB, the UE,
 * the peer MME `mme2` and the SGW (see s10-sgw.h).
 */

#include "test-common.h"
#include "s10-peer.h"
#include "s10-sgw.h"

#define S10_RECV_TIMEOUT        5000    /* ms */
#define S10_HOLDING_WAIT        23000   /* ms, MME_TIMER_S10_HOLDING + 3 s */

#define OLD_MME_S10_TEID        0xabc0
#define OLD_SGW_S11_TEID        0x1100
#define NEW_MME_S10_TEID        0x7777  /* when the test plays the new MME */

typedef struct tau_ctx_s {
    test_ue_t *test_ue;
    test_sess_t *sess;
    bson_t *doc;
    ogs_socknode_t *s1ap;
    test_s10_peer_t peer;   /* mme2 */
    test_s10_sgw_t sgw;
    uint8_t nas[512];       /* TAU Request sent by the UE */
    int nas_len;
    uint32_t tau_ul_count;
} tau_ctx_t;

static test_ue_t *ue_add(const char *msin)
{
    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;

    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));
    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    mobile_identity_suci.home_network_pki_value = 0;

    test_ue = test_ue_add_by_suci(&mobile_identity_suci, msin);
    ogs_assert(test_ue);

    test_ue->e_cgi.cell_id = 0x1079baf0;
    test_ue->nas.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.value = OGS_NAS_ATTACH_TYPE_EPS_ATTACH;
    test_ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    test_ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    return test_ue;
}

static void ctx_setup(abts_case *tc, tau_ctx_t *ctx, const char *msin)
{
    ogs_pkbuf_t *sendbuf, *recvbuf;

    memset(ctx, 0, sizeof(*ctx));

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_open(&ctx->peer));
    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_sgw_open(&ctx->sgw));

    ctx->test_ue = ue_add(msin);
    ctx->sess = test_sess_add_by_apn(
            ctx->test_ue, "internet", OGS_GTP2_RAT_TYPE_EUTRAN);
    ogs_assert(ctx->sess);

    ctx->s1ap = tests1ap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, ctx->s1ap);

    sendbuf = test_s1ap_build_s1_setup_request(
            S1AP_ENB_ID_PR_macroENB_ID, 0x54f64);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));
    recvbuf = testenb_s1ap_read(ctx->s1ap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    tests1ap_recv(NULL, recvbuf);

    ctx->doc = test_db_new_simple(ctx->test_ue);
    ABTS_PTR_NOTNULL(tc, ctx->doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(ctx->test_ue, ctx->doc));
}

static void ctx_teardown(abts_case *tc, tau_ctx_t *ctx)
{
    test_s10_sgw_serve_for(&ctx->sgw, 300);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(ctx->test_ue));
    testenb_s1ap_close(ctx->s1ap);
    /* Release Access Bearers of the UEs still connected to the eNB */
    test_s10_sgw_serve_for(&ctx->sgw, 500);
    test_ue_remove(ctx->test_ue);
    test_s10_sgw_close(&ctx->sgw);
    test_s10_peer_close(&ctx->peer);
}

/* The next NAS message from the MME to the UE, the SGW being served */
static uint8_t recv_emm(abts_case *tc, tau_ctx_t *ctx)
{
    ogs_pkbuf_t *recvbuf = test_s10_s1ap_read(ctx->s1ap, &ctx->sgw);

    ABTS_PTR_NOTNULL(tc, recvbuf);
    if (!recvbuf)
        return 0;
    ctx->test_ue->emm_message_type = 0;
    tests1ap_recv(ctx->test_ue, recvbuf);
    return ctx->test_ue->emm_message_type;
}

/* TAU Reject, then the S1 release removes the UE from the MME */
static void recv_tau_reject(abts_case *tc, tau_ctx_t *ctx)
{
    ogs_pkbuf_t *recvbuf, *sendbuf;

    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_TRACKING_AREA_UPDATE_REJECT,
            recv_emm(tc, ctx));

    /* UE Context Release Command */
    recvbuf = test_s10_s1ap_read(ctx->s1ap, &ctx->sgw);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    tests1ap_recv(ctx->test_ue, recvbuf);

    sendbuf = test_s1ap_build_ue_context_release_complete(ctx->test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));
}

static void send_nas(abts_case *tc, tau_ctx_t *ctx, ogs_pkbuf_t *emmbuf)
{
    ogs_pkbuf_t *sendbuf = NULL;

    ABTS_PTR_NOTNULL(tc, emmbuf);
    sendbuf = test_s1ap_build_uplink_nas_transport(ctx->test_ue, emmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));
}

/*
 * The UE was registered in `mme2` with a GUTI of `mme2`, the default
 * bearer EBI 5 and this EPS security context (EIA2, EEA0).
 */
static void ue_from_old_mme(tau_ctx_t *ctx, uint32_t m_tmsi)
{
    test_ue_t *test_ue = ctx->test_ue;
    ogs_plmn_id_t plmn_id;

    ogs_plmn_id_build(&plmn_id, 999, 70, 2);
    ogs_nas_from_plmn_id(&test_ue->nas_eps_guti.nas_plmn_id, &plmn_id);
    test_ue->nas_eps_guti.mme_gid = 2;
    test_ue->nas_eps_guti.mme_code = 2;
    test_ue->nas_eps_guti.m_tmsi = m_tmsi;

    test_ue->nas.ksi = 1;
    memset(test_ue->kasme, 0x44, sizeof(test_ue->kasme));
    test_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA2;
    test_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EEA0;
    ogs_kdf_nas_eps(OGS_KDF_NAS_INT_ALG, test_ue->selected_int_algorithm,
            test_ue->kasme, test_ue->knas_int);
    ogs_kdf_nas_eps(OGS_KDF_NAS_ENC_ALG, test_ue->selected_enc_algorithm,
            test_ue->kasme, test_ue->knas_enc);
    test_ue->security_context_available = 1;
    test_ue->ul_count = 7;
    test_ue->dl_count.i32 = 3;

    ogs_assert(test_bearer_add(ctx->sess, 5));
}

static void send_tau_request(abts_case *tc, tau_ctx_t *ctx)
{
    ogs_pkbuf_t *emmbuf, *sendbuf;

    memset(&ctx->test_ue->tau_request_param, 0,
            sizeof(ctx->test_ue->tau_request_param));
    ctx->test_ue->tau_request_param.ue_network_capability = 1;

    ctx->tau_ul_count = ctx->test_ue->ul_count;
    emmbuf = testemm_build_tau_request(ctx->test_ue, false,
            OGS_NAS_EPS_UPDATE_TYPE_TA_UPDATING, true, false);
    ABTS_PTR_NOTNULL(tc, emmbuf);
    ogs_assert(emmbuf->len <= (int)sizeof(ctx->nas));
    memcpy(ctx->nas, emmbuf->data, emmbuf->len);
    ctx->nas_len = emmbuf->len;

    memset(&ctx->test_ue->initial_ue_param, 0,
            sizeof(ctx->test_ue->initial_ue_param));
    sendbuf = test_s1ap_build_initial_ue_message(ctx->test_ue, emmbuf,
            S1AP_RRC_Establishment_Cause_mo_Signalling, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));
}

/* Context Request received by `mme2` : returns the S10 TEID of the MME */
static uint32_t recv_context_request(abts_case *tc, tau_ctx_t *ctx,
        uint32_t *sqn)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_context_request_t *req = &message.context_request;
    ogs_gtp2_guti_t guti;
    ogs_gtp2_complete_request_message_t complete;
    ogs_gtp2_f_teid_t *f_teid = NULL;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_recv(
                &ctx->peer, S10_RECV_TIMEOUT, &message, sqn));
    ABTS_INT_EQUAL(tc, OGS_GTP2_CONTEXT_REQUEST_TYPE, message.h.type);
    if (message.h.type != OGS_GTP2_CONTEXT_REQUEST_TYPE)
        return 0;

    ABTS_INT_EQUAL(tc, 0, message.h.teid);
    ABTS_INT_EQUAL(tc, OGS_GTP2_GUTI_LEN,
            ogs_gtp2_parse_guti(&guti, &req->guti));
    ABTS_INT_EQUAL(tc, ctx->test_ue->nas_eps_guti.m_tmsi, guti.m_tmsi);

    ABTS_TRUE(tc, ogs_gtp2_parse_complete_request_message(
                &complete, &req->complete_tau_request_message) > 0);
    ABTS_INT_EQUAL(tc, OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_TAU_REQUEST,
            complete.type);
    ABTS_TRUE(tc, complete.len == ctx->nas_len &&
            memcmp(complete.data, ctx->nas, ctx->nas_len) == 0);

    ABTS_INT_EQUAL(tc, 1, req->rat_type.presence);
    ABTS_INT_EQUAL(tc, OGS_GTP2_RAT_TYPE_EUTRAN, req->rat_type.u8);

    ABTS_INT_EQUAL(tc, 1,
            req->s3_s16_s10_n26_address_and_teid_for_control_plane.presence);
    if (!req->s3_s16_s10_n26_address_and_teid_for_control_plane.presence)
        return 0;
    f_teid = req->s3_s16_s10_n26_address_and_teid_for_control_plane.data;
    ABTS_INT_EQUAL(tc, OGS_GTP2_F_TEID_S10_MME_GTP_C, f_teid->interface_type);
    return be32toh(f_teid->teid);
}

/* Accepted Context Response of `mme2` (one PDN connection, EBI 5) */
static void send_context_response(abts_case *tc, tau_ctx_t *ctx,
        uint32_t mme_s10_teid, uint32_t sqn, const char *old_sgw)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_context_response_t *rsp = &message.context_response;
    ogs_gtp2_tlv_pdn_connection_t *pdn =
        &rsp->mme_sgsn_amf_ue_eps_pdn_connections[0];
    ogs_gtp2_tlv_bearer_context_t *bearer = &pdn->bearer_contexts[0];
    ogs_gtp2_cause_t cause;
    ogs_gtp2_mm_context_t mm;
    ogs_gtp2_bearer_qos_t qos;
    ogs_gtp2_ambr_t ambr;
    ogs_gtp2_f_teid_t sender, sgw_s11, pgw_s5c, sgw_s1u, pgw_s5u;
    uint8_t mm_buf[256], qos_buf[GTP2_BEARER_QOS_LEN];
    char apn[OGS_MAX_APN_LEN+1];
    uint8_t ipv4[OGS_IPV4_LEN] = { 10, 45, 0, 9 };

    memset(&message, 0, sizeof(message));
    message.h.type = OGS_GTP2_CONTEXT_RESPONSE_TYPE;

    memset(&cause, 0, sizeof(cause));
    cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    rsp->cause.presence = 1;
    rsp->cause.data = &cause;
    rsp->cause.len = sizeof(cause);

    rsp->imsi.presence = 1;
    rsp->imsi.data = ctx->test_ue->imsi_buf;
    rsp->imsi.len = ctx->test_ue->imsi_len;

    memset(&mm, 0, sizeof(mm));
    mm.ksi_asme = ctx->test_ue->nas.ksi;
    mm.nas_integrity_algorithm = ctx->test_ue->selected_int_algorithm;
    mm.nas_cipher_algorithm = ctx->test_ue->selected_enc_algorithm;
    mm.nas_downlink_count = ctx->test_ue->dl_count.i32;
    mm.nas_uplink_count = ctx->tau_ul_count;
    memcpy(mm.kasme, ctx->test_ue->kasme, sizeof(mm.kasme));
    mm.ue_network_capability_len = 2;
    mm.ue_network_capability[0] = 0xe0;
    mm.ue_network_capability[1] = 0xe0;
    mm.ensct = OGS_GTP2_MM_CONTEXT_ENSCT_NATIVE;
    rsp->mme_sgsn_amf_ue_mm_context.presence = 1;
    ABTS_TRUE(tc, ogs_gtp2_build_mm_context(&rsp->mme_sgsn_amf_ue_mm_context,
                &mm, mm_buf, sizeof(mm_buf)) > 0);

    pdn->presence = 1;
    pdn->apn.presence = 1;
    pdn->apn.len = ogs_fqdn_build(apn, "internet", strlen("internet"));
    pdn->apn.data = apn;
    pdn->ipv4_address.presence = 1;
    pdn->ipv4_address.data = ipv4;
    pdn->ipv4_address.len = OGS_IPV4_LEN;
    pdn->linked_eps_bearer_id.presence = 1;
    pdn->linked_eps_bearer_id.u8 = 5;
    pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.presence = 1;
    pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data = &pgw_s5c;
    pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.len =
        test_s10_f_teid(&pgw_s5c, OGS_GTP2_F_TEID_S5_S8_PGW_GTP_C,
                TEST_S10_PGW_ADDRESS, 0x5c01);

    bearer->presence = 1;
    bearer->eps_bearer_id.presence = 1;
    bearer->eps_bearer_id.u8 = 5;
    /* PDN Connection : instance 0 is the SGW S1-U F-TEID,
     * instance 1 the PGW S5/S8-U F-TEID */
    bearer->s1_u_enodeb_f_teid.presence = 1;
    bearer->s1_u_enodeb_f_teid.data = &sgw_s1u;
    bearer->s1_u_enodeb_f_teid.len = test_s10_f_teid(&sgw_s1u,
            OGS_GTP2_F_TEID_S1_U_SGW_GTP_U, TEST_S10_SGW_S1U_ADDRESS, 0x1105);
    bearer->s4_u_sgsn_f_teid.presence = 1;
    bearer->s4_u_sgsn_f_teid.data = &pgw_s5u;
    bearer->s4_u_sgsn_f_teid.len = test_s10_f_teid(&pgw_s5u,
            OGS_GTP2_F_TEID_S5_S8_PGW_GTP_U, TEST_S10_PGW_S5U_ADDRESS,
            0x2105);
    memset(&qos, 0, sizeof(qos));
    qos.qci = 9;
    qos.priority_level = 8;
    qos.pre_emption_vulnerability = 1;
    bearer->bearer_level_qos.presence = 1;
    ogs_gtp2_build_bearer_qos(&bearer->bearer_level_qos, &qos,
            qos_buf, sizeof(qos_buf));

    memset(&ambr, 0, sizeof(ambr));
    ambr.uplink = htobe32(1000);
    ambr.downlink = htobe32(2000);
    pdn->aggregate_maximum_bit_rate.presence = 1;
    pdn->aggregate_maximum_bit_rate.data = &ambr;
    pdn->aggregate_maximum_bit_rate.len = sizeof(ambr);

    rsp->sender_f_teid_for_control_plane.presence = 1;
    rsp->sender_f_teid_for_control_plane.data = &sender;
    rsp->sender_f_teid_for_control_plane.len = test_s10_f_teid(&sender,
            OGS_GTP2_F_TEID_S10_MME_GTP_C, TEST_S10_PEER_ADDRESS,
            OLD_MME_S10_TEID);

    rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.presence = 1;
    rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.data = &sgw_s11;
    rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.len =
        test_s10_f_teid(&sgw_s11, OGS_GTP2_F_TEID_S11_S4_SGW_GTP_C,
                old_sgw, OLD_SGW_S11_TEID);

    ABTS_INT_EQUAL(tc, OGS_OK,
            test_s10_peer_send(&ctx->peer, &message, mme_s10_teid, sqn));
}

/* Context Acknowledge received by `mme2` */
static void recv_context_acknowledge(abts_case *tc, tau_ctx_t *ctx,
        uint32_t expected_sqn, bool sgw_change)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_context_acknowledge_t *ack = &message.context_acknowledge;
    ogs_gtp2_cause_t *cause = NULL;
    bool sgwci = false;
    uint32_t sqn = 0;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_recv(
                &ctx->peer, S10_RECV_TIMEOUT, &message, &sqn));
    ABTS_INT_EQUAL(tc, OGS_GTP2_CONTEXT_ACKNOWLEDGE_TYPE, message.h.type);
    if (message.h.type != OGS_GTP2_CONTEXT_ACKNOWLEDGE_TYPE)
        return;

    /* Triggered message : same sequence number (TS 29.274 7.6) */
    ABTS_INT_EQUAL(tc, expected_sqn, sqn);
    ABTS_INT_EQUAL(tc, OLD_MME_S10_TEID, message.h.teid);
    cause = ack->cause.data;
    ABTS_INT_EQUAL(tc, OGS_GTP2_CAUSE_REQUEST_ACCEPTED,
            cause ? cause->value : 0);
    if (ack->indication_flags.presence && ack->indication_flags.len >= 1)
        sgwci = ((ogs_gtp2_indication_t *)ack->indication_flags.data)->
            sgw_change_indication;
    ABTS_INT_EQUAL(tc, sgw_change, sgwci);
}

/* TAU Accept with radio bearers, then TAU Complete */
static void complete_tau(abts_case *tc, tau_ctx_t *ctx)
{
    ogs_pkbuf_t *sendbuf = NULL;

    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_TRACKING_AREA_UPDATE_ACCEPT,
            recv_emm(tc, ctx));
    /* Protected with the EPS security context of the old MME */
    ABTS_INT_EQUAL(tc, 0, ctx->test_ue->mac_failed);
    /* New GUTI of this MME */
    ABTS_INT_EQUAL(tc, 1, ctx->test_ue->nas_eps_guti.mme_code);

    sendbuf = test_s1ap_build_initial_context_setup_response(ctx->test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));

    send_nas(tc, ctx, testemm_build_tau_complete(ctx->test_ue));

    /* Modify Bearer Request with the eNB S1-U F-TEID */
    test_s10_sgw_serve_for(&ctx->sgw, 1000);
    ABTS_TRUE(tc, ctx->sgw.num_modify_bearer_enb >= 1);
}

/***********************************************************************
 * New MME
 ***********************************************************************/

/* TS 23.401 5.3.3.2 : the old SGW is also used by this MME */
static void test_tau_without_sgw_change(abts_case *tc, void *data)
{
    tau_ctx_t ctx;
    uint32_t mme_s10_teid, sqn = 0;

    ctx_setup(tc, &ctx, "0000000051");
    ue_from_old_mme(&ctx, 0xc0000051);
    send_tau_request(tc, &ctx);

    mme_s10_teid = recv_context_request(tc, &ctx, &sqn);
    ABTS_TRUE(tc, mme_s10_teid != 0);
    send_context_response(tc, &ctx, mme_s10_teid, sqn, TEST_S10_SGW_ADDRESS);
    recv_context_acknowledge(tc, &ctx, sqn, false);

    complete_tau(tc, &ctx);

    /* One Modify Bearer Request with the F-TEID of the new MME */
    ABTS_INT_EQUAL(tc, 0, ctx.sgw.num_create_session);
    ABTS_INT_EQUAL(tc, 1, ctx.sgw.num_modify_bearer_mme_change);
    ABTS_INT_EQUAL(tc, 0, ctx.sgw.num_delete_session);

    ctx_teardown(tc, &ctx);
}

/* TS 23.401 5.3.3.1 : the old SGW is unknown, the PDN moves to the SGW */
static void test_tau_with_sgw_change(abts_case *tc, void *data)
{
    tau_ctx_t ctx;
    uint32_t mme_s10_teid, sqn = 0;

    ctx_setup(tc, &ctx, "0000000052");
    ue_from_old_mme(&ctx, 0xc0000052);
    send_tau_request(tc, &ctx);

    mme_s10_teid = recv_context_request(tc, &ctx, &sqn);
    send_context_response(tc, &ctx, mme_s10_teid, sqn, "127.0.0.30");
    recv_context_acknowledge(tc, &ctx, sqn, true);

    complete_tau(tc, &ctx);

    /* Create Session Request with the Operation Indication */
    ABTS_INT_EQUAL(tc, 1, ctx.sgw.num_create_session);
    ABTS_INT_EQUAL(tc, 1, ctx.sgw.create_session_operation_indication);
    ABTS_INT_EQUAL(tc, 0, ctx.sgw.num_modify_bearer_mme_change);

    ctx_teardown(tc, &ctx);
}

/* The old MME does not know the UE : TAU Reject, no Context Acknowledge */
static void test_tau_context_rejected(abts_case *tc, void *data)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_cause_t cause;
    tau_ctx_t ctx;
    uint32_t mme_s10_teid, sqn = 0;

    ctx_setup(tc, &ctx, "0000000053");
    ue_from_old_mme(&ctx, 0xc0000053);
    send_tau_request(tc, &ctx);

    mme_s10_teid = recv_context_request(tc, &ctx, &sqn);

    memset(&message, 0, sizeof(message));
    message.h.type = OGS_GTP2_CONTEXT_RESPONSE_TYPE;
    memset(&cause, 0, sizeof(cause));
    cause.value = OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN;
    message.context_response.cause.presence = 1;
    message.context_response.cause.data = &cause;
    message.context_response.cause.len = sizeof(cause);
    ABTS_INT_EQUAL(tc, OGS_OK,
            test_s10_peer_send(&ctx.peer, &message, mme_s10_teid, sqn));

    recv_tau_reject(tc, &ctx);
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            test_s10_peer_recv(&ctx.peer, 1000, &message, &sqn));
    ABTS_INT_EQUAL(tc, 0, ctx.sgw.num_create_session +
            ctx.sgw.num_modify_bearer + ctx.sgw.num_delete_session);

    ctx_teardown(tc, &ctx);
}

/* The old MME does not answer : TAU Reject after the retransmissions */
static void test_tau_context_timeout(abts_case *tc, void *data)
{
    static ogs_gtp2_message_t message;
    tau_ctx_t ctx;
    uint32_t sqn = 0;
    int count = 0;

    ctx_setup(tc, &ctx, "0000000054");
    ue_from_old_mme(&ctx, 0xc0000054);
    send_tau_request(tc, &ctx);

    /* Retransmitted every T3 (shorter than S10_RECV_TIMEOUT) */
    while (test_s10_peer_recv(&ctx.peer, S10_RECV_TIMEOUT,
                &message, &sqn) == OGS_OK) {
        ABTS_INT_EQUAL(tc, OGS_GTP2_CONTEXT_REQUEST_TYPE, message.h.type);
        if (++count > 4)
            break;
    }
    ABTS_INT_EQUAL(tc,
            ogs_local_conf()->time.message.gtp.n3_response_rcount, count);

    recv_tau_reject(tc, &ctx);

    ctx_teardown(tc, &ctx);
}

/***********************************************************************
 * Old MME : the test program plays the new MME
 ***********************************************************************/

/* Attach to this MME, then ECM-IDLE */
static void attach_and_go_idle(abts_case *tc, tau_ctx_t *ctx)
{
    ogs_pkbuf_t *esmbuf, *emmbuf, *sendbuf;
    test_bearer_t *bearer = NULL;

    memset(&ctx->sess->pdn_connectivity_param,
            0, sizeof(ctx->sess->pdn_connectivity_param));
    ctx->sess->pdn_connectivity_param.eit = 1;
    ctx->sess->pdn_connectivity_param.request_type =
        OGS_NAS_EPS_REQUEST_TYPE_INITIAL;
    esmbuf = testesm_build_pdn_connectivity_request(
            ctx->sess, false, OGS_NAS_EPS_PDN_TYPE_IPV4V6);
    ABTS_PTR_NOTNULL(tc, esmbuf);

    memset(&ctx->test_ue->attach_request_param,
            0, sizeof(ctx->test_ue->attach_request_param));
    ctx->test_ue->attach_request_param.drx_parameter = 1;
    ctx->test_ue->attach_request_param.ms_network_capability = 1;
    ctx->test_ue->attach_request_param.tmsi_status = 1;
    ctx->test_ue->attach_request_param.mobile_station_classmark_2 = 1;
    ctx->test_ue->attach_request_param.ue_usage_setting = 1;
    emmbuf = testemm_build_attach_request(ctx->test_ue, esmbuf, false, false);
    ABTS_PTR_NOTNULL(tc, emmbuf);

    memset(&ctx->test_ue->initial_ue_param, 0,
            sizeof(ctx->test_ue->initial_ue_param));
    sendbuf = test_s1ap_build_initial_ue_message(ctx->test_ue, emmbuf,
            S1AP_RRC_Establishment_Cause_mo_Signalling, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));

    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_AUTHENTICATION_REQUEST, recv_emm(tc, ctx));
    send_nas(tc, ctx, testemm_build_authentication_response(ctx->test_ue));

    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_SECURITY_MODE_COMMAND, recv_emm(tc, ctx));
    ctx->test_ue->mobile_identity_imeisv_presence = true;
    send_nas(tc, ctx, testemm_build_security_mode_complete(ctx->test_ue));

    /* ESM Information Request */
    recv_emm(tc, ctx);
    ctx->sess->esm_information_param.epco = 1;
    send_nas(tc, ctx, testesm_build_esm_information_response(ctx->sess));

    /* Initial Context Setup Request + Attach Accept, after the
     * Create Session Request answered by the fake SGW */
    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_ATTACH_ACCEPT, recv_emm(tc, ctx));

    sendbuf = test_s1ap_build_initial_context_setup_response(ctx->test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));

    bearer = test_bearer_find_by_ue_ebi(ctx->test_ue, 5);
    ogs_assert(bearer);
    esmbuf = testesm_build_activate_default_eps_bearer_context_accept(
            bearer, false);
    ABTS_PTR_NOTNULL(tc, esmbuf);
    send_nas(tc, ctx, testemm_build_attach_complete(ctx->test_ue, esmbuf));

    /* EMM Information */
    recv_emm(tc, ctx);

    /* ECM-IDLE : Release Access Bearers answered by the fake SGW */
    sendbuf = test_s1ap_build_ue_context_release_request(ctx->test_ue,
            S1AP_Cause_PR_radioNetwork,
            S1AP_CauseRadioNetwork_user_inactivity);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));

    sendbuf = test_s10_s1ap_read(ctx->s1ap, &ctx->sgw);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    tests1ap_recv(ctx->test_ue, sendbuf);

    sendbuf = test_s1ap_build_ue_context_release_complete(ctx->test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, testenb_s1ap_send(ctx->s1ap, sendbuf));

    test_s10_sgw_serve_for(&ctx->sgw, 300);
    ABTS_INT_EQUAL(tc, 1, ctx->sgw.num_create_session);
    ABTS_INT_EQUAL(tc, 1, ctx->sgw.num_release_access_bearers);
    /* GUTI of this MME */
    ABTS_INT_EQUAL(tc, 1, ctx->test_ue->nas_eps_guti.mme_code);
}

/* TAU Request of the UE, as received by the new MME */
static void build_tau_request(abts_case *tc, tau_ctx_t *ctx)
{
    ogs_pkbuf_t *emmbuf = NULL;

    memset(&ctx->test_ue->tau_request_param, 0,
            sizeof(ctx->test_ue->tau_request_param));
    ctx->tau_ul_count = ctx->test_ue->ul_count;
    emmbuf = testemm_build_tau_request(ctx->test_ue, false,
            OGS_NAS_EPS_UPDATE_TYPE_TA_UPDATING, true, false);
    ABTS_PTR_NOTNULL(tc, emmbuf);
    ogs_assert(emmbuf->len <= (int)sizeof(ctx->nas));
    memcpy(ctx->nas, emmbuf->data, emmbuf->len);
    ctx->nas_len = emmbuf->len;
    ogs_pkbuf_free(emmbuf);
}

static void send_context_request(abts_case *tc, tau_ctx_t *ctx,
        uint32_t sqn)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_context_request_t *req = &message.context_request;
    ogs_gtp2_guti_t guti;
    ogs_gtp2_complete_request_message_t complete;
    ogs_gtp2_f_teid_t f_teid;
    uint8_t guti_buf[OGS_GTP2_GUTI_LEN], complete_buf[600];

    memset(&message, 0, sizeof(message));
    message.h.type = OGS_GTP2_CONTEXT_REQUEST_TYPE;

    memset(&guti, 0, sizeof(guti));
    memcpy(&guti.nas_plmn_id, &ctx->test_ue->nas_eps_guti.nas_plmn_id,
            OGS_PLMN_ID_LEN);
    guti.mme_gid = ctx->test_ue->nas_eps_guti.mme_gid;
    guti.mme_code = ctx->test_ue->nas_eps_guti.mme_code;
    guti.m_tmsi = ctx->test_ue->nas_eps_guti.m_tmsi;
    req->guti.presence = 1;
    ogs_gtp2_build_guti(&req->guti, &guti, guti_buf, sizeof(guti_buf));

    memset(&complete, 0, sizeof(complete));
    complete.type = OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_TAU_REQUEST;
    complete.data = ctx->nas;
    complete.len = ctx->nas_len;
    req->complete_tau_request_message.presence = 1;
    ogs_gtp2_build_complete_request_message(
            &req->complete_tau_request_message, &complete,
            complete_buf, sizeof(complete_buf));

    req->s3_s16_s10_n26_address_and_teid_for_control_plane.presence = 1;
    req->s3_s16_s10_n26_address_and_teid_for_control_plane.data = &f_teid;
    req->s3_s16_s10_n26_address_and_teid_for_control_plane.len =
        test_s10_f_teid(&f_teid, OGS_GTP2_F_TEID_S10_MME_GTP_C,
                TEST_S10_PEER_ADDRESS, NEW_MME_S10_TEID);

    req->rat_type.presence = 1;
    req->rat_type.u8 = OGS_GTP2_RAT_TYPE_EUTRAN;

    ABTS_INT_EQUAL(tc, OGS_OK,
            test_s10_peer_send(&ctx->peer, &message, 0, sqn));
}

/* Context Response of the MME : returns the cause and its S10 TEID */
static uint8_t recv_context_response(abts_case *tc, tau_ctx_t *ctx,
        uint32_t expected_sqn, uint32_t *mme_s10_teid)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_context_response_t *rsp = &message.context_response;
    ogs_gtp2_cause_t *cause = NULL;
    uint32_t sqn = 0;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_recv(
                &ctx->peer, S10_RECV_TIMEOUT, &message, &sqn));
    ABTS_INT_EQUAL(tc, OGS_GTP2_CONTEXT_RESPONSE_TYPE, message.h.type);
    ABTS_INT_EQUAL(tc, expected_sqn, sqn);
    if (message.h.type != OGS_GTP2_CONTEXT_RESPONSE_TYPE)
        return 0;
    cause = rsp->cause.data;
    if (!cause)
        return 0;
    if (cause->value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        return cause->value;

    ABTS_INT_EQUAL(tc, NEW_MME_S10_TEID, message.h.teid);

    /* IMSI and EPS security context */
    ABTS_INT_EQUAL(tc, ctx->test_ue->imsi_len, rsp->imsi.len);
    ABTS_TRUE(tc, memcmp(rsp->imsi.data, ctx->test_ue->imsi_buf,
                ctx->test_ue->imsi_len) == 0);
    {
        ogs_gtp2_mm_context_t mm;
        ABTS_TRUE(tc, ogs_gtp2_parse_mm_context(&mm,
                    &rsp->mme_sgsn_amf_ue_mm_context) > 0);
        ABTS_INT_EQUAL(tc, ctx->tau_ul_count, mm.nas_uplink_count);
        ABTS_INT_EQUAL(tc, ctx->test_ue->selected_int_algorithm,
                mm.nas_integrity_algorithm);
        ABTS_TRUE(tc, memcmp(mm.kasme, ctx->test_ue->kasme,
                    OGS_GTP2_KASME_LEN) == 0);
    }

    /* PDN Connection set up through the fake SGW */
    {
        ogs_gtp2_tlv_pdn_connection_t *pdn =
            &rsp->mme_sgsn_amf_ue_eps_pdn_connections[0];
        ogs_gtp2_tlv_bearer_context_t *bearer = &pdn->bearer_contexts[0];
        ogs_gtp2_f_teid_t *f_teid = NULL;
        char apn[OGS_MAX_APN_LEN+1];

        ABTS_INT_EQUAL(tc, 1, pdn->presence);
        memset(apn, 0, sizeof(apn));
        ogs_fqdn_parse(apn, pdn->apn.data, pdn->apn.len);
        ABTS_STR_EQUAL(tc, "internet", apn);
        ABTS_INT_EQUAL(tc, 5, pdn->linked_eps_bearer_id.u8);
        ABTS_INT_EQUAL(tc, 1, pdn->ipv4_address.presence);
        f_teid = pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data;
        ABTS_INT_EQUAL(tc, TEST_S10_PGW_S5C_TEID, be32toh(f_teid->teid));
        ABTS_INT_EQUAL(tc, 5, bearer->eps_bearer_id.u8);
        f_teid = bearer->s1_u_enodeb_f_teid.data;
        ABTS_INT_EQUAL(tc, TEST_S10_SGW_S1U_TEID(5), be32toh(f_teid->teid));
        f_teid = bearer->s4_u_sgsn_f_teid.data;
        ABTS_INT_EQUAL(tc, TEST_S10_PGW_S5U_TEID(5), be32toh(f_teid->teid));
        ABTS_INT_EQUAL(tc, 0, pdn->bearer_contexts[1].presence);
    }

    {
        ogs_gtp2_f_teid_t *f_teid =
            rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.data;
        ABTS_PTR_NOTNULL(tc, f_teid);
        if (f_teid)
            ABTS_INT_EQUAL(tc, TEST_S10_SGW_S11_TEID, be32toh(f_teid->teid));
        f_teid = rsp->sender_f_teid_for_control_plane.data;
        ABTS_PTR_NOTNULL(tc, f_teid);
        if (f_teid)
            *mme_s10_teid = be32toh(f_teid->teid);
    }

    return OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
}

static void send_context_acknowledge(abts_case *tc, tau_ctx_t *ctx,
        uint32_t mme_s10_teid, uint32_t sqn, bool sgw_change)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_cause_t cause;
    ogs_gtp2_indication_t indication;

    memset(&message, 0, sizeof(message));
    message.h.type = OGS_GTP2_CONTEXT_ACKNOWLEDGE_TYPE;

    memset(&cause, 0, sizeof(cause));
    cause.value = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    message.context_acknowledge.cause.presence = 1;
    message.context_acknowledge.cause.data = &cause;
    message.context_acknowledge.cause.len = sizeof(cause);

    if (sgw_change) {
        memset(&indication, 0, sizeof(indication));
        indication.sgw_change_indication = 1;
        message.context_acknowledge.indication_flags.presence = 1;
        message.context_acknowledge.indication_flags.data = &indication;
        message.context_acknowledge.indication_flags.len =
            sizeof(indication);
    }

    ABTS_INT_EQUAL(tc, OGS_OK,
            test_s10_peer_send(&ctx->peer, &message, mme_s10_teid, sqn));
}

static void old_mme_releases_ue(abts_case *tc, bool sgw_change)
{
    tau_ctx_t ctx;
    uint32_t mme_s10_teid = 0;
    uint8_t cause;

    ctx_setup(tc, &ctx, sgw_change ? "0000000062" : "0000000061");
    attach_and_go_idle(tc, &ctx);

    /* A TAU Request altered on the way : not checked by the old MME */
    build_tau_request(tc, &ctx);
    ctx.nas[ctx.nas_len - 1] ^= 0x01;
    send_context_request(tc, &ctx, 0x300);
    ABTS_INT_EQUAL(tc, OGS_GTP2_CAUSE_USER_AUTHENTICATION_FAILED,
            recv_context_response(tc, &ctx, 0x300, &mme_s10_teid));

    /* The same TAU Request unaltered */
    ctx.nas[ctx.nas_len - 1] ^= 0x01;
    send_context_request(tc, &ctx, 0x301);
    cause = recv_context_response(tc, &ctx, 0x301, &mme_s10_teid);
    ABTS_INT_EQUAL(tc, OGS_GTP2_CAUSE_REQUEST_ACCEPTED, cause);
    ABTS_TRUE(tc, mme_s10_teid != 0);

    send_context_acknowledge(tc, &ctx, mme_s10_teid, 0x301, sgw_change);

    /* The UE is released when the holding timer expires */
    test_s10_sgw_serve_for(&ctx.sgw, S10_HOLDING_WAIT);
    if (sgw_change) {
        /* The old SGW keeps the PDN connection in the PGW */
        ABTS_INT_EQUAL(tc, 1, ctx.sgw.num_delete_session);
        ABTS_INT_EQUAL(tc, 1, ctx.sgw.delete_session_scope_indication);
        ABTS_INT_EQUAL(tc, 0, ctx.sgw.delete_session_operation_indication);
    } else {
        /* The SGW is now used by the new MME */
        ABTS_INT_EQUAL(tc, 0, ctx.sgw.num_delete_session);
    }

    /* The UE is no longer known */
    build_tau_request(tc, &ctx);
    send_context_request(tc, &ctx, 0x302);
    ABTS_INT_EQUAL(tc, OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN,
            recv_context_response(tc, &ctx, 0x302, &mme_s10_teid));

    ctx_teardown(tc, &ctx);
}

static void test_old_mme_without_sgw_change(abts_case *tc, void *data)
{
    old_mme_releases_ue(tc, false);
}

static void test_old_mme_with_sgw_change(abts_case *tc, void *data)
{
    old_mme_releases_ue(tc, true);
}

abts_suite *test_s10_tau(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test_tau_without_sgw_change, NULL);
    abts_run_test(suite, test_tau_with_sgw_change, NULL);
    abts_run_test(suite, test_tau_context_rejected, NULL);
    abts_run_test(suite, test_tau_context_timeout, NULL);
    abts_run_test(suite, test_old_mme_without_sgw_change, NULL);
    abts_run_test(suite, test_old_mme_with_sgw_change, NULL);

    return suite;
}
