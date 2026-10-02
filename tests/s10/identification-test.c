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
 * S10 Identification (TS 23.401 5.3.2.1 step 3, TS 29.274 7.3.8/7.3.9).
 *
 * The MME under test is `mme1` (GUMMEI 999/70, 2, 1). The test program
 * plays the eNB, the UE, and the peer MME `mme2` (GUMMEI 999/70, 2, 2).
 */

#include "test-common.h"
#include "s10-peer.h"

#define S10_RECV_TIMEOUT        5000    /* ms */
#define S10_GIVE_UP_TIMEOUT     15000   /* ms, after all retransmissions */

typedef struct s10_attach_s {
    test_ue_t *test_ue;
    test_sess_t *sess;
    bson_t *doc;
    ogs_socknode_t *s1ap;
    uint8_t nas[512];       /* Attach Request sent by the UE */
    int nas_len;
} s10_attach_t;

/* UE attached to `mme2` before : its GUTI and an old security context */
static void attach_setup(abts_case *tc, s10_attach_t *ctx,
        const char *msin, uint32_t m_tmsi, uint8_t mme_code)
{
    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    ogs_plmn_id_t plmn_id;
    ogs_pkbuf_t *sendbuf, *recvbuf;
    int rv;

    memset(ctx, 0, sizeof(*ctx));
    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));
    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    mobile_identity_suci.home_network_pki_value = 0;

    ctx->test_ue = test_ue_add_by_suci(&mobile_identity_suci, msin);
    ogs_assert(ctx->test_ue);

    ctx->test_ue->e_cgi.cell_id = 0x1079baf0;
    ctx->test_ue->nas.ksi = 1;
    ctx->test_ue->nas.value = OGS_NAS_ATTACH_TYPE_EPS_ATTACH;
    ctx->test_ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    ctx->test_ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    ogs_plmn_id_build(&plmn_id, 999, 70, 2);
    ogs_nas_from_plmn_id(&ctx->test_ue->nas_eps_guti.nas_plmn_id, &plmn_id);
    ctx->test_ue->nas_eps_guti.mme_gid = 2;
    ctx->test_ue->nas_eps_guti.mme_code = mme_code;
    ctx->test_ue->nas_eps_guti.m_tmsi = m_tmsi;

    /* EPS security context shared with the old MME */
    ctx->test_ue->selected_int_algorithm =
        OGS_NAS_SECURITY_ALGORITHMS_128_EIA2;
    ctx->test_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EEA0;
    memset(ctx->test_ue->knas_int, 0x33, sizeof(ctx->test_ue->knas_int));
    ctx->test_ue->ul_count = 7;

    ctx->sess = test_sess_add_by_apn(
            ctx->test_ue, "internet", OGS_GTP2_RAT_TYPE_EUTRAN);
    ogs_assert(ctx->sess);

    ctx->s1ap = tests1ap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, ctx->s1ap);

    sendbuf = test_s1ap_build_s1_setup_request(
            S1AP_ENB_ID_PR_macroENB_ID, 0x54f64);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testenb_s1ap_send(ctx->s1ap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    recvbuf = testenb_s1ap_read(ctx->s1ap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    tests1ap_recv(NULL, recvbuf);

    ctx->doc = test_db_new_simple(ctx->test_ue);
    ABTS_PTR_NOTNULL(tc, ctx->doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(ctx->test_ue, ctx->doc));
}

static void attach_send(abts_case *tc, s10_attach_t *ctx,
        bool integrity_protected)
{
    ogs_pkbuf_t *esmbuf, *emmbuf, *sendbuf;
    int rv;

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
    ctx->test_ue->attach_request_param.guti = 1;
    ctx->test_ue->attach_request_param.ms_network_capability = 1;
    emmbuf = testemm_build_attach_request(
            ctx->test_ue, esmbuf, integrity_protected, false);
    ABTS_PTR_NOTNULL(tc, emmbuf);

    ogs_assert(emmbuf->len <= (int)sizeof(ctx->nas));
    memcpy(ctx->nas, emmbuf->data, emmbuf->len);
    ctx->nas_len = emmbuf->len;

    memset(&ctx->test_ue->initial_ue_param, 0,
            sizeof(ctx->test_ue->initial_ue_param));
    sendbuf = test_s1ap_build_initial_ue_message(ctx->test_ue, emmbuf,
            S1AP_RRC_Establishment_Cause_mo_Signalling, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testenb_s1ap_send(ctx->s1ap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
}

/* The next NAS message from the MME to the UE */
static uint8_t attach_recv_emm(abts_case *tc, s10_attach_t *ctx)
{
    ogs_pkbuf_t *recvbuf = testenb_s1ap_read(ctx->s1ap);

    ABTS_PTR_NOTNULL(tc, recvbuf);
    if (!recvbuf)
        return 0;
    ctx->test_ue->emm_message_type = 0;
    tests1ap_recv(ctx->test_ue, recvbuf);
    return ctx->test_ue->emm_message_type;
}

static void attach_teardown(abts_case *tc, s10_attach_t *ctx)
{
    ogs_msleep(300);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(ctx->test_ue));
    testenb_s1ap_close(ctx->s1ap);
    test_ue_remove(ctx->test_ue);
}

/* Identification Request sent by the MME : GUTI and Attach Request */
static void check_identification_request(abts_case *tc, s10_attach_t *ctx,
        ogs_gtp2_message_t *message)
{
    ogs_gtp2_identification_request_t *req = NULL;
    ogs_gtp2_guti_t guti;
    ogs_gtp2_complete_request_message_t complete;

    ABTS_INT_EQUAL(tc, OGS_GTP2_IDENTIFICATION_REQUEST_TYPE, message->h.type);
    if (message->h.type != OGS_GTP2_IDENTIFICATION_REQUEST_TYPE)
        return;
    req = &message->identification_request;

    ABTS_INT_EQUAL(tc, 1, req->guti.presence);
    ABTS_INT_EQUAL(tc, OGS_GTP2_GUTI_LEN,
            ogs_gtp2_parse_guti(&guti, &req->guti));
    ABTS_INT_EQUAL(tc, ctx->test_ue->nas_eps_guti.mme_code, guti.mme_code);
    ABTS_INT_EQUAL(tc, ctx->test_ue->nas_eps_guti.m_tmsi, guti.m_tmsi);

    ABTS_INT_EQUAL(tc, 1, req->complete_attach_request_message.presence);
    ABTS_TRUE(tc, ogs_gtp2_parse_complete_request_message(
                &complete, &req->complete_attach_request_message) > 0);
    ABTS_INT_EQUAL(tc, OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_ATTACH_REQUEST,
            complete.type);
    ABTS_INT_EQUAL(tc, ctx->nas_len, complete.len);
    ABTS_TRUE(tc, complete.len == ctx->nas_len &&
            memcmp(complete.data, ctx->nas, ctx->nas_len) == 0);
}

static void send_identification_response(abts_case *tc,
        test_s10_peer_t *peer, uint32_t sqn, uint8_t cause_value,
        test_ue_t *test_ue)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_identification_response_t *rsp =
        &message.identification_response;
    ogs_gtp2_cause_t cause;
    ogs_gtp2_mm_context_t mm;
    uint8_t mm_buf[256];

    memset(&message, 0, sizeof(message));
    message.h.type = OGS_GTP2_IDENTIFICATION_RESPONSE_TYPE;

    memset(&cause, 0, sizeof(cause));
    cause.value = cause_value;
    rsp->cause.presence = 1;
    rsp->cause.data = &cause;
    rsp->cause.len = sizeof(cause);

    if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        rsp->imsi.presence = 1;
        rsp->imsi.data = test_ue->imsi_buf;
        rsp->imsi.len = test_ue->imsi_len;

        memset(&mm, 0, sizeof(mm));
        mm.ksi_asme = 1;
        mm.nas_integrity_algorithm = test_ue->selected_int_algorithm;
        mm.nas_uplink_count = test_ue->ul_count;
        memset(mm.kasme, 0x44, sizeof(mm.kasme));
        mm.ensct = OGS_GTP2_MM_CONTEXT_ENSCT_NATIVE;
        rsp->mme_sgsn_ue_mm_context.presence = 1;
        ABTS_TRUE(tc, ogs_gtp2_build_mm_context(
                    &rsp->mme_sgsn_ue_mm_context, &mm,
                    mm_buf, sizeof(mm_buf)) > 0);
    }

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_send(peer, &message, 0, sqn));
}

/* The old MME knows the UE : the IMSI comes from S10, no Identity Request */
static void test_identification_accepted(abts_case *tc, void *data)
{
    static ogs_gtp2_message_t message;
    test_s10_peer_t peer;
    s10_attach_t ctx;
    uint32_t sqn = 0;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_open(&peer));
    attach_setup(tc, &ctx, "0000000041", 0xc0000041, 2);
    attach_send(tc, &ctx, true);

    ABTS_INT_EQUAL(tc, OGS_OK,
            test_s10_peer_recv(&peer, S10_RECV_TIMEOUT, &message, &sqn));
    check_identification_request(tc, &ctx, &message);
    ABTS_INT_EQUAL(tc, 0, message.h.teid);

    send_identification_response(tc, &peer, sqn,
            OGS_GTP2_CAUSE_REQUEST_ACCEPTED, ctx.test_ue);

    /* The MME knows the IMSI and authenticates the UE through the HSS */
    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_AUTHENTICATION_REQUEST,
            attach_recv_emm(tc, &ctx));

    attach_teardown(tc, &ctx);
    test_s10_peer_close(&peer);
}

/* The old MME does not know the UE : Identity Request to the UE */
static void test_identification_rejected(abts_case *tc, void *data)
{
    static ogs_gtp2_message_t message;
    test_s10_peer_t peer;
    s10_attach_t ctx;
    uint32_t sqn = 0;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_open(&peer));
    attach_setup(tc, &ctx, "0000000042", 0xc0000042, 2);
    attach_send(tc, &ctx, true);

    ABTS_INT_EQUAL(tc, OGS_OK,
            test_s10_peer_recv(&peer, S10_RECV_TIMEOUT, &message, &sqn));
    check_identification_request(tc, &ctx, &message);

    send_identification_response(tc, &peer, sqn,
            OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN, NULL);

    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_IDENTITY_REQUEST,
            attach_recv_emm(tc, &ctx));

    attach_teardown(tc, &ctx);
    test_s10_peer_close(&peer);
}

/* The old MME does not answer : retransmissions, then Identity Request */
static void test_identification_timeout(abts_case *tc, void *data)
{
    static ogs_gtp2_message_t message;
    test_s10_peer_t peer;
    s10_attach_t ctx;
    uint32_t sqn = 0, first_sqn = 0;
    int count = 0;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_open(&peer));
    attach_setup(tc, &ctx, "0000000043", 0xc0000043, 2);
    attach_send(tc, &ctx, true);

    while (test_s10_peer_recv(&peer, S10_GIVE_UP_TIMEOUT,
                &message, &sqn) == OGS_OK) {
        ABTS_INT_EQUAL(tc, OGS_GTP2_IDENTIFICATION_REQUEST_TYPE,
                message.h.type);
        if (count == 0)
            first_sqn = sqn;
        ABTS_INT_EQUAL(tc, first_sqn, sqn);
        if (++count > 4)
            break;
    }
    /*
     * TS 29.274 7.6 : the request is retransmitted, then given up.
     * The GTP layer of Open5GS sends it n3_response_rcount times in total.
     */
    ABTS_INT_EQUAL(tc,
            ogs_local_conf()->time.message.gtp.n3_response_rcount, count);
    ABTS_TRUE(tc, count >= 2);

    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_IDENTITY_REQUEST,
            attach_recv_emm(tc, &ctx));

    attach_teardown(tc, &ctx);
    test_s10_peer_close(&peer);
}

/* The old MME cannot check a message without MAC : no Identification */
static void test_identification_not_protected(abts_case *tc, void *data)
{
    static ogs_gtp2_message_t message;
    test_s10_peer_t peer;
    s10_attach_t ctx;
    uint32_t sqn = 0;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_open(&peer));
    attach_setup(tc, &ctx, "0000000044", 0xc0000044, 2);
    attach_send(tc, &ctx, false);

    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_IDENTITY_REQUEST,
            attach_recv_emm(tc, &ctx));
    ABTS_INT_EQUAL(tc, OGS_ERROR,
            test_s10_peer_recv(&peer, 1000, &message, &sqn));

    attach_teardown(tc, &ctx);
    test_s10_peer_close(&peer);
}

/* Old MME role : Identification Request for a GUTI this MME does not know */
static void test_identification_request_unknown_guti(
        abts_case *tc, void *data)
{
    static ogs_gtp2_message_t message;
    ogs_gtp2_identification_request_t *req =
        &message.identification_request;
    ogs_gtp2_identification_response_t *rsp = NULL;
    ogs_gtp2_cause_t *cause = NULL;
    test_s10_peer_t peer;
    ogs_gtp2_guti_t guti;
    ogs_gtp2_complete_request_message_t complete;
    ogs_plmn_id_t plmn_id;
    uint8_t guti_buf[OGS_GTP2_GUTI_LEN], complete_buf[16];
    const uint8_t nas[] = { 0x17, 0, 0, 0, 0, 1, 0x07, 0x41 };
    uint8_t mme_codes[] = { 1, 9 };     /* this MME, unknown MME */
    uint32_t sqn = 0;
    int i;

    ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_open(&peer));

    for (i = 0; i < 2; i++) {
        memset(&message, 0, sizeof(message));
        message.h.type = OGS_GTP2_IDENTIFICATION_REQUEST_TYPE;

        memset(&guti, 0, sizeof(guti));
        ogs_plmn_id_build(&plmn_id, 999, 70, 2);
        ogs_nas_from_plmn_id(&guti.nas_plmn_id, &plmn_id);
        guti.mme_gid = 2;
        guti.mme_code = mme_codes[i];
        guti.m_tmsi = 0xdead0001;
        req->guti.presence = 1;
        ogs_gtp2_build_guti(&req->guti, &guti, guti_buf, sizeof(guti_buf));

        memset(&complete, 0, sizeof(complete));
        complete.type = OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_ATTACH_REQUEST;
        complete.data = (uint8_t *)nas;
        complete.len = sizeof(nas);
        req->complete_attach_request_message.presence = 1;
        ogs_gtp2_build_complete_request_message(
                &req->complete_attach_request_message,
                &complete, complete_buf, sizeof(complete_buf));

        ABTS_INT_EQUAL(tc, OGS_OK,
                test_s10_peer_send(&peer, &message, 0, 0x100 + i));

        ABTS_INT_EQUAL(tc, OGS_OK, test_s10_peer_recv(
                    &peer, S10_RECV_TIMEOUT, &message, &sqn));
        ABTS_INT_EQUAL(tc, OGS_GTP2_IDENTIFICATION_RESPONSE_TYPE,
                message.h.type);
        ABTS_INT_EQUAL(tc, 0x100 + i, sqn);
        rsp = &message.identification_response;
        ABTS_INT_EQUAL(tc, 1, rsp->cause.presence);
        cause = rsp->cause.data;
        ABTS_INT_EQUAL(tc, OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN,
                cause ? cause->value : 0);
        ABTS_INT_EQUAL(tc, 0, rsp->imsi.presence);
        ABTS_INT_EQUAL(tc, 0, rsp->mme_sgsn_ue_mm_context.presence);
    }

    test_s10_peer_close(&peer);
}

abts_suite *test_s10_identification(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test_identification_accepted, NULL);
    abts_run_test(suite, test_identification_rejected, NULL);
    abts_run_test(suite, test_identification_timeout, NULL);
    abts_run_test(suite, test_identification_not_protected, NULL);
    abts_run_test(suite, test_identification_request_unknown_guti, NULL);

    return suite;
}
