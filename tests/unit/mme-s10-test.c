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

/* S10 peer configuration, selection and TEID (src/mme/mme-s10-context.c) */

#include "mme/mme-s10-context.h"
#include "mme/mme-s10-build.h"
#include "mme/nas-security.h"
#include "core/abts.h"

static int saved_num_of_served_gummei;
static served_gummei_t saved_served_gummei;

/* This MME serves GUMMEI 999/70, MME group 2, MME code 1 */
static void local_gummei_set(void)
{
    served_gummei_t *gummei = &mme_self()->served_gummei[0];

    saved_num_of_served_gummei = mme_self()->num_of_served_gummei;
    memcpy(&saved_served_gummei, gummei, sizeof(*gummei));

    memset(gummei, 0, sizeof(*gummei));
    ogs_plmn_id_build(&gummei->plmn_id[0], 999, 70, 2);
    gummei->num_of_plmn_id = 1;
    gummei->mme_gid[0] = 2;
    gummei->num_of_mme_gid = 1;
    gummei->mme_code[0] = 1;
    gummei->num_of_mme_code = 1;
    mme_self()->num_of_served_gummei = 1;
}

static void local_gummei_restore(void)
{
    mme_self()->num_of_served_gummei = saved_num_of_served_gummei;
    memcpy(&mme_self()->served_gummei[0], &saved_served_gummei,
            sizeof(saved_served_gummei));
}

/*
 * Parse a YAML text whose top level keys are `mme` (the peer list, as
 * under mme.gtpc.client) and optionally `s10` (as mme.s10).
 */
static int parse_yaml(const char *text)
{
    yaml_parser_t parser;
    yaml_document_t document;
    ogs_yaml_iter_t root;
    int rv = OGS_OK;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser,
            (const unsigned char *)text, strlen(text));
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        return OGS_ERROR;
    }
    yaml_parser_delete(&parser);

    ogs_yaml_iter_init(&root, &document);
    while (rv == OGS_OK && ogs_yaml_iter_next(&root)) {
        const char *key = ogs_yaml_iter_key(&root);
        if (!strcmp(key, "mme"))
            rv = mme_s10_parse_peer_config(&root);
        else if (!strcmp(key, "s10"))
            rv = mme_s10_parse_config(&root);
    }

    /* Peer ids are copied, the document can be freed */
    yaml_document_delete(&document);
    return rv;
}

static const char *pool_config =
    "mme:\n"
    "  - id: mme1\n"
    "    address: 127.0.0.2\n"
    "    gummei:\n"
    "      - plmn_id: { mcc: 999, mnc: 70 }\n"
    "        mme_gid: 2\n"
    "        mme_code: 1\n"
    "    tai:\n"
    "      - plmn_id: { mcc: 999, mnc: 70 }\n"
    "        tac: 1\n"
    "  - id: mme2\n"
    "    address: [ 127.0.0.12, 127.0.0.22 ]\n"
    "    port: 2124\n"
    "    tai:\n"
    "      - plmn_id: { mcc: 999, mnc: 70 }\n"
    "        tac: [ 2, 3 ]\n"
    "    gummei:\n"
    "      plmn_id: { mcc: 999, mnc: 70 }\n"
    "      mme_gid: [ 2, 3 ]\n"
    "      mme_code: 2\n"
    "  - id: mme3\n"
    "    address: 127.0.0.13\n"
    "    gummei:\n"
    "      - plmn_id: { mcc: 001, mnc: 01 }\n"
    "        mme_gid: 4\n"
    "        mme_code: 9\n"
    "    tai:\n"
    "      - plmn_id: { mcc: 999, mnc: 70 }\n"
    "        tac: 3\n"
    "s10:\n"
    "  echo_interval: 30\n";

static void mme_s10_test_pool_config(abts_case *tc, void *data)
{
    mme_s10_peer_t *mme2 = NULL, *mme3 = NULL;
    ogs_plmn_id_t plmn_id, other_plmn_id;
    ogs_nas_eps_guti_t guti;
    ogs_eps_tai_t tai;
    ogs_sockaddr_t *sa = NULL;

    local_gummei_set();
    mme_s10_context_init();

    ABTS_INT_EQUAL(tc, OGS_OK, parse_yaml(pool_config));
    ABTS_INT_EQUAL(tc, 3, ogs_list_count(&mme_s10_self()->peer_list));

    /* The entry of this MME is skipped */
    ABTS_INT_EQUAL(tc, OGS_OK, mme_s10_context_validate());
    ABTS_INT_EQUAL(tc, 2, ogs_list_count(&mme_s10_self()->peer_list));
    ABTS_PTR_EQUAL(tc, NULL, mme_s10_peer_find_by_id("mme1"));

    mme2 = mme_s10_peer_find_by_id("mme2");
    mme3 = mme_s10_peer_find_by_id("mme3");
    ABTS_PTR_NOTNULL(tc, mme2);
    ABTS_PTR_NOTNULL(tc, mme3);
    if (!mme2 || !mme3)
        goto out;

    ABTS_INT_EQUAL(tc, 1, mme2->num_of_gummei);
    ABTS_INT_EQUAL(tc, 2, mme2->gummei[0].num_of_mme_gid);
    ABTS_INT_EQUAL(tc, 2, mme2->num_of_tai);
    ABTS_INT_EQUAL(tc, 3, mme2->tai[1].tac);

    /* Periodic Echo is not sent more often than every 60 s */
    ABTS_TRUE(tc, mme_s10_self()->echo_interval == ogs_time_from_sec(60));

    /* Both addresses of mme2, with the configured port */
    ABTS_INT_EQUAL(tc, OGS_OK,
            ogs_addaddrinfo(&sa, AF_UNSPEC, "127.0.0.22", 2124, 0));
    ABTS_PTR_EQUAL(tc, mme2, mme_s10_peer_find_by_addr(sa));
    ogs_freeaddrinfo(sa);
    sa = NULL;
    ABTS_INT_EQUAL(tc, OGS_OK,
            ogs_addaddrinfo(&sa, AF_UNSPEC, "127.0.0.22", 2123, 0));
    ABTS_PTR_EQUAL(tc, NULL, mme_s10_peer_find_by_addr(sa));
    ogs_freeaddrinfo(sa);

    /* Selection by GUMMEI */
    ogs_plmn_id_build(&plmn_id, 999, 70, 2);
    ogs_plmn_id_build(&other_plmn_id, 1, 1, 2);
    ABTS_PTR_EQUAL(tc, mme2, mme_s10_select_peer_by_gummei(&plmn_id, 3, 2));
    ABTS_PTR_EQUAL(tc, mme2, mme_s10_select_peer_by_gummei(&plmn_id, 2, 2));
    ABTS_PTR_EQUAL(tc, NULL, mme_s10_select_peer_by_gummei(&plmn_id, 2, 1));
    ABTS_PTR_EQUAL(tc, NULL, mme_s10_select_peer_by_gummei(&plmn_id, 4, 9));
    ABTS_TRUE(tc, mme_s10_gummei_is_local(&plmn_id, 2, 1));
    ABTS_TRUE(tc, !mme_s10_gummei_is_local(&plmn_id, 2, 2));

    /* Selection by GUTI */
    memset(&guti, 0, sizeof(guti));
    ogs_nas_from_plmn_id(&guti.nas_plmn_id, &other_plmn_id);
    guti.mme_gid = 4;
    guti.mme_code = 9;
    guti.m_tmsi = 0x12345678;
    ABTS_PTR_EQUAL(tc, mme3, mme_s10_select_peer_by_guti(&guti));
    guti.mme_code = 8;
    ABTS_PTR_EQUAL(tc, NULL, mme_s10_select_peer_by_guti(&guti));

    /* Selection by TAI : TAC 3 is served by mme2 and mme3 */
    memset(&tai, 0, sizeof(tai));
    memcpy(&tai.plmn_id, &plmn_id, sizeof(plmn_id));
    tai.tac = 2;
    ABTS_PTR_EQUAL(tc, mme2, mme_s10_select_peer_by_tai(&tai));
    tai.tac = 3;
    ABTS_PTR_EQUAL(tc, mme2, mme_s10_select_peer_by_tai(&tai));
    mme2->path_state = MME_S10_PATH_DOWN;
    ABTS_PTR_EQUAL(tc, mme3, mme_s10_select_peer_by_tai(&tai));
    mme3->path_state = MME_S10_PATH_DOWN;
    ABTS_PTR_EQUAL(tc, mme2, mme_s10_select_peer_by_tai(&tai));
    tai.tac = 9;
    ABTS_PTR_EQUAL(tc, NULL, mme_s10_select_peer_by_tai(&tai));

out:
    mme_s10_context_final();
    local_gummei_restore();
}

static void mme_s10_test_shared_gummei(abts_case *tc, void *data)
{
    const char *config =
        "mme:\n"
        "  - id: mme2\n"
        "    address: 127.0.0.12\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: [ 2, 3 ]\n"
        "  - id: mme3\n"
        "    address: 127.0.0.13\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 3\n";

    local_gummei_set();
    mme_s10_context_init();

    ABTS_INT_EQUAL(tc, OGS_OK, parse_yaml(config));
    ABTS_INT_EQUAL(tc, OGS_ERROR, mme_s10_context_validate());

    mme_s10_context_final();
    local_gummei_restore();
}

static void mme_s10_test_invalid_config(abts_case *tc, void *data)
{
    int i;
    const char *configs[] = {
        /* No id */
        "mme:\n"
        "  - address: 127.0.0.12\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 2\n",

        /* No address */
        "mme:\n"
        "  - id: mme2\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 2\n",

        /* No gummei */
        "mme:\n"
        "  - id: mme2\n"
        "    address: 127.0.0.12\n",

        /* MME code out of range */
        "mme:\n"
        "  - id: mme2\n"
        "    address: 127.0.0.12\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 300\n",

        /* Gummei without mme_gid */
        "mme:\n"
        "  - id: mme2\n"
        "    address: 127.0.0.12\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_code: 2\n",

        /* Invalid MCC */
        "mme:\n"
        "  - id: mme2\n"
        "    address: 127.0.0.12\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 99, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 2\n",

        /* TAI without tac */
        "mme:\n"
        "  - id: mme2\n"
        "    address: 127.0.0.12\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 2\n"
        "    tai:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n",

        /* Duplicated id */
        "mme:\n"
        "  - id: mme2\n"
        "    address: 127.0.0.12\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 2\n"
        "  - id: mme2\n"
        "    address: 127.0.0.13\n"
        "    gummei:\n"
        "      - plmn_id: { mcc: 999, mnc: 70 }\n"
        "        mme_gid: 2\n"
        "        mme_code: 3\n",
    };

    for (i = 0; i < (int)(sizeof(configs) / sizeof(configs[0])); i++) {
        mme_s10_context_init();
        abts_int_equal(tc, OGS_ERROR, parse_yaml(configs[i]), i);
        mme_s10_context_final();
    }
}

static void mme_s10_test_teid(abts_case *tc, void *data)
{
    mme_ue_t *ue = ogs_calloc(2, sizeof(mme_ue_t));

    ogs_assert(ue);
    mme_s10_teid_pool_init(4);

    mme_s10_ue_teid_alloc(&ue[0]);
    mme_s10_ue_teid_alloc(&ue[1]);
    ABTS_TRUE(tc, ue[0].s10.mme_s10_teid != 0);
    ABTS_TRUE(tc, ue[1].s10.mme_s10_teid != 0);
    ABTS_TRUE(tc, ue[0].s10.mme_s10_teid != ue[1].s10.mme_s10_teid);

    ABTS_PTR_EQUAL(tc, &ue[0],
            mme_ue_find_by_s10_local_teid(ue[0].s10.mme_s10_teid));
    ABTS_PTR_EQUAL(tc, &ue[1],
            mme_ue_find_by_s10_local_teid(ue[1].s10.mme_s10_teid));

    {
        uint32_t teid = ue[0].s10.mme_s10_teid;
        mme_s10_ue_teid_free(&ue[0]);
        ABTS_PTR_EQUAL(tc, NULL, mme_ue_find_by_s10_local_teid(teid));
        ABTS_PTR_EQUAL(tc, NULL, ue[0].s10.mme_s10_teid_node);
    }
    /* Freeing twice is harmless */
    mme_s10_ue_teid_free(&ue[0]);

    mme_s10_ue_teid_free(&ue[1]);
    mme_s10_teid_pool_final();
    ogs_free(ue);
}

/* A UE with a native EPS security context (EIA2, EEA0) */
static mme_ue_t *secured_ue_new(void)
{
    mme_ue_t *mme_ue = ogs_calloc(1, sizeof(*mme_ue));
    int i;

    ogs_assert(mme_ue);

    memcpy(mme_ue->imsi, "\x99\x09\x07\x00\x00\x00\x00\xf1", 8);
    mme_ue->imsi_len = 8;
    strcpy(mme_ue->imsi_bcd, "999700000000001");

    mme_ue->security_context_available = 1;
    mme_ue->nas_eps.ue.ksi = 3;
    mme_ue->nas_eps.mme.ksi = 3;
    mme_ue->selected_int_algorithm = OGS_NAS_SECURITY_ALGORITHMS_128_EIA2;
    mme_ue->selected_enc_algorithm = OGS_NAS_SECURITY_ALGORITHMS_EEA0;
    for (i = 0; i < (int)sizeof(mme_ue->knas_int); i++)
        mme_ue->knas_int[i] = 0x10 + i;
    for (i = 0; i < (int)sizeof(mme_ue->kasme); i++)
        mme_ue->kasme[i] = 0x80 + i;
    memset(mme_ue->nh, 0x5a, sizeof(mme_ue->nh));
    mme_ue->nhcc = 2;

    mme_ue->dl_count = 0x000105;
    mme_ue->ul_count.i32 = 0x000003;
    mme_ue->ul_count_accepted = true;

    mme_ue->ue_network_capability.length = 2;
    ((uint8_t *)&mme_ue->ue_network_capability)[1] = 0xe0;
    ((uint8_t *)&mme_ue->ue_network_capability)[2] = 0xe0;
    mme_ue->ms_network_capability.length = 1;
    ((uint8_t *)&mme_ue->ms_network_capability)[1] = 0x20;
    memcpy(mme_ue->imeisv, "\x53\x61\x20\x00\x91\x78\x84\x00", 8);
    mme_ue->imeisv_len = 8;

    mme_ue->ambr.uplink = 1000500;      /* bps -> 1001 kbps */
    mme_ue->ambr.downlink = 2000000;    /* bps -> 2000 kbps */

    return mme_ue;
}

static void mme_s10_test_mm_context_from_ue(abts_case *tc, void *data)
{
    mme_ue_t *mme_ue = secured_ue_new();
    ogs_gtp2_mm_context_t mm, decoded;
    ogs_tlv_octet_t octet;
    uint8_t buf[512];

    mme_s10_build_mm_context(mme_ue, &mm, false);
    ABTS_INT_EQUAL(tc, 3, mm.ksi_asme);
    ABTS_INT_EQUAL(tc, OGS_NAS_SECURITY_ALGORITHMS_128_EIA2,
            mm.nas_integrity_algorithm);
    ABTS_INT_EQUAL(tc, 0x000105, mm.nas_downlink_count);
    ABTS_INT_EQUAL(tc, 0x000003, mm.nas_uplink_count);
    ABTS_TRUE(tc, memcmp(mm.kasme, mme_ue->kasme, OGS_GTP2_KASME_LEN) == 0);
    ABTS_INT_EQUAL(tc, 0, mm.nh_presence);
    ABTS_INT_EQUAL(tc, 1, mm.subscribed_ue_ambr_presence);
    ABTS_INT_EQUAL(tc, 1001, mm.subscribed_ue_ambr.uplink);
    ABTS_INT_EQUAL(tc, 2000, mm.subscribed_ue_ambr.downlink);
    ABTS_INT_EQUAL(tc, 2, mm.ue_network_capability_len);
    ABTS_INT_EQUAL(tc, 0xe0, mm.ue_network_capability[0]);
    ABTS_INT_EQUAL(tc, 1, mm.ms_network_capability_len);
    ABTS_INT_EQUAL(tc, 8, mm.mei_len);
    ABTS_INT_EQUAL(tc, 0, mm.num_of_quadruplets);
    ABTS_INT_EQUAL(tc, OGS_GTP2_MM_CONTEXT_ENSCT_NATIVE, mm.ensct);

    mme_s10_build_mm_context(mme_ue, &mm, true);
    ABTS_INT_EQUAL(tc, 1, mm.nh_presence);
    ABTS_INT_EQUAL(tc, 2, mm.ncc);

    ABTS_TRUE(tc, ogs_gtp2_build_mm_context(&octet, &mm, buf, sizeof(buf)) > 0);
    ABTS_TRUE(tc, ogs_gtp2_parse_mm_context(&decoded, &octet) > 0);
    ABTS_INT_EQUAL(tc, 3, decoded.ksi_asme);
    ABTS_INT_EQUAL(tc, 0x000105, decoded.nas_downlink_count);
    ABTS_TRUE(tc, memcmp(decoded.nh, mme_ue->nh, OGS_GTP2_NH_LEN) == 0);
    ABTS_TRUE(tc, memcmp(decoded.mei, mme_ue->imeisv, 8) == 0);

    ogs_free(mme_ue);
}

/* Integrity protected Attach Request : header, MAC, SQN, then the message */
static int protected_message(mme_ue_t *mme_ue, uint8_t sqn,
        const uint8_t *msg, int msg_len, uint8_t *out)
{
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t mac[4];

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_NAS_HEADROOM + 1 + msg_len);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_NAS_HEADROOM);
    ogs_pkbuf_put_u8(pkbuf, sqn);
    ogs_pkbuf_put_data(pkbuf, msg, msg_len);

    /* The UL NAS COUNT overflow of these vectors is 0 */
    ogs_nas_mac_calculate(mme_ue->selected_int_algorithm,
            mme_ue->knas_int, sqn, 0,
            OGS_NAS_SECURITY_UPLINK_DIRECTION, pkbuf, mac);
    ogs_pkbuf_free(pkbuf);

    out[0] = (OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED << 4) |
        OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    memcpy(out + 1, mac, 4);
    out[5] = sqn;
    memcpy(out + 6, msg, msg_len);

    return 6 + msg_len;
}

static void mme_s10_test_complete_request_check(abts_case *tc, void *data)
{
    mme_ue_t *mme_ue = secured_ue_new();
    /* Plain Attach Request header followed by a few octets */
    const uint8_t attach[] = { 0x07, 0x41, 0x71, 0x0b, 0xf6, 0x99, 0xf9 };
    uint8_t message[64];
    int len;

    /* Valid : SQN 5 after the last accepted UL NAS COUNT 3 */
    len = protected_message(mme_ue, 5, attach, sizeof(attach), message);
    ABTS_TRUE(tc, nas_eps_security_check_complete_request(
                mme_ue, message, len));
    ABTS_INT_EQUAL(tc, 5, mme_ue->ul_count.i32);

    /* The same message again is a replay */
    ABTS_TRUE(tc, !nas_eps_security_check_complete_request(
                mme_ue, message, len));
    ABTS_INT_EQUAL(tc, 5, mme_ue->ul_count.i32);

    /* Altered message : the MAC does not match, the count is unchanged */
    len = protected_message(mme_ue, 6, attach, sizeof(attach), message);
    message[len - 1] ^= 0x01;
    ABTS_TRUE(tc, !nas_eps_security_check_complete_request(
                mme_ue, message, len));
    ABTS_INT_EQUAL(tc, 5, mme_ue->ul_count.i32);
    ABTS_INT_EQUAL(tc, 0, mme_ue->mac_failed);

    /* Plain NAS message */
    message[0] = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    ABTS_TRUE(tc, !nas_eps_security_check_complete_request(
                mme_ue, message, len));

    /* Too short */
    ABTS_TRUE(tc, !nas_eps_security_check_complete_request(
                mme_ue, message, 5));

    /* No security context */
    len = protected_message(mme_ue, 7, attach, sizeof(attach), message);
    mme_ue->security_context_available = 0;
    ABTS_TRUE(tc, !nas_eps_security_check_complete_request(
                mme_ue, message, len));
    mme_ue->security_context_available = 1;
    ABTS_TRUE(tc, nas_eps_security_check_complete_request(
                mme_ue, message, len));

    ogs_free(mme_ue);
}

static void mme_s10_test_identification_messages(abts_case *tc, void *data)
{
    mme_ue_t *mme_ue = secured_ue_new();
    static ogs_gtp2_identification_request_t req;
    static ogs_gtp2_identification_response_t rsp;
    ogs_nas_eps_guti_t guti;
    ogs_plmn_id_t plmn_id;
    ogs_gtp2_guti_t gtp_guti;
    ogs_gtp2_complete_request_message_t complete;
    ogs_gtp2_mm_context_t mm;
    ogs_gtp2_cause_t *cause = NULL;
    const uint8_t nas[] = { 0x17, 1, 2, 3, 4, 5, 0x07, 0x41 };
    ogs_pkbuf_t *pkbuf = NULL;

    memset(&guti, 0, sizeof(guti));
    ogs_plmn_id_build(&plmn_id, 999, 70, 2);
    ogs_nas_from_plmn_id(&guti.nas_plmn_id, &plmn_id);
    guti.mme_gid = 2;
    guti.mme_code = 2;
    guti.m_tmsi = 0xc0000123;

    /* Identification Request */
    pkbuf = mme_s10_build_identification_request(&guti, nas, sizeof(nas));
    ABTS_PTR_NOTNULL(tc, pkbuf);
    memset(&req, 0, sizeof(req));
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_tlv_parse_msg(&req,
                &ogs_gtp2_tlv_desc_identification_request, pkbuf,
                OGS_TLV_MODE_T1_L2_I1));
    ABTS_INT_EQUAL(tc, OGS_GTP2_GUTI_LEN,
            ogs_gtp2_parse_guti(&gtp_guti, &req.guti));
    ABTS_INT_EQUAL(tc, 2, gtp_guti.mme_code);
    ABTS_INT_EQUAL(tc, 0xc0000123, gtp_guti.m_tmsi);
    ABTS_TRUE(tc, ogs_gtp2_parse_complete_request_message(&complete,
                &req.complete_attach_request_message) > 0);
    ABTS_INT_EQUAL(tc, OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_ATTACH_REQUEST,
            complete.type);
    ABTS_INT_EQUAL(tc, sizeof(nas), complete.len);
    ABTS_TRUE(tc, memcmp(nas, complete.data, sizeof(nas)) == 0);
    ogs_pkbuf_free(pkbuf);

    /* Accepted Identification Response : IMSI and MM Context */
    pkbuf = mme_s10_build_identification_response(
            OGS_GTP2_CAUSE_REQUEST_ACCEPTED, mme_ue);
    ABTS_PTR_NOTNULL(tc, pkbuf);
    memset(&rsp, 0, sizeof(rsp));
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_tlv_parse_msg(&rsp,
                &ogs_gtp2_tlv_desc_identification_response, pkbuf,
                OGS_TLV_MODE_T1_L2_I1));
    cause = rsp.cause.data;
    ABTS_INT_EQUAL(tc, OGS_GTP2_CAUSE_REQUEST_ACCEPTED, cause->value);
    ABTS_INT_EQUAL(tc, 8, rsp.imsi.len);
    ABTS_TRUE(tc, memcmp(mme_ue->imsi, rsp.imsi.data, 8) == 0);
    ABTS_TRUE(tc, ogs_gtp2_parse_mm_context(&mm,
                &rsp.mme_sgsn_ue_mm_context) > 0);
    ABTS_INT_EQUAL(tc, 3, mm.ksi_asme);
    ABTS_INT_EQUAL(tc, 0, mm.nh_presence);
    ogs_pkbuf_free(pkbuf);

    /* Rejected Identification Response : the Cause only */
    pkbuf = mme_s10_build_identification_response(
            OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN, NULL);
    ABTS_PTR_NOTNULL(tc, pkbuf);
    memset(&rsp, 0, sizeof(rsp));
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_tlv_parse_msg(&rsp,
                &ogs_gtp2_tlv_desc_identification_response, pkbuf,
                OGS_TLV_MODE_T1_L2_I1));
    cause = rsp.cause.data;
    ABTS_INT_EQUAL(tc, OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN, cause->value);
    ABTS_INT_EQUAL(tc, 0, rsp.imsi.presence);
    ABTS_INT_EQUAL(tc, 0, rsp.mme_sgsn_ue_mm_context.presence);
    ogs_pkbuf_free(pkbuf);

    ogs_free(mme_ue);
}

abts_suite *test_mme_s10(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, mme_s10_test_mm_context_from_ue, NULL);
    abts_run_test(suite, mme_s10_test_complete_request_check, NULL);
    abts_run_test(suite, mme_s10_test_identification_messages, NULL);

    abts_run_test(suite, mme_s10_test_pool_config, NULL);
    abts_run_test(suite, mme_s10_test_shared_gummei, NULL);
    abts_run_test(suite, mme_s10_test_invalid_config, NULL);
    abts_run_test(suite, mme_s10_test_teid, NULL);

    return suite;
}
