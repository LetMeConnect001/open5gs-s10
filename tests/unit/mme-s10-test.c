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

abts_suite *test_mme_s10(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, mme_s10_test_pool_config, NULL);
    abts_run_test(suite, mme_s10_test_shared_gummei, NULL);
    abts_run_test(suite, mme_s10_test_invalid_config, NULL);
    abts_run_test(suite, mme_s10_test_teid, NULL);

    return suite;
}
