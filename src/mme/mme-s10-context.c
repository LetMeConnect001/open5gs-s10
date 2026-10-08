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

#include "ogs-gtp.h"

#include "mme-s10-context.h"
#include "mme-s10-path.h"

static mme_s10_context_t self;
static int context_initialized = 0;

static OGS_POOL(mme_s10_teid_pool, ogs_pool_id_t);
static ogs_hash_t *mme_s10_teid_hash = NULL;

void mme_s10_context_init(void)
{
    ogs_assert(context_initialized == 0);

    memset(&self, 0, sizeof(self));
    ogs_list_init(&self.peer_list);

    context_initialized = 1;
}

void mme_s10_context_final(void)
{
    ogs_assert(context_initialized == 1);

    mme_s10_peer_remove_all();

    context_initialized = 0;
}

mme_s10_context_t *mme_s10_self(void)
{
    return &self;
}

/*
 * Configuration
 *
 *  mme:
 *    gtpc:
 *      client:
 *        mme:
 *          - id: mme2
 *            address: 127.0.0.12       # one address or a list
 *            port: 2123                # optional
 *            gummei:                   # one or more, as in mme.gummei
 *              - plmn_id:
 *                  mcc: 999
 *                  mnc: 70
 *                mme_gid: 2
 *                mme_code: 2
 *            tai:                      # optional, handover target
 *              - plmn_id:
 *                  mcc: 999
 *                  mnc: 70
 *                tac: [2, 3]
 *    s10:
 *      echo_interval: 60               # seconds, optional
 *      restart_counter_file: /var/lib/open5gs/mme-s10-restart-counter
 */

/*
 * Iterate over the value of the current key of 'parent', which is
 * either a mapping or a sequence of mappings. 'iter' iterates over the
 * pairs of each mapping.
 */
#define S10_FOR_EACH_MAPPING(__parent, __array, __iter) \
    ogs_yaml_iter_recurse((__parent), (__array)); \
    do { \
        if (ogs_yaml_iter_type(__array) == YAML_MAPPING_NODE) { \
            memcpy((__iter), (__array), sizeof(ogs_yaml_iter_t)); \
        } else if (ogs_yaml_iter_type(__array) == YAML_SEQUENCE_NODE) { \
            if (!ogs_yaml_iter_next(__array)) \
                break; \
            ogs_yaml_iter_recurse((__array), (__iter)); \
        } else { \
            break; \
        }

#define S10_END_FOR_EACH_MAPPING(__array) \
    } while (ogs_yaml_iter_type(__array) == YAML_SEQUENCE_NODE)

/* Value of the current key of 'parent' : a number or a list of numbers */
static int parse_int_list(ogs_yaml_iter_t *parent,
        long *values, int max, int *num, long min_value, long max_value)
{
    ogs_yaml_iter_t iter;
    const char *name = ogs_yaml_iter_key(parent);

    ogs_yaml_iter_recurse(parent, &iter);
    if (ogs_yaml_iter_type(&iter) == YAML_MAPPING_NODE) {
        ogs_error("S10: `%s` must be a number or a list of numbers", name);
        return OGS_ERROR;
    }

    do {
        const char *v = NULL;
        char *end = NULL;
        long value;

        if (ogs_yaml_iter_type(&iter) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&iter))
                break;
        }

        v = ogs_yaml_iter_value(&iter);
        if (!v)
            continue;

        value = strtol(v, &end, 10);
        if (end == v || *end != '\0' ||
            value < min_value || value > max_value) {
            ogs_error("S10: invalid `%s` value `%s` [%ld..%ld]",
                    name, v, min_value, max_value);
            return OGS_ERROR;
        }
        if (*num >= max) {
            ogs_error("S10: too many `%s` values [max:%d]", name, max);
            return OGS_ERROR;
        }
        values[(*num)++] = value;
    } while (ogs_yaml_iter_type(&iter) == YAML_SEQUENCE_NODE);

    return OGS_OK;
}

/* 'iter' iterates over the pairs of a plmn_id mapping */
static int parse_plmn_id_mapping(ogs_yaml_iter_t *iter, ogs_plmn_id_t *plmn_id)
{
    const char *mcc = NULL, *mnc = NULL;

    while (ogs_yaml_iter_next(iter)) {
        const char *key = ogs_yaml_iter_key(iter);
        ogs_assert(key);
        if (!strcmp(key, "mcc"))
            mcc = ogs_yaml_iter_value(iter);
        else if (!strcmp(key, "mnc"))
            mnc = ogs_yaml_iter_value(iter);
        else
            ogs_warn("unknown key `%s`", key);
    }

    if (!mcc || !mnc || strlen(mcc) != 3 ||
        (strlen(mnc) != 2 && strlen(mnc) != 3)) {
        ogs_error("S10: invalid plmn_id [mcc:%s mnc:%s]",
                mcc ? mcc : "none", mnc ? mnc : "none");
        return OGS_ERROR;
    }

    ogs_plmn_id_build(plmn_id, atoi(mcc), atoi(mnc), strlen(mnc));
    return OGS_OK;
}

/* 'parent' is positioned on the `gummei` key of a peer */
static int parse_gummei(ogs_yaml_iter_t *parent, mme_s10_peer_t *peer)
{
    ogs_yaml_iter_t array, iter;
    long values[GRP_PER_MME];

    S10_FOR_EACH_MAPPING(parent, &array, &iter)
        served_gummei_t *gummei = NULL;
        int i, num;

        if (peer->num_of_gummei >= OGS_MAX_NUM_OF_SERVED_GUMMEI) {
            ogs_error("S10: peer `%s` has too many gummei [max:%d]",
                    peer->id, OGS_MAX_NUM_OF_SERVED_GUMMEI);
            return OGS_ERROR;
        }
        gummei = &peer->gummei[peer->num_of_gummei];
        memset(gummei, 0, sizeof(*gummei));

        while (ogs_yaml_iter_next(&iter)) {
            const char *key = ogs_yaml_iter_key(&iter);
            ogs_assert(key);
            if (!strcmp(key, "plmn_id")) {
                ogs_yaml_iter_t plmn_array, plmn_iter;
                S10_FOR_EACH_MAPPING(&iter, &plmn_array, &plmn_iter)
                    if (gummei->num_of_plmn_id >=
                            OGS_MAX_NUM_OF_PLMN_PER_MME) {
                        ogs_error("S10: peer `%s` has too many plmn_id "
                                "in a gummei", peer->id);
                        return OGS_ERROR;
                    }
                    if (parse_plmn_id_mapping(&plmn_iter,
                            &gummei->plmn_id[gummei->num_of_plmn_id]) !=
                            OGS_OK)
                        return OGS_ERROR;
                    gummei->num_of_plmn_id++;
                S10_END_FOR_EACH_MAPPING(&plmn_array);
            } else if (!strcmp(key, "mme_gid")) {
                num = 0;
                if (parse_int_list(&iter, values,
                        GRP_PER_MME - gummei->num_of_mme_gid, &num,
                        0, 0xffff) != OGS_OK)
                    return OGS_ERROR;
                for (i = 0; i < num; i++)
                    gummei->mme_gid[gummei->num_of_mme_gid++] = values[i];
            } else if (!strcmp(key, "mme_code")) {
                num = 0;
                if (parse_int_list(&iter, values,
                        CODE_PER_MME - gummei->num_of_mme_code, &num,
                        0, 0xff) != OGS_OK)
                    return OGS_ERROR;
                for (i = 0; i < num; i++)
                    gummei->mme_code[gummei->num_of_mme_code++] = values[i];
            } else
                ogs_warn("unknown key `%s`", key);
        }

        if (!gummei->num_of_plmn_id ||
            !gummei->num_of_mme_gid || !gummei->num_of_mme_code) {
            ogs_error("S10: peer `%s` gummei needs plmn_id, mme_gid "
                    "and mme_code", peer->id);
            return OGS_ERROR;
        }
        peer->num_of_gummei++;
    S10_END_FOR_EACH_MAPPING(&array);

    return OGS_OK;
}

/* 'parent' is positioned on the `tai` key of a peer */
static int parse_tai(ogs_yaml_iter_t *parent, mme_s10_peer_t *peer)
{
    ogs_yaml_iter_t array, iter;
    long values[MME_S10_MAX_NUM_OF_TAI];

    S10_FOR_EACH_MAPPING(parent, &array, &iter)
        ogs_plmn_id_t plmn_id;
        bool plmn_id_presence = false;
        int i, num = 0;

        while (ogs_yaml_iter_next(&iter)) {
            const char *key = ogs_yaml_iter_key(&iter);
            ogs_assert(key);
            if (!strcmp(key, "plmn_id")) {
                ogs_yaml_iter_t plmn_iter;
                ogs_yaml_iter_recurse(&iter, &plmn_iter);
                if (parse_plmn_id_mapping(&plmn_iter, &plmn_id) != OGS_OK)
                    return OGS_ERROR;
                plmn_id_presence = true;
            } else if (!strcmp(key, "tac")) {
                if (parse_int_list(&iter, values,
                        MME_S10_MAX_NUM_OF_TAI, &num, 0, 0xffff) != OGS_OK)
                    return OGS_ERROR;
            } else
                ogs_warn("unknown key `%s`", key);
        }

        if (!plmn_id_presence || !num) {
            ogs_error("S10: peer `%s` tai needs plmn_id and tac", peer->id);
            return OGS_ERROR;
        }
        for (i = 0; i < num; i++) {
            if (peer->num_of_tai >= MME_S10_MAX_NUM_OF_TAI) {
                ogs_error("S10: peer `%s` has too many tai [max:%d]",
                        peer->id, MME_S10_MAX_NUM_OF_TAI);
                return OGS_ERROR;
            }
            memcpy(&peer->tai[peer->num_of_tai].plmn_id,
                    &plmn_id, sizeof(plmn_id));
            peer->tai[peer->num_of_tai].tac = values[i];
            peer->num_of_tai++;
        }
    S10_END_FOR_EACH_MAPPING(&array);

    return OGS_OK;
}

/* 'parent' is positioned on the `mme` key of mme.gtpc.client */
int mme_s10_parse_peer_config(ogs_yaml_iter_t *parent)
{
    ogs_yaml_iter_t array, iter;

    S10_FOR_EACH_MAPPING(parent, &array, &iter)
        ogs_yaml_iter_t first_pass, second_pass;
        mme_s10_peer_t *peer = NULL;
        ogs_sockaddr_t *addr = NULL;
        const char *id = NULL;
        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
        int num_of_hostname = 0;
        int family = AF_UNSPEC;
        uint16_t port = ogs_gtp_self()->gtpc_port ?
                ogs_gtp_self()->gtpc_port : OGS_GTPV2_C_UDP_PORT;
        int i, rv;

        memcpy(&first_pass, &iter, sizeof(iter));
        memcpy(&second_pass, &iter, sizeof(iter));

        /* First pass : identity and addresses */
        while (ogs_yaml_iter_next(&first_pass)) {
            const char *key = ogs_yaml_iter_key(&first_pass);
            ogs_assert(key);
            if (!strcmp(key, "id")) {
                id = ogs_yaml_iter_value(&first_pass);
            } else if (!strcmp(key, "address")) {
                ogs_yaml_iter_t hostname_iter;
                ogs_yaml_iter_recurse(&first_pass, &hostname_iter);
                if (ogs_yaml_iter_type(&hostname_iter) == YAML_MAPPING_NODE) {
                    ogs_error("S10: `address` must be an address or a list");
                    return OGS_ERROR;
                }
                do {
                    const char *v = NULL;
                    if (ogs_yaml_iter_type(&hostname_iter) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&hostname_iter))
                            break;
                    }
                    v = ogs_yaml_iter_value(&hostname_iter);
                    if (!v)
                        continue;
                    if (num_of_hostname >= OGS_MAX_NUM_OF_HOSTNAME) {
                        ogs_error("S10: too many addresses [max:%d]",
                                OGS_MAX_NUM_OF_HOSTNAME);
                        return OGS_ERROR;
                    }
                    hostname[num_of_hostname++] = v;
                } while (ogs_yaml_iter_type(&hostname_iter) ==
                        YAML_SEQUENCE_NODE);
            } else if (!strcmp(key, "port")) {
                const char *v = ogs_yaml_iter_value(&first_pass);
                if (v) port = atoi(v);
            } else if (!strcmp(key, "family")) {
                const char *v = ogs_yaml_iter_value(&first_pass);
                if (v) family = atoi(v);
                if (family != AF_UNSPEC &&
                    family != AF_INET && family != AF_INET6) {
                    ogs_warn("Ignore family(%d)", family);
                    family = AF_UNSPEC;
                }
            } else if (!strcmp(key, "gummei") || !strcmp(key, "tai")) {
                /* Second pass */
            } else
                ogs_warn("unknown key `%s`", key);
        }

        if (!id || !*id) {
            ogs_error("S10: a peer MME has no `id`");
            return OGS_ERROR;
        }
        if (mme_s10_peer_find_by_id(id)) {
            ogs_error("S10: duplicated peer id `%s`", id);
            return OGS_ERROR;
        }
        if (!num_of_hostname) {
            ogs_error("S10: peer `%s` has no `address`", id);
            return OGS_ERROR;
        }

        for (i = 0; i < num_of_hostname; i++) {
            rv = ogs_addaddrinfo(&addr, family, hostname[i], port, 0);
            if (rv != OGS_OK) {
                ogs_error("S10: peer `%s` cannot resolve `%s`",
                        id, hostname[i]);
                ogs_freeaddrinfo(addr);
                return OGS_ERROR;
            }
        }
        ogs_filter_ip_version(&addr,
                ogs_global_conf()->parameter.no_ipv4,
                ogs_global_conf()->parameter.no_ipv6,
                ogs_global_conf()->parameter.prefer_ipv4);
        if (!addr) {
            ogs_error("S10: peer `%s` has no usable address", id);
            return OGS_ERROR;
        }

        peer = mme_s10_peer_add(id, addr);
        ogs_assert(peer);

        /* Second pass : GUMMEI and TAI */
        while (ogs_yaml_iter_next(&second_pass)) {
            const char *key = ogs_yaml_iter_key(&second_pass);
            ogs_assert(key);
            rv = OGS_OK;
            if (!strcmp(key, "gummei"))
                rv = parse_gummei(&second_pass, peer);
            else if (!strcmp(key, "tai"))
                rv = parse_tai(&second_pass, peer);
            if (rv != OGS_OK) {
                mme_s10_peer_remove(peer);
                return OGS_ERROR;
            }
        }

        if (!peer->num_of_gummei) {
            ogs_error("S10: peer `%s` has no `gummei`", id);
            mme_s10_peer_remove(peer);
            return OGS_ERROR;
        }
    S10_END_FOR_EACH_MAPPING(&array);

    return OGS_OK;
}

/* 'parent' is positioned on the `s10` key of mme */
int mme_s10_parse_config(ogs_yaml_iter_t *parent)
{
    ogs_yaml_iter_t iter;

    ogs_yaml_iter_recurse(parent, &iter);
    while (ogs_yaml_iter_next(&iter)) {
        const char *key = ogs_yaml_iter_key(&iter);
        ogs_assert(key);
        if (!strcmp(key, "echo_interval")) {
            long values[1];
            int num = 0;
            if (parse_int_list(&iter, values, 1, &num, 0, 86400) != OGS_OK)
                return OGS_ERROR;
            if (num) {
                if (values[0] && values[0] < MME_S10_MIN_ECHO_INTERVAL) {
                    ogs_warn("S10: echo_interval %ld s is below the "
                            "%d s minimum (TS 29.274 7.1.1), using %d s",
                            values[0], MME_S10_MIN_ECHO_INTERVAL,
                            MME_S10_MIN_ECHO_INTERVAL);
                    values[0] = MME_S10_MIN_ECHO_INTERVAL;
                }
                self.echo_interval = ogs_time_from_sec(values[0]);
            }
        } else if (!strcmp(key, "restart_counter_file")) {
            self.restart_counter_file = ogs_yaml_iter_value(&iter);
        } else
            ogs_warn("unknown key `%s`", key);
    }

    return OGS_OK;
}

static bool plmn_id_in_gummei(
        const served_gummei_t *gummei, const ogs_plmn_id_t *plmn_id)
{
    int i;
    for (i = 0; i < gummei->num_of_plmn_id; i++)
        if (memcmp(&gummei->plmn_id[i], plmn_id, OGS_PLMN_ID_LEN) == 0)
            return true;
    return false;
}

static bool mme_gid_in_gummei(const served_gummei_t *gummei, uint16_t mme_gid)
{
    int i;
    for (i = 0; i < gummei->num_of_mme_gid; i++)
        if (gummei->mme_gid[i] == mme_gid)
            return true;
    return false;
}

static bool mme_code_in_gummei(
        const served_gummei_t *gummei, uint8_t mme_code)
{
    int i;
    for (i = 0; i < gummei->num_of_mme_code; i++)
        if (gummei->mme_code[i] == mme_code)
            return true;
    return false;
}

static bool gummei_match(const served_gummei_t *gummei,
        const ogs_plmn_id_t *plmn_id, uint16_t mme_gid, uint8_t mme_code)
{
    return plmn_id_in_gummei(gummei, plmn_id) &&
        mme_gid_in_gummei(gummei, mme_gid) &&
        mme_code_in_gummei(gummei, mme_code);
}

/* True if at least one GUMMEI is described by both entries */
static bool gummei_overlap(
        const served_gummei_t *a, const served_gummei_t *b)
{
    int i;
    bool plmn = false, gid = false, code = false;

    for (i = 0; i < a->num_of_plmn_id && !plmn; i++)
        plmn = plmn_id_in_gummei(b, &a->plmn_id[i]);
    for (i = 0; i < a->num_of_mme_gid && !gid; i++)
        gid = mme_gid_in_gummei(b, a->mme_gid[i]);
    for (i = 0; i < a->num_of_mme_code && !code; i++)
        code = mme_code_in_gummei(b, a->mme_code[i]);

    return plmn && gid && code;
}

static bool peer_is_local(mme_s10_peer_t *peer)
{
    int i, j;

    for (i = 0; i < peer->num_of_gummei; i++)
        for (j = 0; j < mme_self()->num_of_served_gummei; j++)
            if (gummei_overlap(&peer->gummei[i],
                        &mme_self()->served_gummei[j]))
                return true;

    return false;
}

static bool peer_overlap(mme_s10_peer_t *a, mme_s10_peer_t *b)
{
    int i, j;

    for (i = 0; i < a->num_of_gummei; i++)
        for (j = 0; j < b->num_of_gummei; j++)
            if (gummei_overlap(&a->gummei[i], &b->gummei[j]))
                return true;

    return false;
}

/*
 * TS 23.007 : the restart counter is incremented at each
 * restart and kept in non-volatile memory.
 */
static uint8_t restart_counter_init(void)
{
    uint8_t value = (uint8_t)time(NULL);
    FILE *fp = NULL;

    if (!self.restart_counter_file)
        return value;

    fp = fopen(self.restart_counter_file, "r");
    if (fp) {
        unsigned int previous;
        if (fscanf(fp, "%u", &previous) == 1)
            value = (uint8_t)(previous + 1);
        fclose(fp);
    }

    fp = fopen(self.restart_counter_file, "w");
    if (fp) {
        fprintf(fp, "%u\n", value);
        fclose(fp);
    } else {
        ogs_warn("S10: cannot write restart counter file `%s`",
                self.restart_counter_file);
    }

    return value;
}

int mme_s10_context_validate(void)
{
    mme_s10_peer_t *peer = NULL, *next = NULL, *other = NULL;

    /* The same peer list can be used by every MME of a pool */
    ogs_list_for_each_safe(&self.peer_list, next, peer) {
        if (peer_is_local(peer)) {
            ogs_info("S10: peer `%s` uses a GUMMEI of this MME, "
                    "entry skipped", peer->id);
            mme_s10_peer_remove(peer);
        }
    }

    /* A GUMMEI identifies one MME (TS 23.003 clause 2.8) */
    ogs_list_for_each(&self.peer_list, peer) {
        for (other = ogs_list_next(peer); other;
                other = ogs_list_next(other)) {
            if (peer_overlap(peer, other)) {
                ogs_error("S10: peers `%s` and `%s` share a GUMMEI",
                        peer->id, other->id);
                return OGS_ERROR;
            }
        }
    }

    self.local_recovery = restart_counter_init();

    if (ogs_list_count(&self.peer_list))
        ogs_info("S10: %d peer MME(s), restart counter %u",
                ogs_list_count(&self.peer_list), self.local_recovery);

    return OGS_OK;
}

mme_s10_peer_t *mme_s10_peer_add(const char *id, ogs_sockaddr_t *addr)
{
    mme_s10_peer_t *peer = NULL;

    ogs_assert(id);
    ogs_assert(addr);

    peer = ogs_calloc(1, sizeof(*peer));
    ogs_assert(peer);

    peer->id = ogs_strdup(id);
    ogs_assert(peer->id);

    peer->gnode.sa_list = addr;
    ogs_list_init(&peer->gnode.local_list);
    ogs_list_init(&peer->gnode.remote_list);

    ogs_list_add(&self.peer_list, peer);

    return peer;
}

void mme_s10_peer_remove(mme_s10_peer_t *peer)
{
    ogs_assert(peer);

    ogs_list_remove(&self.peer_list, peer);

    if (peer->t_echo)
        ogs_timer_delete(peer->t_echo);

    ogs_gtp_xact_delete_all(&peer->gnode);
    ogs_freeaddrinfo(peer->gnode.sa_list);

    ogs_free(peer->id);
    ogs_free(peer);
}

void mme_s10_peer_remove_all(void)
{
    mme_s10_peer_t *peer = NULL, *next = NULL;

    ogs_list_for_each_safe(&self.peer_list, next, peer)
        mme_s10_peer_remove(peer);
}

mme_s10_peer_t *mme_s10_peer_find_by_addr(const ogs_sockaddr_t *addr)
{
    mme_s10_peer_t *peer = NULL;
    ogs_sockaddr_t *sa = NULL;

    ogs_assert(addr);

    ogs_list_for_each(&self.peer_list, peer) {
        if (ogs_sockaddr_is_equal(&peer->gnode.addr, addr) == true)
            return peer;
        for (sa = peer->gnode.sa_list; sa; sa = sa->next)
            if (ogs_sockaddr_is_equal(sa, addr) == true)
                return peer;
    }

    return NULL;
}

mme_s10_peer_t *mme_s10_peer_find_by_id(const char *id)
{
    mme_s10_peer_t *peer = NULL;

    ogs_assert(id);

    ogs_list_for_each(&self.peer_list, peer)
        if (!strcmp(peer->id, id))
            return peer;

    return NULL;
}

mme_s10_peer_t *mme_s10_peer_find_by_gnode(ogs_gtp_node_t *gnode)
{
    mme_s10_peer_t *peer = NULL;

    ogs_list_for_each(&self.peer_list, peer)
        if (&peer->gnode == gnode)
            return peer;

    return NULL;
}

mme_s10_peer_t *mme_s10_select_peer_by_gummei(
        const ogs_plmn_id_t *plmn_id, uint16_t mme_gid, uint8_t mme_code)
{
    mme_s10_peer_t *peer = NULL;
    int i;

    ogs_assert(plmn_id);

    ogs_list_for_each(&self.peer_list, peer)
        for (i = 0; i < peer->num_of_gummei; i++)
            if (gummei_match(&peer->gummei[i], plmn_id, mme_gid, mme_code))
                return peer;

    return NULL;
}

mme_s10_peer_t *mme_s10_select_peer_by_guti(const ogs_nas_eps_guti_t *guti)
{
    ogs_plmn_id_t plmn_id;

    ogs_assert(guti);

    ogs_nas_to_plmn_id(&plmn_id, &guti->nas_plmn_id);
    return mme_s10_select_peer_by_gummei(
            &plmn_id, guti->mme_gid, guti->mme_code);
}

/*
 * Several MMEs of a pool may serve the same TAI. A peer whose path is
 * known to be down is used only when no other peer serves the TAI.
 */
mme_s10_peer_t *mme_s10_select_peer_by_tai(const ogs_eps_tai_t *tai)
{
    mme_s10_peer_t *peer = NULL, *fallback = NULL;
    int i;

    ogs_assert(tai);

    ogs_list_for_each(&self.peer_list, peer) {
        for (i = 0; i < peer->num_of_tai; i++) {
            if (peer->tai[i].tac != tai->tac ||
                memcmp(&peer->tai[i].plmn_id, &tai->plmn_id,
                    OGS_PLMN_ID_LEN) != 0)
                continue;
            if (peer->path_state != MME_S10_PATH_DOWN)
                return peer;
            if (!fallback)
                fallback = peer;
            break;
        }
    }

    return fallback;
}

bool mme_s10_gummei_is_local(
        const ogs_plmn_id_t *plmn_id, uint16_t mme_gid, uint8_t mme_code)
{
    int i;

    ogs_assert(plmn_id);

    for (i = 0; i < mme_self()->num_of_served_gummei; i++)
        if (gummei_match(&mme_self()->served_gummei[i],
                    plmn_id, mme_gid, mme_code))
            return true;

    return false;
}

void mme_s10_teid_pool_init(int max_ue)
{
    ogs_pool_init(&mme_s10_teid_pool, max_ue);
    ogs_pool_random_id_generate(&mme_s10_teid_pool);

    mme_s10_teid_hash = ogs_hash_make();
    ogs_assert(mme_s10_teid_hash);
}

void mme_s10_teid_pool_final(void)
{
    ogs_assert(mme_s10_teid_hash);
    ogs_hash_destroy(mme_s10_teid_hash);
    mme_s10_teid_hash = NULL;

    ogs_pool_final(&mme_s10_teid_pool);
}

void mme_s10_ue_init(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    mme_s10_ue_teid_alloc(mme_ue);

    mme_ue->s10.t_holding = ogs_timer_add(ogs_app()->timer_mgr,
            mme_s10_holding_timer_expire, OGS_UINT_TO_POINTER(mme_ue->id));
    ogs_assert(mme_ue->s10.t_holding);
}

void mme_s10_ue_fini(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (mme_ue->s10.t_holding) {
        ogs_timer_delete(mme_ue->s10.t_holding);
        mme_ue->s10.t_holding = NULL;
    }

    mme_s10_ue_teid_free(mme_ue);
}

void mme_s10_ue_teid_alloc(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    ogs_assert(mme_ue->s10.mme_s10_teid_node == NULL);

    ogs_pool_alloc(&mme_s10_teid_pool, &mme_ue->s10.mme_s10_teid_node);
    ogs_assert(mme_ue->s10.mme_s10_teid_node);

    mme_ue->s10.mme_s10_teid = *(mme_ue->s10.mme_s10_teid_node);
    ogs_hash_set(mme_s10_teid_hash, &mme_ue->s10.mme_s10_teid,
            sizeof(mme_ue->s10.mme_s10_teid), mme_ue);
}

void mme_s10_ue_teid_free(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (!mme_ue->s10.mme_s10_teid_node)
        return;

    ogs_hash_set(mme_s10_teid_hash, &mme_ue->s10.mme_s10_teid,
            sizeof(mme_ue->s10.mme_s10_teid), NULL);
    ogs_pool_free(&mme_s10_teid_pool, mme_ue->s10.mme_s10_teid_node);
    mme_ue->s10.mme_s10_teid_node = NULL;
    mme_ue->s10.mme_s10_teid = 0;
}

mme_ue_t *mme_ue_find_by_s10_local_teid(uint32_t teid)
{
    ogs_assert(mme_s10_teid_hash);
    return ogs_hash_get(mme_s10_teid_hash, &teid, sizeof(teid));
}
