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
 * S10 reference point between MMEs (TS 23.401 clause 5.1, TS 23.002).
 * GTPv2-C over UDP port 2123 (TS 29.274).
 *
 * The peer MMEs are configured statically. Each peer is known by its
 * GUMMEIs (to find the old MME of a GUTI, TS 23.003 clause 2.8) and by
 * the TAIs it serves (to find the target MME of a handover).
 * DNS based selection (TS 29.303) can later replace the static lookups
 * behind mme_s10_select_peer_by_*().
 */

#ifndef MME_S10_CONTEXT_H
#define MME_S10_CONTEXT_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MME_S10_MAX_NUM_OF_TAI          64

/*
 * TS 29.274 clause 7.1.1 : an Echo Request shall not be sent more often
 * than every 60 s on each path.
 */
#define MME_S10_MIN_ECHO_INTERVAL       60

typedef enum {
    MME_S10_PATH_UNKNOWN = 0,   /* No Echo exchanged yet */
    MME_S10_PATH_UP,
    MME_S10_PATH_DOWN,          /* Echo Request not answered (TS 23.007) */
} mme_s10_path_state_e;

typedef struct mme_s10_peer_s {
    /*
     * Must be the first member: the GTP node is used as a list node and
     * an event only carries the GTP node.
     */
    ogs_gtp_node_t  gnode;

    char            *id;        /* Operator name, e.g. "mme2" */

    int             num_of_gummei;
    served_gummei_t gummei[OGS_MAX_NUM_OF_SERVED_GUMMEI];

    int             num_of_tai;
    ogs_eps_tai_t   tai[MME_S10_MAX_NUM_OF_TAI];

    /* Path management (TS 29.274 clause 7.1, TS 23.007) */
    mme_s10_path_state_e path_state;
    bool            remote_recovery_presence;
    uint8_t         remote_recovery;    /* Restart counter of the peer */
    ogs_timer_t     *t_echo;
} mme_s10_peer_t;

typedef struct mme_s10_context_s {
    ogs_list_t      peer_list;

    /* Periodic Echo Request, 0 if disabled */
    ogs_time_t      echo_interval;

    /*
     * Local restart counter sent in the Recovery IE (TS 23.007).
     * It is incremented at each restart and stored in the file below.
     * Without a file, it is derived from the start time.
     */
    const char      *restart_counter_file;
    uint8_t         local_recovery;
} mme_s10_context_t;

void mme_s10_context_init(void);
void mme_s10_context_final(void);
mme_s10_context_t *mme_s10_self(void);

/* Configuration : mme.gtpc.client.mme (peers) and mme.s10 */
int mme_s10_parse_peer_config(ogs_yaml_iter_t *parent);
int mme_s10_parse_config(ogs_yaml_iter_t *parent);
int mme_s10_context_validate(void);

mme_s10_peer_t *mme_s10_peer_add(const char *id, ogs_sockaddr_t *addr);
void mme_s10_peer_remove(mme_s10_peer_t *peer);
void mme_s10_peer_remove_all(void);

mme_s10_peer_t *mme_s10_peer_find_by_addr(const ogs_sockaddr_t *addr);
mme_s10_peer_t *mme_s10_peer_find_by_id(const char *id);
mme_s10_peer_t *mme_s10_peer_find_by_gnode(ogs_gtp_node_t *gnode);

/* Peer selection */
mme_s10_peer_t *mme_s10_select_peer_by_gummei(
        const ogs_plmn_id_t *plmn_id, uint16_t mme_gid, uint8_t mme_code);
mme_s10_peer_t *mme_s10_select_peer_by_guti(const ogs_nas_eps_guti_t *guti);
mme_s10_peer_t *mme_s10_select_peer_by_tai(const ogs_eps_tai_t *tai);

/* GUMMEI served by this MME (mme.gummei) */
bool mme_s10_gummei_is_local(
        const ogs_plmn_id_t *plmn_id, uint16_t mme_gid, uint8_t mme_code);

/* Local S10 TEID of the UE (TS 29.274 clause 5.5) */
void mme_s10_teid_pool_init(int max_ue);
void mme_s10_teid_pool_final(void);
void mme_s10_ue_teid_alloc(mme_ue_t *mme_ue);
void mme_s10_ue_teid_free(mme_ue_t *mme_ue);
mme_ue_t *mme_ue_find_by_s10_local_teid(uint32_t teid);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_CONTEXT_H */
