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

#ifndef MME_S10_HANDLER_H
#define MME_S10_HANDLER_H

#include "mme-event.h"
#include "mme-s10-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Mobility management messages carried on S10 (TS 29.274 Table 6.1-1) */
#define MME_S10_IS_MOBILITY_MESSAGE(__type) \
    ((__type) >= OGS_GTP2_IDENTIFICATION_REQUEST_TYPE && \
     (__type) <= OGS_GTP2_CONFIGURATION_TRANSFER_TUNNEL_TYPE)

/* MME_EVENT_S10_MESSAGE, message already parsed */
void mme_s10_handle_message(
        ogs_gtp_node_t *gnode, ogs_gtp2_message_t *message);

/* MME_EVENT_S10_TIMER */
void mme_s10_handle_timer(mme_event_t *e);

/* Restart counter received from a peer (TS 23.007) */
void mme_s10_handle_recovery(mme_s10_peer_t *peer, uint8_t recovery);

/* GTP-C path failure towards a peer (TS 23.007) */
void mme_s10_handle_path_failure(mme_s10_peer_t *peer);

/*
 * New MME, TS 23.401 5.3.2.1 step 3 : Attach Request with a GUTI of a
 * peer MME. Sends an Identification Request to the old MME and returns
 * true when the answer is awaited. Returns false when the Identity
 * procedure must be used instead.
 */
bool mme_s10_identification_start(enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        ogs_nas_eps_attach_request_t *attach_request, ogs_pkbuf_t *pkbuf,
        ogs_nas_security_header_type_t h);

/* No usable Identification Response : fall back to Identity Request */
void mme_s10_handle_identification_failure(
        ogs_pool_id_t mme_ue_id, ogs_pool_id_t xact_id);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_HANDLER_H */
