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

/*
 * Peer MME of an old GUTI given by the UE, or NULL when no peer can be
 * asked : GUTI of this MME, unknown GUMMEI, path down, or a NAS message
 * that the old MME cannot check because it is not integrity protected.
 */
mme_s10_peer_t *mme_s10_peer_of_old_guti(
        const ogs_nas_eps_mobile_identity_t *identity,
        ogs_nas_security_header_type_t h, ogs_nas_eps_guti_t *nas_guti);

/*
 * TAU with MME change (TS 23.401 5.3.3.1 and 5.3.3.2), mme-s10-tau.c
 */

/* New MME : TAU Request with an old GUTI of a peer MME. Sends a Context
 * Request and returns true when the answer is awaited. */
bool mme_s10_context_start(enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        ogs_nas_eps_tracking_area_update_request_t *tau_request,
        ogs_pkbuf_t *pkbuf, ogs_nas_security_header_type_t h);

/* New MME */
void mme_s10_handle_context_response(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_context_response_t *rsp);
void mme_s10_handle_context_failure(
        ogs_pool_id_t mme_ue_id, ogs_pool_id_t xact_id);
void mme_s10_handle_tau_modify_bearer_response(enb_ue_t *enb_ue,
        mme_ue_t *mme_ue, mme_ue_t *mme_ue_from_teid,
        ogs_gtp2_modify_bearer_response_t *rsp);
void mme_s10_handle_tau_sessions_updated(enb_ue_t *enb_ue, mme_ue_t *mme_ue);
void mme_s10_handle_tau_failure(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, uint8_t emm_cause);

/* Old MME */
void mme_s10_handle_context_request(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_context_request_t *req);
void mme_s10_handle_context_acknowledge(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_context_acknowledge_t *ack);
void mme_s10_handle_holding_timer(mme_ue_t *mme_ue);
void mme_s10_handle_old_ue_released(mme_ue_t *mme_ue);

/* Old MME : Cancel Location while the context is held for a new MME.
 * Returns true when the release is left to the holding timer. */
bool mme_s10_cancel_location_delayed(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_HANDLER_H */
