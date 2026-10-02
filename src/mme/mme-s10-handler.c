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

#include "mme-timer.h"
#include "mme-s10-path.h"
#include "mme-s10-handler.h"

static void path_up(mme_s10_peer_t *peer)
{
    if (peer->path_state == MME_S10_PATH_DOWN)
        ogs_info("S10: path to peer `%s` restored", peer->id);
    peer->path_state = MME_S10_PATH_UP;
}

void mme_s10_handle_recovery(mme_s10_peer_t *peer, uint8_t recovery)
{
    ogs_assert(peer);

    if (!peer->remote_recovery_presence) {
        peer->remote_recovery_presence = true;
        peer->remote_recovery = recovery;
        ogs_debug("S10: peer `%s` restart counter %u", peer->id, recovery);
        return;
    }

    if (peer->remote_recovery != recovery) {
        /*
         * TS 23.007 : a new restart counter means that the peer
         * has restarted and lost the contexts it had. No S10 procedure
         * keeps a context with a peer beyond its own transaction.
         */
        ogs_warn("S10: peer `%s` has restarted [restart counter %u -> %u]",
                peer->id, peer->remote_recovery, recovery);
        peer->remote_recovery = recovery;
    }
}

void mme_s10_handle_path_failure(mme_s10_peer_t *peer)
{
    ogs_assert(peer);

    if (peer->path_state != MME_S10_PATH_DOWN)
        ogs_error("S10: path to peer `%s` failed, "
                "no answer to Echo Request", peer->id);
    peer->path_state = MME_S10_PATH_DOWN;
}

static void handle_echo_request(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_echo_request_t *req)
{
    ogs_debug("S10: Echo Request from `%s`", peer->id);

    /* Recovery is mandatory in Echo Request (TS 29.274 Table 7.1.1-1) */
    if (req->recovery.presence)
        mme_s10_handle_recovery(peer, req->recovery.u8);
    else
        ogs_warn("S10: no Recovery in Echo Request from `%s`", peer->id);

    path_up(peer);

    ogs_gtp2_send_echo_response(xact, mme_s10_self()->local_recovery, 0);
}

static void handle_echo_response(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_echo_response_t *rsp)
{
    ogs_debug("S10: Echo Response from `%s`", peer->id);

    if (rsp->recovery.presence)
        mme_s10_handle_recovery(peer, rsp->recovery.u8);
    else
        ogs_warn("S10: no Recovery in Echo Response from `%s`", peer->id);

    path_up(peer);
}

void mme_s10_handle_message(
        ogs_gtp_node_t *gnode, ogs_gtp2_message_t *message)
{
    int rv;
    uint8_t type;
    mme_s10_peer_t *peer = NULL;
    mme_ue_t *mme_ue = NULL;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(gnode);
    ogs_assert(message);

    peer = mme_s10_peer_find_by_gnode(gnode);
    if (!peer) {
        ogs_error("S10: unknown peer");
        return;
    }

    rv = ogs_gtp_xact_receive(gnode, &message->h, &xact);
    if (rv != OGS_OK)
        return;

    type = message->h.type;

    if (message->h.teid_presence && message->h.teid != 0) {
        mme_ue = mme_ue_find_by_s10_local_teid(message->h.teid);
        if (!mme_ue)
            ogs_debug("S10: no UE for TEID 0x%x", message->h.teid);
    }

    switch (type) {
    case OGS_GTP2_ECHO_REQUEST_TYPE:
        handle_echo_request(peer, xact, &message->echo_request);
        break;

    case OGS_GTP2_ECHO_RESPONSE_TYPE:
        handle_echo_response(peer, xact, &message->echo_response);
        break;

    case OGS_GTP2_IDENTIFICATION_REQUEST_TYPE:
    case OGS_GTP2_CONTEXT_REQUEST_TYPE:
    case OGS_GTP2_FORWARD_RELOCATION_REQUEST_TYPE:
    case OGS_GTP2_FORWARD_RELOCATION_COMPLETE_NOTIFICATION_TYPE:
    case OGS_GTP2_FORWARD_ACCESS_CONTEXT_NOTIFICATION_TYPE:
    case OGS_GTP2_RELOCATION_CANCEL_REQUEST_TYPE:
        /* The S10 procedures are not handled: the peer gets an answer
         * instead of a timeout and can fall back at once. */
        ogs_warn("S10: message type %d from `%s` is not supported",
                type, peer->id);
        mme_s10_send_error_response(
                xact, type, OGS_GTP2_CAUSE_SERVICE_NOT_SUPPORTED);
        break;

    case OGS_GTP2_CONFIGURATION_TRANSFER_TUNNEL_TYPE:
        /* No response is defined for this message */
        ogs_warn("S10: Configuration Transfer Tunnel from `%s` "
                "is not supported", peer->id);
        break;

    default:
        ogs_warn("S10: unexpected message type %d from `%s`",
                type, peer->id);
        break;
    }
}

void mme_s10_handle_timer(mme_event_t *e)
{
    mme_s10_peer_t *peer = NULL;

    ogs_assert(e);

    peer = mme_s10_peer_find_by_gnode(e->gnode);
    if (!peer) {
        ogs_error("S10: peer has already been removed");
        return;
    }

    switch (e->timer_id) {
    case MME_TIMER_S10_ECHO:
        mme_s10_send_echo_request(peer);
        if (peer->t_echo && mme_s10_self()->echo_interval)
            ogs_timer_start(peer->t_echo, mme_s10_self()->echo_interval);
        break;
    default:
        ogs_error("Unknown timer[%s:%d]",
                mme_timer_get_name(e->timer_id), e->timer_id);
        break;
    }
}
