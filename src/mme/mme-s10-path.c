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

#include "mme-event.h"
#include "mme-timer.h"
#include "mme-s10-handler.h"
#include "mme-s10-path.h"

static void echo_timer_expire(void *data)
{
    int rv;
    mme_s10_peer_t *peer = data;
    mme_event_t *e = NULL;

    ogs_assert(peer);

    e = mme_event_new(MME_EVENT_S10_TIMER);
    ogs_assert(e);
    e->timer_id = MME_TIMER_S10_ECHO;
    e->gnode = &peer->gnode;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        mme_event_free(e);
    }
}

int mme_s10_open(void)
{
    int rv;
    char buf[OGS_ADDRSTRLEN];
    mme_s10_peer_t *peer = NULL;

    ogs_list_for_each(&mme_s10_self()->peer_list, peer) {
        rv = ogs_gtp_connect(
                ogs_gtp_self()->gtpc_sock, ogs_gtp_self()->gtpc_sock6,
                &peer->gnode);
        if (rv != OGS_OK) {
            ogs_error("S10: cannot use peer `%s`", peer->id);
            return rv;
        }

        if (mme_s10_self()->echo_interval) {
            peer->t_echo = ogs_timer_add(
                    ogs_app()->timer_mgr, echo_timer_expire, peer);
            ogs_assert(peer->t_echo);
            ogs_timer_start(peer->t_echo, mme_s10_self()->echo_interval);
        }

        ogs_info("S10: peer `%s` [%s]:%d", peer->id,
                OGS_ADDR(&peer->gnode.addr, buf),
                OGS_PORT(&peer->gnode.addr));
    }

    return OGS_OK;
}

void mme_s10_close(void)
{
    mme_s10_peer_t *peer = NULL;

    ogs_list_for_each(&mme_s10_self()->peer_list, peer) {
        if (peer->t_echo)
            ogs_timer_stop(peer->t_echo);
    }
}

/* No Echo Response after all the retransmissions (TS 29.274 clause 7.6) */
static void echo_timeout(ogs_gtp_xact_t *xact, void *data)
{
    mme_s10_peer_t *peer = mme_s10_peer_find_by_gnode(data);

    if (!peer) {
        ogs_error("S10: peer has already been removed");
        return;
    }

    mme_s10_handle_path_failure(peer);
}

int mme_s10_send_echo_request(mme_s10_peer_t *peer)
{
    int rv;
    ogs_gtp2_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(peer);

    memset(&h, 0, sizeof(h));
    h.type = OGS_GTP2_ECHO_REQUEST_TYPE;
    h.teid = 0;

    pkbuf = ogs_gtp2_build_echo_request(
            h.type, mme_s10_self()->local_recovery, 0);
    if (!pkbuf) {
        ogs_error("ogs_gtp2_build_echo_request() failed");
        return OGS_ERROR;
    }

    xact = ogs_gtp_xact_local_create(
            &peer->gnode, &h, pkbuf, echo_timeout, &peer->gnode);
    if (!xact) {
        ogs_error("ogs_gtp_xact_local_create() failed");
        return OGS_ERROR;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);

    return rv;
}

int mme_s10_send_error_response(
        ogs_gtp_xact_t *xact, uint8_t request_type, uint8_t cause_value)
{
    uint8_t response_type;

    ogs_assert(xact);

    switch (request_type) {
    case OGS_GTP2_IDENTIFICATION_REQUEST_TYPE:
        response_type = OGS_GTP2_IDENTIFICATION_RESPONSE_TYPE;
        break;
    case OGS_GTP2_CONTEXT_REQUEST_TYPE:
        response_type = OGS_GTP2_CONTEXT_RESPONSE_TYPE;
        break;
    case OGS_GTP2_FORWARD_RELOCATION_REQUEST_TYPE:
        response_type = OGS_GTP2_FORWARD_RELOCATION_RESPONSE_TYPE;
        break;
    case OGS_GTP2_FORWARD_RELOCATION_COMPLETE_NOTIFICATION_TYPE:
        response_type = OGS_GTP2_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE_TYPE;
        break;
    case OGS_GTP2_FORWARD_ACCESS_CONTEXT_NOTIFICATION_TYPE:
        response_type = OGS_GTP2_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE_TYPE;
        break;
    case OGS_GTP2_RELOCATION_CANCEL_REQUEST_TYPE:
        response_type = OGS_GTP2_RELOCATION_CANCEL_RESPONSE_TYPE;
        break;
    default:
        ogs_error("S10: no response for message type %d", request_type);
        return OGS_ERROR;
    }

    /*
     * TS 29.274 clause 5.5.2 : the TEID of the peer is not looked up and
     * is set to zero. The cause is then not "Context not found".
     */
    ogs_gtp2_send_error_message(xact, 0, response_type, cause_value);

    return OGS_OK;
}
