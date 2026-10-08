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
#include "mme-sm.h"
#include "mme-gtp-path.h"
#include "mme-fd-path.h"
#include "nas-path.h"
#include "nas-security.h"
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

    /* The local transaction of the Echo Request ends here */
    ogs_expect(ogs_gtp_xact_commit(xact) == OGS_OK);

    if (rsp->recovery.presence)
        mme_s10_handle_recovery(peer, rsp->recovery.u8);
    else
        ogs_warn("S10: no Recovery in Echo Response from `%s`", peer->id);

    path_up(peer);
}

static void nas_guti_from_gtp(
        ogs_nas_eps_guti_t *nas_guti, const ogs_gtp2_guti_t *guti)
{
    memset(nas_guti, 0, sizeof(*nas_guti));
    memcpy(&nas_guti->nas_plmn_id, &guti->nas_plmn_id, OGS_PLMN_ID_LEN);
    nas_guti->mme_gid = guti->mme_gid;
    nas_guti->mme_code = guti->mme_code;
    nas_guti->m_tmsi = guti->m_tmsi;
}

/*
 * Old MME, TS 23.401 5.3.2.1 step 3 : verify the Attach Request by its
 * NAS MAC, then answer with the IMSI and the MM Context of the UE.
 */
static void handle_identification_request(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_identification_request_t *req)
{
    uint8_t cause = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    mme_ue_t *mme_ue = NULL;
    ogs_gtp2_guti_t guti;
    ogs_nas_eps_guti_t nas_guti;
    ogs_plmn_id_t plmn_id;
    ogs_gtp2_complete_request_message_t complete;

    if (!req->guti.presence ||
        ogs_gtp2_parse_guti(&guti, &req->guti) <= 0) {
        /* RAI and P-TMSI identify a UE of an SGSN, not of this MME */
        ogs_warn("S10: Identification Request from `%s` without GUTI",
                peer->id);
        cause = OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN;
        goto out;
    }

    nas_guti_from_gtp(&nas_guti, &guti);
    ogs_nas_to_plmn_id(&plmn_id, &nas_guti.nas_plmn_id);
    if (!mme_s10_gummei_is_local(&plmn_id, nas_guti.mme_gid,
                nas_guti.mme_code))
        mme_ue = NULL;
    else
        mme_ue = mme_ue_find_by_guti(&nas_guti);

    ogs_info("S10: Identification Request from `%s` "
            "GUTI[G:%d,C:%d,M_TMSI:0x%x] IMSI[%s]", peer->id,
            nas_guti.mme_gid, nas_guti.mme_code, nas_guti.m_tmsi,
            mme_ue ? mme_ue->imsi_bcd : "Unknown");

    if (!mme_ue || !MME_UE_HAVE_IMSI(mme_ue)) {
        cause = OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN;
        goto out;
    }

    if (!req->complete_attach_request_message.presence ||
        ogs_gtp2_parse_complete_request_message(&complete,
            &req->complete_attach_request_message) <= 0 ||
        complete.type !=
            OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_ATTACH_REQUEST) {
        ogs_warn("[%s] S10: no Complete Attach Request Message",
                mme_ue->imsi_bcd);
        cause = OGS_GTP2_CAUSE_USER_AUTHENTICATION_FAILED;
        goto out;
    }

    if (!nas_eps_security_check_complete_request(
                mme_ue, complete.data, complete.len)) {
        cause = OGS_GTP2_CAUSE_USER_AUTHENTICATION_FAILED;
        goto out;
    }

out:
    if (cause != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        mme_ue = NULL;

    mme_s10_send_identification_response(xact, cause, mme_ue);
}

/*
 * New MME : continue the Attach procedure, with the IMSI from the old
 * MME, or with an Identity Request to the UE.
 *
 * The EPS security context received from the old MME is not taken into
 * use: the UE is authenticated again (authentication is optional in
 * TS 23.401 5.3.2.1 step 5a, and always allowed).
 */
static void identification_done(mme_ue_t *mme_ue, bool success)
{
    int r, xact_count;
    enb_ue_t *enb_ue = NULL;

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue) {
        ogs_error("[%s] S1 context has already been removed",
                mme_ue->imsi_bcd);
        return;
    }

    if (!OGS_FSM_CHECK(&mme_ue->sm, emm_state_de_registered)) {
        ogs_warn("[%s] Attach is no longer in progress", mme_ue->imsi_bcd);
        return;
    }

    if (success && MME_UE_HAVE_IMSI(mme_ue)) {
        xact_count = mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR);

        mme_gtp_send_delete_all_sessions(enb_ue, mme_ue,
                OGS_GTP_DELETE_SEND_AUTHENTICATION_REQUEST);

        if (!MME_SESSION_RELEASE_PENDING(mme_ue) &&
            mme_ue_xact_count(mme_ue, OGS_GTP_LOCAL_ORIGINATOR) ==
                xact_count) {
            mme_s6a_send_air(enb_ue, mme_ue, NULL);
        }

        OGS_FSM_TRAN(&mme_ue->sm, &emm_state_authentication);
        return;
    }

    CLEAR_MME_UE_TIMER(mme_ue->t3470);
    r = nas_eps_send_identity_request(mme_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);
}

void mme_s10_handle_identification_failure(
        ogs_pool_id_t mme_ue_id, ogs_pool_id_t xact_id)
{
    mme_ue_t *mme_ue = mme_ue_find_by_id(mme_ue_id);

    if (!mme_ue) {
        ogs_error("S10: UE has already been removed");
        return;
    }
    if (mme_ue->s10.xact_id != xact_id) {
        ogs_warn("S10: stale Identification transaction");
        return;
    }
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;

    identification_done(mme_ue, false);
}

static void handle_identification_response(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_identification_response_t *rsp)
{
    ogs_pool_id_t mme_ue_id, xact_id;
    mme_ue_t *mme_ue = NULL;
    ogs_gtp2_cause_t *cause = NULL;
    ogs_gtp2_mm_context_t mm_context;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    mme_ue_id = OGS_POINTER_TO_UINT(xact->data);
    xact_id = xact->id;

    /* The local transaction ends here */
    ogs_expect(ogs_gtp_xact_commit(xact) == OGS_OK);

    mme_ue = mme_ue_find_by_id(mme_ue_id);
    if (!mme_ue) {
        ogs_error("S10: UE has already been removed");
        return;
    }
    if (mme_ue->s10.xact_id != xact_id) {
        ogs_warn("S10: stale Identification Response");
        return;
    }
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;

    if (rsp->cause.presence && rsp->cause.len >= sizeof(*cause))
        cause = rsp->cause.data;
    if (!cause || cause->value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_warn("S10: Identification Response from `%s` rejected "
                "[cause:%d]", peer->id, cause ? cause->value : 0);
        identification_done(mme_ue, false);
        return;
    }

    if (!rsp->imsi.presence || !rsp->imsi.len ||
        !ogs_buffer_to_bcd(rsp->imsi.data, rsp->imsi.len,
            imsi_bcd, sizeof(imsi_bcd))) {
        ogs_error("S10: Identification Response from `%s` without IMSI",
                peer->id);
        identification_done(mme_ue, false);
        return;
    }

    /* The MM Context is checked even if it is not taken into use */
    if (!rsp->mme_sgsn_ue_mm_context.presence ||
        ogs_gtp2_parse_mm_context(&mm_context,
            &rsp->mme_sgsn_ue_mm_context) <= 0)
        ogs_warn("[%s] S10: no usable MM Context from `%s`",
                imsi_bcd, peer->id);

    ogs_info("[%s] S10: Identification Response from `%s`",
            imsi_bcd, peer->id);

    if (mme_ue_set_imsi(mme_ue, imsi_bcd,
                MME_UE_IMSI_FROM_IDENTIFICATION_RESPONSE) != OGS_OK) {
        ogs_error("[%s] mme_ue_set_imsi() failed", imsi_bcd);
        identification_done(mme_ue, false);
        return;
    }

    identification_done(mme_ue, true);
}

mme_s10_peer_t *mme_s10_peer_of_old_guti(
        const ogs_nas_eps_mobile_identity_t *identity,
        ogs_nas_security_header_type_t h, ogs_nas_eps_guti_t *nas_guti)
{
    ogs_plmn_id_t plmn_id;
    mme_s10_peer_t *peer = NULL;

    ogs_assert(identity);
    ogs_assert(nas_guti);

    if (identity->imsi.type != OGS_NAS_EPS_MOBILE_IDENTITY_GUTI)
        return NULL;

    memset(nas_guti, 0, sizeof(*nas_guti));
    nas_guti->nas_plmn_id = identity->guti.nas_plmn_id;
    nas_guti->mme_gid = identity->guti.mme_gid;
    nas_guti->mme_code = identity->guti.mme_code;
    nas_guti->m_tmsi = identity->guti.m_tmsi;

    ogs_nas_to_plmn_id(&plmn_id, &nas_guti->nas_plmn_id);
    if (mme_s10_gummei_is_local(&plmn_id, nas_guti->mme_gid,
                nas_guti->mme_code))
        return NULL;

    peer = mme_s10_select_peer_by_guti(nas_guti);
    if (!peer)
        return NULL;

    if (peer->path_state == MME_S10_PATH_DOWN) {
        ogs_warn("S10: path to old MME `%s` is down", peer->id);
        return NULL;
    }

    /* The old MME can only check an integrity protected message */
    if (!h.integrity_protected) {
        ogs_info("S10: NAS message not integrity protected, "
                "old MME `%s` not asked", peer->id);
        return NULL;
    }

    return peer;
}

bool mme_s10_identification_start(enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        ogs_nas_eps_attach_request_t *attach_request, ogs_pkbuf_t *pkbuf,
        ogs_nas_security_header_type_t h)
{
    ogs_nas_eps_guti_t nas_guti;
    mme_s10_peer_t *peer = NULL;
    int rv;

    ogs_assert(mme_ue);
    ogs_assert(attach_request);
    ogs_assert(pkbuf);

    peer = mme_s10_peer_of_old_guti(
            &attach_request->eps_mobile_identity, h, &nas_guti);
    if (!peer)
        return false;

    /* Retransmitted Attach Request while the answer is awaited */
    if (mme_ue->s10.xact_id != OGS_INVALID_POOL_ID &&
        ogs_gtp_xact_find_by_id(mme_ue->s10.xact_id))
        return true;
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;

    /* The NAS security header was removed by the S1AP layer */
    if (!ogs_pkbuf_push(pkbuf, sizeof(ogs_nas_eps_security_header_t))) {
        ogs_error("No NAS security header in the Attach Request");
        return false;
    }
    rv = mme_s10_send_identification_request(peer, mme_ue, &nas_guti,
            pkbuf->data, pkbuf->len);
    ogs_assert(ogs_pkbuf_pull(pkbuf, sizeof(ogs_nas_eps_security_header_t)));

    return rv == OGS_OK;
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
        handle_identification_request(
                peer, xact, &message->identification_request);
        break;

    case OGS_GTP2_IDENTIFICATION_RESPONSE_TYPE:
        handle_identification_response(
                peer, xact, &message->identification_response);
        break;

    case OGS_GTP2_CONTEXT_REQUEST_TYPE:
        mme_s10_handle_context_request(
                peer, xact, &message->context_request);
        break;

    case OGS_GTP2_CONTEXT_RESPONSE_TYPE:
        mme_s10_handle_context_response(
                peer, xact, &message->context_response);
        break;

    case OGS_GTP2_CONTEXT_ACKNOWLEDGE_TYPE:
        mme_s10_handle_context_acknowledge(
                peer, xact, mme_ue, &message->context_acknowledge);
        break;

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
    mme_ue_t *mme_ue = NULL;

    ogs_assert(e);

    if (e->timer_id == MME_TIMER_S10_HOLDING) {
        mme_ue = mme_ue_find_by_id(e->mme_ue_id);
        if (!mme_ue) {
            ogs_error("S10: UE has already been removed");
            return;
        }
        mme_s10_handle_holding_timer(mme_ue);
        return;
    }

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
