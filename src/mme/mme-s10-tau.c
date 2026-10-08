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
 * Tracking Area Update with MME change on S10.
 *
 * TS 23.401 5.3.3.1 (with SGW change) and 5.3.3.2 (without SGW change),
 * TS 29.274 7.3.5 Context Request, 7.3.6 Context Response,
 * 7.3.7 Context Acknowledge, TS 33.401 for the EPS security context.
 *
 * New MME
 *   TAU Request (old GUTI of a peer)  -> Context Request
 *   Context Response                  -> IMSI, EPS security context and
 *                                        PDN connections taken into use
 *                                     -> Context Acknowledge
 *   SGW kept    : Modify Bearer Request per PDN connection
 *   SGW changed : Create Session Request per PDN connection
 *   last answer                       -> Update Location to the HSS
 *   Update Location Answer            -> TAU Accept with a new GUTI
 *
 * Old MME
 *   Context Request  -> NAS MAC check of the TAU Request, Context Response,
 *                       holding timer started
 *   Context Ack      -> the UE has moved (or not)
 *   Cancel Location  -> left to the holding timer
 *   holding timer    -> UE released. With an SGW change, the old SGW
 *                       releases the PDN connections without deleting
 *                       them in the PGW (Scope Indication).
 */

#include "ogs-gtp.h"

#include "mme-sm.h"
#include "mme-timer.h"
#include "mme-path.h"
#include "mme-gtp-path.h"
#include "mme-fd-path.h"
#include "nas-path.h"
#include "nas-security.h"
#include "s1ap-path.h"
#include "mme-s10-build.h"
#include "mme-s10-path.h"
#include "mme-s10-handler.h"

/* PTI of the imported PDN connections, away from the values UEs use */
#define MME_S10_IMPORTED_PTI_BASE 254

/***********************************************************************
 * New MME
 ***********************************************************************/

bool mme_s10_context_start(enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        ogs_nas_eps_tracking_area_update_request_t *tau_request,
        ogs_pkbuf_t *pkbuf, ogs_nas_security_header_type_t h)
{
    ogs_nas_eps_guti_t nas_guti;
    mme_s10_peer_t *peer = NULL;
    int rv;

    ogs_assert(mme_ue);
    ogs_assert(tau_request);
    ogs_assert(pkbuf);

    peer = mme_s10_peer_of_old_guti(&tau_request->old_guti, h, &nas_guti);
    if (!peer)
        return false;

    /* Retransmitted TAU Request while the answer is awaited */
    if (mme_ue->s10.xact_id != OGS_INVALID_POOL_ID &&
        ogs_gtp_xact_find_by_id(mme_ue->s10.xact_id))
        return true;
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;

    /* The NAS security header was removed by the S1AP layer */
    if (!ogs_pkbuf_push(pkbuf, sizeof(ogs_nas_eps_security_header_t))) {
        ogs_error("No NAS security header in the TAU Request");
        return false;
    }
    rv = mme_s10_send_context_request(peer, mme_ue, &nas_guti,
            pkbuf->data, pkbuf->len);
    ogs_assert(ogs_pkbuf_pull(pkbuf, sizeof(ogs_nas_eps_security_header_t)));

    return rv == OGS_OK;
}

/*
 * The TAU cannot be completed. The PDN connections are only removed in
 * this MME : they still exist in the old MME, the SGW and the PGW.
 * The UE is rejected (TS 24.301 5.5.3.2.5) and attaches again.
 */
void mme_s10_handle_tau_failure(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, uint8_t emm_cause)
{
    int r;

    ogs_assert(mme_ue);

    ogs_warn("[%s] S10: TAU with MME change failed [EMM_CAUSE:%d]",
            mme_ue->imsi_bcd, emm_cause);

    mme_ue->s10.tau = false;
    GTP_COUNTER_CLEAR(mme_ue, GTP_COUNTER_MODIFY_BEARER_BY_S10_TAU);
    GTP_COUNTER_CLEAR(mme_ue, GTP_COUNTER_CREATE_SESSION_BY_S10_TAU);

    mme_sess_remove_all(mme_ue);

    if (!enb_ue)
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue) {
        ogs_error("[%s] S1 context has already been removed",
                mme_ue->imsi_bcd);
        mme_ue_remove(mme_ue);
        return;
    }

    r = nas_eps_send_tau_reject(enb_ue, mme_ue, emm_cause);
    ogs_expect(r == OGS_OK);

    OGS_FSM_TRAN(&mme_ue->sm, &emm_state_exception);
    mme_send_delete_session_or_mme_ue_context_release(enb_ue, mme_ue);
}

void mme_s10_handle_context_failure(
        ogs_pool_id_t mme_ue_id, ogs_pool_id_t xact_id)
{
    mme_ue_t *mme_ue = mme_ue_find_by_id(mme_ue_id);

    if (!mme_ue) {
        ogs_error("S10: UE has already been removed");
        return;
    }
    if (mme_ue->s10.xact_id != xact_id) {
        ogs_warn("S10: stale Context transaction");
        return;
    }
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;

    mme_s10_handle_tau_failure(NULL, mme_ue,
        OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
}

static bool algorithm_in_order(
        uint8_t algorithm, const uint8_t *order, int num_of_order)
{
    int i;
    for (i = 0; i < num_of_order; i++)
        if (order[i] == algorithm)
            return true;
    return false;
}

/*
 * TS 33.401 : the new MME takes the EPS security context of the old MME
 * into use, without authentication, when it supports its algorithms.
 */
static bool take_security_context(
        mme_ue_t *mme_ue, ogs_gtp2_mm_context_t *mm_context)
{
    int len;

    if (mm_context->nas_integrity_algorithm ==
            OGS_NAS_SECURITY_ALGORITHMS_EIA0 ||
        !algorithm_in_order(mm_context->nas_integrity_algorithm,
            mme_self()->integrity_order,
            mme_self()->num_of_integrity_order) ||
        !algorithm_in_order(mm_context->nas_cipher_algorithm,
            mme_self()->ciphering_order,
            mme_self()->num_of_ciphering_order)) {
        ogs_warn("[%s] S10: NAS algorithms of the old MME not allowed "
                "[EIA%d EEA%d]", mme_ue->imsi_bcd,
                mm_context->nas_integrity_algorithm,
                mm_context->nas_cipher_algorithm);
        return false;
    }

    memcpy(mme_ue->kasme, mm_context->kasme, OGS_SHA256_DIGEST_SIZE);
    mme_ue->nas_eps.mme.ksi = mm_context->ksi_asme;
    mme_ue->nas_eps.ue.ksi = mm_context->ksi_asme;

    mme_ue->selected_int_algorithm = mm_context->nas_integrity_algorithm;
    mme_ue->selected_enc_algorithm = mm_context->nas_cipher_algorithm;
    ogs_kdf_nas_eps(OGS_KDF_NAS_INT_ALG, mme_ue->selected_int_algorithm,
            mme_ue->kasme, mme_ue->knas_int);
    ogs_kdf_nas_eps(OGS_KDF_NAS_ENC_ALG, mme_ue->selected_enc_algorithm,
            mme_ue->kasme, mme_ue->knas_enc);

    /* The UL NAS COUNT is the one of the TAU Request checked by the old
     * MME, the DL NAS COUNT is the one to use for the next message */
    mme_ue->dl_count = mm_context->nas_downlink_count;
    mme_ue->ul_count.i32 = mm_context->nas_uplink_count;
    mme_ue->ul_count_accepted = true;

    mme_ue->security_context_available = 1;
    mme_ue->mac_failed = 0;

    /* UE capabilities : the TAU Request may already carry them */
    len = mm_context->ue_network_capability_len;
    if (!mme_ue->ue_network_capability.length && len &&
        len < (int)sizeof(mme_ue->ue_network_capability)) {
        mme_ue->ue_network_capability.length = len;
        memcpy((uint8_t *)&mme_ue->ue_network_capability + 1,
                mm_context->ue_network_capability, len);
    }
    len = mm_context->ms_network_capability_len;
    if (!mme_ue->ms_network_capability.length && len &&
        len < (int)sizeof(mme_ue->ms_network_capability)) {
        mme_ue->ms_network_capability.length = len;
        memcpy((uint8_t *)&mme_ue->ms_network_capability + 1,
                mm_context->ms_network_capability, len);
    }
    len = mm_context->ue_additional_security_capability_len;
    if (!mme_ue->ue_additional_security_capability.length && len &&
        len < (int)sizeof(mme_ue->ue_additional_security_capability)) {
        mme_ue->ue_additional_security_capability.length = len;
        memcpy((uint8_t *)&mme_ue->ue_additional_security_capability + 1,
                mm_context->ue_additional_security_capability, len);
    }

    len = mm_context->mei_len;
    if (len > 0 && len <= (int)sizeof(mme_ue->imeisv)) {
        memcpy(mme_ue->imeisv, mm_context->mei, len);
        mme_ue->imeisv_len = len;
        ogs_buffer_to_bcd(mme_ue->imeisv, mme_ue->imeisv_len,
                mme_ue->imeisv_bcd, sizeof(mme_ue->imeisv_bcd));
    }

    if (mm_context->subscribed_ue_ambr_presence) {
        mme_ue->ambr.uplink =
            (uint64_t)mm_context->subscribed_ue_ambr.uplink * 1000;
        mme_ue->ambr.downlink =
            (uint64_t)mm_context->subscribed_ue_ambr.downlink * 1000;
    }

    /* TS 33.401 7.2.7 : KeNB from the UL NAS COUNT of the TAU Request,
     * for the radio bearers set up with the TAU Accept */
    ogs_kdf_kenb(mme_ue->kasme, mme_ue->ul_count.i32, mme_ue->kenb);
    ogs_kdf_nh_enb(mme_ue->kasme, mme_ue->kenb, mme_ue->nh);
    mme_ue->nhcc = 1;

    return true;
}

/* The bearer gets the EBI it has in the UE (TS 24.301 6.4) */
static int bearer_set_ebi(mme_ue_t *mme_ue, mme_bearer_t *bearer, uint8_t ebi)
{
    if (bearer->ebi == ebi)
        return OGS_OK;

    mme_ebi_free(mme_ue, bearer->ebi);
    if (mme_ebi_reserve(mme_ue, ebi) != OGS_OK) {
        ogs_error("[%s] S10: EBI[%d] cannot be reserved",
                mme_ue->imsi_bcd, ebi);
        bearer->ebi = INVALID_EPS_BEARER_ID;
        return OGS_ERROR;
    }
    bearer->ebi = ebi;

    return OGS_OK;
}

static int import_bearer(mme_ue_t *mme_ue, mme_bearer_t *bearer,
        ogs_gtp2_tlv_bearer_context_t *ctx)
{
    ogs_gtp2_f_teid_t *f_teid = NULL;
    ogs_gtp2_bearer_qos_t bearer_qos;

    if (bearer_set_ebi(mme_ue, bearer, ctx->eps_bearer_id.u8) != OGS_OK)
        return OGS_ERROR;

    if (MME_S10_PDN_BEARER_SGW_S1U(ctx).presence) {
        f_teid = MME_S10_PDN_BEARER_SGW_S1U(ctx).data;
        bearer->sgw_s1u_teid = be32toh(f_teid->teid);
        if (ogs_gtp2_f_teid_to_ip(f_teid, &bearer->sgw_s1u_ip) != OGS_OK)
            return OGS_ERROR;
    }

    if (!MME_S10_PDN_BEARER_PGW_S5U(ctx).presence) {
        ogs_error("[%s] S10: no PGW S5/S8-U F-TEID [EBI:%d]",
                mme_ue->imsi_bcd, bearer->ebi);
        return OGS_ERROR;
    }
    f_teid = MME_S10_PDN_BEARER_PGW_S5U(ctx).data;
    bearer->pgw_s5u_teid = be32toh(f_teid->teid);
    if (ogs_gtp2_f_teid_to_ip(f_teid, &bearer->pgw_s5u_ip) != OGS_OK)
        return OGS_ERROR;

    if (!ctx->bearer_level_qos.presence ||
        ogs_gtp2_parse_bearer_qos(&bearer_qos, &ctx->bearer_level_qos) !=
            ctx->bearer_level_qos.len) {
        ogs_error("[%s] S10: invalid Bearer QoS [EBI:%d]",
                mme_ue->imsi_bcd, bearer->ebi);
        return OGS_ERROR;
    }
    bearer->qos.index = bearer_qos.qci;
    bearer->qos.arp.priority_level = bearer_qos.priority_level;
    bearer->qos.arp.pre_emption_capability =
        bearer_qos.pre_emption_capability;
    bearer->qos.arp.pre_emption_vulnerability =
        bearer_qos.pre_emption_vulnerability;
    bearer->qos.mbr.uplink = bearer_qos.ul_mbr;
    bearer->qos.mbr.downlink = bearer_qos.dl_mbr;
    bearer->qos.gbr.uplink = bearer_qos.ul_gbr;
    bearer->qos.gbr.downlink = bearer_qos.dl_gbr;

    if (ctx->tft.presence)
        OGS_TLV_STORE_DATA(&bearer->tft, &ctx->tft);

    /* The bearer is active in the UE and in the network */
    if (!OGS_FSM_CHECK(&bearer->sm, esm_state_active))
        OGS_FSM_TRAN(&bearer->sm, esm_state_active);

    return OGS_OK;
}

static int import_pdn_connection(mme_ue_t *mme_ue,
        ogs_gtp2_tlv_pdn_connection_t *pdn, int index)
{
    char apn[OGS_MAX_APN_LEN+1];
    ogs_session_t *session = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL, *default_bearer = NULL;
    ogs_gtp2_f_teid_t *pgw_s5c_teid = NULL;
    ogs_gtp2_ambr_t *ambr = NULL;
    ogs_ip_t ue_ip;
    bool default_found = false;
    int i;

    if (!pdn->apn.presence || !pdn->apn.len ||
        pdn->apn.len > OGS_MAX_APN_LEN ||
        !pdn->linked_eps_bearer_id.presence ||
        !pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.presence ||
        !pdn->bearer_contexts[0].presence ||
        !pdn->aggregate_maximum_bit_rate.presence ||
        pdn->aggregate_maximum_bit_rate.len < sizeof(ogs_gtp2_ambr_t)) {
        ogs_error("[%s] S10: mandatory IE missing in PDN Connection",
                mme_ue->imsi_bcd);
        return OGS_ERROR;
    }

    memset(apn, 0, sizeof(apn));
    if (ogs_fqdn_parse(apn, pdn->apn.data, pdn->apn.len) <= 0) {
        ogs_error("[%s] S10: invalid APN", mme_ue->imsi_bcd);
        return OGS_ERROR;
    }

    /* PDN address : only IP PDN connections are supported */
    memset(&ue_ip, 0, sizeof(ue_ip));
    if (pdn->ipv4_address.presence &&
        pdn->ipv4_address.len == OGS_IPV4_LEN) {
        ue_ip.ipv4 = 1;
        memcpy(&ue_ip.addr, pdn->ipv4_address.data, OGS_IPV4_LEN);
    }
    if (pdn->ipv6_address.presence &&
        pdn->ipv6_address.len == OGS_IPV6_LEN) {
        ue_ip.ipv6 = 1;
        memcpy(ue_ip.addr6, pdn->ipv6_address.data, OGS_IPV6_LEN);
    }
    if (!ue_ip.ipv4 && !ue_ip.ipv6) {
        ogs_error("[%s] S10: PDN Connection [%s] without IP address",
                mme_ue->imsi_bcd, apn);
        return OGS_ERROR;
    }

    session = mme_session_find_by_apn(mme_ue, apn);
    if (!session) {
        if (mme_ue->num_of_session >= OGS_MAX_NUM_OF_SESS) {
            ogs_error("[%s] S10: too many PDN Connections", mme_ue->imsi_bcd);
            return OGS_ERROR;
        }
        session = &mme_ue->session[mme_ue->num_of_session++];
        memset(session, 0, sizeof(*session));
        session->name = ogs_strdup(apn);
        ogs_assert(session->name);
    }

    session->session_type = ue_ip.ipv4 && ue_ip.ipv6 ?
        OGS_PDU_SESSION_TYPE_IPV4V6 :
        ue_ip.ipv4 ? OGS_PDU_SESSION_TYPE_IPV4 : OGS_PDU_SESSION_TYPE_IPV6;
    memcpy(&session->ue_ip, &ue_ip, sizeof(ue_ip));

    pgw_s5c_teid = pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data;
    if (ogs_gtp2_f_teid_to_ip(pgw_s5c_teid, &session->smf_ip) != OGS_OK) {
        ogs_error("[%s] S10: invalid PGW S5/S8 F-TEID", mme_ue->imsi_bcd);
        return OGS_ERROR;
    }

    ambr = pdn->aggregate_maximum_bit_rate.data;
    session->ambr.uplink = (uint64_t)be32toh(ambr->uplink) * 1000;
    session->ambr.downlink = (uint64_t)be32toh(ambr->downlink) * 1000;

    sess = mme_sess_add(mme_ue, MME_S10_IMPORTED_PTI_BASE - index);
    ogs_assert(sess);
    sess->session = session;

    sess->pgw_s5c_teid = be32toh(pgw_s5c_teid->teid);
    memcpy(&sess->pgw_s5c_ip, &session->smf_ip, sizeof(sess->pgw_s5c_ip));
    ogs_ip_to_paa(&ue_ip, &sess->paa);
    sess->ue_request_type.type = session->session_type;
    sess->ue_request_type.value = OGS_NAS_EPS_REQUEST_TYPE_INITIAL;

    /* mme_sess_add() has created the default bearer */
    default_bearer = mme_default_bearer_in_sess(sess);
    ogs_assert(default_bearer);

    for (i = 0; i < OGS_BEARER_PER_UE && pdn->bearer_contexts[i].presence;
            i++) {
        ogs_gtp2_tlv_bearer_context_t *ctx = &pdn->bearer_contexts[i];

        if (!ctx->eps_bearer_id.presence) {
            ogs_error("[%s] S10: Bearer Context without EBI",
                    mme_ue->imsi_bcd);
            return OGS_ERROR;
        }

        if (ctx->eps_bearer_id.u8 == pdn->linked_eps_bearer_id.u8) {
            bearer = default_bearer;
            default_found = true;
        } else {
            bearer = mme_bearer_add(sess);
            if (!bearer)
                return OGS_ERROR;
        }

        if (import_bearer(mme_ue, bearer, ctx) != OGS_OK)
            return OGS_ERROR;
    }

    if (!default_found) {
        ogs_error("[%s] S10: no Bearer Context for the LBI[%d]",
                mme_ue->imsi_bcd, pdn->linked_eps_bearer_id.u8);
        return OGS_ERROR;
    }

    /* The default bearer gives the QoS of the PDN connection */
    memcpy(&session->qos, &default_bearer->qos, sizeof(session->qos));

    ogs_info("[%s] S10: PDN Connection [%s] LBI[%d] bearers[%d]",
            mme_ue->imsi_bcd, apn, default_bearer->ebi,
            ogs_list_count(&sess->bearer_list));

    return OGS_OK;
}

/*
 * Keep the SGW of the old MME when this MME uses it too : TAU without
 * SGW change (5.3.3.2). Otherwise the SGW selected for the UE is used
 * (5.3.3.1). Returns true for an SGW change.
 */
static bool select_sgw(mme_ue_t *mme_ue, ogs_gtp2_f_teid_t *old_sgw_teid)
{
    sgw_ue_t *sgw_ue = NULL;
    mme_sgw_t *old_sgw = NULL;
    ogs_sockaddr_t *addr = NULL, *sa = NULL;

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(sgw_ue);

    if (ogs_gtp2_f_teid_to_sockaddr(old_sgw_teid,
                ogs_gtp_self()->gtpc_port, &addr) == OGS_OK) {
        for (sa = addr; sa && !old_sgw; sa = sa->next)
            old_sgw = mme_sgw_find_by_addr(sa);
        ogs_freeaddrinfo(addr);
    }

    if (old_sgw) {
        if (sgw_ue->sgw != old_sgw)
            sgw_ue_switch_to_sgw(sgw_ue, old_sgw);
        sgw_ue->sgw_s11_teid = be32toh(old_sgw_teid->teid);
        return false;
    }

    /* A new S11 session is created in the selected SGW */
    sgw_ue->sgw_s11_teid = 0;
    return true;
}

static void start_session_updates(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, bool sgw_change)
{
    mme_sess_t *sess = NULL;
    int rv;

    mme_ue->s10.tau = true;
    GTP_COUNTER_CLEAR(mme_ue, GTP_COUNTER_MODIFY_BEARER_BY_S10_TAU);
    GTP_COUNTER_CLEAR(mme_ue, GTP_COUNTER_CREATE_SESSION_BY_S10_TAU);

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        if (sgw_change) {
            GTP_COUNTER_INCREMENT(
                    mme_ue, GTP_COUNTER_CREATE_SESSION_BY_S10_TAU);
            rv = mme_gtp_send_create_session_request(enb_ue, sess,
                    OGS_GTP_CREATE_IN_TRACKING_AREA_UPDATE);
        } else {
            GTP_COUNTER_INCREMENT(
                    mme_ue, GTP_COUNTER_MODIFY_BEARER_BY_S10_TAU);
            rv = mme_gtp_send_modify_bearer_request_in_tau(enb_ue, sess);
        }
        if (rv != OGS_OK) {
            mme_s10_handle_tau_failure(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_NETWORK_FAILURE);
            return;
        }
    }
}

/* Takes the context of the old MME into use. Returns the GTP cause. */
static uint8_t import_context(mme_ue_t *mme_ue,
        ogs_gtp2_context_response_t *rsp, ogs_gtp2_f_teid_t **old_sgw_teid)
{
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    ogs_gtp2_mm_context_t mm_context;
    int i;

    if (!rsp->imsi.presence || !rsp->imsi.len ||
        rsp->imsi.len > OGS_MAX_IMSI_LEN ||
        !ogs_buffer_to_bcd(rsp->imsi.data, rsp->imsi.len,
            imsi_bcd, sizeof(imsi_bcd))) {
        ogs_error("S10: Context Response without valid IMSI");
        return OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
    }

    if (!rsp->mme_sgsn_amf_ue_mm_context.presence ||
        ogs_gtp2_parse_mm_context(&mm_context,
            &rsp->mme_sgsn_amf_ue_mm_context) <= 0) {
        ogs_error("[%s] S10: no usable MM Context", imsi_bcd);
        return OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
    }

    if (!rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.presence) {
        ogs_error("[%s] S10: no SGW S11 F-TEID", imsi_bcd);
        return OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
    }
    *old_sgw_teid =
        rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.data;

    if (!rsp->mme_sgsn_amf_ue_eps_pdn_connections[0].presence) {
        ogs_error("[%s] S10: no PDN Connection", imsi_bcd);
        return OGS_GTP2_CAUSE_CONDITIONAL_IE_MISSING;
    }

    if (mme_ue_set_imsi(mme_ue, imsi_bcd,
                MME_UE_IMSI_FROM_CONTEXT_RESPONSE) != OGS_OK) {
        ogs_error("[%s] mme_ue_set_imsi() failed", imsi_bcd);
        return OGS_GTP2_CAUSE_SYSTEM_FAILURE;
    }

    /* A stale context of this IMSI in this MME is replaced */
    if (ogs_list_count(&mme_ue->sess_list)) {
        ogs_warn("[%s] S10: local PDN connections replaced",
                mme_ue->imsi_bcd);
        mme_sess_remove_all(mme_ue);
    }

    if (!take_security_context(mme_ue, &mm_context))
        return OGS_GTP2_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED;

    for (i = 0; i < OGS_MAX_NUM_OF_SESS &&
            rsp->mme_sgsn_amf_ue_eps_pdn_connections[i].presence; i++) {
        if (import_pdn_connection(mme_ue,
                &rsp->mme_sgsn_amf_ue_eps_pdn_connections[i], i) !=
                OGS_OK)
            return OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT;
    }

    return OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
}

void mme_s10_handle_context_response(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_context_response_t *rsp)
{
    ogs_pool_id_t mme_ue_id, xact_id;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_gtp2_cause_t *cause = NULL;
    ogs_gtp2_f_teid_t *peer_teid = NULL, *old_sgw_teid = NULL;
    uint8_t cause_value;
    bool sgw_change;

    ogs_assert(peer);
    ogs_assert(xact);
    ogs_assert(rsp);

    mme_ue_id = OGS_POINTER_TO_UINT(xact->data);
    xact_id = xact->id;

    mme_ue = mme_ue_find_by_id(mme_ue_id);
    if (!mme_ue) {
        ogs_error("S10: UE has already been removed");
        return;
    }
    if (mme_ue->s10.xact_id != xact_id) {
        ogs_warn("S10: stale Context Response");
        return;
    }
    mme_ue->s10.xact_id = OGS_INVALID_POOL_ID;
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    if (rsp->cause.presence && rsp->cause.len >= sizeof(*cause))
        cause = rsp->cause.data;

    /* TS 29.274 7.3.7 : no Context Acknowledge for a rejection */
    if (!cause || cause->value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_warn("S10: Context Response from `%s` rejected [cause:%d]",
                peer->id, cause ? cause->value : 0);
        mme_s10_handle_tau_failure(enb_ue, mme_ue,
            OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
        return;
    }

    /* The Context Acknowledge is sent to the TEID of the old MME */
    if (!rsp->sender_f_teid_for_control_plane.presence) {
        ogs_error("S10: Context Response from `%s` without Sender F-TEID",
                peer->id);
        mme_s10_handle_tau_failure(enb_ue, mme_ue,
            OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
        return;
    }
    peer_teid = rsp->sender_f_teid_for_control_plane.data;
    mme_ue->s10.peer_s10_teid = be32toh(peer_teid->teid);

    if (!enb_ue || !OGS_FSM_CHECK(&mme_ue->sm, emm_state_de_registered)) {
        ogs_warn("S10: TAU is no longer in progress");
        mme_s10_send_context_acknowledge(xact, mme_ue,
                OGS_GTP2_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED, false);
        if (!enb_ue)
            mme_s10_handle_tau_failure(NULL, mme_ue,
                OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
        return;
    }

    cause_value = import_context(mme_ue, rsp, &old_sgw_teid);
    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        /* The old MME keeps the UE */
        mme_s10_send_context_acknowledge(xact, mme_ue, cause_value, false);
        mme_s10_handle_tau_failure(enb_ue, mme_ue,
            OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
        return;
    }

    sgw_change = select_sgw(mme_ue, old_sgw_teid);

    ogs_info("[%s] S10: Context Response from `%s`, %s SGW change",
            mme_ue->imsi_bcd, peer->id, sgw_change ? "with" : "without");

    mme_s10_send_context_acknowledge(xact, mme_ue,
            OGS_GTP2_CAUSE_REQUEST_ACCEPTED, sgw_change);

    /* TS 23.401 5.3.3.1 step 20 : a new GUTI with the GUMMEI of this MME */
    mme_ue_new_guti(mme_ue);

    OGS_FSM_TRAN(&mme_ue->sm, &emm_state_initial_context_setup);

    start_session_updates(enb_ue, mme_ue, sgw_change);
}

void mme_s10_handle_tau_modify_bearer_response(enb_ue_t *enb_ue,
        mme_ue_t *mme_ue, mme_ue_t *mme_ue_from_teid,
        ogs_gtp2_modify_bearer_response_t *rsp)
{
    ogs_gtp2_cause_t *cause = NULL;

    ogs_assert(mme_ue);
    ogs_assert(rsp);

    /* Late answer after a failure of the TAU */
    if (!mme_ue->s10.tau) {
        ogs_warn("[%s] S10: Modify Bearer Response ignored",
                mme_ue->imsi_bcd);
        return;
    }

    if (rsp->cause.presence && rsp->cause.len >= sizeof(*cause))
        cause = rsp->cause.data;

    if (!mme_ue_from_teid || !cause ||
        cause->value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("[%s] S10: Modify Bearer Request rejected [cause:%d]",
                mme_ue->imsi_bcd, cause ? cause->value : 0);
        mme_s10_handle_tau_failure(enb_ue, mme_ue,
                OGS_NAS_EMM_CAUSE_NETWORK_FAILURE);
        return;
    }

    GTP_COUNTER_CHECK(mme_ue, GTP_COUNTER_MODIFY_BEARER_BY_S10_TAU,
        mme_s10_handle_tau_sessions_updated(enb_ue, mme_ue);
    );
}

/* TS 23.401 5.3.3.1 step 12 : the HSS cancels the UE in the old MME */
void mme_s10_handle_tau_sessions_updated(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    mme_ue->s10.tau = false;

    if (!enb_ue)
        enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    ogs_info("[%s] S10: PDN connections moved, Update Location",
            mme_ue->imsi_bcd);
    mme_s6a_send_ulr(enb_ue, mme_ue, 0);
}

/***********************************************************************
 * Old MME
 ***********************************************************************/

void mme_s10_handle_context_request(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, ogs_gtp2_context_request_t *req)
{
    uint8_t cause = OGS_GTP2_CAUSE_REQUEST_ACCEPTED;
    mme_ue_t *mme_ue = NULL;
    ogs_gtp2_f_teid_t *peer_teid = NULL;
    bool ms_validated = false;

    ogs_assert(peer);
    ogs_assert(xact);
    ogs_assert(req);

    if (!req->s3_s16_s10_n26_address_and_teid_for_control_plane.presence) {
        ogs_error("S10: Context Request from `%s` without F-TEID", peer->id);
        cause = OGS_GTP2_CAUSE_MANDATORY_IE_MISSING;
        goto out;
    }
    peer_teid = req->s3_s16_s10_n26_address_and_teid_for_control_plane.data;

    /* MSV : the new MME has authenticated the UE (TS 29.274 8.12) */
    if (req->indication.presence && req->indication.len >= 2)
        ms_validated = ((ogs_gtp2_indication_t *)
                req->indication.data)->ms_validated;

    if (ms_validated && req->imsi.presence) {
        char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
        if (req->imsi.len && req->imsi.len <= OGS_MAX_IMSI_LEN &&
            ogs_buffer_to_bcd(req->imsi.data, req->imsi.len,
                imsi_bcd, sizeof(imsi_bcd)))
            mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    } else if (req->guti.presence) {
        ogs_gtp2_guti_t guti;
        ogs_nas_eps_guti_t nas_guti;
        ogs_plmn_id_t plmn_id;

        if (ogs_gtp2_parse_guti(&guti, &req->guti) > 0) {
            memset(&nas_guti, 0, sizeof(nas_guti));
            memcpy(&nas_guti.nas_plmn_id, &guti.nas_plmn_id,
                    OGS_PLMN_ID_LEN);
            nas_guti.mme_gid = guti.mme_gid;
            nas_guti.mme_code = guti.mme_code;
            nas_guti.m_tmsi = guti.m_tmsi;
            ogs_nas_to_plmn_id(&plmn_id, &nas_guti.nas_plmn_id);
            if (mme_s10_gummei_is_local(&plmn_id,
                        nas_guti.mme_gid, nas_guti.mme_code))
                mme_ue = mme_ue_find_by_guti(&nas_guti);
        }
    }

    if (!mme_ue || !MME_UE_HAVE_IMSI(mme_ue)) {
        ogs_warn("S10: Context Request from `%s` for an unknown UE",
                peer->id);
        cause = OGS_GTP2_CAUSE_IMSI_IMEI_NOT_KNOWN;
        goto out;
    }

    ogs_info("[%s] S10: Context Request from `%s`%s",
            mme_ue->imsi_bcd, peer->id,
            ms_validated ? " (UE validated)" : "");

    if (!ms_validated) {
        ogs_gtp2_complete_request_message_t complete;

        if (!req->complete_tau_request_message.presence ||
            ogs_gtp2_parse_complete_request_message(&complete,
                &req->complete_tau_request_message) <= 0 ||
            complete.type !=
                OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_TAU_REQUEST ||
            !nas_eps_security_check_complete_request(
                mme_ue, complete.data, complete.len)) {
            /* TS 23.401 5.3.3.1 step 5 : the new MME authenticates the
             * UE and asks again with the MSV flag */
            cause = OGS_GTP2_CAUSE_USER_AUTHENTICATION_FAILED;
            goto out;
        }
    }

    mme_ue->s10.peer_s10_teid = be32toh(peer_teid->teid);
    if (mme_s10_send_context_response(xact, mme_ue) != OGS_OK)
        return;

    /* TS 23.401 5.3.3.1 step 4 : the UE is kept until the timer expires */
    mme_ue->s10.context_sent = true;
    mme_ue->s10.moved = false;
    mme_ue->s10.sgw_change = false;
    ogs_timer_start(mme_ue->s10.t_holding,
            mme_timer_cfg(MME_TIMER_S10_HOLDING)->duration);
    return;

out:
    mme_s10_send_error_response(xact, OGS_GTP2_CONTEXT_REQUEST_TYPE, cause);
}

void mme_s10_handle_context_acknowledge(mme_s10_peer_t *peer,
        ogs_gtp_xact_t *xact, mme_ue_t *mme_ue,
        ogs_gtp2_context_acknowledge_t *ack)
{
    ogs_gtp2_cause_t *cause = NULL;
    ogs_gtp2_indication_t *indication = NULL;

    ogs_assert(peer);
    ogs_assert(xact);
    ogs_assert(ack);

    /* The transaction of the Context Request ends here */
    ogs_expect(ogs_gtp_xact_commit(xact) == OGS_OK);

    if (!mme_ue || !mme_ue->s10.context_sent) {
        ogs_warn("S10: unexpected Context Acknowledge from `%s`", peer->id);
        return;
    }

    if (ack->cause.presence && ack->cause.len >= sizeof(*cause))
        cause = ack->cause.data;
    if (!cause || cause->value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        /* The new MME has not taken the UE : it stays here */
        ogs_warn("[%s] S10: Context Acknowledge from `%s` rejected "
                "[cause:%d]", mme_ue->imsi_bcd, peer->id,
                cause ? cause->value : 0);
        mme_ue->s10.context_sent = false;
        mme_ue->s10.moved = false;
        ogs_timer_stop(mme_ue->s10.t_holding);
        return;
    }

    if (ack->indication_flags.presence && ack->indication_flags.len >= 1) {
        indication = ack->indication_flags.data;
        mme_ue->s10.sgw_change = indication->sgw_change_indication;
    }
    mme_ue->s10.moved = true;

    ogs_info("[%s] S10: UE moved to `%s`, %s SGW change",
            mme_ue->imsi_bcd, peer->id,
            mme_ue->s10.sgw_change ? "with" : "without");
}

void mme_s10_handle_old_ue_released(mme_ue_t *mme_ue)
{
    enb_ue_t *enb_ue = NULL;
    int r;

    ogs_assert(mme_ue);

    ogs_info("[%s] S10: UE context released", mme_ue->imsi_bcd);

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (enb_ue) {
        r = s1ap_send_ue_context_release_command(enb_ue,
                S1AP_Cause_PR_nas, S1AP_CauseNas_normal_release,
                S1AP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
    } else {
        mme_ue_remove(mme_ue);
    }
}

/* TS 23.401 5.3.3.1 step 18 and 5.3.3.2 step 15 */
void mme_s10_handle_holding_timer(mme_ue_t *mme_ue)
{
    sgw_ue_t *sgw_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    if (!mme_ue->s10.context_sent)
        return;

    if (!mme_ue->s10.moved) {
        /* No Context Acknowledge : the UE stays in this MME */
        ogs_warn("[%s] S10: no Context Acknowledge, UE kept",
                mme_ue->imsi_bcd);
        mme_ue->s10.context_sent = false;
        return;
    }

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    if (mme_ue->s10.sgw_change && sgw_ue &&
        SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
        /* The old SGW releases the PDN connections without deleting
         * them in the PGW. The last answer releases the UE. */
        ogs_list_for_each(&mme_ue->sess_list, sess) {
            ogs_assert(OGS_OK == mme_gtp_send_delete_session_request(
                        enb_ue, sgw_ue, sess,
                        OGS_GTP_DELETE_IN_MME_RELOCATION));
        }
        return;
    }

    /* Without SGW change, the SGW is now used by the new MME */
    mme_s10_handle_old_ue_released(mme_ue);
}

bool mme_s10_cancel_location_delayed(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (!mme_ue->s10.context_sent)
        return false;

    ogs_info("[%s] S10: Cancel Location, UE released by the holding timer",
            mme_ue->imsi_bcd);
    return true;
}
