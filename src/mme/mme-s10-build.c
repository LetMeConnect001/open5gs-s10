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

#include "mme-s10-build.h"

#define MME_S10_MM_CONTEXT_MAX_LEN 512

/* bps to kbps, rounded upwards (TS 29.274 8.38) */
static uint32_t bps_to_kbps(uint64_t bps)
{
    uint64_t kbps = (bps + 999) / 1000;
    return kbps > 0xffffffff ? 0xffffffff : (uint32_t)kbps;
}

void mme_s10_build_mm_context(
        mme_ue_t *mme_ue, ogs_gtp2_mm_context_t *mm_context, bool with_nh)
{
    int len;

    ogs_assert(mme_ue);
    ogs_assert(mm_context);

    memset(mm_context, 0, sizeof(*mm_context));

    mm_context->security_mode =
        OGS_GTP2_MM_CONTEXT_SECURITY_MODE_EPS_SECURITY_CONTEXT_AND_QUADRUPLETS;
    mm_context->ksi_asme = mme_ue->nas_eps.mme.ksi & 0x07;
    mm_context->nas_integrity_algorithm = mme_ue->selected_int_algorithm;
    mm_context->nas_cipher_algorithm = mme_ue->selected_enc_algorithm;

    /* Downlink : the NAS COUNT to use for the next message.
     * Uplink : the NAS COUNT of the last accepted message. */
    mm_context->nas_downlink_count = mme_ue->dl_count & 0xffffff;
    mm_context->nas_uplink_count = mme_ue->ul_count.i32 & 0xffffff;

    memcpy(mm_context->kasme, mme_ue->kasme, OGS_GTP2_KASME_LEN);

    if (with_nh) {
        mm_context->nh_presence = true;
        memcpy(mm_context->nh, mme_ue->nh, OGS_GTP2_NH_LEN);
        mm_context->ncc = mme_ue->nhcc;
    }

    if (mme_ue->ambr.uplink || mme_ue->ambr.downlink) {
        mm_context->subscribed_ue_ambr_presence = true;
        mm_context->subscribed_ue_ambr.uplink =
            bps_to_kbps(mme_ue->ambr.uplink);
        mm_context->subscribed_ue_ambr.downlink =
            bps_to_kbps(mme_ue->ambr.downlink);
    }

    /* The NAS IEs are copied without their length octet */
    len = mme_ue->ue_network_capability.length;
    if (len > 0 && len <= OGS_GTP2_MAX_UE_NETWORK_CAPABILITY_LEN) {
        mm_context->ue_network_capability_len = len;
        memcpy(mm_context->ue_network_capability,
                (uint8_t *)&mme_ue->ue_network_capability + 1, len);
    }

    len = mme_ue->ms_network_capability.length;
    if (len > 0 && len <= OGS_GTP2_MAX_MS_NETWORK_CAPABILITY_LEN) {
        mm_context->ms_network_capability_len = len;
        memcpy(mm_context->ms_network_capability,
                (uint8_t *)&mme_ue->ms_network_capability + 1, len);
    }

    /* MEI is coded as in the MEI IE (TS 29.274 8.10) */
    len = mme_ue->imeisv_len;
    if (len > 0 && len <= OGS_GTP2_MAX_MEI_LEN) {
        mm_context->mei_len = len;
        memcpy(mm_context->mei, mme_ue->imeisv, len);
    }

    len = mme_ue->ue_additional_security_capability.length;
    if (len > 0 && len <= OGS_GTP2_MAX_UE_ADDITIONAL_SECURITY_CAPABILITY_LEN) {
        mm_context->ue_additional_security_capability_len = len;
        memcpy(mm_context->ue_additional_security_capability,
                (uint8_t *)&mme_ue->ue_additional_security_capability + 1,
                len);
    }

    mm_context->ensct = OGS_GTP2_MM_CONTEXT_ENSCT_NATIVE;
}

ogs_pkbuf_t *mme_s10_build_identification_request(
        const ogs_nas_eps_guti_t *guti, const uint8_t *nas, int nas_len)
{
    ogs_gtp2_message_t *message = NULL;
    ogs_gtp2_identification_request_t *req = NULL;
    ogs_gtp2_guti_t gtp_guti;
    ogs_gtp2_complete_request_message_t complete;
    uint8_t guti_buf[OGS_GTP2_GUTI_LEN];
    uint8_t *complete_buf = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(guti);
    ogs_assert(nas);
    ogs_assert(nas_len > 0);

    /* ogs_gtp2_message_t is too large for the stack */
    message = ogs_calloc(1, sizeof(*message));
    ogs_assert(message);
    complete_buf = ogs_malloc(nas_len + 1);
    ogs_assert(complete_buf);

    message->h.type = OGS_GTP2_IDENTIFICATION_REQUEST_TYPE;
    req = &message->identification_request;

    memset(&gtp_guti, 0, sizeof(gtp_guti));
    memcpy(&gtp_guti.nas_plmn_id, &guti->nas_plmn_id, OGS_PLMN_ID_LEN);
    gtp_guti.mme_gid = guti->mme_gid;
    gtp_guti.mme_code = guti->mme_code;
    gtp_guti.m_tmsi = guti->m_tmsi;
    req->guti.presence = 1;
    ogs_assert(ogs_gtp2_build_guti(
                &req->guti, &gtp_guti, guti_buf, sizeof(guti_buf)) > 0);

    memset(&complete, 0, sizeof(complete));
    complete.type = OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_ATTACH_REQUEST;
    complete.data = (uint8_t *)nas;
    complete.len = nas_len;
    req->complete_attach_request_message.presence = 1;
    ogs_assert(ogs_gtp2_build_complete_request_message(
                &req->complete_attach_request_message,
                &complete, complete_buf, nas_len + 1) > 0);

    pkbuf = ogs_gtp2_build_msg(message);

    ogs_free(complete_buf);
    ogs_free(message);

    return pkbuf;
}

ogs_pkbuf_t *mme_s10_build_identification_response(
        uint8_t cause_value, mme_ue_t *mme_ue)
{
    ogs_gtp2_message_t *message = NULL;
    ogs_gtp2_identification_response_t *rsp = NULL;
    ogs_gtp2_cause_t cause;
    ogs_gtp2_mm_context_t mm_context;
    uint8_t mm_context_buf[MME_S10_MM_CONTEXT_MAX_LEN];
    ogs_pkbuf_t *pkbuf = NULL;

    message = ogs_calloc(1, sizeof(*message));
    ogs_assert(message);

    message->h.type = OGS_GTP2_IDENTIFICATION_RESPONSE_TYPE;
    rsp = &message->identification_response;

    memset(&cause, 0, sizeof(cause));
    cause.value = cause_value;
    rsp->cause.presence = 1;
    rsp->cause.data = &cause;
    rsp->cause.len = sizeof(cause);

    if (cause_value == OGS_GTP2_CAUSE_REQUEST_ACCEPTED) {
        ogs_assert(mme_ue);
        ogs_assert(mme_ue->imsi_len);

        rsp->imsi.presence = 1;
        rsp->imsi.data = mme_ue->imsi;
        rsp->imsi.len = mme_ue->imsi_len;

        mme_s10_build_mm_context(mme_ue, &mm_context, false);
        rsp->mme_sgsn_ue_mm_context.presence = 1;
        if (ogs_gtp2_build_mm_context(&rsp->mme_sgsn_ue_mm_context,
                    &mm_context, mm_context_buf,
                    sizeof(mm_context_buf)) <= 0) {
            ogs_error("[%s] Cannot build MM Context", mme_ue->imsi_bcd);
            ogs_free(message);
            return NULL;
        }
    }

    pkbuf = ogs_gtp2_build_msg(message);
    ogs_free(message);

    return pkbuf;
}

/* F-TEID of this MME on S10 for the UE */
static int build_local_s10_f_teid(mme_ue_t *mme_ue,
        ogs_gtp2_f_teid_t *f_teid, int *len)
{
    memset(f_teid, 0, sizeof(*f_teid));
    f_teid->interface_type = OGS_GTP2_F_TEID_S10_MME_GTP_C;
    f_teid->teid = htobe32(mme_ue->s10.mme_s10_teid);
    return ogs_gtp2_sockaddr_to_f_teid(
            ogs_gtp_self()->gtpc_addr, ogs_gtp_self()->gtpc_addr6,
            f_teid, len);
}

ogs_pkbuf_t *mme_s10_build_context_request(mme_ue_t *mme_ue,
        const ogs_nas_eps_guti_t *guti, const uint8_t *nas, int nas_len)
{
    ogs_gtp2_message_t *message = NULL;
    ogs_gtp2_context_request_t *req = NULL;
    ogs_gtp2_guti_t gtp_guti;
    ogs_gtp2_complete_request_message_t complete;
    ogs_gtp2_f_teid_t s10_teid;
    ogs_nas_plmn_id_t target_plmn_id;
    uint8_t guti_buf[OGS_GTP2_GUTI_LEN];
    uint8_t *complete_buf = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    int len;

    ogs_assert(mme_ue);
    ogs_assert(guti);
    ogs_assert(nas);
    ogs_assert(nas_len > 0);

    message = ogs_calloc(1, sizeof(*message));
    ogs_assert(message);
    complete_buf = ogs_malloc(nas_len + 1);
    ogs_assert(complete_buf);

    message->h.type = OGS_GTP2_CONTEXT_REQUEST_TYPE;
    req = &message->context_request;

    memset(&gtp_guti, 0, sizeof(gtp_guti));
    memcpy(&gtp_guti.nas_plmn_id, &guti->nas_plmn_id, OGS_PLMN_ID_LEN);
    gtp_guti.mme_gid = guti->mme_gid;
    gtp_guti.mme_code = guti->mme_code;
    gtp_guti.m_tmsi = guti->m_tmsi;
    req->guti.presence = 1;
    ogs_assert(ogs_gtp2_build_guti(
                &req->guti, &gtp_guti, guti_buf, sizeof(guti_buf)) > 0);

    memset(&complete, 0, sizeof(complete));
    complete.type = OGS_GTP2_COMPLETE_REQUEST_MESSAGE_TYPE_TAU_REQUEST;
    complete.data = (uint8_t *)nas;
    complete.len = nas_len;
    req->complete_tau_request_message.presence = 1;
    ogs_assert(ogs_gtp2_build_complete_request_message(
                &req->complete_tau_request_message,
                &complete, complete_buf, nas_len + 1) > 0);

    ogs_assert(OGS_OK == build_local_s10_f_teid(mme_ue, &s10_teid, &len));
    req->s3_s16_s10_n26_address_and_teid_for_control_plane.presence = 1;
    req->s3_s16_s10_n26_address_and_teid_for_control_plane.data = &s10_teid;
    req->s3_s16_s10_n26_address_and_teid_for_control_plane.len = len;

    req->rat_type.presence = 1;
    req->rat_type.u8 = OGS_GTP2_RAT_TYPE_EUTRAN;

    /* The PLMN selected by the UE, from its current TAI */
    ogs_nas_from_plmn_id(&target_plmn_id, &mme_ue->tai.plmn_id);
    req->target_plmn_id.presence = 1;
    req->target_plmn_id.data = &target_plmn_id;
    req->target_plmn_id.len = sizeof(target_plmn_id);

    pkbuf = ogs_gtp2_build_msg(message);

    ogs_free(complete_buf);
    ogs_free(message);

    return pkbuf;
}

/* Buffers of the IEs of one PDN Connection */
typedef struct pdn_buf_s {
    char apn[OGS_MAX_APN_LEN+1];
    uint8_t ipv4[OGS_IPV4_LEN];
    uint8_t ipv6[OGS_IPV6_LEN];
    ogs_gtp2_f_teid_t pgw_s5c;
    ogs_gtp2_ambr_t ambr;
    struct {
        ogs_gtp2_f_teid_t sgw_s1u;
        ogs_gtp2_f_teid_t pgw_s5u;
        uint8_t qos[GTP2_BEARER_QOS_LEN];
    } bearer[OGS_BEARER_PER_UE];
} pdn_buf_t;

static int build_pdn_connection(mme_sess_t *sess,
        ogs_gtp2_tlv_pdn_connection_t *pdn, pdn_buf_t *buf)
{
    ogs_session_t *session = sess->session;
    mme_bearer_t *bearer = NULL, *default_bearer = NULL;
    ogs_ip_t ip;
    int i, len;

    if (!session || !session->name) {
        ogs_error("Session without APN");
        return OGS_ERROR;
    }
    default_bearer = mme_default_bearer_in_sess(sess);
    if (!default_bearer) {
        ogs_error("[%s] No default bearer", session->name);
        return OGS_ERROR;
    }

    pdn->presence = 1;

    pdn->apn.presence = 1;
    pdn->apn.len = ogs_fqdn_build(buf->apn, session->name,
            strlen(session->name));
    pdn->apn.data = buf->apn;

    /* PDN Address : from the PAA allocated by the PGW */
    memset(&ip, 0, sizeof(ip));
    if (ogs_paa_to_ip(&sess->paa, &ip) == OGS_OK) {
        if (ip.ipv4) {
            memcpy(buf->ipv4, &ip.addr, OGS_IPV4_LEN);
            pdn->ipv4_address.presence = 1;
            pdn->ipv4_address.data = buf->ipv4;
            pdn->ipv4_address.len = OGS_IPV4_LEN;
        }
        if (ip.ipv6) {
            memcpy(buf->ipv6, ip.addr6, OGS_IPV6_LEN);
            pdn->ipv6_address.presence = 1;
            pdn->ipv6_address.data = buf->ipv6;
            pdn->ipv6_address.len = OGS_IPV6_LEN;
        }
    }

    pdn->linked_eps_bearer_id.presence = 1;
    pdn->linked_eps_bearer_id.u8 = default_bearer->ebi;

    memset(&buf->pgw_s5c, 0, sizeof(buf->pgw_s5c));
    buf->pgw_s5c.interface_type = OGS_GTP2_F_TEID_S5_S8_PGW_GTP_C;
    buf->pgw_s5c.teid = htobe32(sess->pgw_s5c_teid);
    if (ogs_gtp2_ip_to_f_teid(&sess->pgw_s5c_ip, &buf->pgw_s5c, &len) !=
            OGS_OK) {
        ogs_error("[%s] No PGW S5/S8 address", session->name);
        return OGS_ERROR;
    }
    pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.presence = 1;
    pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.data = &buf->pgw_s5c;
    pdn->pgw_s5_s8_ip_address_for_control_plane_or_pmip.len = len;

    i = 0;
    ogs_list_for_each(&sess->bearer_list, bearer) {
        ogs_gtp2_tlv_bearer_context_t *ctx = NULL;
        ogs_gtp2_bearer_qos_t bearer_qos;

        if (i >= OGS_BEARER_PER_UE)
            break;
        ctx = &pdn->bearer_contexts[i];
        ctx->presence = 1;

        ctx->eps_bearer_id.presence = 1;
        ctx->eps_bearer_id.u8 = bearer->ebi;

        if (bearer->tft.len && bearer->tft.data) {
            ctx->tft.presence = 1;
            ctx->tft.data = bearer->tft.data;
            ctx->tft.len = bearer->tft.len;
        }

        memset(&buf->bearer[i].sgw_s1u, 0, sizeof(buf->bearer[i].sgw_s1u));
        buf->bearer[i].sgw_s1u.interface_type =
            OGS_GTP2_F_TEID_S1_U_SGW_GTP_U;
        buf->bearer[i].sgw_s1u.teid = htobe32(bearer->sgw_s1u_teid);
        if (ogs_gtp2_ip_to_f_teid(&bearer->sgw_s1u_ip,
                    &buf->bearer[i].sgw_s1u, &len) == OGS_OK) {
            MME_S10_PDN_BEARER_SGW_S1U(ctx).presence = 1;
            MME_S10_PDN_BEARER_SGW_S1U(ctx).data = &buf->bearer[i].sgw_s1u;
            MME_S10_PDN_BEARER_SGW_S1U(ctx).len = len;
        }

        memset(&buf->bearer[i].pgw_s5u, 0, sizeof(buf->bearer[i].pgw_s5u));
        buf->bearer[i].pgw_s5u.interface_type =
            OGS_GTP2_F_TEID_S5_S8_PGW_GTP_U;
        buf->bearer[i].pgw_s5u.teid = htobe32(bearer->pgw_s5u_teid);
        if (ogs_gtp2_ip_to_f_teid(&bearer->pgw_s5u_ip,
                    &buf->bearer[i].pgw_s5u, &len) == OGS_OK) {
            MME_S10_PDN_BEARER_PGW_S5U(ctx).presence = 1;
            MME_S10_PDN_BEARER_PGW_S5U(ctx).data = &buf->bearer[i].pgw_s5u;
            MME_S10_PDN_BEARER_PGW_S5U(ctx).len = len;
        }

        memset(&bearer_qos, 0, sizeof(bearer_qos));
        bearer_qos.qci = bearer->qos.index;
        bearer_qos.priority_level = bearer->qos.arp.priority_level;
        bearer_qos.pre_emption_capability =
            bearer->qos.arp.pre_emption_capability;
        bearer_qos.pre_emption_vulnerability =
            bearer->qos.arp.pre_emption_vulnerability;
        bearer_qos.ul_mbr = bearer->qos.mbr.uplink;
        bearer_qos.dl_mbr = bearer->qos.mbr.downlink;
        bearer_qos.ul_gbr = bearer->qos.gbr.uplink;
        bearer_qos.dl_gbr = bearer->qos.gbr.downlink;
        ctx->bearer_level_qos.presence = 1;
        ogs_gtp2_build_bearer_qos(&ctx->bearer_level_qos, &bearer_qos,
                buf->bearer[i].qos, GTP2_BEARER_QOS_LEN);

        i++;
    }

    /* APN-AMBR in kbps (TS 29.274 8.7), mandatory */
    memset(&buf->ambr, 0, sizeof(buf->ambr));
    buf->ambr.uplink = htobe32(bps_to_kbps(session->ambr.uplink));
    buf->ambr.downlink = htobe32(bps_to_kbps(session->ambr.downlink));
    pdn->aggregate_maximum_bit_rate.presence = 1;
    pdn->aggregate_maximum_bit_rate.data = &buf->ambr;
    pdn->aggregate_maximum_bit_rate.len = sizeof(buf->ambr);

    return OGS_OK;
}

ogs_pkbuf_t *mme_s10_build_context_response(
        uint8_t cause_value, mme_ue_t *mme_ue)
{
    ogs_gtp2_message_t *message = NULL;
    ogs_gtp2_context_response_t *rsp = NULL;
    ogs_gtp2_cause_t cause;
    ogs_gtp2_mm_context_t mm_context;
    uint8_t mm_context_buf[MME_S10_MM_CONTEXT_MAX_LEN];
    ogs_gtp2_f_teid_t s10_teid, sgw_s11_teid;
    pdn_buf_t *pdn_buf = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    sgw_ue_t *sgw_ue = NULL;
    mme_sess_t *sess = NULL;
    ogs_ip_t sgw_ip;
    int i, len;

    message = ogs_calloc(1, sizeof(*message));
    ogs_assert(message);
    pdn_buf = ogs_calloc(OGS_MAX_NUM_OF_SESS, sizeof(*pdn_buf));
    ogs_assert(pdn_buf);

    message->h.type = OGS_GTP2_CONTEXT_RESPONSE_TYPE;
    rsp = &message->context_response;

    memset(&cause, 0, sizeof(cause));
    cause.value = cause_value;
    rsp->cause.presence = 1;
    rsp->cause.data = &cause;
    rsp->cause.len = sizeof(cause);

    if (cause_value != OGS_GTP2_CAUSE_REQUEST_ACCEPTED)
        goto build;

    ogs_assert(mme_ue);
    ogs_assert(mme_ue->imsi_len);

    rsp->imsi.presence = 1;
    rsp->imsi.data = mme_ue->imsi;
    rsp->imsi.len = mme_ue->imsi_len;

    mme_s10_build_mm_context(mme_ue, &mm_context, false);
    rsp->mme_sgsn_amf_ue_mm_context.presence = 1;
    if (ogs_gtp2_build_mm_context(&rsp->mme_sgsn_amf_ue_mm_context,
                &mm_context, mm_context_buf, sizeof(mm_context_buf)) <= 0) {
        ogs_error("[%s] Cannot build MM Context", mme_ue->imsi_bcd);
        goto error;
    }

    i = 0;
    ogs_list_for_each(&mme_ue->sess_list, sess) {
        if (i >= OGS_MAX_NUM_OF_SESS)
            break;
        if (build_pdn_connection(sess,
                    &rsp->mme_sgsn_amf_ue_eps_pdn_connections[i],
                    &pdn_buf[i]) != OGS_OK) {
            ogs_error("[%s] Cannot build PDN Connection", mme_ue->imsi_bcd);
            goto error;
        }
        i++;
    }

    ogs_assert(OGS_OK == build_local_s10_f_teid(mme_ue, &s10_teid, &len));
    rsp->sender_f_teid_for_control_plane.presence = 1;
    rsp->sender_f_teid_for_control_plane.data = &s10_teid;
    rsp->sender_f_teid_for_control_plane.len = len;

    /* SGW S11 F-TEID : the new MME keeps this SGW or relocates it */
    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (sgw_ue && sgw_ue->sgw && sgw_ue->sgw_s11_teid) {
        ogs_sockaddr_t *addr = &sgw_ue->sgw->gnode.addr;

        memset(&sgw_ip, 0, sizeof(sgw_ip));
        if (ogs_sockaddr_to_ip(
                    addr->ogs_sa_family == AF_INET ? addr : NULL,
                    addr->ogs_sa_family == AF_INET6 ? addr : NULL,
                    &sgw_ip) == OGS_OK) {
            memset(&sgw_s11_teid, 0, sizeof(sgw_s11_teid));
            sgw_s11_teid.interface_type = OGS_GTP2_F_TEID_S11_S4_SGW_GTP_C;
            sgw_s11_teid.teid = htobe32(sgw_ue->sgw_s11_teid);
            if (ogs_gtp2_ip_to_f_teid(&sgw_ip, &sgw_s11_teid, &len) ==
                    OGS_OK) {
                rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.
                    presence = 1;
                rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.
                    data = &sgw_s11_teid;
                rsp->sgw_s11_s4_ip_address_and_teid_for_control_plane.
                    len = len;
            }
        }
    }

build:
    pkbuf = ogs_gtp2_build_msg(message);

    ogs_free(pdn_buf);
    ogs_free(message);
    return pkbuf;

error:
    ogs_free(pdn_buf);
    ogs_free(message);
    return NULL;
}

ogs_pkbuf_t *mme_s10_build_context_acknowledge(
        uint8_t cause_value, bool sgw_change)
{
    ogs_gtp2_message_t *message = NULL;
    ogs_gtp2_context_acknowledge_t *ack = NULL;
    ogs_gtp2_cause_t cause;
    ogs_gtp2_indication_t indication;
    ogs_pkbuf_t *pkbuf = NULL;

    message = ogs_calloc(1, sizeof(*message));
    ogs_assert(message);

    message->h.type = OGS_GTP2_CONTEXT_ACKNOWLEDGE_TYPE;
    ack = &message->context_acknowledge;

    memset(&cause, 0, sizeof(cause));
    cause.value = cause_value;
    ack->cause.presence = 1;
    ack->cause.data = &cause;
    ack->cause.len = sizeof(cause);

    /* SGWCI : the new MME has selected a new SGW (TS 29.274 8.12) */
    memset(&indication, 0, sizeof(indication));
    if (sgw_change) {
        indication.sgw_change_indication = 1;
        ack->indication_flags.presence = 1;
        ack->indication_flags.data = &indication;
        ack->indication_flags.len = sizeof(indication);
    }

    pkbuf = ogs_gtp2_build_msg(message);
    ogs_free(message);

    return pkbuf;
}
