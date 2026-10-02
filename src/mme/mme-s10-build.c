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
