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

#ifndef MME_S10_BUILD_H
#define MME_S10_BUILD_H

#include "mme-s10-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MM Context (TS 29.274 8.38, EPS Security Context and Quadruplets)
 * from the current EPS security context of the UE. No authentication
 * vector is transferred. NH and NCC are added only when 'with_nh' is set.
 */
void mme_s10_build_mm_context(
        mme_ue_t *mme_ue, ogs_gtp2_mm_context_t *mm_context, bool with_nh);

/* TS 29.274 7.3.8 : 'nas' is the complete Attach Request message */
ogs_pkbuf_t *mme_s10_build_identification_request(
        const ogs_nas_eps_guti_t *guti, const uint8_t *nas, int nas_len);

/* TS 29.274 7.3.9 : IMSI and MM Context only with an acceptance cause */
ogs_pkbuf_t *mme_s10_build_identification_response(
        uint8_t cause_value, mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_BUILD_H */
