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

#ifndef MME_S10_PATH_H
#define MME_S10_PATH_H

#include "mme-s10-context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Connect the peers on the GTP-C sockets opened by mme_gtp_open() */
int mme_s10_open(void);
void mme_s10_close(void);

int mme_s10_send_echo_request(mme_s10_peer_t *peer);

/*
 * Identification (TS 23.401 5.3.2.1 step 3, TS 29.274 7.3.8 and 7.3.9)
 * 'nas' is the complete Attach Request message, security header included.
 */
int mme_s10_send_identification_request(mme_s10_peer_t *peer,
        mme_ue_t *mme_ue, const ogs_nas_eps_guti_t *guti,
        const uint8_t *nas, int nas_len);
int mme_s10_send_identification_response(
        ogs_gtp_xact_t *xact, uint8_t cause_value, mme_ue_t *mme_ue);

/*
 * Reply to an S10 request with a response that only carries a Cause.
 * 'request_type' is the type of the received request.
 */
int mme_s10_send_error_response(
        ogs_gtp_xact_t *xact, uint8_t request_type, uint8_t cause_value);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_PATH_H */
