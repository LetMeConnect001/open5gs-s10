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
 * Reply to an S10 request with a response that only carries a Cause.
 * 'request_type' is the type of the received request.
 */
int mme_s10_send_error_response(
        ogs_gtp_xact_t *xact, uint8_t request_type, uint8_t cause_value);

#ifdef __cplusplus
}
#endif

#endif /* MME_S10_PATH_H */
