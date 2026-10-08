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

#include <arpa/inet.h>
#include <poll.h>

#include "s10-peer.h"

static struct sockaddr_in mme_addr(void)
{
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(OGS_GTPV2_C_UDP_PORT);
    inet_pton(AF_INET, TEST_S10_MME_ADDRESS, &sin.sin_addr);

    return sin;
}

int test_s10_peer_open(test_s10_peer_t *peer)
{
    return test_s10_peer_open_at(peer, TEST_S10_PEER_ADDRESS);
}

int test_s10_peer_open_at(test_s10_peer_t *peer, const char *address)
{
    struct sockaddr_in sin;
    int on = 1;

    ogs_assert(peer);
    ogs_assert(address);

    peer->last = NULL;
    peer->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (peer->fd < 0)
        return OGS_ERROR;
    setsockopt(peer->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(OGS_GTPV2_C_UDP_PORT);
    inet_pton(AF_INET, address, &sin.sin_addr);

    if (bind(peer->fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        ogs_error("Cannot bind the fake GTPv2-C node [%s]:%d",
                address, OGS_GTPV2_C_UDP_PORT);
        close(peer->fd);
        peer->fd = -1;
        return OGS_ERROR;
    }

    return OGS_OK;
}

void test_s10_peer_close(test_s10_peer_t *peer)
{
    ogs_assert(peer);

    if (peer->fd >= 0)
        close(peer->fd);
    peer->fd = -1;

    if (peer->last)
        ogs_pkbuf_free(peer->last);
    peer->last = NULL;
}

int test_s10_peer_recv(test_s10_peer_t *peer, int timeout_ms,
        ogs_gtp2_message_t *message, uint32_t *sqn)
{
    struct pollfd pfd;
    uint8_t buf[OGS_MAX_SDU_LEN];
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp2_header_t *h = NULL;
    int rv;

    ogs_assert(peer);
    ogs_assert(message);
    ogs_assert(sqn);

    pfd.fd = peer->fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0)
        return OGS_ERROR;

    size = recv(peer->fd, buf, sizeof(buf), 0);
    if (size < OGS_GTPV2C_HEADER_LEN - OGS_GTP2_TEID_LEN)
        return OGS_ERROR;

    pkbuf = ogs_pkbuf_alloc(NULL, size);
    ogs_assert(pkbuf);
    ogs_pkbuf_put_data(pkbuf, buf, size);

    h = (ogs_gtp2_header_t *)pkbuf->data;
    *sqn = OGS_GTP2_SQN_TO_XID(h->teid_presence ? h->sqn : h->sqn_only);

    rv = ogs_gtp2_parse_msg(message, pkbuf);

    /* The parsed message points into the received buffer */
    if (peer->last)
        ogs_pkbuf_free(peer->last);
    peer->last = pkbuf;

    return rv;
}

int test_s10_peer_send(test_s10_peer_t *peer,
        ogs_gtp2_message_t *message, uint32_t teid, uint32_t sqn)
{
    struct sockaddr_in sin = mme_addr();
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp2_header_t *h = NULL;
    ssize_t sent;

    ogs_assert(peer);
    ogs_assert(message);

    pkbuf = ogs_gtp2_build_msg(message);
    if (!pkbuf)
        return OGS_ERROR;

    ogs_assert(ogs_pkbuf_push(pkbuf, OGS_GTPV2C_HEADER_LEN));
    h = (ogs_gtp2_header_t *)pkbuf->data;
    memset(h, 0, OGS_GTPV2C_HEADER_LEN);
    h->version = 2;
    h->teid_presence = 1;
    h->type = message->h.type;
    h->length = htobe16(pkbuf->len - 4);
    h->teid = htobe32(teid);
    h->sqn = OGS_GTP2_XID_TO_SQN(sqn);

    sent = sendto(peer->fd, pkbuf->data, pkbuf->len, 0,
            (struct sockaddr *)&sin, sizeof(sin));
    ogs_pkbuf_free(pkbuf);

    return sent > 0 ? OGS_OK : OGS_ERROR;
}
