/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A deterministic RPCSEC_GSS provider for testing.
 *
 * libevpl implements the RPCSEC_GSS wire framing and state machine but
 * deliberately links no GSS mechanism (see evpl_rpc2_gss.h).  Exercising that
 * machinery therefore needs a provider, and a real Kerberos one would be both
 * heavyweight and -- more importantly -- untestable: the interesting cases are
 * the failures, and a real mechanism cannot be told to fail on demand.
 *
 * This stub is instead fully deterministic and externally controllable.  Its
 * MIC is a plain FNV-1a hash of the message, so a test driver can compute a
 * valid verifier for itself, and its accept/verify behaviour is selected per
 * case through gss_stub_set_behaviour().  That turns the mechanism into
 * another dimension the model can drive rather than an opaque dependency.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

struct evpl_rpc2_gss_provider;

/* What the next accept() should do. */
#define GSS_STUB_ACCEPT_COMPLETE 0   /* establish the context immediately   */
#define GSS_STUB_ACCEPT_CONTINUE 1   /* one more leg required               */
#define GSS_STUB_ACCEPT_FAIL     2   /* mechanism-level failure             */
/* A mechanism-level failure that still hands back a token for the server to
 * relay -- the normal shape of a rejection a real mechanism wants the peer to
 * see, and the only way to reach the server's "free the token we were given
 * but will never send" path. */
#define GSS_STUB_ACCEPT_FAIL_TOK 3

/* Whether verify_mic() should honour the checksum or reject regardless. */
#define GSS_STUB_VERIFY_HONEST   0
#define GSS_STUB_VERIFY_REJECT   1

/*
 * What get_mic() should do when asked to sign a message that is NOT four bytes
 * long.  The four-byte MICs are the RPC-level verifiers (a checksum over a
 * seq_num or over the seq_window); anything longer is the integrity service's
 * databody.  Keying on the length lets a case break the *reply* signing that
 * RFC 2203 sec 5.3.3.4.1 governs without also breaking the context handshake
 * that has to succeed first.
 */
#define GSS_STUB_MIC_HONEST      0
#define GSS_STUB_MIC_FAIL_BODY   1   /* refuse to sign the databody         */
#define GSS_STUB_MIC_HUGE_BODY   2   /* sign it, but with an outsized MIC   */

/* Whether wrap() should seal or refuse.  A mechanism that cannot seal a reply
 * is the privacy analogue of GSS_STUB_MIC_FAIL_BODY, and reaches rpc2's
 * "fall through with the reply unsealed" path. */
#define GSS_STUB_WRAP_HONEST     0
#define GSS_STUB_WRAP_FAIL       1

/* Bigger than the 512-byte checksum headroom rpc2.c reserves in an integrity
 * reply, so a MIC this size is one it cannot emit. */
#define GSS_STUB_MIC_HUGE_LEN    600

void
gss_stub_set_behaviour(
    int accept_mode,
    int verify_mode,
    int mic_mode);

/* Independent of set_behaviour so a case can steer sealing without disturbing
 * the accept/verify/mic modes the rest of the suite relies on. */
void
gss_stub_set_wrap_mode(
    int wrap_mode);

/* The MIC the stub computes, and which a driver can therefore reproduce to
* build a verifier the stub will accept.  Always GSS_STUB_MIC_LEN bytes. */
#define GSS_STUB_MIC_LEN   8

/* Length of the token every accept() leg hands back.  Deliberately not a
 * multiple of four -- see gss_stub_accept(). */
#define GSS_STUB_TOKEN_LEN 5

void
gss_stub_mic(
    const void *msg,
    size_t      msg_len,
    uint8_t     out[GSS_STUB_MIC_LEN]);

/*
 * The stub's seal, exposed so a driver can build a token the stub will unseal
 * -- the privacy counterpart of gss_stub_mic().
 *
 * A token is [4-byte plaintext length][plaintext XOR keystream][MIC over the
 * plaintext].  It is emphatically not cryptography; what it has to be is
 * reversible, length-changing (so the code cannot accidentally work by
 * treating the token as the plaintext), and tamper-evident (so a corrupted
 * token fails to unseal rather than yielding garbage arguments).
 *
 * Returns the token length, or 0 if out_cap is too small.  A token is
 * GSS_STUB_SEAL_OVERHEAD bytes longer than its plaintext.
 */
#define GSS_STUB_SEAL_OVERHEAD (4 + GSS_STUB_MIC_LEN)

size_t
gss_stub_seal(
    const void *plain,
    size_t      plain_len,
    void       *out,
    size_t      out_cap);

const struct evpl_rpc2_gss_provider *
gss_stub_provider(
    void);
