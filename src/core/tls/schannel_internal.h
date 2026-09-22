// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#define SECURITY_WIN32
#include "core/os.h"
#include <security.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include "core/evpl.h"
#include "core/logging.h"
#include "core/evpl_shared.h"
#include "core/tls/engine.h"
#include "core/tls/tls.h"

struct evpl_schannel_shared {
    evpl_mutex_t       lock;
    CredHandle         credentials[2];
    PCCERT_CONTEXT     certificate;
    NCRYPT_KEY_HANDLE  key;
    NCRYPT_PROV_HANDLE provider;
    WCHAR              key_name[64];
    HCERTSTORE         roots;
    HCERTSTORE         identity_store;
    HCERTCHAINENGINE   chain_engine;
    int                verify_peer;
};

struct evpl_schannel_shared * evpl_schannel_credentials(
    struct evpl *,
    int);
int evpl_schannel_verify(
    struct evpl_schannel_shared *,
    CtxtHandle *,
    int);
extern unsigned char evpl_schannel_alpn[256];
extern unsigned int  evpl_schannel_alpn_length;
