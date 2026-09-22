// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <windows.h>
#include <ncrypt.h>
#include <stdio.h>
#include <wchar.h>

/* Run in CI after the TLS processes exit, in a fresh runner user profile.
 * Named keys are necessary for Schannel, but normal shutdown must remove them. */
int
main(void)
{
    NCRYPT_PROV_HANDLE provider;
    NCryptKeyName     *key   = NULL;
    void              *state = NULL;
    SECURITY_STATUS    status;
    int                leaked = 0;

    if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0)) {
        return 1;
    }
    while ((status = NCryptEnumKeys(provider, NULL, &key, &state, NCRYPT_SILENT_FLAG)) == ERROR_SUCCESS) {
        if (wcsncmp(key->pszName, L"libevpl-tls-", 11) == 0) {
            fwprintf(stderr, L"TLS key remained after process exit: %ls\n", key->pszName);
            leaked = 1;
        }
        NCryptFreeBuffer(key);
    }
    if (state) {
        NCryptFreeBuffer(state);
    }
    NCryptFreeObject(provider);
    return leaked || status != NTE_NO_MORE_ITEMS;
} /* main */
