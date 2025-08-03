// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <evpl/evpl.h>
#include <stddef.h>

int main(void) {
    struct evpl_global_config *config;
    
    config = evpl_global_config_init();
    if (config == NULL) {
        return 1;
    }
    
    // Test setting various cipher lists - just verify the API works
    evpl_global_config_set_tls_cipher_list(config, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    evpl_global_config_set_tls_cipher_list(config, "ECDHE-RSA-AES128-GCM-SHA256");
    evpl_global_config_set_tls_cipher_list(config, NULL);
    
    // Also test other TLS settings
    evpl_global_config_set_tls_verify_peer(config, 0);
    evpl_global_config_set_tls_ktls_enabled(config, 1);
    
    evpl_global_config_release(config);
    
    return 0;
}