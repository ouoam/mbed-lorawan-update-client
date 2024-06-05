
add_library(metadata-header INTERFACE)

target_include_directories(metadata-header
    INTERFACE
        .
        update-client-metadata-header
)

target_sources(metadata-header
    INTERFACE
        source/arm_uc_buffer_utilities.c
        source/arm_uc_crypto_hmac_mbedtls.c
        source/arm_uc_metadata_header_v2.c
)
