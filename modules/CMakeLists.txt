
add_subdirectory(metadata-header)

target_include_directories(mbed-lorawan-update-client
    INTERFACE
        .
        update-client-common
)
