
add_library(mbed-lorawan-update-client INTERFACE)

add_subdirectory(crypto)
add_subdirectory(fragmentation)
add_subdirectory(modules)
add_subdirectory(patch)
add_subdirectory(tiny-aes128)

target_include_directories(mbed-lorawan-update-client
    INTERFACE
        mbed-lorawan-update-client
        janpatch
)

target_sources(mbed-lorawan-update-client
    INTERFACE
        mbed-lorawan-update-client/BDFile.cpp
        mbed-lorawan-update-client/mbed_delta_update.cpp
)

target_compile_definitions(mbed-lorawan-update-client
    INTERFACE
        HEADER_SIZE=0x70
)

target_link_libraries(mbed-lorawan-update-client
    INTERFACE
        tiny-aes128
        metadata-header
)
