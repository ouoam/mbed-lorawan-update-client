
target_include_directories(mbed-lorawan-update-client
    INTERFACE
        .
        decompressor/
)

target_sources(mbed-lorawan-update-client
    INTERFACE
        decompressor/Decompressor.c
        ddelta.cpp
        Z_ARI_FILE.cpp
)
