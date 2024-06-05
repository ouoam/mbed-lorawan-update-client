
target_include_directories(mbed-lorawan-update-client
    INTERFACE
        .
        crypto
)

target_sources(mbed-lorawan-update-client
    INTERFACE
        source/FragmentationCrc32.cpp
        source/FragmentationEcdsaVerify.cpp
        source/FragmentationSha256.cpp
)
