
target_include_directories(mbed-lorawan-update-client
    INTERFACE
        fragmentation
)

target_sources(mbed-lorawan-update-client
    INTERFACE
        source/FragmentationBlockDeviceWrapper.cpp
        source/FragmentationMath.cpp
        source/FragmentationSession.cpp
)
