
add_library(tiny-aes128 INTERFACE)

target_include_directories(tiny-aes128
    INTERFACE
        .
)

target_sources(tiny-aes128
    INTERFACE
        tiny-aes.cpp
)
