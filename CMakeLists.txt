cmake_minimum_required(VERSION 3.5)

project(semux-pow)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_STANDARD 11)

include_directories("./phc-winner-argon2/include")
include_directories("./phc-winner-argon2/src")

add_executable(semux-pow
    ./phc-winner-argon2/src/blake2/blake2b.c
    ./phc-winner-argon2/src/argon2.c
    ./phc-winner-argon2/src/core.c
    ./phc-winner-argon2/src/encoding.c
    ./phc-winner-argon2/src/ref.c
    ./phc-winner-argon2/src/thread.c
    main.c)

target_link_libraries(semux-pow pthread)
