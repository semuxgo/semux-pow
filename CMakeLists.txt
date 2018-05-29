cmake_minimum_required(VERSION 3.5)

project(semux-pow)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_STANDARD 11)

# Argon2
include_directories("./phc-winner-argon2/include")
include_directories("./phc-winner-argon2/src")
link_directories("./phc-winner-argon2")

# Compile
add_executable(semux-pow main.c)

# Link
target_link_libraries(semux-pow argon2 pthread)
