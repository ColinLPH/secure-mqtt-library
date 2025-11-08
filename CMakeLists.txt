cmake_minimum_required(VERSION 3.11)
project (smqtt VERSION 1.0.0 DESCRIPTION "Secure MQTT 5.0 implementation in C" LANGUAGES C)

option(BUILD_SHARED_LIBS "Build shared instead of static libraries" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(SMQTT_SOURCES
    src/smqtt_broker.c
    src/smqtt_client.c
)

add_library(smqtt ${SMQTT_SOURCES})

set_target_properties(smqtt PROPERTIES OUTPUT_NAME "smqtt" PREFIX "lib")

find_package(OpenSSL REQUIRED)
target_link_libraries(smqtt PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_compile_options(smqtt PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS smqtt
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/ DESTINATION include)

