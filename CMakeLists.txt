cmake_minimum_required(VERSION 3.9)


project(test_gm)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
add_compile_options(-g -fPIC -Wimplicit-function-declaration)
#设定编译参数
set(CMAKE_BUILD_TYPE "Debug")
 
set(CMAKE_CXX_STANDARD 17)



#find_package(OpenSSL REQUIRED)
#if(OPENSSL_FOUND)
#  include_directories(${OPENSSL_INCLUDE_DIRS})
#  message(STATUS "OpenSSL Found!")
#endif()
 
#设定头文件路径
include_directories("./include" )

#include_directories("路径1"  “路径2”...)



link_directories("./lib")
#link_directories("路径1"  “路径2”...)
 
#添加子目录,作用相当于进入子目录里面，展开子目录的CMakeLists.txt
#同时执行，子目录中的CMakeLists.txt一般是编译成一个库，作为一个模块
#在父目录中可以直接引用子目录生成的库
#add_subdirectory(math)
 #设定源码列表.
aux_source_directory("./src" SRC_FILES)



enable_testing()




add_test(NAME test_sm2 COMMAND test_sm2)

add_executable(test_sm2 ./test/test_sm2.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_sm2 PRIVATE -fpermissive)

target_link_libraries(test_sm2 PRIVATE
libcrypto.a
libssl.a
pthread
dl)


add_test(NAME test_sm3 COMMAND test_sm3)

add_executable(test_sm3 ./test/test_sm3.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_sm3 PRIVATE -fpermissive)

target_link_libraries(test_sm3 PRIVATE
libcrypto.a
libssl.a
pthread
dl)

add_test(NAME test_sm4 COMMAND test_sm4)

add_executable(test_sm4 ./test/test_sm4.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_sm4 PRIVATE -fpermissive)

target_link_libraries(test_sm4 PRIVATE
libcrypto.a
libssl.a
pthread
dl)

add_test(NAME test_hex COMMAND test_hex)

add_executable(test_hex ./test/test_hex.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_hex PRIVATE -fpermissive)

target_link_libraries(test_hex PRIVATE
libcrypto.a
libssl.a
pthread
dl)


add_executable(test_aes ./test/test_aes.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_aes PRIVATE -fpermissive)

target_link_libraries(test_aes PRIVATE
libcrypto.a
libssl.a
pthread
dl)

add_executable(test_rsa ./test/test_rsa.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_rsa PRIVATE -fpermissive)

target_link_libraries(test_rsa PRIVATE
libcrypto.a
libssl.a
pthread
dl)

add_executable(test_sha ./test/test_sha.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_sha PRIVATE -fpermissive)

target_link_libraries(test_sha PRIVATE
libcrypto.a
libssl.a
pthread
dl)

add_executable(test_ssl ./test/test_ssl.cc ${INCLUDE_FILES} ${SRC_FILES})

target_compile_options(test_ssl PRIVATE )

target_link_libraries(test_ssl PRIVATE
libssl.a
libcrypto.a
pthread
dl)
