cmake_minimum_required(VERSION 3.9)


project(software_service_gm)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
add_compile_options(-g -fPIC -Wimplicit-function-declaration)
#设定编译参数
set(CMAKE_BUILD_TYPE "Debug")
 
set(CMAKE_CXX_STANDARD 11)



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

 
#生成动/静态库
#add_library(动/静态链接库名称  SHARED/STATIC(可选，默认STATIC)  源码列表)
#可以单独生成多个模块
 
#add_library(dnassl  SHARED  ${SRC_FILES} ${SRC_CERT_FILES})
#生成可执行文件
add_library(software_service_gm STATIC ${SRC_FILES} )
target_compile_definitions(software_service_gm PRIVATE DEBUG ) 
 
 
target_link_libraries(software_service_gm PRIVATE
pthread
m
dl
)#就是g++ 编译选项中-l后的内容，不要有多余空格


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
