__enable_cxx17()

set(SRCS impl/lmuserdb.cpp)

if(NOT TARGET SQLite::SQLite3)
    find_package(SQLite3 REQUIRED)
endif()
if(NOT TARGET openssl::openssl)
    find_package(OpenSSL REQUIRED)
endif()

set(LIBS SQLite::SQLite3 openssl::openssl)

set(INCS ${CMAKE_CURRENT_SOURCE_DIR} 
        ${CMAKE_CURRENT_SOURCE_DIR}/include 
        ${CMAKE_CURRENT_SOURCE_DIR}/impl
        ${CMAKE_CURRENT_SOURCE_DIR}/ormpp
        )
set(INTERFACES ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(DEFS ORMPP_ENABLE_SQLITE3)

# set(LM_DB_STATIC 1)
__add_common_library(lm_db)
