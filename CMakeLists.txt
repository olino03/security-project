cmake_minimum_required(VERSION 3.14)
project(encryptron C)

# Set C standard and policies
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Configure libtommath
if(NOT TARGET libtommath)
    # Try to find system installation first
    find_path(LTM_INCLUDE_DIR tommath.h
        PATHS
        /usr/include
        /usr/local/include
        "$ENV{ProgramFiles}/libtom/include"
    )
    
    find_library(LTM_LIBRARY
        NAMES tommath libtommath
        PATHS
        /usr/lib
        /usr/local/lib
        "$ENV{ProgramFiles}/libtom/lib"
    )
    
    if(LTM_INCLUDE_DIR AND LTM_LIBRARY)
        message(STATUS "Found system libtommath")
        add_library(libtommath INTERFACE IMPORTED)
        target_include_directories(libtommath INTERFACE ${LTM_INCLUDE_DIR})
        target_link_libraries(libtommath INTERFACE ${LTM_LIBRARY})
    else()
        # Fetch and build libtommath
        message(STATUS "Downloading libtommath v1.3.0")
        
        include(FetchContent)
        FetchContent_Declare(
            libtommath
            URL https://github.com/libtom/libtommath/archive/refs/tags/v1.3.0.tar.gz
            URL_HASH SHA256=6d099e93ff00fa9b18346f4bcd97dcc48c3e91286f7e16c4ac5515a7171c3149
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        
        FetchContent_MakeAvailable(libtommath)
        
        # Modern libtommath creates its own target
        if(NOT TARGET libtommath)
            # Fallback for older versions
            file(GLOB LTM_SOURCES 
                "${libtommath_SOURCE_DIR}/*.c"
                "${libtommath_SOURCE_DIR}/headers/*.h"
            )
            add_library(libtommath STATIC ${LTM_SOURCES})
            target_include_directories(libtommath PUBLIC 
                ${libtommath_SOURCE_DIR}
                ${libtommath_SOURCE_DIR}/headers
            )
        endif()
    endif()
endif()

# Project sources (exclude headers from source files)
file(GLOB_RECURSE PROJECT_SOURCES
    "src/*.c"
)

# Create executable
add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE include)
target_link_libraries(${PROJECT_NAME} PRIVATE libtommath)

# Installation (optional)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)