# Works with 3.11 and tested through 3.15
cmake_minimum_required(VERSION 3.11...3.16)

# Project name and a few useful settings. Other commands can pick up the results
project(PDBGen VERSION 0.1)

# Only do these if this is the main project, and not if it is included through add_subdirectory
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Optionally set things like CMAKE_CXX_STANDARD, CMAKE_POSITION_INDEPENDENT_CODE here

    # Let's ensure -std=c++xx instead of -std=g++xx
    set(CMAKE_CXX_EXTENSIONS OFF)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    # Let's nicely support folders in IDE's
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

# Add LLVM for their pdb tooling
find_package(LLVM REQUIRED CONFIG)
llvm_map_components_to_libnames(llvm_libs core support DebugInfoPDB)

# LLVM packages built with Visual Studio may embed the DIA SDK path from the
# machine where LLVM was built. Prefer the DIA SDK for the active VS instance.
if(MSVC AND TARGET LLVMDebugInfoPDB)
    get_target_property(pdb_link_libraries LLVMDebugInfoPDB INTERFACE_LINK_LIBRARIES)
    if(pdb_link_libraries)
        set(has_embedded_dia_library FALSE)
        foreach(pdb_link_library IN LISTS pdb_link_libraries)
            if(pdb_link_library MATCHES "[Dd][Ii][Aa][Gg][Uu][Ii][Dd][Ss]\\.lib$")
                set(has_embedded_dia_library TRUE)
                break()
            endif()
        endforeach()

        if(has_embedded_dia_library)
            find_file(PDBGEN_DIA_GUIDS_LIBRARY diaguids.lib
                PATHS
                    "${CMAKE_GENERATOR_INSTANCE}/DIA SDK/lib/amd64"
                    "$ENV{VSINSTALLDIR}/DIA SDK/lib/amd64"
                NO_DEFAULT_PATH
            )
            if(NOT PDBGEN_DIA_GUIDS_LIBRARY)
                message(FATAL_ERROR "Could not find diaguids.lib in the active Visual Studio instance")
            endif()

            set(pdb_link_libraries_without_dia)
            foreach(pdb_link_library IN LISTS pdb_link_libraries)
                if(NOT pdb_link_library MATCHES "[Dd][Ii][Aa][Gg][Uu][Ii][Dd][Ss]\\.lib$")
                    list(APPEND pdb_link_libraries_without_dia "${pdb_link_library}")
                endif()
            endforeach()
            list(APPEND pdb_link_libraries_without_dia "${PDBGEN_DIA_GUIDS_LIBRARY}")
            set_property(TARGET LLVMDebugInfoPDB PROPERTY INTERFACE_LINK_LIBRARIES
                "${pdb_link_libraries_without_dia}")
        endif()
    endif()
endif()

# Disable this warning because it comes from llvm.
add_compile_options(/wd4624 /wd4996)

add_executable(pdbgen main.cpp)
target_compile_features(pdbgen PRIVATE cxx_std_17)

target_include_directories(pdbgen PUBLIC ${LLVM_INCLUDE_DIRS})
target_link_libraries(pdbgen PRIVATE ${llvm_libs})
