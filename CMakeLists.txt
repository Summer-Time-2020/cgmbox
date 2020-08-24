cmake_minimum_required (VERSION 2.6)
project(cgmbox)

#set window dll info
if(MSVC)
    set(MY_VERSIONINFO_RC "${CMAKE_SOURCE_DIR}/VersionInfo.rc")
    configure_file("${CMAKE_SOURCE_DIR}/VersionInfo.rc.in"
                   "${MY_VERSIONINFO_RC}")
else()
	add_definitions("-fvisibility=hidden")			   
endif()

file(GLOB_RECURSE CURRENT_HEADERS  *.h *.hpp)
source_group("Include" FILES ${CURRENT_HEADERS}) 

include_directories(${CMAKE_SOURCE_DIR}/include) 
aux_source_directory(${CMAKE_SOURCE_DIR}/src DIR_CGMBOX_SRCS)
add_library(cgmbox SHARED ${DIR_CGMBOX_SRCS} ${MY_VERSIONINFO_RC} ${CURRENT_HEADERS})

set_target_properties(cgmbox PROPERTIES
	OUTPUT_NAME "cgmbox"
	CLEAN_DIRECT_OUTPUT 1
	ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/ # set out path
	RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/)



	
	



 


