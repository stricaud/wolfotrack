

PROJECT(sdlwolf)

SET(SRC ct_build.c objs.c misc.c id_ca.c id_vh.c id_us.c
	wl_act1.c wl_act2.c wl_act3.c wl_agent.c wl_game.c
	wl_inter.c wl_menu.c wl_play.c wl_state.c wl_text.c wl_main.c
	wl_debug.c vi_comm.c sd_comm.c sd_sdl.c vi_sdl.c fmopl.c wl_draw)

ADD_EXECUTABLE(sdlwolf3d ${SRC})

## SDL
FIND_PACKAGE(SDL)
IF(SDL_FOUND)
	MESSAGE(STATUS "SDL library found")
	SET(LIBS ${LIBS} ${SDL_LIBRARY})
	INCLUDE_DIRECTORIES(${SDL_INCLUDE_DIR})
ELSE(SDL_FOUND)
	MESSAGE(FATAL_ERROR "Can't find SDL library developpement files!")
ENDIF(SDL_FOUND)

## SDL_Mixer
FIND_PACKAGE(SDL_mixer)
IF(SDLMIXER_FOUND)
	MESSAGE(STATUS "SDL_mixer library found")
	SET(LIBS ${LIBS} ${SDLMIXER_LIBRARY})
	INCLUDE_DIRECTORIES(${SDLMIXER_INCLUDE_DIR})
ELSE(SDLMIXER_FOUND)
	MESSAGE(FATAL_ERROR "Can't find SDL_mixer library developpement files!")
ENDIF(SDLMIXER_FOUND)


## libnetfilter_conntrack
INCLUDE(UsePkgConfig)
PKGCONFIG("libnetfilter_conntrack" NFCT_INCLUDE_DIR NFCT_LINK_DIR
	NFCT_LINK_FLAGS NFCT_CFLAGS)
IF(NFCT_LINK_FLAGS)
	MESSAGE(STATUS "libnetfilter_conntrack library found")
	INCLUDE_DIRECTORIES(${NFCT_INCLUDE_DIR})
	SET(LIBS ${LIBS} ${NFCT_LINK_FLAGS})
	SET(CFLAGS ${CFLAGS} ${NFCT_CFLAGS})
	SET(LIBS_DIR ${LIBS_DIR} ${NFCT_LINK_DIR})
ELSE(NFCT_LINK_FLAGS)
	MESSAGE(FATAL_ERROR "Can't find libnetfilter_conntrack library developpement files!")
ENDIF(NFCT_LINK_FLAGS)


SET(CMAKE_BUILD_TYPE ${BUILD})
SET(CMAKE_CFLAGS ${CFLAGS})
LINK_DIRECTORIES(${LIBS_DIR})
TARGET_LINK_LIBRARIES(sdlwolf3d ${LIBS} "m")
