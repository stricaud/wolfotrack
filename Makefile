# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.4

# Default target executed when no arguments are given to make.
default_target: all

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canoncical targets will work.
.SUFFIXES:

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# The program to use to edit the cache.
CMAKE_EDIT_COMMAND = /usr/bin/ccmake

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/toady/wolfotrack

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/toady/wolfotrack

# Include the progress variables for this target.
include CMakeFiles/progress.make

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/bin/ccmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/toady/wolfotrack/CMakeFiles $(CMAKE_ALL_PROGRESS)
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/toady/wolfotrack/CMakeFiles 0

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean

# The main clean target
clean/fast: clean

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1

#=============================================================================
# Target rules for targets named sdlwolf3d

# Build rule for target.
sdlwolf3d: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 sdlwolf3d

# fast build rule for target.
sdlwolf3d/fast:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/build

# target to build an object file
ct_build.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/ct_build.o

# target to preprocess a source file
ct_build.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/ct_build.i

# target to generate assembly for a file
ct_build.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/ct_build.s

# target to build an object file
fmopl.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/fmopl.o

# target to preprocess a source file
fmopl.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/fmopl.i

# target to generate assembly for a file
fmopl.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/fmopl.s

# target to build an object file
id_ca.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_ca.o

# target to preprocess a source file
id_ca.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_ca.i

# target to generate assembly for a file
id_ca.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_ca.s

# target to build an object file
id_us.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_us.o

# target to preprocess a source file
id_us.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_us.i

# target to generate assembly for a file
id_us.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_us.s

# target to build an object file
id_vh.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_vh.o

# target to preprocess a source file
id_vh.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_vh.i

# target to generate assembly for a file
id_vh.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/id_vh.s

# target to build an object file
misc.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/misc.o

# target to preprocess a source file
misc.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/misc.i

# target to generate assembly for a file
misc.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/misc.s

# target to build an object file
objs.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/objs.o

# target to preprocess a source file
objs.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/objs.i

# target to generate assembly for a file
objs.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/objs.s

# target to build an object file
sd_comm.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/sd_comm.o

# target to preprocess a source file
sd_comm.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/sd_comm.i

# target to generate assembly for a file
sd_comm.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/sd_comm.s

# target to build an object file
sd_sdl.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/sd_sdl.o

# target to preprocess a source file
sd_sdl.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/sd_sdl.i

# target to generate assembly for a file
sd_sdl.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/sd_sdl.s

# target to build an object file
vi_comm.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/vi_comm.o

# target to preprocess a source file
vi_comm.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/vi_comm.i

# target to generate assembly for a file
vi_comm.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/vi_comm.s

# target to build an object file
vi_sdl.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/vi_sdl.o

# target to preprocess a source file
vi_sdl.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/vi_sdl.i

# target to generate assembly for a file
vi_sdl.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/vi_sdl.s

# target to build an object file
wl_act1.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act1.o

# target to preprocess a source file
wl_act1.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act1.i

# target to generate assembly for a file
wl_act1.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act1.s

# target to build an object file
wl_act2.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act2.o

# target to preprocess a source file
wl_act2.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act2.i

# target to generate assembly for a file
wl_act2.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act2.s

# target to build an object file
wl_act3.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act3.o

# target to preprocess a source file
wl_act3.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act3.i

# target to generate assembly for a file
wl_act3.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_act3.s

# target to build an object file
wl_agent.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_agent.o

# target to preprocess a source file
wl_agent.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_agent.i

# target to generate assembly for a file
wl_agent.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_agent.s

# target to build an object file
wl_debug.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_debug.o

# target to preprocess a source file
wl_debug.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_debug.i

# target to generate assembly for a file
wl_debug.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_debug.s

# target to build an object file
wl_draw.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_draw.o

# target to preprocess a source file
wl_draw.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_draw.i

# target to generate assembly for a file
wl_draw.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_draw.s

# target to build an object file
wl_game.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_game.o

# target to preprocess a source file
wl_game.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_game.i

# target to generate assembly for a file
wl_game.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_game.s

# target to build an object file
wl_inter.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_inter.o

# target to preprocess a source file
wl_inter.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_inter.i

# target to generate assembly for a file
wl_inter.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_inter.s

# target to build an object file
wl_main.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_main.o

# target to preprocess a source file
wl_main.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_main.i

# target to generate assembly for a file
wl_main.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_main.s

# target to build an object file
wl_menu.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_menu.o

# target to preprocess a source file
wl_menu.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_menu.i

# target to generate assembly for a file
wl_menu.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_menu.s

# target to build an object file
wl_play.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_play.o

# target to preprocess a source file
wl_play.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_play.i

# target to generate assembly for a file
wl_play.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_play.s

# target to build an object file
wl_state.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_state.o

# target to preprocess a source file
wl_state.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_state.i

# target to generate assembly for a file
wl_state.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_state.s

# target to build an object file
wl_text.o:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_text.o

# target to preprocess a source file
wl_text.i:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_text.i

# target to generate assembly for a file
wl_text.s:
	$(MAKE) -f CMakeFiles/sdlwolf3d.dir/build.make CMakeFiles/sdlwolf3d.dir/wl_text.s

# Help Target
help::
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... sdlwolf3d"
	@echo "... ct_build.o"
	@echo "... ct_build.i"
	@echo "... ct_build.s"
	@echo "... fmopl.o"
	@echo "... fmopl.i"
	@echo "... fmopl.s"
	@echo "... id_ca.o"
	@echo "... id_ca.i"
	@echo "... id_ca.s"
	@echo "... id_us.o"
	@echo "... id_us.i"
	@echo "... id_us.s"
	@echo "... id_vh.o"
	@echo "... id_vh.i"
	@echo "... id_vh.s"
	@echo "... misc.o"
	@echo "... misc.i"
	@echo "... misc.s"
	@echo "... objs.o"
	@echo "... objs.i"
	@echo "... objs.s"
	@echo "... sd_comm.o"
	@echo "... sd_comm.i"
	@echo "... sd_comm.s"
	@echo "... sd_sdl.o"
	@echo "... sd_sdl.i"
	@echo "... sd_sdl.s"
	@echo "... vi_comm.o"
	@echo "... vi_comm.i"
	@echo "... vi_comm.s"
	@echo "... vi_sdl.o"
	@echo "... vi_sdl.i"
	@echo "... vi_sdl.s"
	@echo "... wl_act1.o"
	@echo "... wl_act1.i"
	@echo "... wl_act1.s"
	@echo "... wl_act2.o"
	@echo "... wl_act2.i"
	@echo "... wl_act2.s"
	@echo "... wl_act3.o"
	@echo "... wl_act3.i"
	@echo "... wl_act3.s"
	@echo "... wl_agent.o"
	@echo "... wl_agent.i"
	@echo "... wl_agent.s"
	@echo "... wl_debug.o"
	@echo "... wl_debug.i"
	@echo "... wl_debug.s"
	@echo "... wl_draw.o"
	@echo "... wl_draw.i"
	@echo "... wl_draw.s"
	@echo "... wl_game.o"
	@echo "... wl_game.i"
	@echo "... wl_game.s"
	@echo "... wl_inter.o"
	@echo "... wl_inter.i"
	@echo "... wl_inter.s"
	@echo "... wl_main.o"
	@echo "... wl_main.i"
	@echo "... wl_main.s"
	@echo "... wl_menu.o"
	@echo "... wl_menu.i"
	@echo "... wl_menu.s"
	@echo "... wl_play.o"
	@echo "... wl_play.i"
	@echo "... wl_play.s"
	@echo "... wl_state.o"
	@echo "... wl_state.i"
	@echo "... wl_state.s"
	@echo "... wl_text.o"
	@echo "... wl_text.i"
	@echo "... wl_text.s"



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0

