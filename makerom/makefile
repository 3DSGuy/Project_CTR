# C++/C Recursive Project Makefile 
# (c) Jack
# Version 8 (20220420)

# Project Name
PROJECT_NAME = makerom

# Project Relative Paths
PROJECT_PATH = $(CURDIR)
PROJECT_SRC_PATH = src
PROJECT_SRC_SUBDIRS = $(PROJECT_SRC_PATH)
#PROJECT_INCLUDE_PATH = include
#PROJECT_TESTSRC_PATH = test
#PROJECT_TESTSRC_SUBDIRS = $(PROJECT_TESTSRC_PATH)
PROJECT_BIN_PATH = bin
#PROJECT_DOCS_PATH = docs
#PROJECT_DOXYFILE_PATH = Doxyfile

# Determine if the root makefile has been established, and if not establish this makefile as the root makefile
ifeq ($(ROOT_PROJECT_NAME),)
	export ROOT_PROJECT_NAME = $(PROJECT_NAME)
	export ROOT_PROJECT_PATH = $(PROJECT_PATH)
	export ROOT_PROJECT_DEPENDENCY_PATH = $(ROOT_PROJECT_PATH)/deps
endif

# Project Dependencies
PROJECT_DEPEND = mbedtls blz yaml
PROJECT_DEPEND_LOCAL_DIR = libmbedtls libblz libyaml

# Generate compiler flags for including project include path
ifneq ($(PROJECT_INCLUDE_PATH),)
	INC += -I"$(PROJECT_INCLUDE_PATH)"
endif

# Generate compiler flags for local included dependencies
ifneq ($(PROJECT_DEPEND_LOCAL_DIR),)
	LIB += $(foreach dep,$(PROJECT_DEPEND_LOCAL_DIR), -L"$(ROOT_PROJECT_DEPENDENCY_PATH)/$(dep)/bin")
	INC += $(foreach dep,$(PROJECT_DEPEND_LOCAL_DIR), -I"$(ROOT_PROJECT_DEPENDENCY_PATH)/$(dep)/include")
endif

# Generate compiler flags for external dependencies
ifneq ($(PROJECT_DEPEND),)
	LIB += $(foreach dep,$(PROJECT_DEPEND), -l$(dep))
endif

# Detect Platform
ifeq ($(PROJECT_PLATFORM),)
	ifeq ($(OS), Windows_NT)
		export PROJECT_PLATFORM = WIN32
	else
		UNAME = $(shell uname -s)
		ifeq ($(UNAME), Darwin)
			export PROJECT_PLATFORM = MACOS
		else
			export PROJECT_PLATFORM = GNU
		endif
	endif
endif

# Detect Architecture
ifeq ($(PROJECT_PLATFORM_ARCH),)
	ifeq ($(PROJECT_PLATFORM), WIN32)
		export PROJECT_PLATFORM_ARCH = x86_64
	else ifeq ($(PROJECT_PLATFORM), GNU)
		export PROJECT_PLATFORM_ARCH = $(shell uname -m)
	else ifeq ($(PROJECT_PLATFORM), MACOS)
		export PROJECT_PLATFORM_ARCH = $(shell uname -m)
	else
		export PROJECT_PLATFORM_ARCH = x86_64
	endif
endif

# Generate platform specific compiler flags
ifeq ($(PROJECT_PLATFORM), WIN32)
	# Windows Flags/Libs
	CC = x86_64-w64-mingw32-gcc
	CXX = x86_64-w64-mingw32-g++
	DEFINEFLAGS =
	WARNFLAGS = -Wall -Wno-unused-value -Wno-unused-but-set-variable
	ARCHFLAGS =
	INC +=
	LIB += -static
	ARFLAGS = cr -o
else ifeq ($(PROJECT_PLATFORM), GNU)
	# GNU/Linux Flags/Libs
	#CC = 
	#CXX =
	DEFINEFLAGS = -D_GNU_SOURCE
	WARNFLAGS = -Wall -Wno-unused-value -Wno-unused-but-set-variable
	ARCHFLAGS =
	INC +=
	LIB +=
	ARFLAGS = cr -o
else ifeq ($(PROJECT_PLATFORM), MACOS)
	# MacOS Flags/Libs
	#CC = 
	#CXX =
	DEFINEFLAGS =
	WARNFLAGS = -Wall -Wno-unused-value -Wno-unused-private-field
	ARCHFLAGS = -arch $(PROJECT_PLATFORM_ARCH)
	INC +=
	LIB += -liconv
	ARFLAGS = rc
endif

# Compiler Flags
CXXFLAGS = -std=c++11 $(INC) $(DEFINEFLAGS) $(WARNFLAGS) $(ARCHFLAGS) -fPIC
CFLAGS = -std=c11 $(INC) $(DEFINEFLAGS) $(WARNFLAGS) $(ARCHFLAGS) -fPIC

# Object Files
SRC_OBJ = $(foreach dir,$(PROJECT_SRC_SUBDIRS),$(subst .cpp,.o,$(wildcard $(dir)/*.cpp))) $(foreach dir,$(PROJECT_SRC_SUBDIRS),$(subst .cc,.o,$(wildcard $(dir)/*.cc))) $(foreach dir,$(PROJECT_SRC_SUBDIRS),$(subst .c,.o,$(wildcard $(dir)/*.c)))
TESTSRC_OBJ = $(foreach dir,$(PROJECT_TESTSRC_SUBDIRS),$(subst .cpp,.o,$(wildcard $(dir)/*.cpp))) $(foreach dir,$(PROJECT_TESTSRC_SUBDIRS),$(subst .cc,.o,$(wildcard $(dir)/*.cc))) $(foreach dir,$(PROJECT_TESTSRC_SUBDIRS),$(subst .c,.o,$(wildcard $(dir)/*.c)))

# all is the default, user should specify what the default should do
#	- 'static_lib' for building source as a static library
#	- 'program' for building source as executable program
#	- 'test_program' for building the test program
# test_program can be used with program or static_lib, but program and static_lib cannot be used together
all: program
	
clean: clean_object_files remove_binary_dir

# Object Compile Rules
%.o: %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -c $< -o $@ 

%.o: %.cpp
	@echo CXX $<
	@$(CXX) $(CXXFLAGS) -c $< -o $@ 

%.o: %.cc
	@echo CXX $<
	@$(CXX) $(CXXFLAGS) -c $< -o $@ 

# Binary Directory
.PHONY: create_binary_dir
create_binary_dir:
	@mkdir -p "$(PROJECT_BIN_PATH)"

.PHONY: remove_binary_dir
remove_binary_dir:
ifneq ($(PROJECT_BIN_PATH),)
	@rm -rf "$(PROJECT_BIN_PATH)"
endif

.PHONY: clean_object_files
clean_object_files:
	@rm -f $(SRC_OBJ) $(TESTSRC_OBJ)

# Build Library
static_lib: $(SRC_OBJ) create_binary_dir
	@echo LINK $(PROJECT_BIN_PATH)/$(PROJECT_NAME).a
	@ar $(ARFLAGS) "$(PROJECT_BIN_PATH)/$(PROJECT_NAME).a" $(SRC_OBJ)

# Build Program
program: $(SRC_OBJ) create_binary_dir
	@echo LINK $(PROJECT_BIN_PATH)/$(PROJECT_NAME)
	@$(CXX) $(LDFLAGS) $(ARCHFLAGS) $(SRC_OBJ) $(LIB) -o "$(PROJECT_BIN_PATH)/$(PROJECT_NAME)"

# Build Test Program
test_program: $(TESTSRC_OBJ) $(SRC_OBJ) create_binary_dir
ifneq ($(PROJECT_TESTSRC_PATH),)
	@echo LINK $(PROJECT_BIN_PATH)/$(PROJECT_NAME)_test
	@$(CXX) $(ARCHFLAGS) $(TESTSRC_OBJ) $(SRC_OBJ) $(LIB) -o "$(PROJECT_BIN_PATH)/$(PROJECT_NAME)_test"
endif

# Documentation
.PHONY: docs
docs:
ifneq ($(PROJECT_DOCS_PATH),)
	doxygen "$(PROJECT_DOXYFILE_PATH)"
endif

.PHONY: clean_docs
clean_docs:
ifneq ($(PROJECT_DOCS_PATH),)
	@rm -rf "$(PROJECT_DOCS_PATH)"
endif

# Dependencies
.PHONY: deps
deps:
	@$(foreach lib,$(PROJECT_DEPEND_LOCAL_DIR), cd "$(ROOT_PROJECT_DEPENDENCY_PATH)/$(lib)" && $(MAKE) static_lib && cd "$(PROJECT_PATH)";)

.PHONY: clean_deps
clean_deps:
	@$(foreach lib,$(PROJECT_DEPEND_LOCAL_DIR), cd "$(ROOT_PROJECT_DEPENDENCY_PATH)/$(lib)" && $(MAKE) clean && cd "$(PROJECT_PATH)";)