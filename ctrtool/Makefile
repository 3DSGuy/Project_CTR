# Sources
SRC_DIR = . polarssl tinyxml
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c))) $(foreach dir,$(SRC_DIR),$(subst .cpp,.o,$(wildcard $(dir)/*.cpp)))

# Compiler Settings
OUTPUT = ctrtool
CXXFLAGS = -I.
CFLAGS = -O2 -flto -Wall -Wno-unused-variable  -Wno-unused-result -I.
CC = gcc
CXX = g++
ifeq ($(OS),Windows_NT)
    #Windows Build CFG
    CFLAGS += -Wno-unused-but-set-variable
    LIBS += -static -static-libgcc -static-libstdc++ -lpthread -L libwinpthread-1.dll
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        # OS X
        CFLAGS +=
        LIBS += -liconv
    else
        # Linux
        CFLAGS += -Wno-unused-but-set-variable
        LIBS +=
    endif
endif

main: $(OBJS)
	$(CXX) -o $(OUTPUT) $(LIBS) $(OBJS)

clean:
	rm -rf $(OUTPUT) $(OBJS)
