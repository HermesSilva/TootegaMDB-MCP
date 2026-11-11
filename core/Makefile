# TootegaMDB-MCP — núcleo em C.
#
#   make            build nativo de desenvolvimento      -> build/tmdb
#   make debug      com ASan/UBSan                       -> build/tmdb-debug
#   make linux      estático (musl), para distribuição   -> ../dist/linux-x64/tmdb
#   make windows    estático (mingw-w64)                 -> ../dist/win32-x64/tmdb.exe
#
# `linux` e `windows` são pensados para rodar dentro do container de build
# (scripts/build-dist.sh), onde o cc é musl e o mingw está instalado.

SRC   := $(wildcard src/*.c src/crypto/*.c)
HDR   := $(wildcard src/*.h src/crypto/*.h)
WARN  := -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
         -Wformat=2 -Wno-format-nonliteral # formatos traduzidos vêm da tabela de mensagens
BUILD := $(shell cat ../BUILD 2>/dev/null || echo 0)
STD   := -std=c11 -DTM_BUILD=$(BUILD)
CC    ?= cc
MINGW ?= x86_64-w64-mingw32-gcc
DIST  ?= ../dist

.PHONY: all debug linux windows clean

all: build/tmdb

build/tmdb: $(SRC) $(HDR) ../BUILD
	@mkdir -p build
	$(CC) $(STD) -O2 -g $(WARN) $(SRC) -o $@

debug: build/tmdb-debug

build/tmdb-debug: $(SRC) $(HDR)
	@mkdir -p build
	$(CC) $(STD) -O1 -g $(WARN) -Wno-format-truncation -fsanitize=address,undefined \
		-fno-omit-frame-pointer $(SRC) -o $@

linux: $(SRC) $(HDR)
	@mkdir -p $(DIST)/linux-x64
	$(CC) $(STD) -O2 $(WARN) -static -s $(SRC) -o $(DIST)/linux-x64/tmdb

windows: $(SRC) $(HDR)
	@mkdir -p $(DIST)/win32-x64
	$(MINGW) $(STD) -O2 $(WARN) -D__USE_MINGW_ANSI_STDIO=1 -static -s $(SRC) \
		-o $(DIST)/win32-x64/tmdb.exe -lws2_32 -lbcrypt -lcrypt32

clean:
	rm -rf build
