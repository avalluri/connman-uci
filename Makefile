PREFIX=/usr/local
libdir=$(PREFIX)/lib
bindir=$(PREFIX)/bin
CC ?= gcc

SRCDIR=.
BUILDIR=.
OBJDIR=$(BUILDIR)/.obj/
RPCD_PLUGIN=1

UBOX_LIBS=-lubox
UCI_LIBS=-luci
UBUS_LIBS=-lubus
INCLUDES=-I.
CFLAGS=-c -Wall -g -fPIC
COMMON_LIBS=$(UBOX_LIBS) $(UCI_LIBS)

SOURCES=$(shell find $(SRCDIR) -name '*.c')
OBJECTS := $(patsubst ./%.c,%.o,$(SOURCES))
TARGETS=libnetwork-uci.so connmanupd
ifeq ($(RPCD_PLUGIN), 1)
TARGETS += network.so
else
TARGETS += networkd
endif

all: $(TARGETS) $(SOURCES)
info:
	@echo SOURCES = $(SOURCES)
	@echo OBJECTS = $(OBJECTS)
	@echo CFLAGS  = $(CFLAGS)
	@echo LDFLAGS = $(LDFLAGS)
	@echo LIBS    = $(COMMON_LIBS) $(UBUS_LIBS) 

%.o: %.c
	$(CC) -o $@ $(CFLAGS) $(INCLUDES) $<

libnetwork-uci.so: log.o gutils.o uci-parser.o interface.o
	$(CC) -o $@ $^ -shared $(LDFLAGS) $(COMMON_LIBS)

connmanupd: uci2connman.o libnetwork-uci.so
	$(CC) -o $@ $^ $(LDFLAGS) $(COMMON_LIBS)

networkd: ubus.o libnetwork-uci.so
	$(CC) -o $@ $^ $(LDFLAGS) $(UBUS_LIBS)

network.so: ubus.o libnetwork-uci.so
	$(CC) -o $@ $^ -shared $(LDFLAGS) $(COMMON_LIBS) $(UBUS_LIBS) -DRPC_PLUGIN

install:
	mkdir -p $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(bindir)
	install libnetwork-uci.so $(DESTDIR)$(libdir)/
	install connmanupd $(DESTDIR)$(bindir)/
ifeq ($(RPCD_PLUGIN), 1)
	mkdir -p "$(DESTDIR)$(libdir)/rpcd/"
	install network.so "$(DESTDIR)$(libdir)/rpcd/"
else
	install networkd $(DESTDIR)$(bindir)/
endif

.PHONY = clean install

clean:
	rm -rf $(OBJECTS) $(BUILDIR)/$(TARGETS) || true


