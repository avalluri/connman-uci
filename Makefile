SRCDIR=.
BUILDIR=.
OBJDIR=$(BUILDIR)/.obj/

CC= gcc
UBOX_LIBS=-lubox
UCI_LIBS=-luci
UBUS_LIBS=-lubus
GLIB_LIBS=$(shell pkg-config --libs glib-2.0 gio-2.0)
GLIB_CFLAGS=$(shell pkg-config --cflags glib-2.0 gio-2.0)
CFLAGS=-c -Wall -g
INCLUDES=-I.
LDFLAGS=

SOURCES=$(shell find $(SRCDIR) -name '*.c')
OBJECTS := $(patsubst ./%.c,%.o,$(SOURCES))
#TARGETS=connmanupd networkd
TARGETS=networkd

all: $(TARGETS) $(SOURCES)
info:
	@echo SOURCES = $(SOURCES)
	@echo OBJECTS = $(OBJECTS)
	@echo CFLAGS  = $(CFLAGS)
	@echo LDFLAGS = $(LDFLAGS)
	@echo LIBS    = $(UCI_LIBS) $(UBUS_LIBS) $(GLIB_LIBS)

%.o: %.c
	$(CC) -o $@ $(CFLAGS) $(INCLUDES) $<

connmanupd: uci2connman.o log.o
	$(CC) -o $@ $^ $(LDFLAGS) $(COMMON_LIBS) $(UCI_LIBS)

networkd: ubus.o log.o interface.o gutils.o uci-parser.o
	$(CC) -o $@ $^ $(LDFLAGS) $(UBUS_LIBS) $(UCI_LIBS) $(UBOX_LIBS)

.PHONY = clean

clean:
	rm -rf $(OBJECTS) $(BUILDIR)/$(TARGETS) || true


