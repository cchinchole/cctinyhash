CC      = gcc
AR      = ar
OBJDIR  = build
SRCS    = $(wildcard *.c)
OBJS    = $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))
CFLAGS	= -Wall -Wextra -Wpedantic -std=c11 -Iinclude -Iinternal

PREFIX  ?= /usr/local
LIBDIR  = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include

.PHONY: all build install uninstall clean

all build: libccth.a

libccth.a: $(OBJS)
	$(AR) rcs $@ $^

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

install: libccth.a
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 644 libccth.a $(DESTDIR)$(LIBDIR)/
	install -m 644 include/ccth.h $(DESTDIR)$(INCLUDEDIR)/
uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/libccth.a
	rm -f $(DESTDIR)$(INCLUDEDIR)/ccth.h

clean:
	rm -rf $(OBJDIR) libccth.a 
