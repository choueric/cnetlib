CC=gcc
EXEC=test

DEPLIBS=../libcnetlib.a
LIBS=$(DEPLIBS) -lpthread
INC=-I..
CFLAGS=-Wall -Werror -g -O2 -std=gnu99 $(INC)

SRCS=$(wildcard *.c)
OBJS=$(SRCS:%.c=%.o)
DEPS=$(SRCS:%.c=%.d)

SUBDIRS=..

export

.PHONY: all subdir $(SUBDIRS) clean

all: subdir $(EXEC)

-include $(SRCS:%.c=%.d)

subdir:$(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

$(EXEC): $(OBJS) $(DEPLIBS)
	$(CC) $(OBJS) -o $(EXEC) $(LIBS)

$(DEPS):%.d:%.c 
	@set -e rm -f $@
	$(CC) -MM $(CFLAGS) $< > $@.1234
	@sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.1234 > $@
	@rm -f $@.1234

-include $(DEPS)

clean_dirs := $(addprefix _clean_,$(SUBDIRS) )

$(clean_dirs):
	$(MAKE) -C $(patsubst _clean_%,%,$@) clean

clean: $(clean_dirs)
	rm -rf $(EXEC) *.d *.o
