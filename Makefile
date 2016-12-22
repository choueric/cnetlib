SRCS=$(wildcard *.c)
OBJS=$(SRCS:%.c=%.o)
DEPS=$(SRCS:%.c=%.d)

CFLAGS+=-fPIC

STARGET=libcnetlib.a
DTARGET=libcnetlib.so

all:$(STARGET) $(DTARGET)

$(DEPS):%.d:%.c 
	@set -e rm -f $@
	$(CC) -MM $(CFLAGS) $< > $@.1234
	@sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.1234 > $@
	@rm -f $@.1234

-include $(DEPS)

$(STARGET):$(OBJS)
	$(AR) -r $@ $(OBJS)

$(DTARGET):$(OBJS)
	$(CC) $(OBJS) -shared -o $(DTARGET)

clean:
	rm -rf *.d *.o $(STARGET) $(DTARGET)
