ROOT = ../..

include $(ROOT)/Makefile.common

BINS = bank

.PHONY:	all clean

all:	$(BINS)

%.o:	%.c
	$(Verb) $(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

$(BINS):	%:	%.o $(TMLIB)
	$(Verb) $(CC) -o $@ $< $(LDFLAGS)

clean:
	$(Verb) rm -f $(BINS) *.o
