SUBDIRS=lib/TLS lib/KTLS lib/tinySTM

all: $(addsuffix /.make, $(SUBDIRS))

%/.make:
	make -C $(@D)

# vim:ft=make
#
