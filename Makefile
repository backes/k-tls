SUBDIRS=lib/TLS lib/KTLS lib/tinySTM test

# Provide these targets, which delegate to all subdirs
# (all must be first, to be default target!)
RecursiveTargets=all clean

$(RecursiveTargets): % : $(addsuffix /.make%, $(SUBDIRS))

.PHONY: $(RecursiveTargets) test

$(foreach t,$(RecursiveTargets),%/.make$(t)):
	make -C $(@D) $(subst $(@D)/.make,,$@)

test:
	make -C test test

# vim:ft=make
#
