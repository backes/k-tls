SUBDIRS=lib/TLS lib/KTLS lib/tinySTM

# Provide these targets, which delegate to all subdirs
# (all must be first, to be default target!)
RecursiveTargets=all clean

$(RecursiveTargets): % : $(addsuffix /.make%, $(SUBDIRS))

$(foreach t,$(RecursiveTargets),%/.make$(t)):
	make -C $(@D) $(subst $(@D)/.make,,$@)

# vim:ft=make
#
