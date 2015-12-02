.PHONY:	all

TESTS = intset

.PHONY:	all $(TESTS)

all:	$(TESTS)

clean: $(addsuffix /.makeclean, $(TESTS))

%/.makeclean:
	@$(MAKE) -C $(@D) clean

$(TESTS):
	$(MAKE) -C $@ $(TARGET)
