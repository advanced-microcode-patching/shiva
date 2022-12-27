SUBDIRS := $(wildcard aarch64_patches/*)
all: $(SUBDIRS)
	$(SUBDIRS):
		$(MAKE) -C $@
.PHONY: all $(SUBDIRS)
