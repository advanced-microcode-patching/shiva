SUBDIRS = dataonly_interposing data_interposing rodata_interposing bss_interposing cfs_patch1 amp_challenge10 fsplice
subdirs:
		for dir in $(SUBDIRS); do \
			$(MAKE) -C $$dir; \
		done
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean;

