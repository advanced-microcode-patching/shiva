SUBDIRS = example1 example2 example3 example4 example5 example6 

subdirs:
		for dir in $(SUBDIRS); do \
			$(MAKE) -C $$dir; \
		done
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean;

