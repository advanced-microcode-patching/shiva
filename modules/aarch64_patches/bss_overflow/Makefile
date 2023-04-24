INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"

	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c bss_patch2.c
	gcc -O0 -g bss_vuln.c -o bss_vuln
	$(SHIVA-LD_PATH) -e bss_vuln -p bss_patch2.o -i /lib/shiva -s /opt/shiva/modules -o bss_vuln.patched
	chown root:root bss_vuln
	chmod u+s bss_vuln
