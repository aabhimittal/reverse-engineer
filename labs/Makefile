# Build the rex labs. Requires: cc (gcc or clang). Optional: clang + lld for PE/Mach-O.
#   make            # Linux ELF labs
#   make all-formats  # also PE and Mach-O (needs clang, lld-link, llvm-dlltool, ld64.lld)
CC ?= cc
OUT := build

.PHONY: all clean all-formats firmware
all: $(OUT)/crackme $(OUT)/crackme.stripped $(OUT)/vuln firmware

$(OUT):
	mkdir -p $(OUT)

$(OUT)/crackme: binary/01-crackme/crackme.c | $(OUT)
	$(CC) -O1 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -o $@ $<

$(OUT)/crackme.stripped: $(OUT)/crackme
	strip -o $@ $<

$(OUT)/vuln: binary/02-vuln/vuln.c | $(OUT)
	$(CC) -O0 -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro -w -o $@ $<

firmware: | $(OUT)
	python3 firmware/make_firmware.py $(OUT)/firmware.bin

all-formats: all
	../scripts/build-fixtures.sh $(OUT)

clean:
	rm -rf $(OUT)
