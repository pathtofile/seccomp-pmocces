CC ?= clang
CFLAGS := -g -Wall

APPS = pmocces
all: $(APPS)

$(APPS): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean: kill
	rm -rf $(OUTPUT) $(APPS)

kill:
	killall -qs 9 $(APPS) | true
