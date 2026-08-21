# Host-side unit tests for the Aegis detection engines. No ESP-IDF required.
#   make        - build and run every suite
#   make clean  - remove build artifacts
CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror -O1 -g \
           -I../../components/engine/include -I.
ENGINE  := ../../components/engine/src
BIN     := ./bin

SUITES  := test_deauth test_eviltwin test_beacon_flood test_ble

.PHONY: all clean
all: $(SUITES:%=run-%)
	@echo "\nAll suites passed."

run-%: $(BIN)/%
	@echo "--- $< ---"; $<

$(BIN)/test_deauth:       test_deauth.c       $(ENGINE)/deauth_detect.c   | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@
$(BIN)/test_eviltwin:     test_eviltwin.c     $(ENGINE)/eviltwin_detect.c | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@
$(BIN)/test_beacon_flood: test_beacon_flood.c $(ENGINE)/beacon_flood.c    | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@
$(BIN)/test_ble:          test_ble.c          $(ENGINE)/ble_threat.c      | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@

$(BIN):
	@mkdir -p $(BIN)

clean:
	@rm -rf $(BIN)
