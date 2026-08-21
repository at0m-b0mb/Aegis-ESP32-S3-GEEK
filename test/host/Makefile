# Host-side unit tests + UI mockups for Aegis. No ESP-IDF required.
#   make           - build and run every unit-test suite
#   make mockups   - render the dashboard UI to BMP files in ./out
#   make clean     - remove build artifacts
CC      ?= cc
INC     := -I../../components/engine/include -I../../components/ui/include -I.
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror -O1 -g $(INC)
ENGINE  := ../../components/engine/src
UI      := ../../components/ui/src
BIN     := ./bin

SUITES  := test_deauth test_eviltwin test_beacon_flood test_ble test_canvas test_ui

.PHONY: all clean mockups
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
$(BIN)/test_canvas:       test_canvas.c       $(UI)/canvas.c $(UI)/font5x8.c | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@
$(BIN)/test_ui:           test_ui.c           $(UI)/ui.c $(UI)/canvas.c $(UI)/font5x8.c | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@ -lm

mockups: $(BIN)/render_mockup
	@mkdir -p out && $(BIN)/render_mockup out

$(BIN)/render_mockup: render_mockup.c $(UI)/ui.c $(UI)/canvas.c $(UI)/font5x8.c | $(BIN)
	$(CC) $(CFLAGS) $^ -o $@ -lm

$(BIN):
	@mkdir -p $(BIN)

clean:
	@rm -rf $(BIN) out
