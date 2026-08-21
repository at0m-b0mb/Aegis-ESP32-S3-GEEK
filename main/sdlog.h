/*
 * sdlog.h - append-only evidence log on the microSD card.
 *
 * Mounts the TF card over SPI3 (board.h pins) as FAT and appends one CSV line
 * per alert to /sdcard/AEGIS.LOG: uptime, verdict, kind, score, MAC, channel,
 * hits, label. If no card is present the whole thing no-ops - Aegis still runs.
 */
#ifndef AEGIS_SDLOG_H
#define AEGIS_SDLOG_H
#include <stdbool.h>
#include "aegis_threat.h"

bool sdlog_init(void);                          /* false if no card mounted   */
bool sdlog_available(void);
void sdlog_alert(uint32_t uptime_s, const aegis_finding_t *f);
#endif
