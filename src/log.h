#ifndef _log_h_
#define _log_h_

#include "dryos.h"

// A fairly generic implementation of a circular buffer for logging,
// which is periodically flushed to disk.

// user is responsible for providing buffer
// (allows use on different stages of ports, and different run time contexts)
int init_log(uint8_t *buf, uint32_t size, char *filename);

// Send some data to be written to disk.
// This is thread safe and blocking re copying
// the data into the central logging buffer.
// Writes to disk happen periodically.
int send_log_data(uint8_t *data, uint32_t size);

#endif // _log_h_
