#pragma once
#include "haywire.h"

#define SU_ATOMIC_READ(_v) 					__sync_fetch_and_add((_v), 0)
#define SU_ATOMIC_INCREMENT(_v) 			(void)__sync_fetch_and_add((_v), 1)
#define SU_ATOMIC_DECREMENT(_v) 			(void)__sync_fetch_and_sub((_v), 1)
#ifdef DEBUG
#define INCREMENT_STAT(stat) SU_ATOMIC_INCREMENT(&stat)
#else
#define INCREMENT_STAT(stat)
#endif /* DEBUG */


extern int stat_connections_created_total;
extern int stat_connections_destroyed_total;
extern int stat_requests_created_total;
extern int stat_requests_destroyed_total;


