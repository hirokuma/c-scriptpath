#ifndef HTLC_H_
#define HTLC_H_

#include <stdbool.h>

typedef enum {
    HTLC_SCRIPT_ADDRESS = 0,
    HTLC_PREIMAGE_REDEEM = 1,
    HTLC_CSV_REDEEM = 2,
} HTLC_REDEEM_TYPE;

void htlc(HTLC_REDEEM_TYPE redeem_type, const char *prevTxStr);

#endif /* HTLC_H_ */
