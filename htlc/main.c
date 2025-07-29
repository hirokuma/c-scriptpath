#include <stdio.h>

#include <wally_core.h>

#include "htlc.h"

int main(int argc, char *argv[])
{
    int rc;

    rc = wally_init(0);
    if (rc != WALLY_OK) {
        printf("error: wally_init fail: %d\n", rc);
        return 1;
    }

    int input;
    char prevTxStr[1024];
    printf("Enter\n");
    printf("   1: get HTLC script address\n");
    printf("   2: redeem by preimage\n");
    printf("   3: redeem by CSV\n\n");
    printf("Your choice: ");
    input = getchar();
    switch (input) {
        case '1':
            htlc(HTLC_SCRIPT_ADDRESS, NULL);
            break;
        case '2':
            printf("Enter raw transaction: ");
            scanf("%1023s", prevTxStr);
            htlc(HTLC_PREIMAGE_REDEEM, prevTxStr);
            break;
        case '3':
            printf("Enter raw transaction: ");
            scanf("%1023s", prevTxStr);
            htlc(HTLC_CSV_REDEEM, prevTxStr);
            break;
        default:
            printf("Invalid input\n");
            return 1;
    }

    rc = wally_cleanup(0);
    if (rc != WALLY_OK) {
        printf("error: wally_cleanup fail: %d\n", rc);
        return 1;
    }
    return 0;
}
