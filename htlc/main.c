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
    printf("Enter\n");
    printf("   1: get HTLC script address\n");
    printf("   2: redeem by preimage\n");
    printf("   3: redeem by CSV\n\n");
    printf("Your choice: ");
    input = getchar();
    switch (input) {
        case '1':
            htlc(true);
            break;
        case '2':
            printf("You entered 2\n");
            htlc(false);
            break;
        case '3':
            printf("You entered 3\n");
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
