#include <stdio.h>

#include "wally_core.h"

void sample1(void);
void sample2(void);
void sample3(void);
void sample4(void);
void sample5(void);

int main(int argc, char *argv[])
{
    int rc;

    rc = wally_init(0);
    if (rc != WALLY_OK) {
        printf("error: wally_init fail: %d\n", rc);
        return 1;
    }

    // one leaf script
    printf("- sample1 ----------------\n");
    sample1();

    // two leaf scripts
    printf("\n\n- sample2 ----------------\n");
    sample2();

    // BIP-65(OP_CHECKLOCKTIMEVERIFY) test
    printf("\n\n- sample3 ----------------\n");
    sample3();

    // BIP-112(OP_CHECKSEQUENCEVERIFY) test
    printf("\n\n- sample4 ----------------\n");
    sample4();

    // btcdeb sample
    printf("\n\n- sample5 ----------------\n");
    sample5();

    rc = wally_cleanup(0);
    if (rc != WALLY_OK) {
        printf("error: wally_cleanup fail: %d\n", rc);
        return 1;
    }
    return 0;
}
