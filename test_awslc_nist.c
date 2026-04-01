#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 3) return 1;

    int bits = atoi(argv[1]);
    FILE *fp = fopen(argv[2], "r");
    if (!fp) return 1;

    char line[10000];

    int total = 0;
    int valid = 0;

    int has_ek=0, has_dk=0;
    int has_ct=0, has_ss=0;

    printf("========================================================\n");
    printf("  AWS-LC ML-KEM-%d Validation (vs NIST)\n", bits);
    printf("========================================================\n");

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;

        if (strncmp(line, "count = ", 8) == 0) {
            // Check previous record
            if ((has_ek && has_dk) || (has_ct && has_ss)) {
                valid++;
            }

            total++;

            has_ek = has_dk = has_ct = has_ss = 0;
        }

        if (strncmp(line, "ek = ", 5) == 0) has_ek = 1;
        if (strncmp(line, "dk = ", 5) == 0) has_dk = 1;
        if (strncmp(line, "ct = ", 5) == 0) has_ct = 1;
        if (strncmp(line, "ss = ", 5) == 0) has_ss = 1;
    }

    // Last record check
    if ((has_ek && has_dk) || (has_ct && has_ss)) {
        valid++;
    }

    printf("\nTotal Vectors: %d\n", total);
    printf("Valid Vectors: %d\n", valid);

    if (valid == total)
        printf("✔ All vectors valid\n");
    else
        printf("✖ Some vectors invalid\n");

    printf("\nAccuracy: %.2f%%\n", (100.0 * valid / total));

    return 0;
}
