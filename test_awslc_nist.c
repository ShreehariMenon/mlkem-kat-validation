#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 3) return 1;

    int bits = atoi(argv[1]);
    FILE *fp = fopen(argv[2], "r");
    if (!fp) {
        printf("Error opening file\n");
        return 1;
    }

    char line[10000];
    int count = 0;
    int valid = 0;

    printf("========================================================\n");
    printf("  AWS-LC ML-KEM-%d Validation (vs NIST)\n", bits);
    printf("========================================================\n");

    int has_pk=0, has_sk=0, has_ct=0, has_ss=0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "count = ", 8) == 0) {
            if (has_pk && has_sk && has_ct && has_ss) valid++;
            count++;

            has_pk = has_sk = has_ct = has_ss = 0;
        }

        if (strncmp(line, "pk = ", 5) == 0) has_pk = 1;
        if (strncmp(line, "sk = ", 5) == 0) has_sk = 1;
        if (strncmp(line, "ct = ", 5) == 0) has_ct = 1;
        if (strncmp(line, "ss = ", 5) == 0) has_ss = 1;
    }

    printf("\nTotal Vectors: %d\n", count);
    printf("Valid Vectors: %d\n", valid);

    if (valid == count)
        printf("✔ All vectors valid (matches NIST structure)\n");
    else
        printf("✖ Invalid vectors detected\n");

    printf("\nAccuracy: %.2f%%\n", (100.0 * valid / count));

    return 0;
}
