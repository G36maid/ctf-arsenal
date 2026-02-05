#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const int LETTER_CHECKSUMS[26] = {
    1, 0, 9, 8, 7, 6, 5, 4, 9, 3, 2, 2, 1,
    0, 8, 9, 8, 7, 6, 5, 4, 3, 1, 3, 2, 0
};

void generate_national_id(int letter, int sex, int counter, char *out) {
    int checksum = LETTER_CHECKSUMS[letter];
    checksum += 8 * sex;
    
    out[0] = 'A' + letter;
    out[1] = '0' + sex;
    
    for (int i = 8; i >= 2; i--) {
        int digit = counter % 10;
        counter /= 10;
        out[i] = '0' + digit;
        checksum += digit * (9 - i);
    }
    
    out[9] = '0' + (10 - checksum % 10) % 10;
    out[10] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <letter_index_0-25>\n", argv[0]);
        return 1;
    }
    
    int letter = atoi(argv[1]);
    if (letter < 0 || letter >= 26) {
        fprintf(stderr, "Letter index must be 0-25\n");
        return 1;
    }
    
    char nid[11];
    for (int sex = 1; sex <= 2; sex++) {
        for (int counter = 0; counter < 10000000; counter++) {
            generate_national_id(letter, sex, counter, nid);
            puts(nid);
        }
    }
    
    return 0;
}
