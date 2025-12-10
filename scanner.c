#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Virus signature byte sequence (machine-code pattern)
 * ----------------------------------------------------
 * After selecting the 8–16 bytes from IDA's Hex View that represent
 * your chosen viral characteristic sequence, fill them into the array
 * below in the form 0x??, 0x??, ...
 *
 * Example:
 * If you selected the bytes: E8 23 01 3D 00 01 75 0A
 * then write:
 *   static const unsigned char VIRUS_SIG[] = {
 *       0xE8, 0x23, 0x01, 0x3D, 0x00, 0x01, 0x75, 0x0A
 *   };
 */

/*
Currently selected signature sequence:
seg000:1425    mov ax, 2521h
seg000:1428    mov dx, 3C8h
seg000:142B    int 21h

seg000:142D    mov ax, 2501h
seg000:1430    mov dx, 8F7h
seg000:1433    int 21h

Bytes:
B8 21 25 BA C8 03 CD 21 B8 01 25 BA F7 08 CD 21
*/

/*
Original signature example:
static const unsigned char VIRUS_SIG[] = {
    0xBA, 0xC8, 0x03, 0xCD, 0x21, 0xB8, 0x01, 0x25,
    0xBA, 0xF7, 0x08, 0xCD, 0x21, 0xBA, 0x37, 0x02
};
*/

static const unsigned char VIRUS_SIG[] = {
    0xB8, 0x21, 0x25, 0xBA, 0xC8, 0x03, 0xCD, 0x21,
    0xB8, 0x01, 0x25, 0xBA, 0xF7, 0x08, 0xCD, 0x21
};

/*
 * Since reordering these two int 21h calls does not affect the virus behavior,
 * the reversed sequence should also be detectable.
 */
static const unsigned char VIRUS_SIG_RE[] = {
    0xB8, 0x01, 0x25, 0xBA, 0xF7, 0x08, 0xCD, 0x21,
    0xB8, 0x21, 0x25, 0xBA, 0xC8, 0x03, 0xCD, 0x21
};

static const size_t SIG_LEN = sizeof(VIRUS_SIG) / sizeof(VIRUS_SIG[0]);

#define NOP_OPCODE 0x90

/*
 * Function: fuzzy_match_skip_any_nops
 * Purpose: Flexible fuzzy matching that allows arbitrary NOP instructions
 *          to appear anywhere inside the signature pattern.
 *
 * Parameters:
 *   buf       - pointer to the file data buffer
 *   buf_len   - length of the data buffer
 *   signature - the virus signature byte array
 *   sig_len   - length of the signature
 *
 * Return value:
 *   1 = match found
 *   0 = no match
 */
int fuzzy_match_skip_any_nops(const unsigned char* buf, size_t buf_len,
    const unsigned char* signature, size_t sig_len) {

    int i, j, k;

    /* Try every possible starting position in the buffer */
    for (i = 0; i <= (int)buf_len; i++) {
        j = 0;  /* index in signature */
        k = 0;  /* offset inside buffer */

        /* Attempt to match the signature */
        while (j < (int)sig_len && (i + k) < (int)buf_len) {

            /* Skip NOPs found inside the file */
            if (buf[i + k] == NOP_OPCODE) {
                k++;
                continue;
            }

            /* Compare signature byte */
            if (buf[i + k] != signature[j]) {
                break;  /* mismatch → abort inner loop */
            }

            /* Both bytes match → advance */
            j++;
            k++;
        }

        /* Success if all signature bytes were matched */
        if (j == (int)sig_len) {
            return 1;
        }
    }

    return 0;  /* no match found */
}


int main(int argc, char* argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open file");
        return 1;
    }

    /* Get file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(fp);
        return 1;
    }

    long filesize = ftell(fp);
    if (filesize < 0) {
        perror("ftell failed");
        fclose(fp);
        return 1;
    }

    rewind(fp);

    /* Allocate buffer and read entire file */
    unsigned char* buf = (unsigned char*)malloc((size_t)filesize);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed (file may be too large)\n");
        fclose(fp);
        return 1;
    }

    size_t read_bytes = fread(buf, 1, (size_t)filesize, fp);
    fclose(fp);

    if (read_bytes != (size_t)filesize) {
        fprintf(stderr, "File read incomplete (expected %ld bytes, got %zu bytes)\n",
            filesize, read_bytes);
        free(buf);
        return 1;
    }

    /* Quick sanity check */
    if (SIG_LEN == 0 || SIG_LEN > (size_t)filesize) {
        printf("Signature length is %zu, cannot match in file.\n", SIG_LEN);
        free(buf);
        return 0;
    }

    /* Naive byte-for-byte matching */
    int found = 0;
    for (long i = 0; i <= filesize - (long)SIG_LEN; i++) {
        if (memcmp(buf + i, VIRUS_SIG, SIG_LEN) == 0) {
            found = 1;
            break;
        }
    }

    /* Also try reversed signature */
    if (found == 0) {
        for (long i = 0; i <= filesize - (long)SIG_LEN; i++) {
            if (memcmp(buf + i, VIRUS_SIG_RE, SIG_LEN) == 0) {
                found = 1;
                break;
            }
        }
    }

    /* Fuzzy signature matching with NOP skipping */
    int found_fuzzy = fuzzy_match_skip_any_nops(buf, (size_t)filesize, VIRUS_SIG, SIG_LEN);
    if (!found_fuzzy) {
        found_fuzzy = fuzzy_match_skip_any_nops(buf, (size_t)filesize, VIRUS_SIG_RE, SIG_LEN);
    }

    free(buf);

    if (found) {
        printf("[Result] File \"%s\" contains the original virus signature!\n", filename);
    } else {
        printf("[Result] File \"%s\" does NOT contain the original virus signature.\n", filename);
    }

    if (found_fuzzy) {
        printf("[Result] File \"%s\" contains the virus signature with NOP tolerance!\n", filename);
    } else {
        printf("[Result] File \"%s\" does NOT contain the virus signature with NOP tolerance.\n", filename);
    }

    return 0;
}
