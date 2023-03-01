#include "bacon.h"

// Add other #includes here if you want.

// returns the bacon code of the letter, -1 otherwise
int char_2_bacon_code(char letter) {
    // if lowercase letters
    if (letter > 96 && letter < 123)
        return letter - 97;
    
    // if uppercase letters
    if (letter > 64 && letter < 91)
        return letter - 65;
    
    // if space to )
    if (letter > 31 && letter < 42)
        return letter - 32 + 26;
    
    // if , to ;
    if (letter > 43 && letter < 60)
        return letter - 44 + 36;

    // if ?
    if (letter == 63)
        return letter - 63 + 52;
    
    // if \0
    if (letter == 0)
        return 63;
    
    return -1;
}

int min(int a, int b) {
    return a < b ? a : b;
}

int encrypt(const char *plaintext, char *ciphertext) {
    int p_n = strlen(plaintext);
    int c_n = strlen(ciphertext);

    // first we find all valid indexes we can update in ciphertext
    int valid_indexes[c_n + 1];
    int valid_size = 0;
    for (int c_i=0; c_i<c_n; c_i++) {
        if (isalpha(ciphertext[c_i])) {
            valid_indexes[valid_size] = c_i;
            valid_size++;
        }
    }

    // we compute the max number of bacon codes we can put
    int max_num_bacon_codes = valid_size / 6;

    // if we can't put any, then that means we don't even have space for EOM code
    if (max_num_bacon_codes < 1)
        return -1;
    
    // we compute the number of bacon codes (excluding EOM) we can actually put from plaintext
    int num_bacon_codes = min(p_n, max_num_bacon_codes - 1);

    // put the non-EOM codes
    int valid_i = 0;
    for (int i=0; i<num_bacon_codes; i++) {
        int bacon_code = char_2_bacon_code(plaintext[i]);

        // we add this case in case plaintext input is invalid
        if (bacon_code < 0)
            return -2;
        
        for (int j=0; j<6; j++) {
            int c_i = valid_indexes[valid_i];

            if ((bacon_code >> (5 - j)) & 1)
                ciphertext[c_i] = toupper(ciphertext[c_i]);
            else
                ciphertext[c_i] = tolower(ciphertext[c_i]);

            valid_i++;
        }
    }

    // then we put the EOM
    for (int i=0; i<6; i++) {
        int c_i = valid_indexes[valid_i];
        ciphertext[c_i] = toupper(ciphertext[c_i]);
        valid_i++;
    }
    
    return num_bacon_codes;
}

// return ascii character associated with code, -1 otherwise
char bacon_code_2_char(unsigned int code) {
    // the code comes in the range [0, 63]
    // method: for every group, we subtract by the smallest code in that group to reset to 0
    // then we add the ascii value of the smallest code in that group
    
    // handles [A to Z]
    if (code < 26)
        return code + 65;
    
    // handles [space to )]
    if (code < 36)
        return code - 26 + 32;
    
    // handles [, to ;]
    if (code < 52)
        return code - 36 + 44;
        
    // handles [?]
    if (code < 53)
        return code - 52 + 63;
    
    // handles unused
    if (code < 63)
        return -1;
    
    // EOM
    if (code < 64)
        return 0;
    
    return -1;
}

int decrypt(const char *ciphertext, char *plaintext) {
    int c_n = strlen(ciphertext);
    int p_n = strlen(plaintext);

    // plaintext_length cannot be 0
    if (!p_n)
        return -1;

    // first convert cipher text into pure binary (we know it cannot be any longer than ciphertxt w/o its null char)
    unsigned int binary_ciphertext[c_n];
    int b_i = 0;
    for (int i=0; i<c_n; i++) {
        char c = ciphertext[i];
        if (isalpha(c)) {
            binary_ciphertext[b_i] = !!isupper(c);
            b_i++;
        }
    }

    // then we break binary into bacon code chunks
    int max_bacon_codes = b_i / 6;

    // stores the current length of the decoded text
    char decoded_buffer[max_bacon_codes];
    int decoded_buffer_i = 0;

    int found_eom = 0;
    int found_invalid_code = 0;
    for (int i=0; i<max_bacon_codes; i++) {
        // generate bacon_code
        unsigned int bacon_code = 0;
        for (int j=0; j<6; j++) {
            bacon_code<<= 1;
            bacon_code|= binary_ciphertext[6*i + j];
        }

        // we try to get the char from the bacon code
        char c = bacon_code_2_char(bacon_code);

        // if code is invalid, our character will be negative
        if (c < 0) {
            found_invalid_code = 1;
            continue;
        }
        
        // inseer code
        decoded_buffer[decoded_buffer_i] = c;
        decoded_buffer_i++;

        if (c == 0) {
            found_eom = 1;
            break;
        }
    }

    // if we finish loop without seeing EOM, then we know it is invalid
    if (!found_eom)
        return -2;
    
    // if we encounter invalid codee deespite seeing EOM
    if (found_invalid_code)
        return -3;

    // right now, decoded_buffer_i is the total number of bacon codes we have (including eom)

    // check if plaintext has enough space for all bacon codes
    if ((p_n + 1) < decoded_buffer_i) {
        // then we cut the decoded_buffer down to the size of plaintext plus its null character
        decoded_buffer_i = p_n + 1;

        // we modify the buffer at index p_n to make it end
        decoded_buffer[p_n] = 0;
    }
    
    // now we copy decoded_buffer to plaintext
    for (int i=0; i<decoded_buffer_i; i++)
        plaintext[i] = decoded_buffer[i];
    
    // we subtract 1 because note earlier we said decoded_buffer_i is the length (including eom)
    return decoded_buffer_i - 1;
}
