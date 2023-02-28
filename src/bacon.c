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
    
    // stores the current length of the decoded text
    int p_i = 0;
    char decoded_buffer[p_n + 1];
    
    // stores whether or not we found EOM bacon code
    int found_eom = 0;

    // convert into binary based on upper/lower case
    unsigned int temp = 0;
    int temp_digits = 0;
    for (int i=0; i<c_n; i++) {
        char c = ciphertext[i];

        // we only want to read alphabet lettters
        if (!isalpha(c))
            continue;
        
        temp<<= 1;
        temp|= !!isupper(c);
        temp_digits++;
        
        // check if this is the 6th letter
        if (temp_digits == 6) {
            char decoded_letter = bacon_code_2_char(temp);
            
            // if letter < 0, then bacon_code is invalid
            if (decoded_letter < 0)
                return -3;
            
            // if decoded_buffer already size plaintext, then we can't add more characters
            if (p_i == p_n)
                return -4;
            decoded_buffer[p_i] = decoded_letter;
            
            // check if letter is \0
            if (decoded_letter == 0) {
                found_eom = 1;
                // we don't add here because NULL does not add to the length
                break;
            }
            
            // we add here because letter is not NULL
            p_i++;
                
            // reset temp
            temp = 0;
            temp_digits = 0;
        }
    }
    
    // we can read cipher text SUCCESSfully without ever reading EOM
    if (!found_eom)
        return -2;
    
    // now we copy decoded_buffer to plaintext
    for (int i=0; i<p_i; i++)
        plaintext[i] = decoded_buffer[i];
    // append null characters at the end
    for (int j=p_i; j<p_n; j++)
        plaintext[j] = 0;
    
    return p_i;
}
