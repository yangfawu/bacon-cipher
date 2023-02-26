#include "bacon.h"

// Add other #includes here if you want.

int encrypt(const char *plaintext, char *ciphertext) {
    return -1000;
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
        if (c == ' ')
            continue;
        if (ispunct(c))
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
