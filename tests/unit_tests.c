/*
DO NOT CHANGE THE CONTENTS OF THIS FILE IN CASE A NEW VERSION IS DISTRIBUTED.
PUT YOUR OWN TEST CASES IN student_tests.c
*/

#include "unit_tests.h"

static char test_log_outfile[100];

int run_using_system(char *test_name) {
    char executable[100];
    sprintf(executable, "./bin/%s", test_name);
    assert(access(executable, F_OK) == 0);

    char cmd[500];
    sprintf(test_log_outfile, "%s/%s.log", TEST_OUTPUT_DIR, test_name);
#if defined(__linux__)
    sprintf(cmd, "valgrind -s --leak-check=full --show-leak-kinds=all --track-origins=yes --trace-children=yes --error-exitcode=37 ./bin/%s > %s 2>&1",
	    test_name, test_log_outfile);
#else
    cr_log_warn("Skipping valgrind tests. Run tests on Linux or GitHub for full output.\n");
    sprintf(cmd, "./bin/%s > %s 2>&1", test_name, test_log_outfile);
#endif
    return system(cmd);
}

void assert_normal_exit(int status) {
    cr_expect_eq(status, 0, "The program did not exit normally (status = 0x%x).\n", status);
}

void assert_error_exit(int status) {
    cr_expect_eq(WEXITSTATUS(status), 0xff,
		 "The program did not exit with status 0xff (status was 0x%x).\n", status);
}

void assert_no_valgrind_errors(int status) {
    cr_expect_neq(WEXITSTATUS(status), 37, "Valgrind reported errors -- see %s", test_log_outfile);
    if (WEXITSTATUS(status) == 37) {
        char cmd[200];
        sprintf(cmd, "cat %s", test_log_outfile);
        system(cmd);
    }
}

TestSuite(base_suite, .timeout=TEST_TIMEOUT);

Test(base_suite, encrypt_full_msg, .description="A full plaintext message can be encrypted.") {
    char ciphertext_act[] = "One of the main causes of the fall of the Roman Empire was that lacking zero, they had no way to indicate successful termination of their C programs.";
    char *plaintext = "--Robert Firth";
    int count_act = encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo, tHey haD no wAy To iNDicaTE SUCCESSful termination of their C programs.";
    int count_exp = 14;
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(base_suite, encrypt_full_msg_valgrind) {
    assert_no_valgrind_errors(run_using_system("encrypt_full_msg"));
}

Test(base_suite, encrypt_EOM_only, .description="Ciphertext string has room only for EOM.") {
    char ciphertext_act[] = "Too Short 2022";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "TOO SHOrt 2022";
    int count_exp = 0;
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(base_suite, encrypt_EOM_only_valgrind) {
    assert_no_valgrind_errors(run_using_system("encrypt_EOM_only"));
}

Test(base_suite, encrypt_empty_string, .description="Plaintext is the empty string.") {
    char ciphertext_act[] = "2023 United States of America";
    char *plaintext = "";
    int count_act = encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "2023 UNITED States of America";
    int count_exp = 0;
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(base_suite, encrypt_empty_string_valgrind) {
    assert_no_valgrind_errors(run_using_system("encrypt_empty_string"));
}

Test(base_suite, encrypt_three_chars, .description="Ciphertext string has room only for three characters.") {
    char ciphertext_act[] = "I can store three characters! Yes!";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act);  // s = 010010, t = 010011, o = 001110
    char *ciphertext_exp = "i Can StoRe tHRee CHArACTERS! Yes!";
    int count_exp = 3;
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(base_suite, encrypt_three_chars_valgrind) {
    assert_no_valgrind_errors(run_using_system("encrypt_three_chars"));
}

Test(base_suite, decrypt_full_msg, .description="A full plaintext message was encrypted.") {
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo, tHey haD no wAy To iNDicaTE SUCCESSful termination of their C programs.";
    int count_act = decrypt(ciphertext, plaintext_act);  
    char *plaintext_exp = "--ROBERT FIRTH";
    int count_exp = 14;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(base_suite, decrypt_full_msg_valgrind) {
    assert_no_valgrind_errors(run_using_system("decrypt_full_msg"));
}

Test(base_suite, decrypt_three_chars, .description="Ciphertext string encoded only three characters.") {
    char plaintext_act[] = "@@@@@@@@@";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "i Can StoRe tHRee CHArACTERS! Yes!";
    int count_act = decrypt(ciphertext, plaintext_act);  
    char *plaintext_exp = "STO";
    int count_exp = 3;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(base_suite, decrypt_three_chars_valgrind) {
    assert_no_valgrind_errors(run_using_system("decrypt_three_chars"));
}

/*
DO NOT CHANGE THE CONTENTS OF THIS FILE IN CASE A NEW VERSION IS DISTRIBUTED.
PUT YOUR OWN TEST CASES IN student_tests.c
*/
