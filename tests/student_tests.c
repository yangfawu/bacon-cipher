#include "unit_tests.h"
TestSuite(student_output, .timeout = TEST_TIMEOUT);
TestSuite(student_return, .timeout = TEST_TIMEOUT);
TestSuite(hao_return, .timeout = TEST_TIMEOUT);
TestSuite(hao_output, .timeout = TEST_TIMEOUT);
TestSuite(hao_suite, .timeout = TEST_TIMEOUT);
TestSuite(student_valgrind, .timeout = TEST_TIMEOUT);
//static char test_log_outfile[100];

// int run_using_system(char *test_name)
// {
//     char executable[100];
//     sprintf(executable, "./bin/%s", test_name);
//     assert(access(executable, F_OK) == 0);

//     char cmd[500];
//     sprintf(test_log_outfile, "%s/%s.log", TEST_OUTPUT_DIR, test_name);
// #if defined(__linux__)
//     sprintf(cmd, "valgrind -s --leak-check=full --show-leak-kinds=all --track-origins=yes --trace-children=yes --error-exitcode=37 ./bin/%s > %s 2>&1",
//             test_name, test_log_outfile);
// #else
//     cr_log_warn("Skipping valgrind tests. Run tests on Linux or GitHub for full output.\n");
//     sprintf(cmd, "./bin/%s > %s 2>&1", test_name, test_log_outfile);
// #endif
//     return system(cmd);
// }

// void expect_normal_exit(int status)
// {
//     cr_expect_eq(status, 0, "The program did not exit normally (status = 0x%x).\n", status);
// }

// void expect_error_exit(int status)
// {
//     cr_expect_eq(WEXITSTATUS(status), 0xff,
//                  "The program did not exit with status 0xff (status was 0x%x).\n", status);
// }

// void expect_no_valgrind_errors(int status)
// {
//     cr_expect_neq(WEXITSTATUS(status), 37, "Valgrind reported errors -- see %s", test_log_outfile);
//     if (WEXITSTATUS(status) == 37)
//     {
//         char cmd[200];
//         sprintf(cmd, "cat %s", test_log_outfile);
//         system(cmd);
//     }
// }
Test(student_output, decrypt_minus_one_and_ohno_plaintext_EOM, .description = "decrypt with -1 error and null size plantext + -2")
{
    char plaintext_act[] = "";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    decrypt(ciphertext, plaintext_act);
    char *plaintext_exp = &plaintext_act;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
}
Test(student_return, decrypt_minus_two_and_ohno_plaintext, .description = "decrypt with -1 error and null size plantext + -2")
{
    char plaintext_act[] = "";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -1;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
Test(student_output, decrypt_minus_two, .description = "decrypt with EOM error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    decrypt(ciphertext, plaintext_act);
    char *plaintext_exp = &plaintext_act;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
}
Test(student_return, decrypt_minus_two, .description = "decrypt with EOM error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -2;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(student_output, decrypt_minus_three, .description = "decrypt with invalid char error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THE MAIn CAUSES of THE fall of The rOman EmpiRe Was THaT LaCkiNg ZeRo";
    decrypt(ciphertext, plaintext_act);
    char *plaintext_exp = &plaintext_act;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
}
Test(student_return, decrypt_minus_three, .description = "decrypt with invalid char error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THE MAIn CAUSES of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -3;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
Test(student_output, encrypt_EOM_only, .description = "Ciphertext string has room only for EOM.")
{
    char ciphertext_act[] = "Too Short 2022 Hel";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "TOO SHOrt 2022 Hel";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(student_return, encrypt_EOM_only, .description = "Ciphertext string has room only for EOMd.")
{
    char ciphertext_act[] = "Too Short 2022 Hel";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act);
    int count_exp = 0;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
Test(student_output, no_EOM_only_encrypt, .description = "No Room For EOM")
{
    char ciphertext_act[] = "";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(student_return, no_EOM_only_encrypt, .description = "No Room for EOM.")
{
    char ciphertext_act[] = "";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act);
    int count_exp = -1;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(student_output, encrypt_four_chars, .description = "Ciphertext string has room only for three characters.")
{
    char ciphertext_act[] = "I can store three characters! Yes!you";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act); // s = 010010, t = 010011, o = 001110, n = 001101
    char *ciphertext_exp = "i Can StoRe tHRee CHAracTErS! YES!YOU";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(student_return, encrypt_four_chars, .description = "Ciphertext string has room only for three characters.")
{
    char ciphertext_act[] = "I can store three characters! Yes!you";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act); // s = 010010, t = 010011, o = 001110
    int count_exp = 4;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
//110111
Test(student_return, decrypt_ret_neg_2, .description = "Ciphertext string contains one or more invalid bacon code.")
{
    char plaintext_act[] = "@@@@@@@@@";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "i Can StORe THRee CHArACTERS! Yes!";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -3;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(student_return, decrypt_ret_neg_1, .description = "no plaintext.")
{
    char plaintext_act[] = "";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "ORe THRee CHArACTERS! Yes!";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -1;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(student_out, encrypt_full_msg, .description = "A full plaintext message can be encrypted.")
{
    char ciphertext_act[] = "One of the main causes of the fall of the Roman Empire was that lacking zero, they had no way to indicate successful termination of their C programs.";
    char *plaintext = "--Robert Firthaaaaa";
    encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo, tHey haD no wAy To iNDicaTE Successful termination of their c prOGRAMS.";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(student_return, encrypt_full_msg, .description = "A full plaintext message can be encrypted.")
{
    char ciphertext_act[] = "One of the main causes of the fall of the Roman Empire was that lacking zero, they had no way to indicate successful termination of their C programs.";
    char *plaintext = "--Robert Firthaaaaa";
    int count_act = encrypt(plaintext, ciphertext_act);
    int count_exp = 19;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
Test(student_return, decrypt_ret_neg_9, .description = "-2 and -3 errors thrown")
{
    char plaintext_act[] = "#";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "i Can StORe THRee CHAraCTERS! Yes!";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -2;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
// Test(student_valgrind, decrypt_minus_two_valgrind)
// {
//     expect_no_valgrind_errors(run_using_system("decrypt_minus_two"));
// }

Test(hao_suite, encrypt_EOM_only, .description = "Ciphertext string has room only for EOM.")
{
    char ciphertext_act[] = "Too Short 2022 Hel";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "TOO SHOrt 2022 Hel";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(hao_return, encrypt_EOM_only, .description = "Ciphertext string has room only for EOMd.")
{
    char ciphertext_act[] = "Too Short 2022 Hel";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act);
    int count_exp = 0;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
Test(hao_suite, no_EOM_only_encrypt, .description = "No Room For EOM")
{
    char ciphertext_act[] = "";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(hao_return, no_EOM_only_encrypt, .description = "No Room for EOM.")
{
    char ciphertext_act[] = "";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act);
    int count_exp = -1;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(hao_suite, encrypt_four_chars, .description = "Ciphertext string has room only for three characters.")
{
    char ciphertext_act[] = "I can store three characters! Yes!you";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act); // s = 010010, t = 010011, o = 001110, n = 001101
    char *ciphertext_exp = "i Can StoRe tHRee CHAracTErS! YES!YOU";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(hao_return, encrypt_four_chars, .description = "Ciphertext string has room only for three characters.")
{
    char ciphertext_act[] = "I can store three characters! Yes!you";
    char *plaintext = "Stony Brook University";
    int count_act = encrypt(plaintext, ciphertext_act); // s = 010010, t = 010011, o = 001110
    int count_exp = 4;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
//110111
Test(hao_return, decrypt_ret_neg_2, .description = "Ciphertext string contains one or more invalid bacon code.")
{
    char plaintext_act[] = "@@@@@@@@@";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "i Can StORe THRee CHArACTERS! Yes!";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -3;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(hao_return, decrypt_ret_neg_1, .description = "no plaintext.")
{
    char plaintext_act[] = "";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "ORe THRee CHArACTERS! Yes!";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -1;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(hao_suite, encrypt_full_msg, .description = "A full plaintext message can be encrypted.")
{
    char ciphertext_act[] = "One of the main causes of the fall of the Roman Empire was that lacking zero, they had no way to indicate successful termination of their C programs.";
    char *plaintext = "--Robert Firthaaaaa";
    encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo, tHey haD no wAy To iNDicaTE Successful termination of their c prOGRAMS.";
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
}
Test(hao_return, encrypt_full_msg, .description = "A full plaintext message can be encrypted.")
{
    char ciphertext_act[] = "One of the main causes of the fall of the Roman Empire was that lacking zero, they had no way to indicate successful termination of their C programs.";
    char *plaintext = "--Robert Firthaaaaa";
    int count_act = encrypt(plaintext, ciphertext_act);
    int count_exp = 19;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}
Test(hao_output, decrypt_minus_two, .description = "decrypt with EOM error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    decrypt(ciphertext, plaintext_act);
    char *plaintext_exp = &plaintext_act;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
}
Test(hao_return, decrypt_minus_two, .description = "decrypt with EOM error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THe mAiN cAuseS of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -2;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(hao_output, decrypt_minus_three, .description = "decrypt with invalid char error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THE MAIn CAUSES of THE fall of The rOman EmpiRe Was THaT LaCkiNg ZeRo";
    decrypt(ciphertext, plaintext_act);
    char *plaintext_exp = &plaintext_act;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
}
Test(hao_return, decrypt_minus_three, .description = "decrypt with invalid char error")
{
    char plaintext_act[] = "*******************";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "One Of THE MAIn CAUSES of THE fall of The rOman EmpiRe Was THaT LaCking ZeRo";
    int count_act = decrypt(ciphertext, plaintext_act);
    int count_exp = -3;
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}