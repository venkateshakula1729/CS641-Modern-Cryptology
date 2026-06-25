#include <iostream>
#include <openssl/bn.h>
#include <string>
using namespace std;

void print_bignum(const string &label, const BIGNUM *num, bool use_hex = true) {
  char *str_val = use_hex ? BN_bn2hex(num) : BN_bn2dec(num);
  int bits = BN_num_bits(num);
  cout << label << " [" << bits << " bits]:\n  " << str_val << "\n";
  OPENSSL_free(str_val);
}

bool execute_miller_rabin(const BIGNUM *candidate, int confidence_rounds,
                          BN_CTX *ctx, bool show_trace = false) {
  if (BN_is_word(candidate, 2) || BN_is_word(candidate, 3))
    return true;
  if (BN_cmp(candidate, BN_value_one()) <= 0 || !BN_is_odd(candidate))
    return false;

  BIGNUM *target_minus_1 = BN_new();
  BIGNUM *odd_part = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *current_val = BN_new();
  BIGNUM *range_max = BN_new();

  BN_copy(target_minus_1, candidate);
  BN_sub_word(target_minus_1, 1);
  BN_copy(odd_part, target_minus_1);

  int twos_count = 0;
  while (!BN_is_bit_set(odd_part, 0)) {
    BN_rshift1(odd_part, odd_part);
    twos_count++;
  }

  if (show_trace) {
    cout << "  [MR Trace] Decomposed n-1 = 2^" << twos_count << " * d. Running "
         << confidence_rounds << " iterations.\n";
  }

  BN_copy(range_max, candidate);
  BN_sub_word(range_max, 3);

  bool is_likely_prime = true;

  for (int round = 0; round < confidence_rounds; ++round) {
    BN_rand_range(base, range_max);
    BN_add_word(base, 2);

    BN_mod_exp(current_val, base, odd_part, candidate, ctx);

    if (BN_is_one(current_val) || BN_cmp(current_val, target_minus_1) == 0) {
      continue;
    }

    bool sequence_passed = false;
    for (int step = 0; step < twos_count - 1; ++step) {
      BN_mod_sqr(current_val, current_val, candidate, ctx);

      if (BN_cmp(current_val, target_minus_1) == 0) {
        sequence_passed = true;
        break;
      }
      if (BN_is_one(current_val)) {
        is_likely_prime = false;
        break;
      }
    }

    if (!is_likely_prime)
      break;
    if (!sequence_passed) {
      is_likely_prime = false;
      break;
    }
  }

  BN_free(target_minus_1);
  BN_free(odd_part);
  BN_free(base);
  BN_free(current_val);
  BN_free(range_max);

  return is_likely_prime;
}

BIGNUM *fetch_random_prime(int bit_length, int mr_iterations, BN_CTX *ctx) {
  BIGNUM *num = BN_new();
  int loops_taken = 0;

  while (true) {
    loops_taken++;

    BN_rand(num, bit_length, 1, BN_RAND_BOTTOM_ODD);

    if (execute_miller_rabin(num, mr_iterations, ctx, false)) {
      cout << "  [+] Discovered " << bit_length << "-bit prime after "
           << loops_taken << " MR attempts.\n";
      return num;
    }
  }
}

void compute_eea(const BIGNUM *A, const BIGNUM *B, BIGNUM *out_gcd,
                 BIGNUM *out_x, BIGNUM *out_y, BN_CTX *ctx) {
  BIGNUM *prev_rem = BN_dup(A), *curr_rem = BN_dup(B);
  BIGNUM *coeff_x_prev = BN_new(), *coeff_x_curr = BN_new();
  BIGNUM *coeff_y_prev = BN_new(), *coeff_y_curr = BN_new();

  BN_one(coeff_x_prev);
  BN_zero(coeff_x_curr);
  BN_zero(coeff_y_prev);
  BN_one(coeff_y_curr);

  BIGNUM *quotient = BN_new(), *temp_rem = BN_new(), *math_tmp = BN_new();
  BIGNUM *next_x = BN_new(), *next_y = BN_new();

  while (!BN_is_zero(curr_rem)) {
    BN_div(quotient, temp_rem, prev_rem, curr_rem, ctx);

    BN_mul(math_tmp, quotient, coeff_x_curr, ctx);
    BN_sub(next_x, coeff_x_prev, math_tmp);

    BN_mul(math_tmp, quotient, coeff_y_curr, ctx);
    BN_sub(next_y, coeff_y_prev, math_tmp);

    BN_copy(prev_rem, curr_rem);
    BN_copy(curr_rem, temp_rem);
    BN_copy(coeff_x_prev, coeff_x_curr);
    BN_copy(coeff_x_curr, next_x);
    BN_copy(coeff_y_prev, coeff_y_curr);
    BN_copy(coeff_y_curr, next_y);
  }

  BN_copy(out_gcd, prev_rem);
  BN_copy(out_x, coeff_x_prev);
  BN_copy(out_y, coeff_y_prev);

  BN_free(prev_rem);
  BN_free(curr_rem);
  BN_free(coeff_x_prev);
  BN_free(coeff_x_curr);
  BN_free(coeff_y_prev);
  BN_free(coeff_y_curr);
  BN_free(quotient);
  BN_free(temp_rem);
  BN_free(math_tmp);
  BN_free(next_x);
  BN_free(next_y);
}

int main() {
  BN_CTX *system_ctx = BN_CTX_new();
  const int TEST_ROUNDS = 40;

  cout << "\n======================================================\n";
  cout << " Part A: Miller-Rabin Primality Test \n";
  cout << "======================================================\n";

  BIGNUM *tester = BN_new();
  vector<string> test_primes = {"7", "13", "104729"};
  vector<string> test_comps = {"4", "15", "561"}; // 561 is Carmichael

  cout << "  Testing Known Primes:\n";
  for (const auto &num_str : test_primes) {
    BN_dec2bn(&tester, num_str.c_str());
    bool res = execute_miller_rabin(tester, TEST_ROUNDS, system_ctx, true);
    cout << "     Target: " << num_str << " -> "
         << (res ? "VALID PRIME" : "COMPOSITE") << "\n";
  }

  cout << "\n  Testing Known Composites:\n";
  for (const auto &num_str : test_comps) {
    BN_dec2bn(&tester, num_str.c_str());
    bool res = execute_miller_rabin(tester, TEST_ROUNDS, system_ctx, true);
    cout << "     Target: " << num_str << " -> "
         << (res ? "VALID PRIME" : "COMPOSITE") << "\n";
  }
  BN_free(tester);

  cout << "\n======================================================\n";
  cout << " Part B: RSA 512-bit Prime Generation\n";
  cout << "======================================================\n";

  BIGNUM *prime_P = fetch_random_prime(512, TEST_ROUNDS, system_ctx);
  print_bignum("Prime_P", prime_P);

  BIGNUM *prime_Q = BN_new();
  do {
    BN_free(prime_Q);
    prime_Q = fetch_random_prime(512, TEST_ROUNDS, system_ctx);
  } while (BN_cmp(prime_P, prime_Q) == 0);

  print_bignum("Prime_Q", prime_Q);
  cout << "  [+] Verified Prime_P is distinctly different from Prime_Q.\n";

  cout << "\n======================================================\n";
  cout << " Part C: Extended Euclidean Algorithm (EEA)\n";
  cout << "======================================================\n";

  BIGNUM *val_A = BN_new(), *val_B = BN_new();
  BIGNUM *calc_gcd = BN_new(), *calc_x = BN_new(), *calc_y = BN_new();
  BIGNUM *eq_check = BN_new(), *term1 = BN_new(), *term2 = BN_new();

  cout << "  Diagnostic Run: EEA(240, 46)\n";
  BN_set_word(val_A, 240);
  BN_set_word(val_B, 46);
  compute_eea(val_A, val_B, calc_gcd, calc_x, calc_y, system_ctx);

  print_bignum("  GCD", calc_gcd, false);
  print_bignum("  Coeff X", calc_x, false);
  print_bignum("  Coeff Y", calc_y, false);

  BN_mul(term1, val_A, calc_x, system_ctx);
  BN_mul(term2, val_B, calc_y, system_ctx);
  BN_add(eq_check, term1, term2);
  cout << "  -> Equation verification (A*X + B*Y = GCD): "
       << (BN_cmp(eq_check, calc_gcd) == 0 ? "PASSED" : "FAILED") << "\n\n";

  cout << " Cryptographic Run: EEA(Prime_P, Prime_Q)\n";
  compute_eea(prime_P, prime_Q, calc_gcd, calc_x, calc_y, system_ctx);
  print_bignum("  GCD(P, Q)", calc_gcd, false);
  cout << "  -> GCD validation: "
       << (BN_is_one(calc_gcd) ? "PASSED (GCD is 1)" : "FAILED") << "\n";

  cout << "\n======================================================\n";
  cout << " Part D: RSA Key Generation\n";
  cout << "======================================================\n";

  BIGNUM *modulus_N = BN_new(), *totient = BN_new();
  BIGNUM *pub_exponent = BN_new(), *priv_exponent = BN_new();

  BN_mul(modulus_N, prime_P, prime_Q, system_ctx);
  print_bignum("Modulus (N)", modulus_N);

  // Totient = (P-1)(Q-1)
  BIGNUM *p_sub_1 = BN_new(), *q_sub_1 = BN_new();
  BN_copy(p_sub_1, prime_P);
  BN_sub_word(p_sub_1, 1);
  BN_copy(q_sub_1, prime_Q);
  BN_sub_word(q_sub_1, 1);
  BN_mul(totient, p_sub_1, q_sub_1, system_ctx);
  print_bignum("Euler's Totient Phi(N)", totient);

  BN_set_word(pub_exponent, 65537);
  print_bignum("Public Exponent (E)", pub_exponent, false);

  compute_eea(pub_exponent, totient, calc_gcd, calc_x, calc_y, system_ctx);
  cout << "  [+] GCD(E, Phi(N)) = "
       << (BN_is_one(calc_gcd) ? "1 (Valid RSA Base)" : "INVALID") << "\n";

  BN_nnmod(priv_exponent, calc_x, totient, system_ctx);
  print_bignum("Private Exponent (D) [Derived via EEA]", priv_exponent);

  BN_mod_mul(eq_check, pub_exponent, priv_exponent, totient, system_ctx);
  cout << "  [+] Key Integrity Check (E * D mod Phi(N) == 1): "
       << (BN_is_one(eq_check) ? "VERIFIED" : "CORRUPT") << "\n";

  cout << "\n======================================================\n";
  cout << " Part E: RSA 1024-bit Cryptosystem Test\n";
  cout << "======================================================\n";

  BIGNUM *plain_msg = BN_new(), *cipher_msg = BN_new(),
         *recovered_msg = BN_new();

  // We are explicitly generating a strictly 1024-bit message
  do {
    BN_rand(plain_msg, 1024, 0, BN_RAND_BOTTOM_ANY);
  } while (BN_cmp(plain_msg, modulus_N) >= 0);

  print_bignum("Plaintext Payload (M)", plain_msg);

  // C = M^E mod N
  BN_mod_exp(cipher_msg, plain_msg, pub_exponent, modulus_N, system_ctx);
  print_bignum("Ciphertext Block (C)", cipher_msg);

  // M = C^D mod N
  BN_mod_exp(recovered_msg, cipher_msg, priv_exponent, modulus_N, system_ctx);
  print_bignum("Decrypted Payload (M')", recovered_msg);

  std::cout << "\n------------------------------------------------------\n";
  if (BN_cmp(plain_msg, recovered_msg) == 0) {
    std::cout << "  SUCCESS : M == M'\n";
    std::cout
        << "     The decrypted output perfectly matches the initial input.\n";
  } else {
    std::cout << " CRITICAL FAILURE: Decryption mismatch.\n";
  }
  std::cout << "------------------------------------------------------\n\n";

  // Memory Cleanup (Keep your existing cleanup here)
  BN_free(val_A);
  BN_free(val_B);
  BN_free(calc_gcd);
  BN_free(calc_x);
  BN_free(calc_y);
  BN_free(eq_check);
  BN_free(term1);
  BN_free(term2);
  BN_free(prime_P);
  BN_free(prime_Q);
  BN_free(modulus_N);
  BN_free(totient);
  BN_free(p_sub_1);
  BN_free(q_sub_1);
  BN_free(pub_exponent);
  BN_free(priv_exponent);
  BN_free(plain_msg);
  BN_free(cipher_msg);
  BN_free(recovered_msg);
  BN_CTX_free(system_ctx);

  return 0;
}