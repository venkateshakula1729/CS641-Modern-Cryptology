#include <iostream>
#include <openssl/bn.h>
#include <string>
using namespace std;

void print_bignum(const string &label, const BIGNUM *num, bool use_hex = true) {
  char *str_val = use_hex ? BN_bn2hex(num) : BN_bn2dec(num);
  std::cout << label << " : " << str_val << "\n";
  OPENSSL_free(str_val);
}

bool custom_primality_test(const BIGNUM *candidate, int confidence_rounds,
                           BN_CTX *ctx) {
  if (BN_is_word(candidate, 2) || BN_is_word(candidate, 3))
    return true;
  if (BN_cmp(candidate, BN_value_one()) <= 0 || !BN_is_odd(candidate))
    return false;

  // We need to express (candidate - 1) as (odd_multiplier * 2^shift_count)
  BIGNUM *val_minus_one = BN_new();
  BIGNUM *odd_multiplier = BN_new();
  BIGNUM *rand_base = BN_new();
  BIGNUM *power_res = BN_new();
  BIGNUM *max_rand_range = BN_new();

  BN_copy(val_minus_one, candidate);
  BN_sub_word(val_minus_one, 1);
  BN_copy(odd_multiplier, val_minus_one);

  int shift_count = 0;
  while (!BN_is_bit_set(odd_multiplier, 0)) {
    BN_rshift1(odd_multiplier, odd_multiplier);
    shift_count++;
  }

  BN_copy(max_rand_range, candidate);
  BN_sub_word(max_rand_range,
              3); // Upper bound for random base is candidate - 2

  bool is_prime_flag = true;

  for (int i = 0; i < confidence_rounds; ++i) {
    BN_rand_range(rand_base, max_rand_range);
    BN_add_word(rand_base, 2);

    BN_mod_exp(power_res, rand_base, odd_multiplier, candidate, ctx);

    if (BN_is_one(power_res) || BN_cmp(power_res, val_minus_one) == 0) {
      continue;
    }

    bool sequence_passed = false;
    for (int step = 0; step < shift_count - 1; ++step) {
      BN_mod_sqr(power_res, power_res, candidate, ctx);

      if (BN_cmp(power_res, val_minus_one) == 0) {
        sequence_passed = true;
        break;
      }
      if (BN_is_one(power_res)) {
        is_prime_flag = false;
        break;
      }
    }

    if (!is_prime_flag)
      break;
    if (!sequence_passed) {
      is_prime_flag = false;
      break;
    }
  }

  BN_free(val_minus_one);
  BN_free(odd_multiplier);
  BN_free(rand_base);
  BN_free(power_res);
  BN_free(max_rand_range);

  return is_prime_flag;
}

void generate_sg_environment(BIGNUM *prime_P, BIGNUM *sub_prime_Q,
                             BN_CTX *ctx) {
  std::cout << "\n========================================================\n";
  std::cout << " [B] Generating 512-bit Sophie-Germain Prime \n";
  std::cout << "========================================================\n";

  const int MR_ITERATIONS = 40;
  int search_attempts = 0;

  while (true) {
    search_attempts++;
    BN_rand(sub_prime_Q, 511, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    if (!custom_primality_test(sub_prime_Q, MR_ITERATIONS, ctx)) {
      continue;
    }
    BN_lshift1(prime_P, sub_prime_Q);
    BN_add_word(prime_P, 1);

    if (custom_primality_test(prime_P, MR_ITERATIONS, ctx)) {
      std::cout << " -> Discovered SG prime architecture after "
                << search_attempts << " tests.\n\n";
      print_bignum("Sub-Prime (Q) [511-bit]", sub_prime_Q);
      print_bignum("Safe Prime  (P) [512-bit]", prime_P);
      break;
    }
  }
}

void find_dh_generator(BIGNUM *dh_generator, const BIGNUM *prime_P,
                       const BIGNUM *sub_prime_Q, BN_CTX *ctx) {
  std::cout << "\n========================================================\n";
  std::cout << " [C] Hunting for a valid Generator of Z*_P\n";
  std::cout << "========================================================\n";

  BIGNUM *order_check = BN_new();
  BIGNUM *p_limit = BN_new();
  BIGNUM *exponent_two = BN_new();

  BN_copy(p_limit, prime_P);
  BN_sub_word(p_limit, 3); // Max random bound
  BN_set_word(exponent_two, 2);

  int gen_attempts = 0;

  while (true) {
    gen_attempts++;

    BN_rand_range(dh_generator, p_limit);
    BN_add_word(dh_generator, 2);

    BN_mod_sqr(order_check, dh_generator, prime_P, ctx);
    if (BN_is_one(order_check))
      continue;

    BN_mod_exp(order_check, dh_generator, sub_prime_Q, prime_P, ctx);
    if (BN_is_one(order_check))
      continue;

    std::cout << " -> Valid generator located in " << gen_attempts
              << " random samples.\n\n";
    print_bignum("Generator (G)", dh_generator);
    break;
  }

  BN_free(order_check);
  BN_free(p_limit);
  BN_free(exponent_two);
}

void execute_dh_exchange(const BIGNUM *prime_P, const BIGNUM *dh_generator,
                         BN_CTX *ctx) {
  std::cout << "\n========================================================\n";
  std::cout << " [D] Simulating Diffie-Hellman Key Exchange\n";
  std::cout << "========================================================\n";

  BIGNUM *alice_priv = BN_new(), *alice_pub = BN_new();
  BIGNUM *bob_priv = BN_new(), *bob_pub = BN_new();
  BIGNUM *alice_shared_sec = BN_new(), *bob_shared_sec = BN_new();
  BIGNUM *range_limit = BN_new();

  BN_copy(range_limit, prime_P);
  BN_sub_word(range_limit, 2);

  BN_rand_range(alice_priv, range_limit);
  BN_add_word(alice_priv, 1);
  BN_mod_exp(alice_pub, dh_generator, alice_priv, prime_P, ctx);

  std::cout << "[ ALICE ]\n";
  print_bignum("  Private Key (a)", alice_priv);
  print_bignum("  Public Broadcast (A)", alice_pub);
  std::cout << "\n";

  BN_rand_range(bob_priv, range_limit);
  BN_add_word(bob_priv, 1);
  BN_mod_exp(bob_pub, dh_generator, bob_priv, prime_P, ctx); // B = G^b mod P

  std::cout << "[ BOB ]\n";
  print_bignum("  Private Key (b)", bob_priv);
  print_bignum("  Public Broadcast (B)", bob_pub);
  std::cout << "\n";

  //  SHARED SECRET DERIVATION
  BN_mod_exp(alice_shared_sec, bob_pub, alice_priv, prime_P,
             ctx); // S_A = B^a mod P
  BN_mod_exp(bob_shared_sec, alice_pub, bob_priv, prime_P,
             ctx); // S_B = A^b mod P

  std::cout << "[ SECRETS DERIVED ]\n";
  print_bignum("  Alice's Shared Secret", alice_shared_sec);
  print_bignum("  Bob's Shared Secret  ", bob_shared_sec);

  std::cout << "\n--------------------------------------------------------\n";
  if (BN_cmp(alice_shared_sec, bob_shared_sec) == 0) {
    std::cout << " >> STATUS: KEY EXCHANGE SUCCESSFUL.\n";
    std::cout << "    Both parties arrived at the exact same shared secret.\n";
  } else {
    std::cout << " >> STATUS: KEY EXCHANGE FAILED.\n";
  }
  std::cout << "--------------------------------------------------------\n\n";

  BN_free(alice_priv);
  BN_free(alice_pub);
  BN_free(bob_priv);
  BN_free(bob_pub);
  BN_free(alice_shared_sec);
  BN_free(bob_shared_sec);
  BN_free(range_limit);
}

// -----------------------------------------------------------------------------
// MAIN PROGRAM EXECUTION
// -----------------------------------------------------------------------------
int main() {
  BN_CTX *system_ctx = BN_CTX_new();

  BIGNUM *prime_P = BN_new();
  BIGNUM *sub_prime_Q = BN_new();
  BIGNUM *dh_generator = BN_new();

  // I have submitted Part (a) in pdf as it is theoretical.

  generate_sg_environment(prime_P, sub_prime_Q, system_ctx);         // Part B
  find_dh_generator(dh_generator, prime_P, sub_prime_Q, system_ctx); // Part C
  execute_dh_exchange(prime_P, dh_generator, system_ctx);            // Part D

  BN_free(prime_P);
  BN_free(sub_prime_Q);
  BN_free(dh_generator);
  BN_CTX_free(system_ctx);

  return 0;
}