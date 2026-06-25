#include <iostream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cmath>
#include <chrono>
#include <string>
#include <unordered_map>
#include <openssl/evp.h>
using namespace std;

// Using high-resolution clock for precise time tracking
typedef  chrono::steady_clock SysClock;


// Computes SHA256 using OpenSSL EVP API
static void compute_sha256(const void *input_data, size_t length,
                           unsigned char output_hash[32]) {
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
  EVP_DigestUpdate(context, input_data, length);
  unsigned int out_len = 32;
  EVP_DigestFinal_ex(context, output_hash, &out_len);
  EVP_MD_CTX_free(context);
}

// Print byte array as hex string
static void display_hash(const unsigned char *buffer, int bytes) {
  for (int i = 0; i < bytes; i++) {
     cout <<  hex <<  setw(2) <<  setfill('0')
              << (int)buffer[i];
  }
   cout <<  dec;
}


static uint64_t extract_prefix_64(const unsigned char hash[32],
                                  int target_bits) {
  uint64_t result = 0;
  int full_bytes = target_bits / 8;
  int leftover_bits = target_bits % 8;

  for (int i = 0; i < full_bytes && i < 8; i++) {
    result = (result << 8) | hash[i];
  }
  if (leftover_bits > 0 && full_bytes < 8) {
    result =
        (result << leftover_bits) | (hash[full_bytes] >> (8 - leftover_bits));
  }
  return result;
}

// Counts identical leading bits between two 256-bit hashes
static int get_match_length(const unsigned char hashA[32],
                            const unsigned char hashB[32]) {
  for (int idx = 0; idx < 32; idx++) {
    if (hashA[idx] != hashB[idx]) {
      unsigned char xor_diff = hashA[idx] ^ hashB[idx];
      int leading_zeros = __builtin_clz((unsigned int)xor_diff) - 24;
      return (idx * 8) + leading_zeros;
    }
  }
  return 256;
}

static  string generate_fast_id(uint64_t sequence_num) {
  static const char base36_chars[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  char buffer[24];
  int length = 0;
  uint64_t current = sequence_num;

  do {
    buffer[length++] = base36_chars[current % 36];
    current /= 36;
  } while (current > 0);

   reverse(buffer, buffer + length);
  return  string(buffer, length) + "@iitk.ac.in";
}

static  mt19937_64 random_gen( random_device{}());

void run_task_a(const  string &my_id, unsigned char target_hash[32]) {
   cout << "--------------------------------------------------------\n";
   cout << "[ Part A: Compute Base Hash ]\n";
   cout << "--------------------------------------------------------\n";
  compute_sha256(my_id.data(), my_id.size(), target_hash);
   cout << "Target Email : " << my_id << "\n";
   cout << "SHA-256 Hash : ";
  display_hash(target_hash, 32);
   cout << "\n\n";
}

uint64_t brute_force_preimage(const unsigned char target[32], int bits,
                               string &hit_email, int timeout) {
  uint64_t target_prefix = extract_prefix_64(target, bits);
  uint64_t iterations = 0;
  unsigned char candidate_hash[32];
  auto start_time = SysClock::now();
C/C++: Edit Configurations (UI)
  while (true) {
     string candidate_email = generate_fast_id(iterations);
    compute_sha256(candidate_email.data(), candidate_email.size(),
                   candidate_hash);
    iterations++;

    if (extract_prefix_64(candidate_hash, bits) == target_prefix) {
      hit_email = candidate_email;
      return iterations;
    }

    if (timeout > 0 && (iterations % 2000000) == 0) {
      auto diff =  chrono::duration_cast<
           chrono::duration<double,  ratio<1>>>(SysClock::now() -
                                                        start_time);
      double time_passed = diff.count();
      if (time_passed > timeout) {
        hit_email = ""; // Timeout triggered
        return iterations;
      }
    }
  }
}

void run_task_b(const unsigned char base_hash[32]) {
   cout << "--------------------------------------------------------\n";
   cout << "[ Part B: Partial Pre-image Search ]\n";
   cout << "--------------------------------------------------------\n";

  const double MAX_RUNTIME_SEC = 3600.0;
  auto search_start = SysClock::now();

  int max_match_bits = 0;
   string best_matching_email;

  int target_bits_list[] = {16, 24, 32, 36, 40, 48, 52, 56};

  for (int bit_target : target_bits_list) {
    auto diff_total =  chrono::duration_cast<
         chrono::duration<double,  ratio<1>>>(SysClock::now() -
                                                      search_start);
    double total_elapsed = diff_total.count();
    double time_left = MAX_RUNTIME_SEC - total_elapsed;

    if (time_left < 5.0) {
       cout << "-> 1 Hour global time budget reached. Halting search.\n";
      break;
    }


    int stage_budget = (int) min(time_left, 3600.0);

     cout << "-> Targeting " << bit_target
              << " bits. (Allocated Time: " << stage_budget << "s)...\n";

     string recovered_id;
    auto t_start = SysClock::now();
    uint64_t hashes_computed =
        brute_force_preimage(base_hash, bit_target, recovered_id, stage_budget);
    auto diff_stage =  chrono::duration_cast<
         chrono::duration<double,  ratio<1>>>(SysClock::now() -
                                                      t_start);
    double stage_time = diff_stage.count();

    if (recovered_id.empty()) {
       cout << "   [!] TIMEOUT after " << hashes_computed << " hashes ("
                << stage_time << "s).\n\n";
      break;
    } else {
      unsigned char temp_hash[32];
      compute_sha256(recovered_id.data(), recovered_id.size(), temp_hash);
      int exact_match = get_match_length(base_hash, temp_hash);

       cout << "   [+] SUCCESS in " << hashes_computed << " iterations ("
                << stage_time << "s)\n";
       cout << "       Match ID  : " << recovered_id << "\n";
       cout << "       Hash Val  : ";
      display_hash(temp_hash, 32);
       cout << "\n";
       cout << "       True Match: " << exact_match << " bits\n\n";

      if (exact_match > max_match_bits) {
        max_match_bits = exact_match;
        best_matching_email = recovered_id;
      }
    }
  }

   cout << "=== LONGEST PREIMAGE MATCH ===\n";
   cout << "Bits : " << max_match_bits << "\n";
   cout << "Email: " << best_matching_email << "\n\n";
}

void run_task_c(const unsigned char base_hash[32]) {
   cout << "--------------------------------------------------------\n";
   cout << "[ Part C: Preimage Benchmarking (50 Trials) ]\n";
   cout << "--------------------------------------------------------\n";

  const int num_trials = 50;
  int targets[] = {16, 24};

  for (int bits : targets) {
     cout << ">>> Running 50 trials for " << bits << "-bit match...\n";
    uint64_t total_hashes = 0;

    for (int t = 0; t < num_trials; t++) {
      uint64_t target_prefix = extract_prefix_64(base_hash, bits);
      uint64_t iters = 0;
      unsigned char h_tmp[32];
      uint64_t seed_offset = random_gen();

      while (true) {
         string id = generate_fast_id(seed_offset + iters);
        compute_sha256(id.data(), id.size(), h_tmp);
        iters++;
        if (extract_prefix_64(h_tmp, bits) == target_prefix)
          break;
      }
      total_hashes += iters;
       cout << "   Run " <<  setw(2) << (t + 1)
                << " | Hashes: " << iters << "\n";
    }

    double average_t = (double)total_hashes / num_trials;
     cout << "\n-> Target: " << bits << " bits\n";
     cout << "-> Average computations (t) : " << average_t << "\n";
     cout << "-> log2(t)                  : " << log2(average_t) << "\n\n";
  }
}

void run_task_d() {
   cout << "--------------------------------------------------------\n";
   cout << "[ Part D: Analysis of Benchmark ]\n";
   cout << "--------------------------------------------------------\n";
   cout << "The benchmark results yield us an empirical log2(t) value of\n";
   cout << "approximately 15 point something, which closely aligns with the theoretical\n";
   cout << "expectation of 16 for a partial pre-image attack.\n\n";
  
   cout << "Because we are trying to match a predetermined 16-bit prefix,\n";
   cout << "every hash computation acts as an independent Bernoulli trial\n";
   cout << "with a success probability of p = 1/(2^16).\n\n";
  
   cout << "The number of trials required to achieve the first success in\n";
   cout << "this type of memoryless scenario perfectly follows a geometric\n";
   cout << "distribution. A fundamental property of the geometric distribution\n";
   cout << "is that the expected number of trials is the inverse of the\n";
   cout << "success probability. Therefore, the expected number of hashes is\n";
   cout << "1/p = 2^16 (or 65,536 trials). Taking the base-2 logarithm of\n";
   cout << "this expected value naturally yields 16. Similar is the case with 24 bits.\n\n";
}

uint64_t search_collision_bday(int bit_target,  string &id1,
                                string &id2, int timeout) {
   unordered_map<uint64_t,  string> hash_map;
  if (bit_target <= 24)
    hash_map.reserve(1 << bit_target);
  else
    hash_map.reserve(1 << 22);

  uint64_t iters = 0;
  unsigned char current_hash[32];
  auto start_t = SysClock::now();

  while (true) {
     string current_id = generate_fast_id(iters);
    compute_sha256(current_id.data(), current_id.size(), current_hash);
    iters++;

    uint64_t prefix_key = extract_prefix_64(current_hash, bit_target);
    auto found = hash_map.find(prefix_key);

    if (found != hash_map.end() && found->second != current_id) {
      id1 = found->second;
      id2 = current_id;
      return iters;
    }
    hash_map[prefix_key] = current_id;

    if (timeout > 0 && (iters % 2000000) == 0) {
      auto diff =  chrono::duration_cast<
           chrono::duration<double,  ratio<1>>>(SysClock::now() -
                                                        start_t);
      double elapsed = diff.count();
      if (elapsed > timeout) {
        id1 = "";
        id2 = "";
        return iters;
      }
    }
  }
}

void run_task_e() {
   cout << "--------------------------------------------------------\n";
   cout << "[ Part E: Birthday Collision Search ]\n";
   cout << "--------------------------------------------------------\n";

  const double TOTAL_BUDGET = 3600.0; // 1 Hour
  auto global_start = SysClock::now();

  int max_coll_bits = 0;
   string top_id1, top_id2;

  int target_bits_list[] = {16, 24, 32, 40, 48, 52, 56};

  for (int bits : target_bits_list) {
    auto diff_total =  chrono::duration_cast<
         chrono::duration<double,  ratio<1>>>(SysClock::now() -
                                                      global_start);
    double elapsed_total = diff_total.count();
    double remaining = TOTAL_BUDGET - elapsed_total;

    if (remaining < 5.0)
      break;
    int level_budget = (int) min(remaining, 3600.0);

     cout << "-> Hunting " << bits
              << "-bit collision (Limit: " << level_budget << "s)...\n";

     string res1, res2;
    auto t0 = SysClock::now();
    uint64_t computed = search_collision_bday(bits, res1, res2, level_budget);
    auto diff_taken =  chrono::duration_cast<
         chrono::duration<double,  ratio<1>>>(SysClock::now() - t0);
    double time_taken = diff_taken.count();

    if (res1.empty()) {
       cout << "   [!] TIMEOUT after " << computed << " computations.\n\n";
      break;
    }

    unsigned char h1[32], h2[32];
    compute_sha256(res1.data(), res1.size(), h1);
    compute_sha256(res2.data(), res2.size(), h2);
    int true_match = get_match_length(h1, h2);

     cout << "   [+] FOUND in " << computed << " iterations (" << time_taken
              << "s)\n";
     cout << "       First ID  : " << res1 << "\n";
     cout << "       Hash 1    : ";
    display_hash(h1, 32);
     cout << "\n";
     cout << "       Second ID : " << res2 << "\n";
     cout << "       Hash 2    : ";
    display_hash(h2, 32);
     cout << "\n";
     cout << "       True Match: " << true_match << " bits\n\n";

    if (true_match > max_coll_bits) {
      max_coll_bits = true_match;
      top_id1 = res1;
      top_id2 = res2;
    }
  }

   cout << "=== LONGEST COLLISION MATCH ===\n";
   cout << "Bits: " << max_coll_bits << "\n";
   cout << "ID 1: " << top_id1 << "\n";
   cout << "ID 2: " << top_id2 << "\n\n";
}

void run_task_f() {
   cout << "--------------------------------------------------------\n";
   cout << "[ Part F: 16-bit Collision Benchmarking (50 Trials) ]\n";
   cout << "--------------------------------------------------------\n";

  uint64_t total_hashes = 0;
  const int num_trials = 50;

  for (int t = 0; t < num_trials; t++) {
     unordered_map<uint64_t,  string> lookup;
    lookup.reserve(1 << 16);
    unsigned char tmp_hash[32];
    uint64_t iters = 0;
    uint64_t shift = random_gen();

    while (true) {
       string id = generate_fast_id(shift + iters);
      compute_sha256(id.data(), id.size(), tmp_hash);
      iters++;

      uint64_t key = extract_prefix_64(tmp_hash, 16);
      if (lookup.count(key) && lookup[key] != id)
        break;
      lookup[key] = id;
    }
    total_hashes += iters;
     cout << "   Run " <<  setw(2) << (t + 1)
              << " | Computations: " << iters << "\n";
  }

  double avg_computations = (double)total_hashes / num_trials;
   cout << "\n-> Average computations (t) : " << avg_computations << "\n";
   cout << "-> log2(t)                  : " << log2(avg_computations)
            << "\n\n";
}

void run_task_g() {
    cout << "--------------------------------------------------------\n";
    cout << "[ Task G: Comparative Analysis ]\n";
    cout << "--------------------------------------------------------\n";
    cout << "The log(t) base 2 value derived from the collision benchmark is\n";
    cout << "approximately 8 point something. This drop by a factor of two \n";
    cout << "compared to previous result demonstrates us the Birthday Paradox.\n\n";
  
    cout << "This represents a fundamental shift from part (c). In a\n";
    cout << "birthday attack, we are no longer aiming for a single, isolated\n";
    cout << "target. Instead, every newly generated hash is compared against\n";
    cout << "the entire pool of previously computed hashes. The number of\n";
    cout << "possible pairings grows quadratically.\n\n";
  
    cout << "Because of this combinatorial explosion, a collision becomes\n";
    cout << "highly probable after computing roughly the square root of the\n";
    cout << "search space (2^(n/2)). For a 16-bit target, this means the\n";
    cout << "expected number of trials drops drastically from 2^16 to roughly\n";
    cout << "2^8 (256). Taking the base-2 logarithm of 256 gives us 8.\n\n";

}

int main() {
  const  string my_email = "akulav22@iitk.ac.in"; // my mail address
  unsigned char h1[32];

  run_task_a(my_email, h1);
  run_task_b(h1);
  run_task_c(h1);
  run_task_d();
  run_task_e();
  run_task_f();
  run_task_g();

   cout << "[ AND WE ARE DONE ]\n";
  return 0;
}