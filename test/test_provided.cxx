#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"
#include "../include/drivers/crypto_driver.hpp"

// --------------------------
// ~~~~ Example RSA Test ~~~~
// This test will verify that
// your rsa-generate function
//  produces a valid keypair
// --------------------------
TEST_CASE("rsa-generation") {
  std::cout << "TESTING: rsa-generation" << std::endl;

  // Generate the RSA keys
  std::shared_ptr<CryptoDriver> crypto_driver = std::make_shared<CryptoDriver>();
  auto student_keys = crypto_driver->RSA_generate_keys();

  // Verify using CryptoPP's Validate() function with level 2.
  CryptoPP::AutoSeededRandomPool rng;
  CHECK(student_keys.first.Validate(rng, 2));
  CHECK(student_keys.second.Validate(rng, 2));
}
