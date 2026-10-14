#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rsa.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class EscrowClient {
public:
  EscrowClient(EscrowConfig escrow_config);
  void run();
  void HandleKeygen(std::string input);
  void HandleDKG(std::string input);
  void HandleDecrypt(std::string input);
  void HandleFlag(std::string input);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleServerKeyExchange();

private:
  EscrowConfig escrow_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  CryptoPP::Integer EG_secret_key_i;   // Our final Shamir share s_i
  CryptoPP::Integer EG_public_key_i;   // G^{z_i} — our partial public key
  CryptoPP::RSA::PublicKey RSA_server_verification_key;

  // DKG state
  std::vector<CryptoPP::Integer> dkg_polynomial; // Our polynomial coefficients

};
