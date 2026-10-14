#pragma once

#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <condition_variable>
#include <cstdint>
#include <utility>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

// DKG coordination state shared across escrow handler threads
struct DKGState {
  std::string group_id;
  std::string creator_id;
  std::map<std::string, DKG_FeldmanCommitment> commitments;
  std::map<std::string, std::vector<DKG_DHPublicValue>> dh_values;
  std::map<std::string, std::vector<DKG_EncryptedShare>> share_bundles;
  std::map<std::string, CryptoPP::Integer> partial_pks;
  std::vector<std::string> escrow_ids;
  int expected_count;
  bool active = false;
  bool finalizing = false;
  bool aborted = false;
  std::uint64_t generation = 0;
  std::mutex mtx;
  std::condition_variable cv;

  void reset(const std::string &new_group_id, const std::string &new_creator_id,
             int n) {
    ++generation;
    group_id = new_group_id;
    creator_id = new_creator_id;
    commitments.clear();
    dh_values.clear();
    share_bundles.clear();
    partial_pks.clear();
    escrow_ids.clear();
    expected_count = n;
    active = true;
    finalizing = false;
    aborted = false;
  }
};

struct PendingDecryption {
  bool active = false;
  std::string group_id;
  std::string requester_id;
  ElGamal_Ciphertext ciphertext;
  // The requesting escrow's ephemeral DH public value; responders encrypt to it.
  CryptoPP::SecByteBlock requester_dh_pub;
  std::string requester_mesh_mac;
  // Encrypted partials, keyed by responder id for deduplication. The server
  // never holds the key that decrypts these.
  std::map<std::string, EncryptedPartialEntry> encrypted_partials;
  std::mutex mtx;
  std::condition_variable cv;
};

class ServerClient {
public:
  ServerClient(ServerConfig server_config);
  void run(int port);
  bool HandleConnection(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                    std::shared_ptr<CryptoDriver> crypto_driver);
  void
  HandleLogin(std::shared_ptr<NetworkDriver> network_driver,
              std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
              std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void HandleRegister(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void HandleDKG(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
      std::string requested_group_id,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void HandleEscrowDecryption(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
      const std::string &escrow_id);
  void HandleFlagGroup(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
      const EscrowToServer_FlagGroup_Message &flag_msg);
  void HandleGroupRequest(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver, const std::string &user_id,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void HandleOneGroupRequest(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver, const std::string &user_id,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
      std::vector<unsigned char> request_data);

private:
  ServerConfig server_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<DBDriver> db_driver;

  CryptoPP::RSA::PrivateKey RSA_signing_key;
  CryptoPP::RSA::PublicKey RSA_verification_key;

  DKGState dkg_state;
  PendingDecryption pending_decryption;

  void ListenForConnections(int port);
  void Reset(std::string _);
  void Users(std::string _);
  bool StartGroupDKG(const std::string &group_id, const std::string &creator_id,
                     bool &ready, std::string &detail);
};
