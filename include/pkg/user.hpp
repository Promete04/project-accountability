#pragma once

#include <iostream>
#include <map>
#include <mutex>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

class UserClient {
public:
  UserClient(std::shared_ptr<NetworkDriver> network_driver,
             std::shared_ptr<CryptoDriver> crypto_driver,
             UserConfig user_config);
  void run();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleServerKeyExchange();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleUserKeyExchange();
  bool HandleLoginOrRegister(std::string input);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  DoLoginOrRegister(std::string input, bool keep_group_session = false);
  bool HandleUser(std::string input);
  bool HandleGroupCreate(std::string input);
  bool HandleGroupSend(std::string input);
  bool HandleGroupFetch(std::string input);
  std::vector<std::string> check_group_pertenece(const std::string &address,
                                                 int port);
  std::vector<std::string> get_registered_users(const std::string &address,
                                                int port);
  std::string get_id() const;

  std::vector<std::pair<std::string, std::string>>
  FetchGroupMessagesStructured(const std::string &address, int port,
                               const std::string &group_id);

private:
  std::string id;
  Certificate_Message certificate;

  UserConfig user_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  // Serializes every network operation. The TUI drives this client from several
  // threads, and they all share the single `network_driver` above, so requests
  // must never interleave on the same socket.
  std::mutex network_mtx;

  // Per-group incremental message state, guarded by network_mtx. The poller asks
  // only for messages newer than the cursor and appends them to the cache, so it
  // never re-transfers or re-decrypts the whole history. Keyed "ip:port/group".
  std::map<std::string, int> group_fetch_cursor;
  std::map<std::string, std::vector<std::pair<std::string, std::string>>>
      group_message_cache;
  // Sender certificates are static for this demo. Cache them per server so a
  // newly fetched chat message does not require another certificate request.
  std::map<std::string, Certificate_Message> group_sender_certificates;

  CryptoPP::RSA::PrivateKey RSA_signing_key;
  CryptoPP::RSA::PublicKey RSA_verification_key;
  CryptoPP::RSA::PrivateKey RSA_encryption_private_key;
  CryptoPP::RSA::PublicKey RSA_encryption_public_key;
  CryptoPP::RSA::PublicKey RSA_server_verification_key;
  CryptoPP::RSA::PublicKey RSA_remote_verification_key;
  // Highest group-message id already fetched this session, per group. Lets
  // group-fetch pull only newer messages; resets to 0 on restart.
  std::map<std::string, int> group_cursors;

  void
  ReceiveThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  SendThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  Certificate_Message FetchCertificate(const std::string &address, int port,
                                       const std::string &user_id);
  bool VerifyGroupMessageSignature(const std::string &address, int port,
                                   const std::string &group_id,
                                   const GroupChatMessage &message);
  CryptoPP::Integer FetchElectionPublicKey(const std::string &address, int port,
                                           const std::string &group_id);
  bool EnsureGroupDKG(const std::string &address, int port,
                      const std::string &group_id);
  ServerToUser_GroupMessages_Message
  FetchGroupState(const std::string &address, int port,
                  const std::string &group_id, int since_id = 0);
};
