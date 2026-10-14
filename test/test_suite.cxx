#include "../include-shared/config.hpp"
#include "../include-shared/constants.hpp"
#include "../include-shared/keyloaders.hpp"
#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"
#include "../include/drivers/crypto_driver.hpp"
#include "../include/drivers/db_driver.hpp"
#include "../include/pkg/server.hpp"
#include "../include/pkg/user.hpp"
#include "../include/pkg/vote.hpp"
#include "doctest/doctest.h"

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <filesystem>
#include <mutex>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// ================================================================
// Helpers
// ================================================================

static std::shared_ptr<CryptoDriver> make_cd() {
  return std::make_shared<CryptoDriver>();
}

static CryptoPP::SecByteBlock make_key(unsigned char fill = 0x01,
                                       size_t sz = 32) {
  CryptoPP::SecByteBlock k(sz);
  memset(k.data(), fill, sz);
  return k;
}

// ================================================================
// Diffie-Hellman
// ================================================================

TEST_CASE("Diffie-Hellman Key Exchange") {
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();

  SUBCASE("Shared secrets match between two parties") {
    auto [dhA, privA, pubA] = crypto_driver->DH_initialize();
    auto [dhB, privB, pubB] = crypto_driver->DH_initialize();

    auto sharedA = crypto_driver->DH_generate_shared_key(dhA, privA, pubB);
    auto sharedB = crypto_driver->DH_generate_shared_key(dhB, privB, pubA);
    CHECK(sharedA == sharedB);

    CHECK(crypto_driver->AES_generate_key(sharedA) ==
          crypto_driver->AES_generate_key(sharedB));
    CHECK(crypto_driver->HMAC_generate_key(sharedA) ==
          crypto_driver->HMAC_generate_key(sharedB));
  }

  SUBCASE("Independent parties generate distinct public keys") {
    auto [dhA, privA, pubA] = crypto_driver->DH_initialize();
    auto [dhB, privB, pubB] = crypto_driver->DH_initialize();
    CHECK(pubA != pubB);
    CHECK(privA != privB);
  }

  SUBCASE("Wrong private key yields different shared secret") {
    auto [dhA, privA, pubA] = crypto_driver->DH_initialize();
    auto [dhB, privB, pubB] = crypto_driver->DH_initialize();
    auto [dhC, privC, pubC] = crypto_driver->DH_initialize();
    auto sharedAB = crypto_driver->DH_generate_shared_key(dhA, privA, pubB);
    auto sharedCB = crypto_driver->DH_generate_shared_key(dhC, privC, pubB);
    CHECK(sharedAB != sharedCB);
  }
}

TEST_CASE("basic RSA group-key envelope") {
  CryptoDriver crypto;
  auto [private_key, public_key] = crypto.RSA_generate_keys();
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer exponent(prng, 1, DL_Q - 1);
  CryptoPP::Integer group_secret =
      CryptoPP::ModularExponentiation(DL_G, exponent, DL_P);
  CryptoPP::Integer wrapped = public_key.ApplyFunction(group_secret);
  CryptoPP::Integer recovered = private_key.CalculateInverse(prng, wrapped);
  CHECK(wrapped != group_secret);
  CHECK(recovered == group_secret);
}

TEST_CASE("Persistent encrypted group records") {
  const std::string db_path = "/tmp/group-pipeline-test.db";
  std::filesystem::remove(db_path);
  DBDriver db;
  REQUIRE(db.open(db_path) == SQLITE_OK);
  db.init_tables();
  GroupRow group{"group-1", "alice", CryptoPP::Integer(3), CryptoPP::Integer(7), "signature"};
  std::vector<std::string> members{"alice", "bob"};
  std::vector<GroupEnvelopeRow> envelopes{{"alice", "wrapped-a"}, {"bob", "wrapped-b"}};
  REQUIRE(db.create_group(group, members, envelopes));
  GroupEnvelopeRow envelope;
  CHECK(db.get_group_envelope("group-1", "bob", envelope));
  CHECK(envelope.wrapped_group_key == "wrapped-b");
  REQUIRE(db.add_group_message(
      "group-1", {0, "alice", "iv", "cipher", "mac", "rsa-signature"}));
  auto messages = db.get_group_messages("group-1");
  REQUIRE(messages.size() == 1);
  CHECK(messages[0].ciphertext == "cipher");
  CHECK(messages[0].signature == "rsa-signature");
  db.close();
  std::filesystem::remove(db_path);
}

TEST_CASE("Legacy group schema upgrades without losing DKG") {
  const std::string db_path = "/tmp/group-schema-migration-test.db";
  std::filesystem::remove(db_path);

  sqlite3 *legacy_db = nullptr;
  REQUIRE(sqlite3_open(db_path.c_str(), &legacy_db) == SQLITE_OK);
  REQUIRE(sqlite3_exec(legacy_db,
                       "CREATE TABLE chat_group(group_id TEXT PRIMARY KEY NOT NULL);",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
  REQUIRE(sqlite3_exec(
              legacy_db,
              "CREATE TABLE group_message(id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT NOT NULL, sender_id TEXT NOT NULL, iv BLOB NOT NULL, ciphertext BLOB NOT NULL, mac BLOB NOT NULL);",
              nullptr, nullptr, nullptr) == SQLITE_OK);
  REQUIRE(sqlite3_exec(
              legacy_db,
              "CREATE TABLE group_dkg(group_id TEXT PRIMARY KEY, creator_id TEXT NOT NULL, public_key TEXT NOT NULL);",
              nullptr, nullptr, nullptr) == SQLITE_OK);
  REQUIRE(sqlite3_exec(legacy_db,
                       "INSERT INTO group_dkg VALUES('chat2', 'alice', '42');",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
  REQUIRE(sqlite3_close(legacy_db) == SQLITE_OK);

  DBDriver db;
  REQUIRE(db.open(db_path) == SQLITE_OK);
  db.init_tables();
  GroupDKGRow dkg;
  REQUIRE(db.get_group_dkg("chat2", dkg));
  CHECK(dkg.creator_id == "alice");

  GroupRow group{"chat2", "alice", CryptoPP::Integer(3),
                 CryptoPP::Integer(7), "signature"};
  CHECK(db.create_group(group, {"alice"}, {{"alice", "envelope"}}));
  REQUIRE(db.add_group_message(
      "chat2", {0, "alice", "iv", "cipher", "mac", "new-signature"}));
  const auto messages = db.get_group_messages("chat2");
  REQUIRE(messages.size() == 1);
  CHECK(messages[0].signature == "new-signature");
  REQUIRE(db.close() == SQLITE_OK);
  std::filesystem::remove(db_path);
}

TEST_CASE("Group-scoped escrow keys persist independently") {
  const std::string db_path = "/tmp/group-dkg-test.db";
  std::filesystem::remove(db_path);
  DBDriver db;
  REQUIRE(db.open(db_path) == SQLITE_OK);
  db.init_tables();

  REQUIRE(db.store_group_dkg({"group-a", "alice", CryptoPP::Integer(101)},
                             {{"1", CryptoPP::Integer(11)},
                              {"2", CryptoPP::Integer(12)}}));
  REQUIRE(db.store_group_dkg({"group-b", "alice", CryptoPP::Integer(202)},
                             {{"1", CryptoPP::Integer(21)},
                              {"2", CryptoPP::Integer(22)}}));
  REQUIRE(db.close() == SQLITE_OK);

  DBDriver reopened;
  REQUIRE(reopened.open(db_path) == SQLITE_OK);
  reopened.init_tables();
  GroupDKGRow group_a;
  GroupDKGRow group_b;
  REQUIRE(reopened.get_group_dkg("group-a", group_a));
  REQUIRE(reopened.get_group_dkg("group-b", group_b));
  CHECK(group_a.public_key == CryptoPP::Integer(101));
  CHECK(group_b.public_key == CryptoPP::Integer(202));
  CHECK(group_a.creator_id == "alice");
  CryptoPP::Integer partial;
  REQUIRE(reopened.get_group_dkg_partial_key("group-a", "1", partial));
  CHECK(partial == CryptoPP::Integer(11));
  CHECK_FALSE(reopened.get_group_dkg_partial_key("group-a", "3", partial));

  ServerToEscrow_DecryptRequest_Message request;
  request.group_id = "group-a";
  request.ciphertext.a = CryptoPP::Integer(5);
  request.ciphertext.b = CryptoPP::Integer(9);
  std::vector<unsigned char> encoded;
  request.serialize(encoded);
  ServerToEscrow_DecryptRequest_Message decoded;
  decoded.deserialize(encoded);
  CHECK(decoded.group_id == "group-a");
  CHECK(decoded.ciphertext.a == CryptoPP::Integer(5));
  CHECK(decoded.ciphertext.b == CryptoPP::Integer(9));

  ServerToUser_GroupDKGStatus_Message status;
  status.ready = false;
  status.started = true;
  status.group_id = "group-a";
  status.detail = "Escrow DKG started.";
  encoded.clear();
  status.serialize(encoded);
  ServerToUser_GroupDKGStatus_Message decoded_status;
  decoded_status.deserialize(encoded);
  CHECK(decoded_status.started);
  CHECK_FALSE(decoded_status.ready);
  CHECK(decoded_status.group_id == "group-a");

  reopened.close();
  std::filesystem::remove(db_path);
}

TEST_CASE("Threshold recovery verifies the final Shamir-share public keys") {
  const CryptoPP::Integer secret(47);
  const CryptoPP::Integer linear(9);
  const CryptoPP::Integer quadratic(5);
  const auto share_at = [&](int x) {
    const CryptoPP::Integer point(x);
    return (secret + linear * point + quadratic * point * point) % DL_Q;
  };

  const CryptoPP::Integer threshold_pk = CryptoPP::ModularExponentiation(
      DL_G, secret, DL_P);
  const ElGamal_Ciphertext ciphertext = VoteClient::Encrypt(
      CryptoPP::Integer(12345), threshold_pk);
  std::vector<Escrow_PartialDecryption_Message> partials;
  for (int escrow_id = 1; escrow_id <= 3; ++escrow_id) {
    const CryptoPP::Integer share = share_at(escrow_id);
    const CryptoPP::Integer partial_pk = CryptoPP::ModularExponentiation(
        DL_G, share, DL_P);
    auto [decryption, proof] = VoteClient::PartialDecrypt(ciphertext,
                                                           partial_pk, share);
    Escrow_PartialDecryption_Message response;
    response.escrow_id = std::to_string(escrow_id);
    response.dec = decryption;
    response.zkp = proof;
    CHECK(VoteClient::VerifyPartialDecryptZKP(response, partial_pk));
    partials.push_back(response);
  }
  CHECK(VoteClient::CombineResults(ciphertext, partials) ==
        CryptoPP::Integer(12345));
}
