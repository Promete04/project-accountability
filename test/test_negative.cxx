// Negative-path / graceful-refusal tests.
//
// The theme of this file: every layer must *refuse gracefully* on bad input —
// wrong keys, tampered ciphertexts, forged signatures, wrong group ids, absent
// records — and never crash. "Graceful" means one of: a boolean false, an empty
// result, or a caught std::exception (the handlers upstream wrap every call in
// try/catch). Nothing here may abort the process.

#include "../include-shared/config.hpp"
#include "../include-shared/constants.hpp"
#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"
#include "../include/drivers/crypto_driver.hpp"
#include "../include/drivers/db_driver.hpp"
#include "../include/pkg/vote.hpp"
#include "doctest/doctest.h"

#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

// ================================================================
// Helpers
// ================================================================

namespace {

std::shared_ptr<CryptoDriver> cd() { return std::make_shared<CryptoDriver>(); }

CryptoPP::SecByteBlock filled_key(unsigned char fill, size_t sz = 32) {
  CryptoPP::SecByteBlock k(sz);
  memset(k.data(), fill, sz);
  return k;
}

// True if an AES decryption *refused gracefully* (threw) or at least did not
// hand back the original plaintext. Used for wrong-key / tampering cases where
// CBC+PKCS padding makes a thrown exception only probable, not guaranteed.
bool aes_decrypt_refused_or_differs(const std::shared_ptr<CryptoDriver> &crypto,
                                    CryptoPP::SecByteBlock key,
                                    CryptoPP::SecByteBlock iv,
                                    const std::string &ciphertext,
                                    const std::string &original) {
  try {
    return crypto->AES_decrypt(key, iv, ciphertext) != original;
  } catch (const std::exception &) {
    return true; // threw = refused gracefully
  }
}

// A fresh, unique on-disk DB for a test, tables initialised.
struct ScratchDB {
  std::string path;
  DBDriver db;
  explicit ScratchDB(const std::string &name)
      : path("/tmp/neg-" + name + ".db") {
    std::filesystem::remove(path);
    REQUIRE(db.open(path) == SQLITE_OK);
    db.init_tables();
  }
  ~ScratchDB() {
    db.close();
    std::filesystem::remove(path);
  }
};

CryptoPP::Integer modexp(const CryptoPP::Integer &b, const CryptoPP::Integer &e) {
  return CryptoPP::ModularExponentiation(b, e, DL_P);
}

} // namespace

// ================================================================
// AES symmetric encryption
// ================================================================

TEST_CASE("AES: round-trip and graceful refusal on bad key/ciphertext") {
  auto crypto = cd();
  CryptoPP::SecByteBlock key = filled_key(0x11);
  std::string plaintext = "the quick brown fox jumps over the lazy dog!!";

  auto [ciphertext, iv] = crypto->AES_encrypt(key, plaintext);

  SUBCASE("correct key round-trips") {
    CHECK(crypto->AES_decrypt(key, iv, ciphertext) == plaintext);
  }
  SUBCASE("wrong key does not reveal plaintext") {
    CryptoPP::SecByteBlock wrong = filled_key(0x22);
    CHECK(aes_decrypt_refused_or_differs(crypto, wrong, iv, ciphertext, plaintext));
  }
  SUBCASE("tampered ciphertext does not reveal plaintext") {
    std::string tampered = ciphertext;
    tampered[0] ^= 0xFF;
    CHECK(aes_decrypt_refused_or_differs(crypto, key, iv, tampered, plaintext));
  }
  SUBCASE("wrong IV corrupts output without crashing") {
    CryptoPP::SecByteBlock wrong_iv = filled_key(0x00, iv.size());
    // Wrong IV keeps padding valid but garbles the first block; must not crash.
    bool ok = false;
    try {
      ok = crypto->AES_decrypt(key, wrong_iv, ciphertext) != plaintext;
    } catch (const std::exception &) {
      ok = true;
    }
    CHECK(ok);
  }
}

// ================================================================
// HMAC
// ================================================================

TEST_CASE("HMAC: verify accepts genuine and refuses tampered/wrong-key") {
  auto crypto = cd();
  CryptoPP::SecByteBlock key = filled_key(0x33);
  std::string msg = "authenticated-associated-data";
  std::string mac = crypto->HMAC_generate(key, msg);

  CHECK(crypto->HMAC_verify(key, msg, mac));
  CHECK_FALSE(crypto->HMAC_verify(key, msg + "x", mac));       // tampered message
  CHECK_FALSE(crypto->HMAC_verify(key, msg, mac + "00"));      // tampered tag
  CHECK_FALSE(crypto->HMAC_verify(filled_key(0x44), msg, mac)); // wrong key
  CHECK_FALSE(crypto->HMAC_verify(key, msg, ""));               // empty tag
}

// ================================================================
// encrypt_and_tag / decrypt_and_verify (the channel AEAD wrapper)
// ================================================================

TEST_CASE("Channel AEAD: tamper and wrong-key handling") {
  auto crypto = cd();
  CryptoPP::SecByteBlock aes = filled_key(0x55);
  CryptoPP::SecByteBlock hmac = filled_key(0x66);

  UserToServer_GroupMembershipRequest_Message msg;
  msg.user_id = "alice";
  std::vector<unsigned char> wire = crypto->encrypt_and_tag(aes, hmac, &msg);

  SUBCASE("genuine message verifies and decodes") {
    auto [data, valid] = crypto->decrypt_and_verify(aes, hmac, wire);
    REQUIRE(valid);
    UserToServer_GroupMembershipRequest_Message got;
    got.deserialize(data);
    CHECK(got.user_id == "alice");
  }
  SUBCASE("wrong HMAC key => valid=false, no crash") {
    auto [data, valid] = crypto->decrypt_and_verify(aes, filled_key(0x77), wire);
    CHECK_FALSE(valid);
  }
  SUBCASE("tampered MAC field => valid=false") {
    HMACTagged_Wrapper wrapper;
    wrapper.deserialize(wire);
    wrapper.mac[0] ^= 0xFF;
    std::vector<unsigned char> retampered;
    wrapper.serialize(retampered);
    auto [data, valid] = crypto->decrypt_and_verify(aes, hmac, retampered);
    CHECK_FALSE(valid);
  }
  SUBCASE("wrong AES key refuses gracefully") {
    bool refused = false;
    try {
      auto [data, valid] = crypto->decrypt_and_verify(filled_key(0x88), hmac, wire);
      refused = !valid; // if it didn't throw it must at least report invalid
    } catch (const std::exception &) {
      refused = true;
    }
    CHECK(refused);
  }
}

// ================================================================
// RSA signatures / certificates
// ================================================================

TEST_CASE("RSA signatures: forgery and tampering are rejected") {
  auto crypto = cd();
  auto [sk, pk] = crypto->RSA_generate_keys();
  auto [other_sk, other_pk] = crypto->RSA_generate_keys();

  std::vector<unsigned char> message = str2chvec("certificate-body");
  std::string sig = crypto->RSA_sign(sk, message);

  CHECK(crypto->RSA_verify(pk, message, sig));
  CHECK_FALSE(crypto->RSA_verify(other_pk, message, sig));        // wrong key
  CHECK_FALSE(crypto->RSA_verify(pk, str2chvec("tampered"), sig)); // wrong message
  std::string bad_sig = sig;
  bad_sig[0] ^= 0xFF;
  CHECK_FALSE(crypto->RSA_verify(pk, message, bad_sig));           // mangled sig
  CHECK_FALSE(crypto->RSA_verify(pk, message, ""));                // empty sig
}

// ================================================================
// Authentication primitive: salted password hash
// ================================================================

TEST_CASE("Salted password login: wrong password or salt is refused") {
  // Mirrors HandleRegister/HandleLogin: the client sends H(password || salt)
  // and the server stores and later compares exactly that value. There is no
  // pepper and no time-based second factor in this protocol.
  auto crypto = cd();
  const std::string salt = "0123456789abcdef";
  const std::string password = "correct horse battery staple";
  const std::string stored = crypto->hash(password + salt); // set at registration

  auto authenticates = [&](const std::string &provided_hspw) {
    return provided_hspw == stored;
  };

  CHECK(authenticates(crypto->hash(password + salt)));               // correct
  CHECK_FALSE(authenticates(crypto->hash("wrong password" + salt))); // wrong pw
  CHECK_FALSE(authenticates(crypto->hash(password + "wrongsalt")));  // wrong salt
  CHECK_FALSE(authenticates(""));                                    // no response

  // Each registration draws a fresh salt, so the same password does not yield
  // the same stored hash across accounts.
  const std::string other_salt =
      byteblock_to_string(crypto->png(SALT_SIZE));
  CHECK(crypto->hash(password + other_salt) != stored);
}

// ================================================================
// Message serialization round-trips (new / changed message types)
// ================================================================

TEST_CASE("GroupFetch carries the incremental since_id across the wire") {
  UserToServer_GroupFetch_Message msg;
  msg.group_id = "team-alpha";
  msg.since_id = 42;
  std::vector<unsigned char> wire;
  msg.serialize(wire);
  UserToServer_GroupFetch_Message got;
  got.deserialize(wire);
  CHECK(got.group_id == "team-alpha");
  CHECK(got.since_id == 42);
}

TEST_CASE("Group messages sign a canonical encrypted record") {
  auto crypto = cd();
  auto [signing_key, verification_key] = crypto->RSA_generate_keys();
  UserToServer_GroupSend_Message message;
  message.group_id = "team-alpha";
  message.iv = "sixteen-byte-iv!";
  message.ciphertext = "opaque-ciphertext";
  message.mac = "01234567890123456789012345678901";
  message.signature = crypto->RSA_sign(
      signing_key,
      group_message_signature_input(message.group_id, "alice", message.iv,
                                    message.ciphertext, message.mac));

  std::vector<unsigned char> wire;
  message.serialize(wire);
  UserToServer_GroupSend_Message received;
  received.deserialize(wire);
  CHECK(received.signature == message.signature);
  CHECK(crypto->RSA_verify(
      verification_key,
      group_message_signature_input(received.group_id, "alice", received.iv,
                                    received.ciphertext, received.mac),
      received.signature));
  CHECK_FALSE(crypto->RSA_verify(
      verification_key,
      group_message_signature_input(received.group_id, "bob", received.iv,
                                    received.ciphertext, received.mac),
      received.signature));
  CHECK_FALSE(crypto->RSA_verify(
      verification_key,
      group_message_signature_input(received.group_id, "alice", received.iv,
                                    received.ciphertext + "x", received.mac),
      received.signature));
}

TEST_CASE("Group membership request/response round-trip") {
  UserToServer_GroupMembershipRequest_Message req;
  req.user_id = "bob";
  std::vector<unsigned char> wire;
  req.serialize(wire);
  UserToServer_GroupMembershipRequest_Message got_req;
  got_req.deserialize(wire);
  CHECK(got_req.user_id == "bob");

  SUBCASE("empty membership list") {
    ServerToUser_GroupMembershipResponse_Message resp;
    std::vector<unsigned char> rwire;
    resp.serialize(rwire);
    ServerToUser_GroupMembershipResponse_Message got;
    got.deserialize(rwire);
    CHECK(got.group_ids.empty());
  }
  SUBCASE("multiple groups") {
    ServerToUser_GroupMembershipResponse_Message resp;
    resp.group_ids = {"g1", "g2", "g3"};
    std::vector<unsigned char> rwire;
    resp.serialize(rwire);
    ServerToUser_GroupMembershipResponse_Message got;
    got.deserialize(rwire);
    REQUIRE(got.group_ids.size() == 3);
    CHECK(got.group_ids[0] == "g1");
    CHECK(got.group_ids[2] == "g3");
  }
}

TEST_CASE("Escrow keygen request binds the requested group ID") {
  EscrowToServer_Keygen_Message msg;
  msg.escrow_id = "2";
  msg.group_id = "chat2";
  msg.auth_tag = "authenticated-group-binding";
  std::vector<unsigned char> wire;
  msg.serialize(wire);

  EscrowToServer_Keygen_Message got;
  got.deserialize(wire);
  CHECK(got.escrow_id == "2");
  CHECK(got.group_id == "chat2");
  CHECK(got.auth_tag == "authenticated-group-binding");
}

TEST_CASE("Escrow flag-flow messages round-trip") {
  auto crypto = cd();
  auto [dh, priv, pub] = crypto->DH_initialize();

  SUBCASE("FlagGroup carries the requester DH public value") {
    EscrowToServer_FlagGroup_Message msg;
    msg.escrow_id = "1";
    msg.group_id = "g";
    msg.requester_dh_pub = pub;
    std::vector<unsigned char> wire;
    msg.serialize(wire);
    EscrowToServer_FlagGroup_Message got;
    got.deserialize(wire);
    CHECK(got.escrow_id == "1");
    CHECK(got.group_id == "g");
    CHECK(got.requester_dh_pub == pub);
  }

  SUBCASE("EncryptedPartial carries responder pubkey + opaque blob") {
    EscrowToServer_EncryptedPartial_Message msg;
    msg.from_id = "2";
    msg.group_id = "g";
    msg.responder_dh_pub = pub;
    msg.iv = "sixteen-byte-iv!";
    msg.ciphertext = "opaque-blob-bytes";
    std::vector<unsigned char> wire;
    msg.serialize(wire);
    EscrowToServer_EncryptedPartial_Message got;
    got.deserialize(wire);
    CHECK(got.from_id == "2");
    CHECK(got.responder_dh_pub == pub);
    CHECK(got.iv == "sixteen-byte-iv!");
    CHECK(got.ciphertext == "opaque-blob-bytes");
  }

  SUBCASE("PartialBundle carries partials + partial_pks + messages") {
    ServerToEscrow_PartialBundle_Message msg;
    msg.group_id = "g";
    msg.ciphertext.a = CryptoPP::Integer(3);
    msg.ciphertext.b = CryptoPP::Integer(5);
    msg.partials.push_back({"2", CryptoPP::Integer(111),
                            byteblock_to_string(pub), "iv2", "blob2"});
    msg.partials.push_back({"3", CryptoPP::Integer(222),
                            byteblock_to_string(pub), "iv3", "blob3"});
    msg.messages.push_back({7, "alice", "iv", "cipher", "mac", "signature"});
    auto [signing_key, verification_key] = crypto->RSA_generate_keys();
    (void)signing_key;
    Certificate_Message certificate;
    certificate.id = "alice";
    certificate.verification_key = verification_key;
    certificate.encryption_key = verification_key;
    certificate.server_signature = "server-signature";
    msg.sender_certificates.push_back(std::move(certificate));
    std::vector<unsigned char> wire;
    msg.serialize(wire);
    ServerToEscrow_PartialBundle_Message got;
    got.deserialize(wire);
    CHECK(got.group_id == "g");
    CHECK(got.ciphertext.a == CryptoPP::Integer(3));
    REQUIRE(got.partials.size() == 2);
    CHECK(got.partials[0].from_id == "2");
    CHECK(got.partials[0].partial_pk == CryptoPP::Integer(111));
    CHECK(got.partials[1].ciphertext == "blob3");
    REQUIRE(got.messages.size() == 1);
    CHECK(got.messages[0].message_id == 7);
    CHECK(got.messages[0].sender_id == "alice");
    CHECK(got.messages[0].signature == "signature");
    REQUIRE(got.sender_certificates.size() == 1);
    CHECK(got.sender_certificates[0].id == "alice");
  }
}

// ================================================================
// Threshold decryption: ZKP forgery and combination edge cases
// ================================================================

namespace {
// A degree-1 (threshold-2) sharing of `secret`, so any 2 of 3 shares recover it.
struct ThresholdFixture {
  CryptoPP::Integer secret{47};
  CryptoPP::Integer slope{9};
  CryptoPP::Integer plaintext{12345};
  CryptoPP::Integer threshold_pk;
  ElGamal_Ciphertext ciphertext;

  ThresholdFixture() {
    threshold_pk = modexp(DL_G, secret);
    ciphertext = VoteClient::Encrypt(plaintext, threshold_pk);
  }
  CryptoPP::Integer share_at(int x) const {
    return (secret + slope * CryptoPP::Integer(x)) % DL_Q;
  }
  Escrow_PartialDecryption_Message partial(int escrow_id) const {
    CryptoPP::Integer share = share_at(escrow_id);
    CryptoPP::Integer pk_i = modexp(DL_G, share);
    auto [dec, zkp] = VoteClient::PartialDecrypt(ciphertext, pk_i, share);
    Escrow_PartialDecryption_Message m;
    m.escrow_id = std::to_string(escrow_id);
    m.group_id = "g";
    m.dec = dec;
    m.zkp = zkp;
    return m;
  }
  CryptoPP::Integer pk_of(int escrow_id) const {
    return modexp(DL_G, share_at(escrow_id));
  }
};
} // namespace

TEST_CASE("Partial-decryption ZKP rejects forgeries") {
  ThresholdFixture fx;
  Escrow_PartialDecryption_Message good = fx.partial(1);

  CHECK(VoteClient::VerifyPartialDecryptZKP(good, fx.pk_of(1)));

  SUBCASE("verification against the wrong escrow's public key fails") {
    CHECK_FALSE(VoteClient::VerifyPartialDecryptZKP(good, fx.pk_of(2)));
  }
  SUBCASE("tampered partial decryption value fails") {
    Escrow_PartialDecryption_Message tampered = good;
    tampered.dec.d = (tampered.dec.d + 1) % DL_P;
    CHECK_FALSE(VoteClient::VerifyPartialDecryptZKP(tampered, fx.pk_of(1)));
  }
  SUBCASE("tampered proof response fails") {
    Escrow_PartialDecryption_Message tampered = good;
    tampered.zkp.s = (tampered.zkp.s + 1) % DL_Q;
    CHECK_FALSE(VoteClient::VerifyPartialDecryptZKP(tampered, fx.pk_of(1)));
  }
  SUBCASE("proof bound to a different ciphertext fails") {
    Escrow_PartialDecryption_Message tampered = good;
    tampered.dec.aggregate_ciphertext.a =
        (tampered.dec.aggregate_ciphertext.a + 1) % DL_P;
    CHECK_FALSE(VoteClient::VerifyPartialDecryptZKP(tampered, fx.pk_of(1)));
  }
}

TEST_CASE("Threshold combination: any 2-of-3 recovers, below-threshold does not") {
  ThresholdFixture fx;

  SUBCASE("every 2-subset recovers the plaintext") {
    for (auto pair : std::vector<std::pair<int, int>>{{1, 2}, {1, 3}, {2, 3}}) {
      std::vector<Escrow_PartialDecryption_Message> partials{
          fx.partial(pair.first), fx.partial(pair.second)};
      CHECK(VoteClient::CombineResults(fx.ciphertext, partials) == fx.plaintext);
    }
  }
  SUBCASE("a single share (below threshold) does not recover, and never crashes") {
    std::vector<Escrow_PartialDecryption_Message> one{fx.partial(1)};
    CryptoPP::Integer result;
    CHECK_NOTHROW(result = VoteClient::CombineResults(fx.ciphertext, one));
    CHECK(result != fx.plaintext);
  }
}

// ================================================================
// Escrow-initiated flag: DH-wrapped partials round-trip (no server sees them)
// ================================================================

TEST_CASE("Flag flow: responder wraps partial to requester; requester recovers") {
  auto crypto = cd();
  ThresholdFixture fx;

  // Requester (escrow 1) makes an ephemeral DH keypair to receive partials.
  auto [dhR, privR, pubR] = crypto->DH_initialize();

  std::vector<Escrow_PartialDecryption_Message> collected;
  // Requester contributes its own partial directly.
  collected.push_back(fx.partial(1));

  // Responder (escrow 2) wraps its partial under DH(responder, requester).
  Escrow_PartialDecryption_Message responder_partial = fx.partial(2);
  std::vector<unsigned char> plain;
  responder_partial.serialize(plain);

  auto [dhX, privX, pubX] = crypto->DH_initialize();
  CryptoPP::SecByteBlock shared_resp =
      crypto->DH_generate_shared_key(dhX, privX, pubR);
  CryptoPP::SecByteBlock wrap_key = crypto->AES_generate_key(shared_resp);
  auto [blob, blob_iv] = crypto->AES_encrypt(wrap_key, chvec2str(plain));

  // Requester derives the same key the other way and unwraps.
  CryptoPP::SecByteBlock shared_req =
      crypto->DH_generate_shared_key(dhR, privR, pubX);
  CryptoPP::SecByteBlock unwrap_key = crypto->AES_generate_key(shared_req);
  REQUIRE(unwrap_key == wrap_key);

  std::string recovered_plain = crypto->AES_decrypt(unwrap_key, blob_iv, blob);
  std::vector<unsigned char> recovered_bytes = str2chvec(recovered_plain);
  Escrow_PartialDecryption_Message unwrapped;
  unwrapped.deserialize(recovered_bytes);
  CHECK(VoteClient::VerifyPartialDecryptZKP(unwrapped, fx.pk_of(2)));
  collected.push_back(unwrapped);

  CHECK(VoteClient::CombineResults(fx.ciphertext, collected) == fx.plaintext);

  SUBCASE("an eavesdropper without the requester's private key cannot unwrap") {
    auto [dhE, privE, pubE] = crypto->DH_initialize();
    CryptoPP::SecByteBlock eaves_shared =
        crypto->DH_generate_shared_key(dhE, privE, pubX);
    CryptoPP::SecByteBlock eaves_key = crypto->AES_generate_key(eaves_shared);
    CHECK(aes_decrypt_refused_or_differs(crypto, eaves_key, blob_iv, blob,
                                         recovered_plain));
  }
}

// ================================================================
// Database: unknown records refuse gracefully; access-control queries
// ================================================================

TEST_CASE("DB: lookups of absent records return false/empty, never crash") {
  ScratchDB s("absent");

  GroupRow group;
  CHECK_FALSE(s.db.get_group("no-such-group", group));
  GroupDKGRow dkg;
  CHECK_FALSE(s.db.get_group_dkg("no-such-group", dkg));
  GroupEnvelopeRow env;
  CHECK_FALSE(s.db.get_group_envelope("no-such-group", "nobody", env));
  CryptoPP::Integer partial;
  CHECK_FALSE(s.db.get_group_dkg_partial_key("no-such-group", "1", partial));
  CHECK_FALSE(s.db.is_group_member("no-such-group", "nobody"));
  CHECK(s.db.get_user_groups("nobody").empty());
  CHECK(s.db.get_group_messages("no-such-group").empty());
  CHECK(s.db.find_user("nobody").user_id.empty());
}

TEST_CASE("DB: group creation is atomic and rejects duplicates / mismatches") {
  ScratchDB s("create");
  GroupRow group{"g1", "alice", CryptoPP::Integer(3), CryptoPP::Integer(7), "sig"};
  std::vector<std::string> members{"alice", "bob"};
  std::vector<GroupEnvelopeRow> envelopes{{"alice", "wa"}, {"bob", "wb"}};

  REQUIRE(s.db.create_group(group, members, envelopes));

  SUBCASE("re-creating the same group id fails without partial writes") {
    CHECK_FALSE(s.db.create_group(group, members, envelopes));
  }
  SUBCASE("member/envelope count mismatch is rejected") {
    GroupRow g2{"g2", "alice", CryptoPP::Integer(1), CryptoPP::Integer(2), "sig"};
    std::vector<GroupEnvelopeRow> too_few{{"alice", "wa"}};
    CHECK_FALSE(s.db.create_group(g2, members, too_few));
    GroupRow after;
    CHECK_FALSE(s.db.get_group("g2", after)); // nothing was written
  }
  SUBCASE("empty membership is rejected") {
    GroupRow g3{"g3", "alice", CryptoPP::Integer(1), CryptoPP::Integer(2), "sig"};
    CHECK_FALSE(s.db.create_group(g3, {}, {}));
  }
}

TEST_CASE("DB: membership listing is per-user and correct") {
  ScratchDB s("membership");
  REQUIRE(s.db.create_group(
      {"team-a", "alice", CryptoPP::Integer(1), CryptoPP::Integer(2), "sig"},
      {"alice", "bob"}, {{"alice", "wa"}, {"bob", "wb"}}));
  REQUIRE(s.db.create_group(
      {"team-b", "alice", CryptoPP::Integer(1), CryptoPP::Integer(2), "sig"},
      {"alice"}, {{"alice", "wa"}}));

  auto alice = s.db.get_user_groups("alice");
  REQUIRE(alice.size() == 2);
  CHECK(alice[0] == "team-a"); // ORDER BY group_id
  CHECK(alice[1] == "team-b");

  auto bob = s.db.get_user_groups("bob");
  REQUIRE(bob.size() == 1);
  CHECK(bob[0] == "team-a");

  CHECK(s.db.get_user_groups("carol").empty());
  CHECK(s.db.is_group_member("team-a", "bob"));
  CHECK_FALSE(s.db.is_group_member("team-b", "bob")); // bob not in team-b
}

TEST_CASE("DB: a non-member cannot fetch a group's envelope") {
  ScratchDB s("envelope");
  REQUIRE(s.db.create_group(
      {"g", "alice", CryptoPP::Integer(1), CryptoPP::Integer(2), "sig"},
      {"alice", "bob"}, {{"alice", "wa"}, {"bob", "wb"}}));

  GroupEnvelopeRow env;
  CHECK(s.db.get_group_envelope("g", "alice", env));
  CHECK(env.wrapped_group_key == "wa");
  CHECK_FALSE(s.db.get_group_envelope("g", "carol", env)); // outsider refused
}

TEST_CASE("DB: incremental fetch returns only messages after the cursor") {
  ScratchDB s("incremental");
  REQUIRE(s.db.create_group(
      {"g", "alice", CryptoPP::Integer(1), CryptoPP::Integer(2), "sig"},
      {"alice"}, {{"alice", "wa"}}));
  for (int i = 0; i < 3; ++i)
    REQUIRE(s.db.add_group_message(
        "g", {0, "alice", "iv", "cipher" + std::to_string(i), "mac",
              "signature"}));

  auto all = s.db.get_group_messages("g", 0);
  REQUIRE(all.size() == 3);
  int last = all.back().id;

  CHECK(s.db.get_group_messages("g", all[0].id).size() == 2); // after 1st
  CHECK(s.db.get_group_messages("g", last).empty());          // fully caught up
  CHECK(s.db.get_group_messages("g", last + 100).empty());    // beyond the end
}

TEST_CASE("DB: user records round-trip and reject duplicate ids") {
  ScratchDB s("users");
  UserRow alice;
  alice.user_id = "alice";
  alice.password_hash = "h";
  alice.password_salt = "s";
  alice.prg_seed = "seed";
  alice.certificate_data = "cert";
  s.db.insert_user(alice);

  UserRow found = s.db.find_user("alice");
  CHECK(found.user_id == "alice");
  CHECK(found.password_hash == "h");

  // A second insert with the same id must not corrupt the stored row.
  UserRow impostor;
  impostor.user_id = "alice";
  impostor.password_hash = "evil";
  s.db.insert_user(impostor);
  CHECK(s.db.find_user("alice").password_hash == "h");
}
