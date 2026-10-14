#include "../../include/pkg/escrow.hpp"
#include "../../include/pkg/escrow_mesh.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/escrow_security.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/vote.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace {
src::severity_logger<logging::trivial::severity_level> lg;

// Group IDs are user supplied. Encode them before using them in a local key
// filename so a group name can never select a path outside the configured
// escrow-key directory.
std::string group_file_suffix(const std::string &group_id) {
  static const char hex[] = "0123456789abcdef";
  std::string suffix;
  suffix.reserve(group_id.size() * 2);
  for (unsigned char byte : group_id) {
    suffix.push_back(hex[byte >> 4]);
    suffix.push_back(hex[byte & 0x0f]);
  }
  return suffix;
}

std::string group_secret_path(const EscrowConfig &config,
                              const std::string &group_id) {
  return config.escrow_secret_key_path + ".group-" +
         group_file_suffix(group_id) + ".secret";
}

std::string group_partial_public_path(const EscrowConfig &config,
                                      const std::string &group_id) {
  return config.escrow_public_key_path + ".group-" +
         group_file_suffix(group_id) + ".partial-public";
}

std::string escrow_auth_tag(std::shared_ptr<CryptoDriver> crypto_driver,
                            const std::string &escrow_id,
                            const std::string &purpose,
                            const std::string &binding = "") {
  const std::string &secret = escrow_server_auth_secret(escrow_id);
  const CryptoPP::SecByteBlock material(
      reinterpret_cast<const CryptoPP::byte *>(secret.data()), secret.size());
  return crypto_driver->HMAC_generate(
      crypto_driver->HMAC_generate_key(material),
      "escrow-auth-v1|" + purpose + "|" + escrow_id + "|" + binding);
}

std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
escrow_mesh_keys(std::shared_ptr<CryptoDriver> crypto_driver) {
  const std::string &secret = escrow_mesh_secret();
  const CryptoPP::SecByteBlock material(
      reinterpret_cast<const CryptoPP::byte *>(secret.data()), secret.size());
  return {crypto_driver->AES_generate_key(material),
          crypto_driver->HMAC_generate_key(material)};
}

std::string dkg_share_context(const std::string &group_id,
                              const std::string &from_id,
                              const std::string &to_id,
                              const std::string &iv,
                              const std::string &ciphertext) {
  return "dkg-share-v1|" + group_id + "|" + from_id + "|" + to_id +
         "|" + iv + ciphertext;
}

std::string escrow_flag_context(const std::string &escrow_id,
                                const std::string &group_id,
                                const CryptoPP::SecByteBlock &requester_dh_pub) {
  return "escrow-flag-v1|" + escrow_id + "|" + group_id + "|" +
         byteblock_to_string(requester_dh_pub);
}

std::string encrypted_partial_context(
    const std::string &from_id, const std::string &group_id,
    const CryptoPP::SecByteBlock &requester_dh_pub,
    const CryptoPP::SecByteBlock &responder_dh_pub, const std::string &iv,
    const std::string &ciphertext) {
  return "escrow-partial-v1|" + from_id + "|" + group_id + "|" +
         byteblock_to_string(requester_dh_pub) + "|" +
         byteblock_to_string(responder_dh_pub) + "|" + iv + ciphertext;
}

}

/**
 * Constructor
 */
EscrowClient::EscrowClient(EscrowConfig escrow_config) {
  // Make shared variables.
  this->escrow_config = escrow_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = std::make_shared<CryptoDriver>();
  this->network_driver = std::make_shared<NetworkDriverImpl>();
  
  this->cli_driver->init();

  // Load server public key
  try {
    LoadRSAPublicKey(escrow_config.server_verification_key_path,
                     this->RSA_server_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading server public key; "
                                    "application may be non-functional.");
  }
}

void EscrowClient::run() {
  // Start REPL
  REPLDriver<EscrowClient> repl = REPLDriver<EscrowClient>(this);
  repl.add_action("keygen", "keygen <group-id>", &EscrowClient::HandleKeygen);
  repl.add_action("decrypt", "decrypt", &EscrowClient::HandleDecrypt);
  repl.add_action("flag", "flag <group-id>", &EscrowClient::HandleFlag);
  repl.run();
}

/**
 * Diffie-Hellman key exchange with server.
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
EscrowClient::HandleServerKeyExchange() {
  // Generate keypair and send public to server
  auto [dh, priv, pub] = this->crypto_driver->DH_initialize();

  EscrowToServer_DHPublicValue_Message user_msg;
  user_msg.public_value = pub;
  std::vector<unsigned char> user_msg_data;
  user_msg.serialize(user_msg_data);
  this->network_driver->send(user_msg_data);

  // Receive response and verify RSA signature
  ServerToEscrow_DHPublicValue_Message server_msg;
  std::vector<unsigned char> server_msg_data = this->network_driver->read();
  server_msg.deserialize(server_msg_data);

  std::vector<unsigned char> to_verify = concat_byteblocks(
      server_msg.server_public_value, server_msg.escrow_public_value);
  bool sig_valid =
      this->crypto_driver->RSA_verify(this->RSA_server_verification_key,
                                      to_verify, server_msg.server_signature);
  if (!sig_valid) {
    throw std::runtime_error("Server DH signature verification failed.");
  }

  // Verify the server echoed back our public value.
  if (server_msg.escrow_public_value != pub) {
    throw std::runtime_error("Server echoed wrong escrow public value.");
  }

  // Compute shared key and derive AES + HMAC keys
  CryptoPP::SecByteBlock shared_key =
      this->crypto_driver->DH_generate_shared_key(
          dh, priv, server_msg.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(shared_key);
  return {AES_key, HMAC_key};
}

void EscrowClient::HandleKeygen(std::string input) {
  try {
    try {
      this->network_driver->disconnect();
    } catch (...) {
      // Ignore disconnect errors if the socket wasn't connected
    }
    this->network_driver = std::make_shared<NetworkDriverImpl>();
    std::vector<std::string> input_split = string_split(input, ' ');
    if (input_split.size() != 2 || input_split[1].empty()) {
      this->cli_driver->print_left("Usage: keygen <group-id>");
      return;
    }
    this->network_driver->connect(escrow_config.server_ip,
                                  escrow_config.server_port);
    this->HandleDKG(input_split[1]);
  } catch (std::exception &e) {
    this->cli_driver->print_warning(e.what());
  }
}


/**
 * Handle Distributed Key Generation (DKG) protocol.
 * 
 * Protocol flow:
 * 1. Server channel DH key exchange
 * 2. Send escrow ID, receive DKGStart
 * 3. Generate polynomial + Feldman commitments, send to server
 * 4. Receive all commitments
 * 5. Encrypt shares with the escrow-only mesh AES/HMAC keys, send to server
 * 6. Receive + authenticate + decrypt shares from other escrows
 * 7. Verify shares against Feldman commitments (abort on failure)
 * 8. Compute final share + public key, save to disk
 */
void EscrowClient::HandleDKG(std::string requested_group_id) {
  if (requested_group_id.empty()) {
    throw std::runtime_error("A group ID is required for escrow DKG.");
  }
  auto [aes_key, hmac_key] = this->HandleServerKeyExchange();
  std::string my_id = this->escrow_config.escrow_id;

  // Send escrow ID to server
  EscrowToServer_Keygen_Message id_msg;
  id_msg.escrow_id = my_id;
  id_msg.group_id = requested_group_id;
  if (!is_authorized_escrow(my_id)) {
    throw std::runtime_error("This escrow ID is not in the configured roster.");
  }
  id_msg.auth_tag = escrow_auth_tag(this->crypto_driver, my_id, "keygen",
                                    requested_group_id);
  std::vector<unsigned char> id_msg_data =
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &id_msg);
  this->network_driver->send(id_msg_data);

  // Receive DKGStart from server
  auto [start_data, start_valid] = crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, network_driver->read());
  if (!start_valid) {
    throw std::runtime_error("Invalid HMAC on DKGStart message.");
  }
  ServerToEscrow_DKGStart_Message start_msg;
  start_msg.deserialize(start_data);

  int n = start_msg.n;
  int t = start_msg.t;
  const std::string group_id = start_msg.group_id;
  if (group_id != requested_group_id) {
    throw std::runtime_error("Server DKG group does not match the requested group ID.");
  }
  std::vector<std::string> all_escrow_ids = start_msg.escrow_ids;
  const auto &expected_escrows = authorized_escrow_ids();
  if (n != THRESHOLD_N || t != THRESHOLD_T ||
      all_escrow_ids.size() != expected_escrows.size() ||
      !std::equal(all_escrow_ids.begin(), all_escrow_ids.end(),
                  expected_escrows.begin()) ||
      std::find(all_escrow_ids.begin(), all_escrow_ids.end(), my_id) ==
          all_escrow_ids.end()) {
    throw std::runtime_error("Server sent a DKG roster or threshold different from the configured escrow set.");
  }

  this->cli_driver->print_info("DKG started for group " + group_id + ": N=" + std::to_string(n) +
                                ", T=" + std::to_string(t) +
                                ", my ID=" + my_id);

  // ===================== Step 1: Generate polynomial + commitments =====================
  this->dkg_polynomial = this->crypto_driver->DKG_generate_polynomial(t);
  std::vector<CryptoPP::Integer> my_commitments =
      this->crypto_driver->DKG_feldman_commitments(this->dkg_polynomial);

  // Send commitments to server
  EscrowToServer_DKGCommitment_Message commit_msg;
  commit_msg.escrow_id = my_id;
  commit_msg.commitment.dealer_id = my_id;
  commit_msg.commitment.commitments = my_commitments;
  std::vector<unsigned char> commit_data =
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &commit_msg);
  this->network_driver->send(commit_data);

  this->cli_driver->print_info("Sent Feldman commitments to server.");

  // Receive all commitments from server
  auto [all_commit_data, all_commit_valid] = crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, network_driver->read());
  if (!all_commit_valid) {
    throw std::runtime_error("Invalid HMAC on AllCommitments message.");
  }
  ServerToEscrow_DKGAllCommitments_Message all_commit_msg;
  all_commit_msg.deserialize(all_commit_data);

  // Store commitments indexed by dealer_id
  std::map<std::string, std::vector<CryptoPP::Integer>> all_commitments_map;
  for (const auto &fc : all_commit_msg.all_commitments) {
    if (!is_authorized_escrow(fc.dealer_id) ||
        fc.commitments.size() != static_cast<size_t>(THRESHOLD_T) ||
        !all_commitments_map.emplace(fc.dealer_id, fc.commitments).second) {
      throw std::runtime_error("Malformed or duplicate Feldman commitment.");
    }
  }
  if (all_commitments_map.size() != static_cast<size_t>(THRESHOLD_N))
    throw std::runtime_error("DKG is missing a configured escrow commitment.");

  this->cli_driver->print_info("Received all " +
      std::to_string(all_commit_msg.all_commitments.size()) +
      " Feldman commitments.");

  // ===================== Step 2: Encrypt + send escrow-only shares =====================
  // The pre-provisioned mesh key is known to the fixed escrow roster only.
  // The server has distinct per-escrow authentication keys, so it cannot read
  // or manufacture these share envelopes.
  auto [mesh_aes, mesh_hmac] = escrow_mesh_keys(this->crypto_driver);
  int my_idx = std::stoi(my_id); // Escrow IDs are "1", "2", "3"

  EscrowToServer_DKGShareBundle_Message share_bundle_msg;
  share_bundle_msg.from_id = my_id;

  for (const auto &peer_id : all_escrow_ids) {
    if (peer_id == my_id) continue;

    int peer_idx = std::stoi(peer_id);
    CryptoPP::Integer share_val =
        this->crypto_driver->DKG_evaluate_polynomial(this->dkg_polynomial, peer_idx);

    // Serialize the share as a string
    std::string share_str = CryptoPP::IntToString(share_val);

    auto [ciphertext, iv] =
        this->crypto_driver->AES_encrypt(mesh_aes, share_str);
    std::string iv_str = byteblock_to_string(iv);

    DKG_EncryptedShare es;
    es.from_id = my_id;
    es.to_id = peer_id;
    es.iv = iv_str;
    es.ciphertext = ciphertext;
    es.mac = this->crypto_driver->HMAC_generate(
        mesh_hmac, dkg_share_context(group_id, es.from_id, es.to_id, es.iv,
                                     es.ciphertext));
    share_bundle_msg.shares.push_back(es);
  }

  std::vector<unsigned char> share_bundle_data =
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &share_bundle_msg);
  this->network_driver->send(share_bundle_data);

  this->cli_driver->print_info("Sent encrypted shares to all peers.");

  // ===================== Step 3: Receive + authenticate + decrypt shares =====================
  auto [share_delivery_data, share_delivery_valid] = crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, network_driver->read());
  if (!share_delivery_valid) {
    throw std::runtime_error("Invalid HMAC on share delivery message.");
  }
  ServerToEscrow_DKGShareDelivery_Message share_delivery_msg;
  share_delivery_msg.deserialize(share_delivery_data);
  if (share_delivery_msg.shares.size() !=
      static_cast<size_t>(THRESHOLD_N - 1)) {
    throw std::runtime_error("DKG share delivery has the wrong number of shares.");
  }

  // Start final share with our own polynomial evaluated at our index
  CryptoPP::Integer final_share =
      this->crypto_driver->DKG_evaluate_polynomial(this->dkg_polynomial, my_idx);

  std::set<std::string> seen_senders;
  for (const auto &es : share_delivery_msg.shares) {
    std::string sender_id = es.from_id;
    if (sender_id == my_id || !is_authorized_escrow(sender_id) ||
        es.to_id != my_id || !seen_senders.insert(sender_id).second) {
      throw std::runtime_error("Malformed DKG share sender or recipient.");
    }
    if (!this->crypto_driver->HMAC_verify(
            mesh_hmac, dkg_share_context(group_id, es.from_id, es.to_id,
                                         es.iv, es.ciphertext), es.mac)) {
      throw std::runtime_error("Invalid escrow-mesh HMAC on share from " +
                               sender_id + ".");
    }
    CryptoPP::SecByteBlock iv = string_to_byteblock(es.iv);
    if (iv.size() != CryptoPP::AES::BLOCKSIZE) {
      throw std::runtime_error("Invalid IV on share from escrow " + sender_id);
    }

    std::string share_str =
        this->crypto_driver->AES_decrypt(mesh_aes, iv, es.ciphertext);
    CryptoPP::Integer received_share(share_str.c_str());

    // Verify against Feldman commitments
    auto it = all_commitments_map.find(sender_id);
    if (it == all_commitments_map.end()) {
      throw std::runtime_error(
          "WARNING: No commitments found for escrow " + sender_id +
          ". DKG ABORTED — communications may have been tampered with.");
    }

    bool valid = this->crypto_driver->DKG_verify_share(
        my_idx, received_share, it->second);
    if (!valid) {
      throw std::runtime_error(
          "WARNING: Share from escrow " + sender_id +
          " FAILED Feldman verification! DKG ABORTED — "
          "communications may have been tampered with or the dealer is malicious.");
    }

    this->cli_driver->print_info("Share from escrow " + sender_id +
                                  " verified successfully.");

    // Accumulate into final share
    final_share = (final_share + received_share) % DL_Q;
  }

  // Ensure positive
  if (final_share.IsNegative()) {
    final_share += DL_Q;
  }

  // ===================== Step 5: Compute keys + send completion =====================
  this->EG_secret_key_i = final_share;
  // This is the public verification key for this escrow's *final* Shamir
  // share z_i. It must match the exponent used in PartialDecrypt's ZKP.
  this->EG_public_key_i = CryptoPP::ModularExponentiation(
      DL_G, this->EG_secret_key_i, DL_P);

  // Send DKGComplete
  EscrowToServer_DKGComplete_Message complete_msg;
  complete_msg.escrow_id = my_id;
  complete_msg.partial_pk = this->EG_public_key_i;
  std::vector<unsigned char> complete_data =
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &complete_msg);
  this->network_driver->send(complete_data);

  // Persist the final share and its verification key under this group ID. A
  // share for one group is never consulted for another group.
  SaveInteger(group_secret_path(this->escrow_config, group_id), this->EG_secret_key_i);
  SaveInteger(group_partial_public_path(this->escrow_config, group_id),
              this->EG_public_key_i);

  // Clear polynomial from memory
  this->dkg_polynomial.clear();
  this->cli_driver->print_success(
      "DKG complete for group " + group_id + "; its escrow share was saved.");
}

/**
 * Handle partial decryption of a flagged message.
 */
void EscrowClient::HandleDecrypt(std::string _) {
  this->cli_driver->print_info("Connecting to server at " + escrow_config.server_ip + ":" + std::to_string(escrow_config.server_port));
  
  try {
    try {
      this->network_driver->disconnect();
    } catch (...) {
    }
    this->network_driver = std::make_shared<NetworkDriverImpl>();
    this->network_driver->connect(escrow_config.server_ip, escrow_config.server_port);
    auto [aes_key, hmac_key] = this->HandleServerKeyExchange();

    EscrowToServer_DecryptReady_Message ready_msg;
    ready_msg.escrow_id = escrow_config.escrow_id;
    ready_msg.auth_tag = escrow_auth_tag(this->crypto_driver,
                                         ready_msg.escrow_id, "decrypt");
    std::vector<unsigned char> ready_data =
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &ready_msg);
    this->network_driver->send(ready_data);

    auto [request_data, request_valid] = this->crypto_driver->decrypt_and_verify(
        aes_key, hmac_key, this->network_driver->read());
    if (!request_valid) {
      throw std::runtime_error("Invalid HMAC on decryption request.");
    }
    ServerToEscrow_DecryptRequest_Message request_msg;
    request_msg.deserialize(request_data);

    if (request_msg.group_id.empty()) {
      throw std::runtime_error("Decryption request does not name a group.");
    }
    if (request_msg.requester_dh_pub.empty()) {
      throw std::runtime_error("Decryption request is missing the requester's key.");
    }
    auto [mesh_aes, mesh_hmac] = escrow_mesh_keys(this->crypto_driver);
    (void)mesh_aes;
    if (request_msg.requester_mesh_mac.empty() ||
        !this->crypto_driver->HMAC_verify(
            mesh_hmac,
            escrow_flag_context(request_msg.requester_id, request_msg.group_id,
                                request_msg.requester_dh_pub),
            request_msg.requester_mesh_mac)) {
      throw std::runtime_error("Decryption request was not authorized by an escrow.");
    }
    // The escrow independently selects the only share authorised for the
    // supplied group. The server cannot substitute a different group's share.
    LoadInteger(group_secret_path(this->escrow_config, request_msg.group_id),
                this->EG_secret_key_i);
    LoadInteger(group_partial_public_path(this->escrow_config,
                                          request_msg.group_id),
                this->EG_public_key_i);
    auto [partial, proof] = VoteClient::PartialDecrypt(
        request_msg.ciphertext, this->EG_public_key_i, this->EG_secret_key_i);
    Escrow_PartialDecryption_Message partial_msg;
    partial_msg.escrow_id = escrow_config.escrow_id;
    partial_msg.group_id = request_msg.group_id;
    partial_msg.dec = partial;
    partial_msg.zkp = proof;

    // Wrap the partial under a fresh DH secret shared with the requesting
    // escrow. The server relays this blob but cannot read it, so it never
    // learns the partial (and therefore never recovers the group key).
    std::vector<unsigned char> partial_plain;
    partial_msg.serialize(partial_plain);
    auto [dh, my_priv, my_pub] = this->crypto_driver->DH_initialize();
    CryptoPP::SecByteBlock shared = this->crypto_driver->DH_generate_shared_key(
        dh, my_priv, request_msg.requester_dh_pub);
    CryptoPP::SecByteBlock wrap_key = this->crypto_driver->AES_generate_key(shared);
    CryptoPP::SecByteBlock wrap_hmac = this->crypto_driver->HMAC_generate_key(shared);
    auto [blob, blob_iv] =
        this->crypto_driver->AES_encrypt(wrap_key, chvec2str(partial_plain));

    EscrowToServer_EncryptedPartial_Message response_msg;
    response_msg.from_id = escrow_config.escrow_id;
    response_msg.group_id = request_msg.group_id;
    response_msg.responder_dh_pub = my_pub;
    response_msg.iv = byteblock_to_string(blob_iv);
    response_msg.ciphertext = blob;
    response_msg.mac = this->crypto_driver->HMAC_generate(
        wrap_hmac, encrypted_partial_context(
                       response_msg.from_id, response_msg.group_id,
                       request_msg.requester_dh_pub,
                       response_msg.responder_dh_pub, response_msg.iv,
                       response_msg.ciphertext));
    std::vector<unsigned char> response_data =
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response_msg);
    this->network_driver->send(response_data);
    this->network_driver->disconnect();
    this->cli_driver->print_success("Decryption complete! Encrypted partial sent to server.");
  } catch (const std::exception &e) {
    this->cli_driver->print_warning(e.what());
  }
}

/**
 * Flag a group for decryption. This escrow asks the server to gather threshold
 * partial decryptions — each encrypted to us — then recovers the group AES key
 * and decrypts the group's stored messages locally. The server never sees the
 * key or any plaintext.
 */
void EscrowClient::HandleFlag(std::string input) {
  std::vector<std::string> parts = string_split(input, ' ');
  if (parts.size() != 2 || parts[1].empty()) {
    this->cli_driver->print_left("Usage: flag <group-id>");
    return;
  }
  const std::string group_id = parts[1];

  try {
    try {
      this->network_driver->disconnect();
    } catch (...) {
    }
    this->network_driver = std::make_shared<NetworkDriverImpl>();
    this->network_driver->connect(escrow_config.server_ip,
                                  escrow_config.server_port);
    auto [aes_key, hmac_key] = this->HandleServerKeyExchange();

    // Ephemeral DH keypair used to receive every responder's encrypted partial.
    auto [dh, my_priv, my_pub] = this->crypto_driver->DH_initialize();

    EscrowToServer_FlagGroup_Message flag_msg;
    flag_msg.escrow_id = this->escrow_config.escrow_id;
    flag_msg.group_id = group_id;
    flag_msg.requester_dh_pub = my_pub;
    auto [mesh_aes, mesh_hmac] = escrow_mesh_keys(this->crypto_driver);
    (void)mesh_aes;
    flag_msg.mesh_mac = this->crypto_driver->HMAC_generate(
        mesh_hmac, escrow_flag_context(flag_msg.escrow_id, flag_msg.group_id,
                                       flag_msg.requester_dh_pub));
    flag_msg.auth_tag = escrow_auth_tag(this->crypto_driver,
                                        flag_msg.escrow_id, "flag",
                                        escrow_flag_context(
                                            flag_msg.escrow_id,
                                            flag_msg.group_id,
                                            flag_msg.requester_dh_pub));
    std::vector<unsigned char> flag_data =
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &flag_msg);
    this->network_driver->send(flag_data);
    this->cli_driver->print_info(
        "Flag sent for group " + group_id + "; waiting for threshold escrows.");

    // The server blocks until it has THRESHOLD_T encrypted partials, then sends
    // them together with the group's stored ciphertexts.
    auto [bundle_data, bundle_valid] = this->crypto_driver->decrypt_and_verify(
        aes_key, hmac_key, this->network_driver->read());
    if (!bundle_valid) {
      throw std::runtime_error("Invalid HMAC on partial bundle.");
    }
    ServerToEscrow_PartialBundle_Message bundle;
    bundle.deserialize(bundle_data);
    this->network_driver->disconnect();

    // Contribute our own partial locally so the threshold counts us as one of
    // the t decryptors (server only gathered t-1 from others).
    std::vector<Escrow_PartialDecryption_Message> partials;
    {
      CryptoPP::Integer my_sk, my_pk;
      LoadInteger(group_secret_path(this->escrow_config, group_id), my_sk);
      LoadInteger(group_partial_public_path(this->escrow_config, group_id), my_pk);
      auto [my_partial, my_proof] =
          VoteClient::PartialDecrypt(bundle.ciphertext, my_pk, my_sk);
      Escrow_PartialDecryption_Message mine;
      mine.escrow_id = this->escrow_config.escrow_id;
      mine.group_id = group_id;
      mine.dec = my_partial;
      mine.zkp = my_proof;
      partials.push_back(mine);
    }

    // Decrypt each relayed partial, verify its ZKP against the escrow's partial
    // public key, and collect the valid ones.
    for (const auto &entry : bundle.partials) {
      if (entry.from_id == this->escrow_config.escrow_id) {
        continue; // never double-count our own share
      }
      CryptoPP::SecByteBlock responder_pub =
          string_to_byteblock(entry.responder_dh_pub);
      CryptoPP::SecByteBlock shared =
          this->crypto_driver->DH_generate_shared_key(dh, my_priv, responder_pub);
      CryptoPP::SecByteBlock wrap_key =
          this->crypto_driver->AES_generate_key(shared);
      CryptoPP::SecByteBlock wrap_hmac =
          this->crypto_driver->HMAC_generate_key(shared);
      CryptoPP::SecByteBlock iv = string_to_byteblock(entry.iv);

      if (!this->crypto_driver->HMAC_verify(
              wrap_hmac,
              encrypted_partial_context(entry.from_id, group_id, my_pub,
                                        responder_pub, entry.iv,
                                        entry.ciphertext),
              entry.mac)) {
        this->cli_driver->print_warning(
            "Discarded unauthenticated partial from escrow " + entry.from_id + ".");
        continue;
      }

      std::string partial_plain;
      try {
        partial_plain =
            this->crypto_driver->AES_decrypt(wrap_key, iv, entry.ciphertext);
      } catch (...) {
        this->cli_driver->print_warning(
            "Could not decrypt partial from escrow " + entry.from_id + "; skipping.");
        continue;
      }
      std::vector<unsigned char> partial_bytes = str2chvec(partial_plain);
      Escrow_PartialDecryption_Message pd;
      pd.deserialize(partial_bytes);

      if (pd.escrow_id != entry.from_id || pd.group_id != group_id ||
          pd.dec.aggregate_ciphertext.a != bundle.ciphertext.a ||
          pd.dec.aggregate_ciphertext.b != bundle.ciphertext.b) {
        this->cli_driver->print_warning(
            "Partial from escrow " + entry.from_id +
            " is for a different ciphertext; skipping.");
        continue;
      }
      if (!VoteClient::VerifyPartialDecryptZKP(pd, entry.partial_pk)) {
        this->cli_driver->print_warning(
            "ZKP from escrow " + entry.from_id + " failed; skipping.");
        continue;
      }
      partials.push_back(pd);
    }

    if (partials.size() < THRESHOLD_T) {
      throw std::runtime_error("Received fewer than the threshold of valid partials.");
    }

    // Recover the group key and turn it back into the group's AES/HMAC subkeys.
    CryptoPP::Integer recovered =
        VoteClient::CombineResults(bundle.ciphertext, partials);
    CryptoPP::SecByteBlock secret = integer_to_byteblock(recovered);
    CryptoPP::SecByteBlock group_aes = this->crypto_driver->AES_generate_key(secret);
    CryptoPP::SecByteBlock group_hmac = this->crypto_driver->HMAC_generate_key(secret);

    this->cli_driver->print_success(
        "Recovered group key for " + group_id + "; decrypting " +
        std::to_string(bundle.messages.size()) + " message(s).");

    std::map<std::string, CryptoPP::RSA::PublicKey> signing_keys;
    for (auto &certificate : bundle.sender_certificates) {
      std::vector<unsigned char> certificate_to_verify =
          concat_string_and_two_rsakeys(certificate.id,
                                        certificate.verification_key,
                                        certificate.encryption_key);
      if (!this->crypto_driver->RSA_verify(
              this->RSA_server_verification_key, certificate_to_verify,
              certificate.server_signature)) {
        this->cli_driver->print_warning(
            "Discarded invalid certificate in the escrow message bundle.");
        continue;
      }
      signing_keys.emplace(certificate.id, certificate.verification_key);
    }

    // Verify and decrypt every stored message locally, skipping any that fail.
    for (const auto &m : bundle.messages) {
      if (!this->crypto_driver->HMAC_verify(
              group_hmac, group_id + m.sender_id + m.iv + m.ciphertext, m.mac)) {
        this->cli_driver->print_warning(
            "Message " + std::to_string(m.message_id) + " from " + m.sender_id +
            " failed HMAC verification; skipping.");
        continue;
      }
      auto sender_key = signing_keys.find(m.sender_id);
      if (sender_key == signing_keys.end() ||
          !this->crypto_driver->RSA_verify(
              sender_key->second,
              group_message_signature_input(group_id, m.sender_id, m.iv,
                                            m.ciphertext, m.mac),
              m.signature)) {
        this->cli_driver->print_warning(
            "Message " + std::to_string(m.message_id) + " from " +
            m.sender_id + " failed signature verification; skipping.");
        continue;
      }
      std::string plaintext = this->crypto_driver->AES_decrypt(
          group_aes, string_to_byteblock(m.iv), m.ciphertext);
      this->cli_driver->print_success(
          "[" + std::to_string(m.message_id) + "] " + m.sender_id + ": " + plaintext);
    }
  } catch (const std::exception &e) {
    this->cli_driver->print_warning(e.what());
  }
}
