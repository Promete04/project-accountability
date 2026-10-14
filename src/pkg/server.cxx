#include <cmath>
#include <algorithm>
#include <chrono>
#include <cryptopp/secblock.h>
#include <cstdlib>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <utility>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <vector>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/escrow_security.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"
#include "../../include/pkg/vote.hpp"

namespace {

constexpr size_t kMaxIdentifierBytes = 128;
constexpr size_t kMaxGroupMembers = 64;
constexpr size_t kMaxEnvelopeBytes = 8192;
constexpr size_t kMaxChatCiphertextBytes = 64 * 1024;
// RSA_KEYSIZE is 3072 bits, so RSA-PSS signatures are 384 bytes. Keep a small
// allowance while bounding malformed network input.
constexpr size_t kMaxChatSignatureBytes = 512;

void require_message_type(std::vector<unsigned char> &data,
                          MessageType::T expected,
                          const char *context) {
  if (get_message_type(data) != expected)
    throw std::runtime_error(std::string("Unexpected message type for ") + context + ".");
}

std::string escrow_flag_context(const std::string &escrow_id,
                                const std::string &group_id,
                                const CryptoPP::SecByteBlock &requester_dh_pub) {
  return "escrow-flag-v1|" + escrow_id + "|" + group_id + "|" +
         byteblock_to_string(requester_dh_pub);
}

bool verify_escrow_auth_tag(std::shared_ptr<CryptoDriver> crypto_driver,
                            const std::string &escrow_id,
                            const std::string &purpose,
                            const std::string &tag,
                            const std::string &binding = "") {
  if (!is_authorized_escrow(escrow_id))
    return false;
  const std::string &secret = escrow_server_auth_secret(escrow_id);
  const CryptoPP::SecByteBlock material(
      reinterpret_cast<const CryptoPP::byte *>(secret.data()), secret.size());
  const CryptoPP::SecByteBlock key =
      crypto_driver->HMAC_generate_key(material);
  return crypto_driver->HMAC_verify(
      key, "escrow-auth-v1|" + purpose + "|" + escrow_id + "|" + binding,
      tag);
}

} // namespace

/**
 * Constructor
 */
ServerClient::ServerClient(ServerConfig server_config) {
  this->server_config = server_config;
  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();

  // Initialize database driver.
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(server_config.server_db_path);
  this->db_driver->init_tables();

  // Load server keys.
  try {
    LoadRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find server keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_signing_key = keys.first;
    this->RSA_verification_key = keys.second;
    SaveRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    SaveRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  }

}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ServerClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&ServerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Start REPL
  REPLDriver<ServerClient> repl = REPLDriver<ServerClient>(this);
  repl.add_action("reset", "reset", &ServerClient::Reset);
  repl.add_action("users", "users", &ServerClient::Users);
  repl.run();
}

/**
 * Reserve a group ID for its creator and start its DKG. The user-facing group
 * creation request is the only path that invokes this method.
 */
bool ServerClient::StartGroupDKG(const std::string &group_id,
                                 const std::string &creator_id, bool &ready,
                                 std::string &detail) {
  ready = false;
  if (group_id.empty()) {
    detail = "A group ID is required.";
    return false;
  }
  std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
  if (this->dkg_state.active) {
    if (this->dkg_state.group_id == group_id &&
        this->dkg_state.creator_id == creator_id) {
      detail = "Escrow DKG is already in progress for this group.";
      return true;
    }
    detail = "A DKG is already active for another group.";
    return false;
  }
  GroupDKGRow existing;
  if (this->db_driver->get_group_dkg(group_id, existing)) {
    if (existing.creator_id != creator_id) {
      detail = "This group ID is already reserved by another creator.";
      return false;
    }
    ready = true;
    detail = "Escrow DKG is ready; submitting the encrypted group setup.";
    return true;
  }
  this->dkg_state.reset(group_id, creator_id, THRESHOLD_N);
  detail = "Escrow DKG started. Escrows must now run 'keygen <group-id>'; repeat group-create once it completes.";
  this->cli_driver->print_info("Group creation requested by " + creator_id +
                               "; waiting for " +
                               std::to_string(THRESHOLD_N) +
                               " escrows to create the key for group " +
                               group_id + ".");
  return true;
}

/**
 * Reset database
 *
 */
void ServerClient::Reset(std::string _) {
  this->cli_driver->print_info("Erasing users!");
  this->db_driver->reset_tables();
}

/**
 * Prints all usernames
 */
void ServerClient::Users(std::string _) {
  this->cli_driver->print_info("Printing users!");
  std::vector<std::string> usernames = this->db_driver->get_users();
  if (usernames.size() == 0) {
    this->cli_driver->print_info("No registered users!");
    return;
  }
  for (std::string username : usernames) {
    this->cli_driver->print_info(username);
  }
}

/**
 * @brief This is the logic for the listener thread
 */
void ServerClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&ServerClient::HandleConnection, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle keygen and handle either logins or registrations.
 */
bool ServerClient::HandleConnection(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  try {
    // Key exchange
    auto [aes_key, hmac_key] =
        this->HandleKeyExchange(network_driver, crypto_driver);

    // Determine login or register and act accordingly
    auto [id_data, id_valid] = crypto_driver->decrypt_and_verify(
        aes_key, hmac_key, network_driver->read());
    if (!id_valid) {
      throw std::runtime_error("Invalid HMAC on ID prompt message.");
    }
    MessageType::T msg_type = get_message_type(id_data);
    if (msg_type == MessageType::EscrowToServer_Keygen_Message) {
      EscrowToServer_Keygen_Message k_msg;
      k_msg.deserialize(id_data);
      if (k_msg.group_id.empty() ||
          k_msg.group_id.size() > kMaxIdentifierBytes) {
        throw std::runtime_error("Rejected escrow keygen request with invalid group ID.");
      }
      if (!verify_escrow_auth_tag(crypto_driver, k_msg.escrow_id, "keygen",
                                  k_msg.auth_tag, k_msg.group_id)) {
        throw std::runtime_error("Rejected unauthenticated escrow keygen request.");
      }
      this->HandleDKG(network_driver, crypto_driver, k_msg.escrow_id,
                      k_msg.group_id,
                               std::pair(aes_key, hmac_key));
    } else if (msg_type == MessageType::EscrowToServer_DecryptReady_Message) {
      EscrowToServer_DecryptReady_Message ready_msg;
      ready_msg.deserialize(id_data);
      if (!verify_escrow_auth_tag(crypto_driver, ready_msg.escrow_id,
                                  "decrypt", ready_msg.auth_tag)) {
        throw std::runtime_error("Rejected unauthenticated escrow decrypt request.");
      }
      this->HandleEscrowDecryption(network_driver, crypto_driver,
                                   std::pair(aes_key, hmac_key),
                                   ready_msg.escrow_id);
    } else if (msg_type == MessageType::EscrowToServer_FlagGroup_Message) {
      EscrowToServer_FlagGroup_Message flag_msg;
      flag_msg.deserialize(id_data);
      if (!verify_escrow_auth_tag(crypto_driver, flag_msg.escrow_id, "flag",
                                  flag_msg.auth_tag,
                                  escrow_flag_context(
                                      flag_msg.escrow_id, flag_msg.group_id,
                                      flag_msg.requester_dh_pub))) {
        throw std::runtime_error("Rejected unauthenticated escrow flag request.");
      }
      this->HandleFlagGroup(network_driver, crypto_driver,
                            std::pair(aes_key, hmac_key), flag_msg);
    } else if (msg_type == MessageType::UserToServer_IDPrompt_Message) {

      UserToServer_IDPrompt_Message id_msg;
      id_msg.deserialize(id_data);
      if (id_msg.id.empty() || id_msg.id.size() > kMaxIdentifierBytes) {
        throw std::runtime_error("Invalid account identifier length.");
      }

      if (id_msg.new_user) {
        this->HandleRegister(network_driver, crypto_driver, id_msg.id,
                             std::pair(aes_key, hmac_key));
      } else {
        this->HandleLogin(network_driver, crypto_driver, id_msg.id,
                          std::pair(aes_key, hmac_key));
      }
    } else {
      throw std::runtime_error("Unexpected initial message type.");
    }

    // Disconnect and return
    network_driver->disconnect();
    return true;
  } catch (std::exception &e) {
    this->cli_driver->print_warning("Error in connection handler: " +
                                    std::string(e.what()));
    network_driver->disconnect();
    return false;
  }
}

/**
 * Handle DKG protocol for a single escrow connection.
 * Multiple threads (one per escrow) run this concurrently.
 * Barriers synchronize each phase via dkg_state.mtx + dkg_state.cv.
 */
void ServerClient::HandleDKG(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::string requested_group_id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {

  auto [aes_key, hmac_key] = keys;

  std::string dkg_group_id;
  std::string dkg_creator_id;
  std::uint64_t dkg_generation;
  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (!this->dkg_state.active) {
      throw std::runtime_error("No group creation is waiting for escrow DKG.");
    }
    if (this->dkg_state.group_id != requested_group_id) {
      throw std::runtime_error("Escrow keygen group ID does not match the active DKG.");
    }
    dkg_group_id = this->dkg_state.group_id;
    dkg_creator_id = this->dkg_state.creator_id;
    dkg_generation = this->dkg_state.generation;
  }

  // We never proceed without all N escrows, but a stalled or failed peer must
  // not hang the others — or leave dkg_state active forever, which would block
  // every future group creation. Each barrier is therefore bounded by a timeout,
  // and any failure aborts the whole DKG and frees the slot.
  constexpr auto kBarrierTimeout = std::chrono::seconds(60);

  // Wake every waiter and free the slot so a fresh DKG can start. Caller holds
  // dkg_state.mtx.
  auto abort_dkg = [&]() {
    if (this->dkg_state.generation != dkg_generation)
      return;
    this->dkg_state.aborted = true;
    this->dkg_state.active = false;
    this->dkg_state.finalizing = false;
    this->dkg_state.cv.notify_all();
  };

  // Wait for `done` under an already-held lock, bounded by the barrier timeout
  // and short-circuited if another thread aborted the DKG.
  auto barrier_wait = [&](std::unique_lock<std::mutex> &lock,
                          const std::function<bool()> &done) {
    bool ok = this->dkg_state.cv.wait_for(lock, kBarrierTimeout, [&] {
      return this->dkg_state.generation != dkg_generation ||
             this->dkg_state.aborted || !this->dkg_state.active || done();
    });
    if (!ok) {
      abort_dkg();
      throw std::runtime_error("DKG timed out waiting for all escrows.");
    }
    if (this->dkg_state.generation != dkg_generation) {
      throw std::runtime_error("DKG was superseded by a newer round.");
    }
    if (this->dkg_state.aborted || !this->dkg_state.active) {
      throw std::runtime_error("DKG aborted because another escrow failed.");
    }
  };

  try {

  this->cli_driver->print_info("Escrow " + id + " connected for DKG for group " +
                               dkg_group_id + ".");

  // Register this escrow
  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (this->dkg_state.generation != dkg_generation)
      throw std::runtime_error("DKG was superseded by a newer round.");
    if (!is_authorized_escrow(id))
      throw std::runtime_error("Escrow is not in the configured DKG roster.");
    if (std::find(this->dkg_state.escrow_ids.begin(),
                  this->dkg_state.escrow_ids.end(), id) !=
        this->dkg_state.escrow_ids.end()) {
      throw std::runtime_error("Escrow " + id + " has already joined this DKG.");
    }
    if (this->dkg_state.escrow_ids.size() >=
        static_cast<size_t>(this->dkg_state.expected_count)) {
      throw std::runtime_error("The configured escrow roster is already full.");
    }
    this->dkg_state.escrow_ids.push_back(id);
    this->dkg_state.cv.notify_all();
    // Wait until all N escrows have registered
    barrier_wait(lock, [&]{
      return (int)this->dkg_state.escrow_ids.size() == this->dkg_state.expected_count;
    });
  }

  // Send DKGStart to this escrow
  ServerToEscrow_DKGStart_Message start_msg;
  start_msg.group_id = dkg_group_id;
  start_msg.n = THRESHOLD_N;
  start_msg.t = THRESHOLD_T;
  start_msg.escrow_ids.assign(authorized_escrow_ids().begin(),
                               authorized_escrow_ids().end());
  std::vector<unsigned char> start_data =
      crypto_driver->encrypt_and_tag(aes_key, hmac_key, &start_msg);
  network_driver->send(start_data);

  // ===================== BARRIER 1: Commitments =====================
  // Receive this escrow's commitment
  auto [commit_data, commit_valid] = crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, network_driver->read());
  if (!commit_valid) {
    throw std::runtime_error("Invalid HMAC on DKG commitment from escrow " + id);
  }
  EscrowToServer_DKGCommitment_Message commit_msg;
  require_message_type(commit_data,
                       MessageType::EscrowToServer_DKGCommitment_Message,
                       "DKG commitment");
  commit_msg.deserialize(commit_data);
  if (commit_msg.escrow_id != id || commit_msg.commitment.dealer_id != id ||
      commit_msg.commitment.commitments.size() != static_cast<size_t>(THRESHOLD_T)) {
    throw std::runtime_error("Malformed DKG commitment identity or degree.");
  }

  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (this->dkg_state.generation != dkg_generation)
      throw std::runtime_error("DKG was superseded by a newer round.");
    this->dkg_state.commitments[id] = commit_msg.commitment;
    this->dkg_state.cv.notify_all();
    barrier_wait(lock, [&]{
      return (int)this->dkg_state.commitments.size() == this->dkg_state.expected_count;
    });
  }

  // Send all commitments to this escrow
  ServerToEscrow_DKGAllCommitments_Message all_commit_msg;
  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (this->dkg_state.generation != dkg_generation ||
        this->dkg_state.aborted || !this->dkg_state.active) {
      throw std::runtime_error("DKG was aborted before commitments were delivered.");
    }
    for (const auto &[eid, fc] : this->dkg_state.commitments) {
      all_commit_msg.all_commitments.push_back(fc);
    }
  }
  std::vector<unsigned char> all_commit_data =
      crypto_driver->encrypt_and_tag(aes_key, hmac_key, &all_commit_msg);
  network_driver->send(all_commit_data);

  this->cli_driver->print_info("Barrier 1 passed: all commitments collected for escrow " + id);

  // ===================== BARRIER 2: escrow-only encrypted shares =====================
  // Shares are protected end-to-end by the pre-provisioned escrow mesh key.
  // The server only stores and relays their opaque AES-CBC/HMAC envelopes.
  // Receive this escrow's share bundle
  auto [share_data, share_valid] = crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, network_driver->read());
  if (!share_valid) {
    throw std::runtime_error("Invalid HMAC on DKG share bundle from escrow " + id);
  }
  EscrowToServer_DKGShareBundle_Message share_msg;
  require_message_type(share_data,
                       MessageType::EscrowToServer_DKGShareBundle_Message,
                       "DKG share bundle");
  share_msg.deserialize(share_data);
  if (share_msg.from_id != id ||
      share_msg.shares.size() != static_cast<size_t>(THRESHOLD_N - 1)) {
    throw std::runtime_error("Malformed DKG share bundle.");
  }
  std::set<std::string> recipients;
  for (const auto &share : share_msg.shares) {
    if (share.from_id != id || share.to_id == id ||
        !is_authorized_escrow(share.to_id) || share.iv.empty() ||
        share.ciphertext.empty() || share.mac.empty() ||
        !recipients.insert(share.to_id).second) {
      throw std::runtime_error("Invalid DKG share envelope metadata.");
    }
  }

  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (this->dkg_state.generation != dkg_generation)
      throw std::runtime_error("DKG was superseded by a newer round.");
    this->dkg_state.share_bundles[id] = share_msg.shares;
    this->dkg_state.cv.notify_all();
    barrier_wait(lock, [&]{
      return (int)this->dkg_state.share_bundles.size() == this->dkg_state.expected_count;
    });
  }

  // Deliver only the shares addressed to this escrow
  ServerToEscrow_DKGShareDelivery_Message share_delivery_msg;
  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (this->dkg_state.generation != dkg_generation ||
        this->dkg_state.aborted || !this->dkg_state.active) {
      throw std::runtime_error("DKG was aborted before shares were delivered.");
    }
    for (const auto &[sender_id, shares] : this->dkg_state.share_bundles) {
      for (const auto &s : shares) {
        if (s.to_id == id) {
          share_delivery_msg.shares.push_back(s);
        }
      }
    }
  }
  std::vector<unsigned char> share_delivery_data =
      crypto_driver->encrypt_and_tag(aes_key, hmac_key, &share_delivery_msg);
  network_driver->send(share_delivery_data);

  this->cli_driver->print_info("Barrier 2 passed: shares distributed for escrow " + id);

  // ===================== BARRIER 3: Completion =====================
  // Receive this escrow's DKGComplete
  auto [complete_data, complete_valid] = crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, network_driver->read());
  if (!complete_valid) {
    throw std::runtime_error("Invalid HMAC on DKG complete from escrow " + id);
  }
  EscrowToServer_DKGComplete_Message complete_msg;
  require_message_type(complete_data,
                       MessageType::EscrowToServer_DKGComplete_Message,
                       "DKG completion");
  complete_msg.deserialize(complete_data);
  if (complete_msg.escrow_id != id || complete_msg.partial_pk <= 0) {
    throw std::runtime_error("Malformed DKG completion message.");
  }

  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (this->dkg_state.generation != dkg_generation)
      throw std::runtime_error("DKG was superseded by a newer round.");
    this->dkg_state.partial_pks[id] = complete_msg.partial_pk;
    this->dkg_state.cv.notify_all();
    barrier_wait(lock, [&]{
      return (int)this->dkg_state.partial_pks.size() == this->dkg_state.expected_count;
    });
  }

  // One of the final barrier participants persists the immutable, group-scoped
  // key material. Keep DKG marked active until that transaction commits so a
  // second `keygen` cannot race it and reuse the same group ID.
  bool persist_result = false;
  CryptoPP::Integer pk;
  std::map<std::string, CryptoPP::Integer> partial_pks;
  {
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    if (this->dkg_state.generation != dkg_generation) {
      throw std::runtime_error("DKG was superseded by a newer round.");
    }
    if (this->dkg_state.active && !this->dkg_state.finalizing) {
      // Feldman constant commitments define the group public key g^F(0).
      // The separately reported partial_pks are g^{F(i)} and are retained for
      // validating each escrow's Chaum-Pedersen partial-decryption proof.
      pk = CryptoPP::Integer::One();
      for (const auto &[eid, commitment] : this->dkg_state.commitments) {
        if (commitment.commitments.empty()) {
          throw std::runtime_error("DKG completion is missing a Feldman commitment.");
        }
        pk = CryptoPP::ModularMultiplication(pk, commitment.commitments[0], DL_P);
      }
      partial_pks = this->dkg_state.partial_pks;
      this->dkg_state.finalizing = true;
      persist_result = true;
    }
  }
  if (persist_result) {
    const bool stored = this->db_driver->store_group_dkg({dkg_group_id,
                                                          dkg_creator_id, pk},
                                                          partial_pks);
    {
      std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
      if (this->dkg_state.generation == dkg_generation) {
        this->dkg_state.active = false;
        this->dkg_state.finalizing = false;
        this->dkg_state.cv.notify_all();
      }
    }
    if (!stored) {
      throw std::runtime_error("Could not persist the group threshold key.");
    }
  }
  this->cli_driver->print_success(
      "DKG complete for escrow " + id + " for group " + dkg_group_id + ".");

  } catch (...) {
    // Any failure (timeout, bad HMAC, another escrow aborting) frees the slot
    // and wakes the remaining escrow threads so none hangs.
    std::unique_lock<std::mutex> lock(this->dkg_state.mtx);
    abort_dkg();
    throw;
  }
}

/**
 * Relay one encrypted partial decryption for the active flag request. The
 * partial is encrypted to the requesting escrow, so the server only forwards
 * an opaque blob and never learns the group key.
 */
void ServerClient::HandleEscrowDecryption(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
    const std::string &escrow_id) {
  auto [aes_key, hmac_key] = keys;
  ElGamal_Ciphertext ciphertext;
  std::string group_id;
  std::string requester_id;
  CryptoPP::SecByteBlock requester_dh_pub;
  std::string requester_mesh_mac;
  {
    std::unique_lock<std::mutex> lock(this->pending_decryption.mtx);
    if (!this->pending_decryption.active) {
      throw std::runtime_error("No decryption request is currently active.");
    }
    ciphertext = this->pending_decryption.ciphertext;
    group_id = this->pending_decryption.group_id;
    requester_id = this->pending_decryption.requester_id;
    requester_dh_pub = this->pending_decryption.requester_dh_pub;
    requester_mesh_mac = this->pending_decryption.requester_mesh_mac;
  }

  // The requester contributes its own partial locally; a relayed partial from
  // the same escrow would double-count its share toward the threshold.
  if (escrow_id == requester_id) {
    throw std::runtime_error("The requesting escrow contributes its own partial locally.");
  }

  // Only escrows enrolled in this group's DKG may partially decrypt it. We look
  // up the partial public key up front so we can hand it to the requester for
  // ZKP verification (the server can no longer verify the proof itself).
  CryptoPP::Integer partial_pk;
  if (!this->db_driver->get_group_dkg_partial_key(group_id, escrow_id,
                                                   partial_pk)) {
    throw std::runtime_error("Decryption attempted by an escrow that is not in this group's DKG.");
  }

  ServerToEscrow_DecryptRequest_Message request_msg;
  request_msg.group_id = group_id;
  request_msg.ciphertext = ciphertext;
  request_msg.requester_id = requester_id;
  request_msg.requester_dh_pub = requester_dh_pub;
  request_msg.requester_mesh_mac = requester_mesh_mac;
  std::vector<unsigned char> request_data =
      crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request_msg);
  network_driver->send(request_data);

  auto [response_data, response_valid] = crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, network_driver->read());
  if (!response_valid) {
    throw std::runtime_error("Invalid HMAC on partial decryption response.");
  }
  EscrowToServer_EncryptedPartial_Message response_msg;
  require_message_type(response_data,
                       MessageType::EscrowToServer_EncryptedPartial_Message,
                       "encrypted partial");
  response_msg.deserialize(response_data);
  if (response_msg.from_id != escrow_id) {
    throw std::runtime_error("Escrow ID does not match its decryption response.");
  }
  if (response_msg.group_id != group_id) {
    throw std::runtime_error("Partial decryption is for a different group.");
  }
  if (response_msg.responder_dh_pub.empty() || response_msg.iv.size() != 16 ||
      response_msg.ciphertext.empty() || response_msg.mac.size() != 32) {
    throw std::runtime_error("Malformed encrypted partial response.");
  }

  EncryptedPartialEntry entry;
  entry.from_id = escrow_id;
  entry.partial_pk = partial_pk;
  entry.responder_dh_pub = byteblock_to_string(response_msg.responder_dh_pub);
  entry.iv = response_msg.iv;
  entry.ciphertext = response_msg.ciphertext;
  entry.mac = response_msg.mac;

  {
    std::unique_lock<std::mutex> lock(this->pending_decryption.mtx);
    if (!this->pending_decryption.active ||
        this->pending_decryption.group_id != group_id ||
        this->pending_decryption.requester_id != requester_id) {
      throw std::runtime_error("Decryption request is no longer active.");
    }
    if (!this->pending_decryption.encrypted_partials.emplace(escrow_id, entry).second) {
      throw std::runtime_error("Duplicate partial decryption from escrow " + escrow_id + ".");
    }
    this->pending_decryption.cv.notify_all();
  }
  this->cli_driver->print_info("Relayed encrypted partial from escrow " + escrow_id + ".");
}

/**
 * Coordinate an escrow-initiated group flag. The server gathers THRESHOLD_T
 * encrypted partials and the group's stored ciphertexts, then hands them to the
 * requesting escrow, which recovers the key and decrypts locally. The server
 * never sees a plaintext partial or the recovered group key.
 */
void ServerClient::HandleFlagGroup(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
    const EscrowToServer_FlagGroup_Message &flag_msg) {
  auto [aes_key, hmac_key] = keys;

  if (flag_msg.group_id.empty() ||
      flag_msg.group_id.size() > kMaxIdentifierBytes ||
      flag_msg.requester_dh_pub.empty() || flag_msg.mesh_mac.empty()) {
    throw std::runtime_error("Malformed escrow flag request.");
  }

  // A flag is only meaningful from an escrow enrolled in the group's DKG.
  CryptoPP::Integer requester_pk;
  if (!this->db_driver->get_group_dkg_partial_key(flag_msg.group_id,
                                                  flag_msg.escrow_id,
                                                  requester_pk)) {
    throw std::runtime_error("Flag requested by an escrow that is not in this group's DKG.");
  }

  GroupRow group;
  if (!this->db_driver->get_group(flag_msg.group_id, group)) {
    throw std::runtime_error("Flag requested for an unknown group.");
  }
  ElGamal_Ciphertext ciphertext;
  ciphertext.a = group.escrow_a;
  ciphertext.b = group.escrow_b;

  ServerToEscrow_PartialBundle_Message bundle;
  {
    std::unique_lock<std::mutex> lock(this->pending_decryption.mtx);
    if (this->pending_decryption.active) {
      throw std::runtime_error("A decryption request is already active.");
    }
    this->pending_decryption.active = true;
    this->pending_decryption.group_id = flag_msg.group_id;
    this->pending_decryption.requester_id = flag_msg.escrow_id;
    this->pending_decryption.ciphertext = ciphertext;
    this->pending_decryption.requester_dh_pub = flag_msg.requester_dh_pub;
    this->pending_decryption.requester_mesh_mac = flag_msg.mesh_mac;
    this->pending_decryption.encrypted_partials.clear();
    this->cli_driver->print_info(
        "Escrow " + flag_msg.escrow_id + " flagged group " + flag_msg.group_id +
        ": waiting for threshold escrow approval.");

    // The requester is itself an enrolled escrow and contributes its own partial
    // locally, so only THRESHOLD_T - 1 partials are needed from *other* escrows.
    // This preserves the true t-of-n threshold (requester + t-1 others).
    const size_t needed_from_others =
        THRESHOLD_T > 0 ? THRESHOLD_T - 1 : 0;

    // A stalled set of escrows must not pin the slot forever; bound the wait.
    constexpr auto kFlagTimeout = std::chrono::seconds(120);
    bool ready = this->pending_decryption.cv.wait_for(
        lock, kFlagTimeout, [&] {
          return this->pending_decryption.encrypted_partials.size() >= needed_from_others;
        });
    if (!ready) {
      this->pending_decryption.active = false;
      throw std::runtime_error("Flag timed out waiting for threshold escrows.");
    }
    for (const auto &[id, entry] : this->pending_decryption.encrypted_partials) {
      bundle.partials.push_back(entry);
    }
    this->pending_decryption.active = false;
  }

  bundle.group_id = flag_msg.group_id;
  bundle.ciphertext = ciphertext;
  std::set<std::string> certificate_senders;
  for (const auto &m : this->db_driver->get_group_messages(flag_msg.group_id)) {
    bundle.messages.push_back(
        {m.id, m.sender_id, m.iv, m.ciphertext, m.mac, m.signature});
    if (certificate_senders.insert(m.sender_id).second) {
      UserRow sender = this->db_driver->find_user(m.sender_id);
      if (!sender.certificate_data.empty()) {
        Certificate_Message certificate;
        std::vector<unsigned char> certificate_data =
            str2chvec(sender.certificate_data);
        certificate.deserialize(certificate_data);
        if (certificate.id == m.sender_id)
          bundle.sender_certificates.push_back(std::move(certificate));
      }
    }
  }

  std::vector<unsigned char> bundle_data =
      crypto_driver->encrypt_and_tag(aes_key, hmac_key, &bundle);
  network_driver->send(bundle_data);
  this->cli_driver->print_success(
      "Delivered encrypted partial bundle to escrow " + flag_msg.escrow_id + ".");
}

/**
 * Serve authenticated group-chat requests on one connection until the client
 * closes it (GroupClose or disconnect). Keeping the session open lets clients —
 * notably the TUI message poller — issue many requests without re-authenticating
 * on each one.
 */
void ServerClient::HandleGroupRequest(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, const std::string &user_id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  auto [aes_key, hmac_key] = keys;
  while (true) {
    std::vector<unsigned char> raw;
    try {
      raw = network_driver->read();
    } catch (const std::exception &) {
      return; // client disconnected — end the session
    }
    auto [request_data, request_valid] =
        crypto_driver->decrypt_and_verify(aes_key, hmac_key, raw);
    if (!request_valid)
      throw std::runtime_error("Invalid HMAC on group request.");
    if (get_message_type(request_data) ==
        MessageType::UserToServer_GroupClose_Message)
      return;
    this->HandleOneGroupRequest(network_driver, crypto_driver, user_id, keys,
                                request_data);
  }
}

/** Handle a single decrypted group-chat request (one request/response pair). */
void ServerClient::HandleOneGroupRequest(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, const std::string &user_id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
    std::vector<unsigned char> request_data) {
  auto [aes_key, hmac_key] = keys;
  MessageType::T type = get_message_type(request_data);

  // Answer group-membership from the authenticated session id only (a caller
  // can never enumerate another user's memberships).
  if (type == MessageType::UserToServer_GroupMembershipRequest_Message) {
    UserToServer_GroupMembershipRequest_Message request;
    request.deserialize(request_data);
    ServerToUser_GroupMembershipResponse_Message response;
    response.group_ids = this->db_driver->get_user_groups(user_id);
    auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
    network_driver->send(response_data);
    return;
  }

  // The directory is intentionally available only inside an authenticated
  // account session.  The claimed user_id in this request is ignored.
  if (type == MessageType::UserToServer_GetRegisteredUsers_Message) {
    UserToServer_GetRegisteredUsers_Message request;
    request.deserialize(request_data);
    ServerToUser_GetRegisteredUsers_Response_Message response;
    response.user_ids = this->db_driver->get_users();
    auto response_data =
        crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
    network_driver->send(response_data);
    return;
  }

  // Certificate request
  if (type == MessageType::UserToServer_CertificateRequest_Message) {

    UserToServer_CertificateRequest_Message request;
    request.deserialize(request_data);
    UserRow user = db_driver->find_user(request.user_id);
    ServerToUser_CertificateResponse_Message response;
    response.found = !user.certificate_data.empty();
    if (response.found) {
      std::vector<unsigned char> certificate_data = str2chvec(user.certificate_data);
      response.certificate.deserialize(certificate_data);
    }
    auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
    network_driver->send(response_data);
    return;
  }

  // Election key request
  if (type == MessageType::UserToServer_ElectionKeyRequest_Message) {
    UserToServer_ElectionKeyRequest_Message request;
    request.deserialize(request_data);
    ServerToUser_ElectionKeyResponse_Message response;
    response.group_id = request.group_id;
    GroupDKGRow dkg;
    response.available = this->db_driver->get_group_dkg(request.group_id, dkg);
    if (response.available) response.public_key = dkg.public_key;
    auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
    network_driver->send(response_data);
    return;
  }

  // DKG init
  if (type == MessageType::UserToServer_GroupDKGStart_Message) {
    UserToServer_GroupDKGStart_Message request;
    request.deserialize(request_data);
    ServerToUser_GroupDKGStatus_Message response;
    response.group_id = request.group_id;
    response.started = this->StartGroupDKG(request.group_id, user_id,
                                            response.ready, response.detail);
    auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key,
                                                         &response);
    network_driver->send(response_data);
    return;
  }

  // Group creation
  if (type == MessageType::UserToServer_GroupCreate_Message) {
    UserToServer_GroupCreate_Message request;
    request.deserialize(request_data);
    std::set<std::string> members(request.member_ids.begin(), request.member_ids.end());
    members.insert(user_id);
    GroupDKGRow dkg;
    std::string reason; // empty == accepted

    if (request.group_id.empty() || request.group_id.size() > kMaxIdentifierBytes)
      reason = "invalid group id";
    else if (request.member_ids.size() > kMaxGroupMembers)
      reason = "too many members";
    else if (!db_driver->get_group_dkg(request.group_id, dkg))
      reason = "no completed DKG for this group";
    else if (dkg.creator_id != user_id)
      reason = "DKG creator '" + dkg.creator_id + "' != requester '" + user_id + "'";

    if (reason.empty())
      for (const auto &member : members)
        if (member.empty() || member.size() > kMaxIdentifierBytes ||
            db_driver->find_user(member).user_id.empty()) {
          reason = "member not registered: '" + member + "'";
          break;
        }

    if (reason.empty()) {
      if (request.member_envelopes.size() != members.size())
        reason = "envelope count " +
                 std::to_string(request.member_envelopes.size()) + " != members " +
                 std::to_string(members.size());
      else if (request.escrow_envelope_a <= 0 || request.escrow_envelope_b <= 0)
        reason = "invalid escrow envelope";
      else if (request.creator_signature.empty())
        reason = "missing creator signature";
    }

    if (reason.empty()) {
      std::set<std::string> envelope_recipients;
      for (const auto &envelope : request.member_envelopes)
        if (envelope.recipient_id.empty() ||
            envelope.recipient_id.size() > kMaxIdentifierBytes ||
            envelope.wrapped_group_key.empty() ||
            envelope.wrapped_group_key.size() > kMaxEnvelopeBytes ||
            !members.count(envelope.recipient_id) ||
            !envelope_recipients.insert(envelope.recipient_id).second) {
          reason = "bad envelope for '" + envelope.recipient_id + "'";
          break;
        }
      if (reason.empty() && envelope_recipients != members)
        reason = "envelope recipients don't match members";
    }

    UserRow creator = db_driver->find_user(user_id);
    if (reason.empty() && creator.certificate_data.empty())
      reason = "creator has no certificate";
    if (reason.empty()) {
      Certificate_Message cert; auto cert_data = str2chvec(creator.certificate_data);
      cert.deserialize(cert_data);
      UserToServer_GroupCreate_Message unsigned_request = request;
      unsigned_request.creator_signature.clear();
      std::vector<unsigned char> to_verify; unsigned_request.serialize(to_verify);
      if (!crypto_driver->RSA_verify(cert.verification_key, to_verify,
                                     request.creator_signature))
        reason = "creator signature verification failed";
    }
    if (reason.empty()) {
      std::vector<std::string> ordered_members(members.begin(), members.end());
      std::sort(ordered_members.begin(), ordered_members.end());
      std::sort(request.member_envelopes.begin(), request.member_envelopes.end(),
                [](const auto &a, const auto &b) { return a.recipient_id < b.recipient_id; });
      GroupRow group{request.group_id, user_id, request.escrow_envelope_a,
                     request.escrow_envelope_b, request.creator_signature};
      std::vector<GroupEnvelopeRow> envelopes;
      for (const auto &e : request.member_envelopes) envelopes.push_back({e.recipient_id, e.wrapped_group_key});
      if (!db_driver->create_group(group, ordered_members, envelopes))
        reason = "db create_group failed (group id already exists?)";
    }
    const bool ok = reason.empty();
    if (!ok)
      this->cli_driver->print_warning("Group create rejected for '" +
                                      request.group_id + "': " + reason);
    ServerToUser_GroupResult_Message response;
    response.success = ok;
    response.detail = ok ? "Group created." : ("Group creation failed: " + reason);
    auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
    network_driver->send(response_data);
    return;
  }

  // Group message send
  if (type == MessageType::UserToServer_GroupSend_Message) {
    UserToServer_GroupSend_Message request;
    request.deserialize(request_data);
    const bool well_formed =
        request.group_id.size() <= kMaxIdentifierBytes &&
        request.iv.size() == 16 && !request.ciphertext.empty() &&
        request.ciphertext.size() <= kMaxChatCiphertextBytes &&
        request.mac.size() == 32 && !request.signature.empty() &&
        request.signature.size() <= kMaxChatSignatureBytes;
    const bool group_member =
        well_formed && db_driver->is_group_member(request.group_id, user_id);
    bool signature_valid = false;
    if (group_member) {
      UserRow sender = db_driver->find_user(user_id);
      if (!sender.certificate_data.empty()) {
        Certificate_Message certificate;
        std::vector<unsigned char> certificate_data =
            str2chvec(sender.certificate_data);
        certificate.deserialize(certificate_data);
        signature_valid = certificate.id == user_id &&
            crypto_driver->RSA_verify(
                certificate.verification_key,
                group_message_signature_input(
                    request.group_id, user_id, request.iv, request.ciphertext,
                    request.mac),
                request.signature);
      }
    }
    bool ok = group_member && signature_valid &&
        db_driver->add_group_message(request.group_id,
            {0, user_id, request.iv, request.ciphertext, request.mac,
             request.signature});
    ServerToUser_GroupResult_Message response;
    response.success = ok;
    response.detail = ok ? "Encrypted message stored."
                         : "Invalid group message, sender signature, or membership.";
    auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
    network_driver->send(response_data);
    return;
  }

  if (type == MessageType::UserToServer_GroupFetch_Message) {
    UserToServer_GroupFetch_Message request;
    request.deserialize(request_data);
    GroupEnvelopeRow envelope;
    if (!db_driver->get_group_envelope(request.group_id, user_id, envelope)) {
      ServerToUser_GroupResult_Message response;
      response.success = false;
      response.detail = "User is not a group member.";
      auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
      network_driver->send(response_data);
      return;
    }
    ServerToUser_GroupMessages_Message response;
    response.group_id = request.group_id;
    response.wrapped_group_key = envelope.wrapped_group_key;
    for (const auto &m : db_driver->get_group_messages(request.group_id, request.since_id))
      response.messages.push_back(
          {m.id, m.sender_id, m.iv, m.ciphertext, m.mac, m.signature});
    auto response_data = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &response);
    network_driver->send(response_data);
    return;
  }
  throw std::runtime_error("Unexpected group request.");
}

/**
 * Diffie-Hellman key exchange.
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ServerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver) {
  // Receive public value
  std::vector<unsigned char> data = network_driver->read();
  CryptoPP::SecByteBlock public_value;

  MessageType::T msg_type = get_message_type(data);

  if (msg_type == MessageType::UserToServer_DHPublicValue_Message) {
    UserToServer_DHPublicValue_Message user_msg;
    user_msg.deserialize(data);
    public_value = user_msg.public_value;
  } else if (msg_type == MessageType::EscrowToServer_DHPublicValue_Message) {
    EscrowToServer_DHPublicValue_Message escrow_msg;
    escrow_msg.deserialize(data);
    public_value = escrow_msg.public_value;
  } else {
    throw std::runtime_error("Unexpected message type during key exchange");
  }

  // Generate, sign and send
  auto [dh, server_priv, server_pub] = crypto_driver->DH_initialize();

  std::vector<unsigned char> server_msg_data;
  if (msg_type == MessageType::UserToServer_DHPublicValue_Message) {
    ServerToUser_DHPublicValue_Message server_msg;
    server_msg.server_public_value = server_pub;
    server_msg.user_public_value = public_value;
    std::vector<unsigned char> to_sign = concat_byteblocks(
        server_msg.server_public_value, server_msg.user_public_value);
    server_msg.server_signature =
        crypto_driver->RSA_sign(this->RSA_signing_key, to_sign);
    server_msg.serialize(server_msg_data);
  } else {
    ServerToEscrow_DHPublicValue_Message server_msg;
    server_msg.server_public_value = server_pub;
    server_msg.escrow_public_value = public_value;
    std::vector<unsigned char> to_sign = concat_byteblocks(
        server_msg.server_public_value, server_msg.escrow_public_value);
    server_msg.server_signature =
        crypto_driver->RSA_sign(this->RSA_signing_key, to_sign);
    server_msg.serialize(server_msg_data);
  }

  network_driver->send(server_msg_data);

  // Compute shared key and derive AES + HMAC keys
  CryptoPP::SecByteBlock shared_key =
      crypto_driver->DH_generate_shared_key(dh, server_priv, public_value);
  CryptoPP::SecByteBlock AES_key = crypto_driver->AES_generate_key(shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(shared_key);
  return {AES_key, HMAC_key};
}

/**
 * Log in the given user.
 */
void ServerClient::HandleLogin(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {

  SecByteBlock AES_key = keys.first;
  SecByteBlock HMAC_key = keys.second;

  UserRow user = this->db_driver->find_user(id);
  const bool known = !user.user_id.empty();

  // Basic password login: return the account's salt, then compare the client's
  // H(password || salt) response to the value stored at registration.
  ServerToUser_Salt_Message salt_msg;
  salt_msg.salt = known ? user.password_salt : "";
  network_driver->send(
      crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &salt_msg));

  auto [pass_msg_de, pass_valid] =
      crypto_driver->decrypt_and_verify(AES_key, HMAC_key,
                                        network_driver->read());
  UserToServer_HashedAndSaltedPassword_Message pass_msg;
  if (pass_valid) {
    require_message_type(pass_msg_de,
                         MessageType::UserToServer_HashedAndSaltedPassword_Message,
                         "password response");
    pass_msg.deserialize(pass_msg_de);
  }

  const bool auth_ok =
      known && pass_valid && pass_msg.hspw == user.password_hash;
  ServerToUser_GroupResult_Message result;
  result.success = auth_ok;
  result.detail = auth_ok ? "Login successful." : "Authentication failed.";
  network_driver->send(
      crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &result));
  if (!auth_ok) {
    this->cli_driver->print_info("Login rejected for '" + id + "'.");
    return;
  }

  this->HandleGroupRequest(network_driver, crypto_driver, id, keys);
}

/**
 * Register the given user.
 */
void ServerClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {

  SecByteBlock AES_key = keys.first;
  SecByteBlock HMAC_key = keys.second;

  UserRow existing_user = this->db_driver->find_user(id);
  const bool is_new = existing_user.user_id.empty();

  // The salt is public and unique per account; the password response stays in
  // the authenticated DH-derived channel.
  SecByteBlock salt_block = crypto_driver->png(SALT_SIZE);
  std::string salt = byteblock_to_string(salt_block);

  ServerToUser_Salt_Message salt_msg;
  salt_msg.salt = salt;
  network_driver->send(
      crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &salt_msg));

  auto [pass_msg_de, pass_valid] =
      crypto_driver->decrypt_and_verify(AES_key, HMAC_key,
                                        network_driver->read());
  UserToServer_HashedAndSaltedPassword_Message pass_msg;
  if (pass_valid) {
    require_message_type(pass_msg_de,
                         MessageType::UserToServer_HashedAndSaltedPassword_Message,
                         "registration password response");
    pass_msg.deserialize(pass_msg_de);
  }

  // Store precisely the salted hash supplied by the client. There is no pepper
  // or time-based second factor in this deliberately small protocol.
  const std::string password_hash = pass_valid ? pass_msg.hspw : "";
  const bool register_ok = is_new && pass_valid;
  ServerToUser_GroupResult_Message result;
  result.success = register_ok;
  result.detail =
      register_ok ? "Registration successful." : "Registration failed.";
  network_driver->send(
      crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &result));
  if (!register_ok) {
    this->cli_driver->print_info("Registration rejected for '" + id + "'.");
    return;
  }

  // Receive the user's verification key, and sign it to create a certificate.
  std::vector<unsigned char> vk_msg_en = network_driver->read();
  auto [vk_msg_de, vk_valid] =
      crypto_driver->decrypt_and_verify(AES_key, HMAC_key, vk_msg_en);

  if (!vk_valid) {
    throw std::runtime_error("VK msg couldn't be verified");
  }

  UserToServer_VerificationKey_Message vk_msg;
  require_message_type(vk_msg_de,
                       MessageType::UserToServer_VerificationKey_Message,
                       "verification-key response");
  vk_msg.deserialize(vk_msg_de);

  Certificate_Message cert_msg;
  cert_msg.id = id;
  cert_msg.verification_key = vk_msg.verification_key;

  cert_msg.encryption_key = vk_msg.encryption_key;
  std::vector<unsigned char> to_sign = concat_string_and_two_rsakeys(
      id, vk_msg.verification_key, vk_msg.encryption_key);
  cert_msg.server_signature =
      crypto_driver->RSA_sign(this->RSA_signing_key, to_sign);

  ServerToUser_IssuedCertificate_Message issued_cert_msg;
  issued_cert_msg.certificate = cert_msg;

  std::vector<unsigned char> issued_cert_en =
      crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &issued_cert_msg);

  try {
    network_driver->send(issued_cert_en);
  } catch (...) {
    throw std::runtime_error("Unexpected error while sending certificate");
  }

  // Store the user in the database.
  UserRow new_user;
  new_user.user_id = id;
  new_user.password_hash = password_hash;
  new_user.password_salt = salt;
  // Retained as an empty legacy database field so pre-existing SQLite files
  // remain readable; it is not part of authentication anymore.
  new_user.prg_seed = "";
  std::vector<unsigned char> certificate_data;
  cert_msg.serialize(certificate_data);
  new_user.certificate_data = chvec2str(certificate_data);
  this->db_driver->insert_user(new_user);
  this->HandleGroupRequest(network_driver, crypto_driver, id, keys);
}
