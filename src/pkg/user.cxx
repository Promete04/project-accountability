#include <chrono>
#include <cmath>
#include <cryptopp/integer.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/drivers/tui/tui_driver.hpp"
#include "../../include/pkg/user.hpp"
#include "../../include/pkg/vote.hpp"
#include "keyloaders.hpp"

/**
 * Constructor. Loads server public key.
 */
UserClient::UserClient(std::shared_ptr<NetworkDriver> network_driver,
                       std::shared_ptr<CryptoDriver> crypto_driver,
                       UserConfig user_config) {

  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->user_config = user_config;

  this->cli_driver->init();

  // Load server's key
  try {
    LoadRSAPublicKey(user_config.server_verification_key_path,
                     this->RSA_server_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    // this->cli_driver->print_warning("Error loading server keys; exiting");
    throw std::runtime_error("Client could not open server's keys.");
  }

  // Load keys
  try {
    LoadRSAPrivateKey(this->user_config.user_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(this->user_config.user_verification_key_path,
                     this->RSA_verification_key);
    LoadRSAPrivateKey(this->user_config.user_encryption_private_key_path,
                      this->RSA_encryption_private_key);
    LoadRSAPublicKey(this->user_config.user_encryption_public_key_path,
                     this->RSA_encryption_public_key);
    LoadCertificate(this->user_config.user_certificate_path, this->certificate);
    this->RSA_verification_key = this->certificate.verification_key;
  } catch (CryptoPP::FileStore::OpenErr) {
    // this->cli_driver->print_warning("Error loading keys, you may consider "
    //                                 "registering or logging in again!");
  } catch (std::runtime_error &_) {
    // this->cli_driver->print_warning("Error loading keys, you may consider "
    //                                 "registering or logging in again!");
  }
}

/**
 * Starts repl.
 */
void UserClient::run() {
  /*
  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);
  repl.add_action("login", "login <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("register", "register <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("listen", "listen <port>", &UserClient::HandleUser);
  repl.add_action("connect", "connect <address> <port>",
                  &UserClient::HandleUser);
  repl.add_action("group-create", "group-create <address> <port> <group-id>
  <member-id,...>", &UserClient::HandleGroupCreate);
  repl.add_action("group-send", "group-send <address> <port> <group-id>
  <message>", &UserClient::HandleGroupSend); repl.add_action("group-fetch",
  "group-fetch <address> <port> <group-id>", &UserClient::HandleGroupFetch);
  repl.run();
  */
  auto self_ptr = std::shared_ptr<UserClient>(this, [](UserClient *) {});
  TUIDriver tui(self_ptr);
  tui.run();
}

/**
 * Diffie-Hellman key exchange with server.
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleServerKeyExchange() {
  // Generate keypair and send public to server
  auto [dh, priv, pub] = this->crypto_driver->DH_initialize();

  UserToServer_DHPublicValue_Message user_msg;
  user_msg.public_value = pub;
  std::vector<unsigned char> user_msg_data;
  user_msg.serialize(user_msg_data);
  this->network_driver->send(user_msg_data);

  // Receive response and verify RSA signature
  ServerToUser_DHPublicValue_Message server_msg;
  std::vector<unsigned char> server_msg_data = this->network_driver->read();
  server_msg.deserialize(server_msg_data);

  std::vector<unsigned char> to_verify = concat_byteblocks(
      server_msg.server_public_value, server_msg.user_public_value);
  bool sig_valid =
      this->crypto_driver->RSA_verify(this->RSA_server_verification_key,
                                      to_verify, server_msg.server_signature);
  if (!sig_valid) {
    throw std::runtime_error("Server DH signature verification failed.");
  }

  // Verify the server echoed back our public value.
  if (server_msg.user_public_value != pub) {
    throw std::runtime_error("Server echoed wrong user public value.");
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

/**
 * Diffie-Hellman key exchange with another user.
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleUserKeyExchange() {
  auto [dh, priv, pub] = this->crypto_driver->DH_initialize();

  UserToUser_DHPublicValue_Message user_msg;
  user_msg.public_value = pub;
  user_msg.certificate = this->certificate;
  user_msg.user_signature = this->crypto_driver->RSA_sign(
      this->RSA_signing_key,
      concat_byteblock_and_cert(user_msg.public_value, user_msg.certificate));

  std::vector<unsigned char> user_msg_data;
  user_msg.serialize(user_msg_data);
  this->network_driver->send(user_msg_data);

  // Receive response and verify certificate via server key
  UserToUser_DHPublicValue_Message fremde_msg;
  std::vector<unsigned char> fremde_msg_data = this->network_driver->read();
  fremde_msg.deserialize(fremde_msg_data);

  std::vector<unsigned char> cert_to_verify = concat_string_and_two_rsakeys(
      fremde_msg.certificate.id, fremde_msg.certificate.verification_key,
      fremde_msg.certificate.encryption_key);

  bool cert_valid = this->crypto_driver->RSA_verify(
      this->RSA_server_verification_key, cert_to_verify,
      fremde_msg.certificate.server_signature);

  if (!cert_valid) {
    throw std::runtime_error("Remote certificate is invalid or forged");
  }

  std::vector<unsigned char> sign_to_verify = concat_byteblock_and_cert(
      fremde_msg.public_value, fremde_msg.certificate);

  bool sig_valid = this->crypto_driver->RSA_verify(
      fremde_msg.certificate.verification_key, sign_to_verify,
      fremde_msg.user_signature);

  if (!sig_valid) {
    throw std::runtime_error("Other user DH signature verification failed.");
  }

  // Save remote key after certificate and signature being validated
  this->RSA_remote_verification_key = fremde_msg.certificate.verification_key;

  // Compute shared key and derive AES + HMAC keys
  CryptoPP::SecByteBlock shared_key =
      this->crypto_driver->DH_generate_shared_key(dh, priv,
                                                  fremde_msg.public_value);
  CryptoPP::SecByteBlock AES_key =
      this->crypto_driver->AES_generate_key(shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      this->crypto_driver->HMAC_generate_key(shared_key);
  return {AES_key, HMAC_key};
}

/**
 * User login or register.
 */
bool UserClient::HandleLoginOrRegister(std::string input) {
  std::lock_guard<std::mutex> net_lock(this->network_mtx);
  try {
    try {
      this->network_driver->disconnect();
    } catch (...) {
      // Ignore disconnect errors if the socket wasn't connected
    }
    this->network_driver = std::make_shared<NetworkDriverImpl>();
    // Connect to server and check if we are registering.
    std::vector<std::string> input_split = string_split(input, ' ');
    if (input_split.size() != 3) {
      // this->cli_driver->print_left("invalid number of arguments.");
      return false;
    }
    std::string address = input_split[1];
    int port = std::stoi(input_split[2]);
    this->network_driver->connect(address, port);
    this->DoLoginOrRegister(input_split[0]);
    return true;
  } catch (std::exception &e) {
    // this->cli_driver->print_warning(e.what());
    return false;
  }
}

/**
 * User login or register protocol.
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::DoLoginOrRegister(std::string input, bool keep_group_session) {
  auto [aes_key, hmac_key] = this->HandleServerKeyExchange();

  UserToServer_IDPrompt_Message id_msg;
  this->id = this->user_config.user_username;
  id_msg.id = this->id;
  id_msg.new_user = (input == "register");

  std::vector<unsigned char> id_msg_data =
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &id_msg);

  this->network_driver->send(id_msg_data);

  // Receive salt from server
  std::vector<unsigned char> salt_msg_data_en = this->network_driver->read();
  auto [salt_msg_data_de, salt_valid] = this->crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, salt_msg_data_en);

  if (!salt_valid) {
    throw std::runtime_error("Salt msg couldn't be verified");
  }

  ServerToUser_Salt_Message salt_msg;
  salt_msg.deserialize(salt_msg_data_de);

  auto hashed_pass = this->crypto_driver->hash(this->user_config.user_password +
                                               salt_msg.salt);

  UserToServer_HashedAndSaltedPassword_Message pass_msg;
  pass_msg.hspw = hashed_pass;

  std::vector<unsigned char> encrypted_pass =
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &pass_msg);

  this->network_driver->send(encrypted_pass);

  // The basic protocol has one password response: registration stores it and
  // login compares it. There is intentionally no time-based second factor.
  auto [auth_data, auth_valid] = this->crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, this->network_driver->read());
  if (!auth_valid) {
    throw std::runtime_error("Authentication result failed integrity check.");
  }
  ServerToUser_GroupResult_Message auth_result;
  auth_result.deserialize(auth_data);
  if (!auth_result.success) {
    throw std::runtime_error(auth_result.detail);
  }

  // Receive certificate from server if registering
  if (id_msg.new_user) {
    auto [sign_priv, sign_pub] = this->crypto_driver->RSA_generate_keys();
    auto [enc_priv, enc_pub] = this->crypto_driver->RSA_generate_keys();
    this->RSA_signing_key = sign_priv;
    this->RSA_verification_key = sign_pub;
    this->RSA_encryption_private_key = enc_priv;
    this->RSA_encryption_public_key = enc_pub;
    UserToServer_VerificationKey_Message vk_msg;
    vk_msg.verification_key = sign_pub;
    vk_msg.encryption_key = enc_pub;
    this->network_driver->send(
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &vk_msg));
    auto [cert_data, cert_valid] = this->crypto_driver->decrypt_and_verify(
        aes_key, hmac_key, this->network_driver->read());
    if (!cert_valid)
      throw std::runtime_error("Cert msg couldn't be verified");
    ServerToUser_IssuedCertificate_Message cert_msg;
    cert_msg.deserialize(cert_data);
    this->certificate = cert_msg.certificate;
    SaveCertificate(this->user_config.user_certificate_path, this->certificate);
    SaveRSAPrivateKey(this->user_config.user_signing_key_path,
                      this->RSA_signing_key);
    SaveRSAPublicKey(this->user_config.user_verification_key_path,
                     this->RSA_verification_key);
    SaveRSAPrivateKey(this->user_config.user_encryption_private_key_path,
                      this->RSA_encryption_private_key);
    SaveRSAPublicKey(this->user_config.user_encryption_public_key_path,
                     this->RSA_encryption_public_key);
  }
  if (!keep_group_session) {
    UserToServer_GroupClose_Message close_msg;
    std::vector<unsigned char> close_data =
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &close_msg);
    this->network_driver->send(close_data);
  }
  return {aes_key, hmac_key};
}

namespace {
std::pair<std::string, int>
group_server_endpoint(const std::vector<std::string> &args) {
  return {args[1], std::stoi(args[2])};
}
} // namespace

// Fetches a certificate for a given user ID from the server.
Certificate_Message UserClient::FetchCertificate(const std::string &address,
                                                 int port,
                                                 const std::string &user_id) {
  this->network_driver = std::make_shared<NetworkDriverImpl>();
  this->network_driver->connect(address, port);
  auto [aes_key, hmac_key] = this->DoLoginOrRegister("login", true);
  UserToServer_CertificateRequest_Message request;
  request.user_id = user_id;
  this->network_driver->send(
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request));
  auto [response_data, response_valid] =
      this->crypto_driver->decrypt_and_verify(aes_key, hmac_key,
                                              this->network_driver->read());
  if (!response_valid)
    throw std::runtime_error("Invalid HMAC on certificate response.");
  ServerToUser_CertificateResponse_Message response;
  response.deserialize(response_data);
  this->network_driver->disconnect();
  if (!response.found)
    throw std::runtime_error("Requested user has no certificate.");
  std::vector<unsigned char> certificate_data;
  response.certificate.serialize(certificate_data);
  std::vector<unsigned char> certificate_to_verify =
      concat_string_and_two_rsakeys(response.certificate.id,
                                    response.certificate.verification_key,
                                    response.certificate.encryption_key);
  if (!this->crypto_driver->RSA_verify(this->RSA_server_verification_key,
                                       certificate_to_verify,
                                       response.certificate.server_signature)) {
    throw std::runtime_error("Server returned an invalid user certificate.");
  }
  if (response.certificate.id != user_id) {
    throw std::runtime_error("Server returned a certificate for a different user.");
  }
  return response.certificate;
}

bool UserClient::VerifyGroupMessageSignature(
    const std::string &address, int port, const std::string &group_id,
    const GroupChatMessage &message) {
  try {
    const std::string certificate_key =
        address + ":" + std::to_string(port) + "/" + message.sender_id;
    auto cached = this->group_sender_certificates.find(certificate_key);
    if (cached == this->group_sender_certificates.end()) {
      Certificate_Message certificate =
          this->FetchCertificate(address, port, message.sender_id);
      cached = this->group_sender_certificates
                   .emplace(certificate_key, std::move(certificate))
                   .first;
    }
    return this->crypto_driver->RSA_verify(
        cached->second.verification_key,
        group_message_signature_input(group_id, message.sender_id, message.iv,
                                      message.ciphertext, message.mac),
        message.signature);
  } catch (const std::exception &) {
    return false;
  }
}

CryptoPP::Integer
UserClient::FetchElectionPublicKey(const std::string &address, int port,
                                   const std::string &group_id) {
  this->network_driver = std::make_shared<NetworkDriverImpl>();
  this->network_driver->connect(address, port);
  auto [aes_key, hmac_key] = this->DoLoginOrRegister("login", true);
  UserToServer_ElectionKeyRequest_Message request;
  request.group_id = group_id;
  this->network_driver->send(
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request));
  auto [data, valid] = this->crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, this->network_driver->read());
  if (!valid)
    throw std::runtime_error("Invalid HMAC on election-key response.");
  ServerToUser_ElectionKeyResponse_Message response;
  response.deserialize(data);
  this->network_driver->disconnect();
  if (response.group_id != group_id)
    throw std::runtime_error(
        "Server returned a threshold key for a different group.");
  if (!response.available)
    throw std::runtime_error("Threshold public key is not available for this "
                             "group; run 'keygen <group-id>' first.");
  return response.public_key;
}

// Ensures that the group DKG has been completed for a given group ID by communicating with the server.
bool UserClient::EnsureGroupDKG(const std::string &address, int port,
                                const std::string &group_id) {
  this->network_driver = std::make_shared<NetworkDriverImpl>();
  this->network_driver->connect(address, port);
  auto [aes_key, hmac_key] = this->DoLoginOrRegister("login", true);
  UserToServer_GroupDKGStart_Message request;
  request.group_id = group_id;
  this->network_driver->send(
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request));
  auto [data, valid] = this->crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, this->network_driver->read());
  if (!valid)
    throw std::runtime_error("Invalid HMAC on group-DKG status.");
  ServerToUser_GroupDKGStatus_Message response;
  response.deserialize(data);
  this->network_driver->disconnect();
  if (response.group_id != group_id)
    throw std::runtime_error(
        "Server returned DKG status for a different group.");
  if (!response.started)
    throw std::runtime_error(response.detail);
  if (!response.ready) {
    // this->cli_driver->print_info(response.detail);
    return false;
  }
  return true;
}

ServerToUser_GroupMessages_Message
UserClient::FetchGroupState(const std::string &address, int port,
                            const std::string &group_id, int since_id) {
  this->network_driver = std::make_shared<NetworkDriverImpl>();
  this->network_driver->connect(address, port);
  auto [aes_key, hmac_key] = this->DoLoginOrRegister("login", true);
  UserToServer_GroupFetch_Message request;
  request.group_id = group_id;
  request.since_id = since_id;
  this->network_driver->send(
      this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request));
  auto [data, valid] = this->crypto_driver->decrypt_and_verify(
      aes_key, hmac_key, this->network_driver->read());
  if (!valid)
    throw std::runtime_error("Invalid HMAC on group response.");
  if (get_message_type(data) == MessageType::ServerToUser_GroupResult_Message) {
    ServerToUser_GroupResult_Message result;
    result.deserialize(data);
    throw std::runtime_error(result.detail);
  }
  ServerToUser_GroupMessages_Message response;
  response.deserialize(data);
  this->network_driver->disconnect();
  return response;
}

bool UserClient::HandleGroupCreate(std::string input) {
  std::lock_guard<std::mutex> net_lock(this->network_mtx);
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 4 && args.size() != 5) {
    // this->cli_driver->print_warning(
    //     "Usage: group-create <address> <port> <group-id> <member-id,...>");
    return false;
  }
  try {
    AutoSeededRandomPool prng;

    auto [address, port] = group_server_endpoint(args);

    // Check if escrow DKG is done.

    // this->cli_driver->print_info("Waiting 60s for escrows to finish DKG...");
    bool ready = false;
    for (int i = 0; i < 60 && !ready; i++) {
      ready = this->EnsureGroupDKG(address, port, args[3]);
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (!ready) {
      // this->cli_driver->print_warning(
      //     "Escrows did not finish DKG in 60s, aborting group create.");
      return false;
    }

    std::vector<std::string> requested_members =
        args.size() == 5 ? string_split(args[4], ',')
                         : std::vector<std::string>{};
    std::set<std::string> members(requested_members.begin(),
                                  requested_members.end());
    members.insert(this->user_config.user_username);

    // Generated k so that we can generate a random G^k in Z_q
    CryptoPP::Integer k(prng, 1, DL_Q - 1);
    CryptoPP::Integer group_secret =
        CryptoPP::ModularExponentiation(DL_G, k, DL_P);

    UserToServer_GroupCreate_Message request;
    request.group_id = args[3];
    request.member_ids.assign(members.begin(), members.end());

    for (const auto &member : request.member_ids) {
      Certificate_Message certificate =
          this->FetchCertificate(address, port, member);
      CryptoPP::Integer wrapped_group_secret =
          certificate.encryption_key.ApplyFunction(group_secret);
      request.member_envelopes.push_back(
          {member, byteblock_to_string(integer_to_byteblock(wrapped_group_secret))});
    }

    CryptoPP::Integer threshold_pk =
        this->FetchElectionPublicKey(address, port, args[3]);

    ElGamal_Ciphertext escrow = VoteClient::Encrypt(group_secret, threshold_pk);
    request.escrow_envelope_a = escrow.a;
    request.escrow_envelope_b = escrow.b;

    std::vector<unsigned char> unsigned_data;
    request.serialize(unsigned_data);
    request.creator_signature =
        this->crypto_driver->RSA_sign(this->RSA_signing_key, unsigned_data);

    this->network_driver = std::make_shared<NetworkDriverImpl>();
    this->network_driver->connect(address, port);
    auto [aes_key, hmac_key] = this->DoLoginOrRegister("login", true);
    this->network_driver->send(
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request));

    auto [data, valid] = this->crypto_driver->decrypt_and_verify(
        aes_key, hmac_key, this->network_driver->read());
    if (!valid)
      throw std::runtime_error("Invalid HMAC on group response.");

    ServerToUser_GroupResult_Message response;
    response.deserialize(data);
    this->network_driver->disconnect();
    // Surface the server's specific reason so the TUI can show it.
    if (!response.success)
      throw std::runtime_error(response.detail);
    return true;
  } catch (...) {
    // Re-throw so the caller (TUI) can display the concrete failure reason.
    throw;
  }
}

bool UserClient::HandleGroupSend(std::string input) {
  std::lock_guard<std::mutex> net_lock(this->network_mtx);
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() < 5) {
    // this->cli_driver->print_warning(
    //     "Usage: group-send <address> <port> <group-id> <message>");
    return false;
  }
  try {
    auto [address, port] = group_server_endpoint(args);
    size_t message_start = 0;
    for (int field = 0; field < 4; ++field)
      message_start = input.find(' ', message_start) + 1;
    std::string plaintext = input.substr(message_start);
    ServerToUser_GroupMessages_Message state =
        this->FetchGroupState(address, port, args[3]);
    AutoSeededRandomPool prng;
    CryptoPP::Integer wrapped_group_secret = byteblock_to_integer(
        string_to_byteblock(state.wrapped_group_key));
    CryptoPP::SecByteBlock group_secret = integer_to_byteblock(
        this->RSA_encryption_private_key.CalculateInverse(prng,
                                                           wrapped_group_secret));
    CryptoPP::SecByteBlock group_aes =
        this->crypto_driver->AES_generate_key(group_secret);
    CryptoPP::SecByteBlock group_hmac =
        this->crypto_driver->HMAC_generate_key(group_secret);
    auto [ciphertext, iv] =
        this->crypto_driver->AES_encrypt(group_aes, plaintext);

    this->network_driver = std::make_shared<NetworkDriverImpl>();
    this->network_driver->connect(address, port);
    auto [aes_key, hmac_key] = this->DoLoginOrRegister("login", true);
    UserToServer_GroupSend_Message request;
    request.group_id = args[3];
    request.iv = byteblock_to_string(iv);
    request.ciphertext = ciphertext;
    const std::string sender_id = this->get_id();
    request.mac = this->crypto_driver->HMAC_generate(
        group_hmac, request.group_id + sender_id + request.iv +
                        request.ciphertext);
    request.signature = this->crypto_driver->RSA_sign(
        this->RSA_signing_key,
        group_message_signature_input(request.group_id, sender_id, request.iv,
                                      request.ciphertext, request.mac));
    this->network_driver->send(
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request));
    auto [data, valid] = this->crypto_driver->decrypt_and_verify(
        aes_key, hmac_key, this->network_driver->read());
    if (!valid)
      throw std::runtime_error("Invalid HMAC on group response.");
    ServerToUser_GroupResult_Message response;
    response.deserialize(data);
    // response.success ? this->cli_driver->print_success(response.detail)
    //                  : this->cli_driver->print_warning(response.detail);
    this->network_driver->disconnect();
    if (response.success) {
      return true;
    }
    return false;

  } catch (const std::exception &e) {
    // this->cli_driver->print_warning(e.what());
    return false;
  }
}

bool UserClient::HandleGroupFetch(std::string input) {
  std::lock_guard<std::mutex> net_lock(this->network_mtx);
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 4) {
    // this->cli_driver->print_warning(
    //     "Usage: group-fetch <address> <port> <group-id>");
    return false;
  }
  try {
    auto [address, port] = group_server_endpoint(args);
    // Only pull messages newer than the highest id seen this session.
    int since_id =
        this->group_cursors.count(args[3]) ? this->group_cursors[args[3]] : 0;
    ServerToUser_GroupMessages_Message response =
        this->FetchGroupState(address, port, args[3], since_id);
    AutoSeededRandomPool prng;
    CryptoPP::Integer wrapped_group_secret = byteblock_to_integer(
        string_to_byteblock(response.wrapped_group_key));
    CryptoPP::SecByteBlock secret = integer_to_byteblock(
        this->RSA_encryption_private_key.CalculateInverse(prng,
                                                           wrapped_group_secret));
    auto aes = this->crypto_driver->AES_generate_key(secret);
    auto hmac = this->crypto_driver->HMAC_generate_key(secret);
    for (const auto &message : response.messages) {
      // Advance the cursor even for a discarded message: the server won't
      // resend it, and re-fetching a tampered ciphertext would fail again
      // anyway.
      if (message.message_id > this->group_cursors[args[3]])
        this->group_cursors[args[3]] = message.message_id;
      std::string authenticated =
          args[3] + message.sender_id + message.iv + message.ciphertext;
      if (!this->crypto_driver->HMAC_verify(hmac, authenticated, message.mac)) {
        // this->cli_driver->print_warning(
        //     "Discarded group message with invalid HMAC.");
        continue;
      }
      if (!this->VerifyGroupMessageSignature(address, port, args[3], message)) {
        // this->cli_driver->print_warning(
        //     "Discarded group message with invalid sender signature.");
        continue;
      }
      // this->cli_driver->print_left(
      //     message.sender_id + ": " +
      //     this->crypto_driver->AES_decrypt(aes, string_to_byteblock(message.iv),
      //                                      message.ciphertext));
    }
    return true;
  } catch (const std::exception &e) {
    // this->cli_driver->print_warning(e.what());
    return false;
  }
}

std::string UserClient::get_id() const {
  if (!this->user_config.user_username.empty()) {
    return this->user_config.user_username;
  }
  return this->certificate.id;
}

std::vector<std::string>
UserClient::check_group_pertenece(const std::string &address, int port) {
  std::lock_guard<std::mutex> net_lock(this->network_mtx);
  std::vector<std::string> joined_groups;
  try {
    // The server answers group membership only for the authenticated session,
    // so we must log in first and send the request on that session (not a bare
    // pre-login handshake, which the server rejects).
    this->network_driver = std::make_shared<NetworkDriverImpl>();
    this->network_driver->connect(address, port);
    auto [aes_key, hmac_key] = this->DoLoginOrRegister("login", true);

    UserToServer_GroupMembershipRequest_Message request;
    request.user_id = this->id;
    this->network_driver->send(
        this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &request));

    auto [data, valid] = this->crypto_driver->decrypt_and_verify(
        aes_key, hmac_key, this->network_driver->read());
    if (valid) {
      ServerToUser_GroupMembershipResponse_Message response;
      response.deserialize(data);
      joined_groups = response.group_ids;
    }
    this->network_driver->disconnect();
  } catch (const std::exception &e) {
    // Silence errors (e.g. bad credentials, disconnect) during background polls.
  }
  return joined_groups;
}

std::vector<std::string>
UserClient::get_registered_users(const std::string &address, int port) {
  std::lock_guard<std::mutex> net_lock(this->network_mtx);
  std::vector<std::string> users;
  try {
    this->network_driver = std::make_shared<NetworkDriverImpl>();
    this->network_driver->connect(address, port);
    auto [AES_key, HMAC_key] = this->DoLoginOrRegister("login", true);

    UserToServer_GetRegisteredUsers_Message request;
    request.user_id = this->get_id();
    std::vector<unsigned char> req_data =
        this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &request);
    this->network_driver->send(req_data);

    std::vector<unsigned char> res_data_en = this->network_driver->read();
    auto [res_data_de, res_valid] =
        this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, res_data_en);

    if (res_valid) {
      ServerToUser_GetRegisteredUsers_Response_Message response;
      response.deserialize(res_data_de);
      users = response.user_ids;
    }

    this->network_driver->disconnect();
  } catch (const std::exception &e) {
    // Silence errors if disconnected
  }
  return users;
}

// (Re)establish a persistent authenticated session to the endpoint, so the
// message poller can reuse it instead of logging in on every fetch. Caller
// holds network_mtx.
std::vector<std::pair<std::string, std::string>>
UserClient::FetchGroupMessagesStructured(const std::string &address, int port,
                                         const std::string &group_id) {
  std::lock_guard<std::mutex> net_lock(this->network_mtx);
  std::string key = address + ":" + std::to_string(port) + "/" + group_id;
  try {
    // Fetch only messages newer than the per-group cursor, decrypt just those,
    // and append to the cache; return the full cache. A fresh connection per
    // poll keeps the protocol simple and self-contained.
    int since = this->group_fetch_cursor.count(key)
                    ? this->group_fetch_cursor[key]
                    : 0;
    ServerToUser_GroupMessages_Message response =
        this->FetchGroupState(address, port, group_id, since);

    AutoSeededRandomPool prng;
    CryptoPP::Integer wrapped_group_secret = byteblock_to_integer(
        string_to_byteblock(response.wrapped_group_key));
    CryptoPP::SecByteBlock secret = integer_to_byteblock(
        this->RSA_encryption_private_key.CalculateInverse(prng,
                                                           wrapped_group_secret));
    auto aes = this->crypto_driver->AES_generate_key(secret);
    auto hmac = this->crypto_driver->HMAC_generate_key(secret);

    auto &cache = this->group_message_cache[key];
    int new_cursor = since;
    for (const auto &message : response.messages) {
      if (message.message_id > new_cursor)
        new_cursor = message.message_id;
      std::string authenticated =
          group_id + message.sender_id + message.iv + message.ciphertext;
      if (!this->crypto_driver->HMAC_verify(hmac, authenticated, message.mac))
        continue;
      if (!this->VerifyGroupMessageSignature(address, port, group_id, message))
        continue;
      std::string decrypted = this->crypto_driver->AES_decrypt(
          aes, string_to_byteblock(message.iv), message.ciphertext);
      cache.push_back({message.sender_id, decrypted});
    }
    this->group_fetch_cursor[key] = new_cursor;
    return cache;
  } catch (const std::exception &e) {
    // Not a member yet, transient error, etc.: serve whatever is cached.
    return this->group_message_cache[key];
  }
}

/**
 * Handles communicating with another user.
 */
bool UserClient::HandleUser(std::string input) {
  try {
    try {
      this->network_driver->disconnect();
    } catch (...) {
      // Ignore disconnect errors if the socket wasn't connected
    }
    this->network_driver = std::make_shared<NetworkDriverImpl>();
    // Handle if connecting or listening; parse user input.
    std::vector<std::string> args = string_split(input, ' ');
    bool isListener = args[0] == "listen";
    if (isListener) {
      if (args.size() != 2) {
        // this->cli_driver->print_warning("Invalid args, usage: listen <port>");
        return false;
      }
      int port = std::stoi(args[1]);
      this->network_driver->listen(port);
    } else {
      if (args.size() != 3) {
        // this->cli_driver->print_warning(
        //     "Invalid args, usage: connect <ip> <port>");
        return false;
      }
      std::string ip = args[1];
      int port = std::stoi(args[2]);
      this->network_driver->connect(ip, port);
    }

    // Exchange keys.
    auto keys = this->HandleUserKeyExchange();

    // Clear the screen
    // this->cli_driver->init();
    // this->cli_driver->print_success("Connected!");

    // Set up communication
    boost::thread msgListener =
        boost::thread(boost::bind(&UserClient::ReceiveThread, this, keys));
    this->SendThread(keys);
    msgListener.join();
    return true;
  } catch (std::exception &e) {
    // this->cli_driver->print_warning(e.what());
    return false;
  }
}

/**
 * Listen for messages and print to CLI.
 */
void UserClient::ReceiveThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  while (true) {
    std::vector<unsigned char> encrypted_msg_data;
    try {
      encrypted_msg_data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // this->cli_driver->print_info("Received EOF; closing connection.");
      return;
    }
    // Check if HMAC is valid.
    auto msg_data = this->crypto_driver->decrypt_and_verify(
        keys.first, keys.second, encrypted_msg_data);
    if (!msg_data.second) {
      // this->cli_driver->print_warning(
      //     "Invalid MAC on message; closing connection.");
      this->network_driver->disconnect();
      throw std::runtime_error("User sent message with invalid MAC.");
    }

    // Decrypt and print.
    UserToUser_Message_Message u2u_msg;
    u2u_msg.deserialize(msg_data.first);
    // this->cli_driver->print_left(u2u_msg.msg);
  }
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  std::string plaintext;
  while (std::getline(std::cin, plaintext)) {
    // Read from STDIN.
    if (plaintext != "") {
      UserToUser_Message_Message u2u_msg;
      u2u_msg.msg = plaintext;

      std::vector<unsigned char> msg_data =
          this->crypto_driver->encrypt_and_tag(keys.first, keys.second,
                                               &u2u_msg);
      try {
        this->network_driver->send(msg_data);
      } catch (std::runtime_error &_) {
        // this->cli_driver->print_info(
        //     "Other side is closed, closing connection");
        this->network_driver->disconnect();
        return;
      }
    }
    // this->cli_driver->print_right(plaintext);
  }
  // this->cli_driver->print_info("Received EOF from user; closing connection");
  this->network_driver->disconnect();
}
