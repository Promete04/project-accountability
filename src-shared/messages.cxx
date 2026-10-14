#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

#include <cstring>

namespace {

void require_bytes(const std::vector<unsigned char> &data, int idx,
                   size_t count) {
  if (idx < 0 || static_cast<size_t>(idx) > data.size() ||
      count > data.size() - static_cast<size_t>(idx)) {
    throw std::runtime_error("Malformed or truncated message.");
  }
}

int checked_count(const CryptoPP::Integer &count, size_t max_count = 65536) {
  if (count.IsNegative() || count > CryptoPP::Integer(max_count))
    throw std::runtime_error("Message collection exceeds the allowed limit.");
  return count.ConvertToLong();
}

} // namespace

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  require_bytes(data, 0, 1);
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the next bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  require_bytes(data, idx, 1);
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the next string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  require_bytes(data, idx, sizeof(size_t));
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));
  require_bytes(data, idx + sizeof(size_t), str_size);

  // Get string
  std::vector<unsigned char> svec(data.begin() + idx + sizeof(size_t),
                                  data.begin() + idx + sizeof(size_t) +
                                      str_size);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

std::vector<unsigned char> group_message_signature_input(
    const std::string &group_id, const std::string &sender_id,
    const std::string &iv, const std::string &ciphertext,
    const std::string &mac) {
  std::vector<unsigned char> data;
  put_string("group-message-signature-v1", data);
  put_string(group_id, data);
  put_string(sender_id, data);
  put_string(iv, data);
  put_string(ciphertext, data);
  put_string(mac, data);
  return data;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  if (get_message_type(data) != MessageType::HMACTagged_Wrapper)
    throw std::runtime_error("Expected an authenticated-message wrapper.");

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

/**
 * serialize Certificate_Message.
 */
void Certificate_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Certificate_Message);

  // Serialize signing key.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);
  std::string encryption_key_str;
  CryptoPP::StringSink encryption_ss(encryption_key_str);
  this->encryption_key.Save(encryption_ss);

  // Add fields.
  put_string(this->id, data);
  put_string(verification_key_str, data);
  put_string(encryption_key_str, data);
  put_string(this->server_signature, data);
}

/**
 * deserialize Certificate_Message.
 */
int Certificate_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::Certificate_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_string(&verification_key_str, data, n);
  std::string encryption_key_str;
  n += get_string(&encryption_key_str, data, n);
  n += get_string(&this->server_signature, data, n);

  // Deserialize signing key.
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);
  CryptoPP::StringSource encryption_ss(encryption_key_str, true);
  this->encryption_key.Load(encryption_ss);
  return n;
}

// ================================================
// USER <=> SERVER MESSAGES
// ================================================

/**
 * serialize UserToServer_DHPublicValue_Message.
 */
void UserToServer_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize UserToServer_DHPublicValue_Message.
 */
int UserToServer_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

/**
 * serialize ServerToUser_DHPublicValue_Message.
 */
void ServerToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_DHPublicValue_Message);

  // Add fields.
  std::string server_public_string =
      byteblock_to_string(this->server_public_value);
  put_string(server_public_string, data);

  std::string user_public_string = byteblock_to_string(this->user_public_value);
  put_string(user_public_string, data);

  put_string(this->server_signature, data);
}

/**
 * deserialize ServerToUser_DHPublicValue_Message.
 */
int ServerToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_DHPublicValue_Message);

  // Get fields.
  int n = 1;
  std::string server_public_string;
  n += get_string(&server_public_string, data, n);
  this->server_public_value = string_to_byteblock(server_public_string);

  std::string user_public_string;
  n += get_string(&user_public_string, data, n);
  this->user_public_value = string_to_byteblock(user_public_string);

  n += get_string(&this->server_signature, data, n);
  return n;
}

/**
 * serialize UserToServer_IDPrompt_Message.
 */
void UserToServer_IDPrompt_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_IDPrompt_Message);

  // Add fields.
  put_string(this->id, data);
  put_bool(this->new_user, data);
}

/**
 * deserialize UserToServer_IDPrompt_Message.
 */
int UserToServer_IDPrompt_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_IDPrompt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_bool(&this->new_user, data, n);
  return n;
}

/**
 * serialize ServerToUser_Salt_Message.
 */
void ServerToUser_Salt_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_Salt_Message);

  // Add fields.
  put_string(this->salt, data);
}

/**
 * deserialize ServerToUser_Salt_Message.
 */
int ServerToUser_Salt_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_Salt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->salt, data, n);
  return n;
}

/**
 * serialize UserToServer_HashedAndSaltedPassword_Message.
 */
void UserToServer_HashedAndSaltedPassword_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back(
      (char)MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Add fields.
  put_string(this->hspw, data);
}

/**
 * deserialize UserToServer_HashedAndSaltedPassword_Message.
 */
int UserToServer_HashedAndSaltedPassword_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->hspw, data, n);
  return n;
}

/**
 * serialize ServerToUser_PRGSeed_Message.
 */
void ServerToUser_PRGSeed_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_PRGSeed_Message);

  // Add fields.
  std::string seed_string = byteblock_to_string(this->seed);
  put_string(seed_string, data);
}

/**
 * deserialize ServerToUser_PRGSeed_Message.
 */
int ServerToUser_PRGSeed_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_PRGSeed_Message);

  // Get fields.
  std::string seed_string;
  int n = 1;
  n += get_string(&seed_string, data, n);
  this->seed = string_to_byteblock(seed_string);
  return n;
}

/**
 * serialize UserToServer_PRGValue_Message.
 */
void UserToServer_PRGValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_PRGValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->value);
  put_string(value_string, data);
}

/**
 * deserialize UserToServer_PRGValue_Message.
 */
int UserToServer_PRGValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_PRGValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->value = string_to_byteblock(value_string);
  return n;
}

void UserToServer_VerificationKey_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_VerificationKey_Message);

  // Add fields.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);
  put_string(verification_key_str, data);
  std::string encryption_key_str;
  CryptoPP::StringSink encryption_ss(encryption_key_str);
  this->encryption_key.Save(encryption_ss);
  put_string(encryption_key_str, data);
}

int UserToServer_VerificationKey_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_VerificationKey_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&verification_key_str, data, n);
  std::string encryption_key_str;
  n += get_string(&encryption_key_str, data, n);

  // Deserialize key
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);
  CryptoPP::StringSource encryption_ss(encryption_key_str, true);
  this->encryption_key.Load(encryption_ss);

  return n;
}

/**
 * serialize ServerToUser_IssuedCertificate_Message.
 */
void ServerToUser_IssuedCertificate_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_IssuedCertificate_Message);

  // Add fields.
  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());
}

/**
 * deserialize ServerToUser_IssuedCertificate_Message.
 */
int ServerToUser_IssuedCertificate_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_IssuedCertificate_Message);

  // Get fields.
  int n = 1;
  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  return n;
}

void UserToServer_CertificateRequest_Message::serialize(
    std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_CertificateRequest_Message);
  put_string(user_id, data);
}

int UserToServer_CertificateRequest_Message::deserialize(
    std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_CertificateRequest_Message);
  return 1 + get_string(&user_id, data, 1);
}

void ServerToUser_CertificateResponse_Message::serialize(
    std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToUser_CertificateResponse_Message);
  put_bool(found, data);
  if (found) {
    std::vector<unsigned char> certificate_data;
    certificate.serialize(certificate_data);
    data.insert(data.end(), certificate_data.begin(), certificate_data.end());
  }
}

int ServerToUser_CertificateResponse_Message::deserialize(
    std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToUser_CertificateResponse_Message);
  int n = 1;
  n += get_bool(&found, data, n);
  if (found) {
    std::vector<unsigned char> certificate_data(data.begin() + n, data.end());
    n += certificate.deserialize(certificate_data);
  }
  return n;
}

void UserToServer_ElectionKeyRequest_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_ElectionKeyRequest_Message);
  put_string(group_id, data);
}
int UserToServer_ElectionKeyRequest_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_ElectionKeyRequest_Message);
  return 1 + get_string(&group_id, data, 1);
}
void ServerToUser_ElectionKeyResponse_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToUser_ElectionKeyResponse_Message);
  put_bool(available, data);
  put_string(group_id, data);
  if (available) put_integer(public_key, data);
}
int ServerToUser_ElectionKeyResponse_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToUser_ElectionKeyResponse_Message);
  int n=1;
  n+=get_bool(&available,data,n);
  n+=get_string(&group_id,data,n);
  if(available)n+=get_integer(&public_key,data,n);
  return n;
}

void UserToServer_GroupDKGStart_Message::serialize(
    std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_GroupDKGStart_Message);
  put_string(group_id, data);
}

int UserToServer_GroupDKGStart_Message::deserialize(
    std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_GroupDKGStart_Message);
  return 1 + get_string(&group_id, data, 1);
}

void ServerToUser_GroupDKGStatus_Message::serialize(
    std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToUser_GroupDKGStatus_Message);
  put_bool(ready, data);
  put_bool(started, data);
  put_string(group_id, data);
  put_string(detail, data);
}

int ServerToUser_GroupDKGStatus_Message::deserialize(
    std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToUser_GroupDKGStatus_Message);
  int n = 1;
  n += get_bool(&ready, data, n);
  n += get_bool(&started, data, n);
  n += get_string(&group_id, data, n);
  n += get_string(&detail, data, n);
  return n;
}

void UserToServer_GroupCreate_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_GroupCreate_Message);
  put_string(group_id, data);
  put_integer(CryptoPP::Integer(member_ids.size()), data);
  for (const auto &member : member_ids) put_string(member, data);
  put_integer(CryptoPP::Integer(member_envelopes.size()), data);
  for (const auto &envelope : member_envelopes) {
    put_string(envelope.recipient_id, data);
    put_string(envelope.wrapped_group_key, data);
  }
  put_integer(escrow_envelope_a, data);
  put_integer(escrow_envelope_b, data);
  put_string(creator_signature, data);
}

int UserToServer_GroupCreate_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_GroupCreate_Message);
  int n = 1;
  n += get_string(&group_id, data, n);
  CryptoPP::Integer count;
  n += get_integer(&count, data, n);
  member_ids.clear();
  for (int i = 0; i < checked_count(count, 1024); ++i) {
    std::string member;
    n += get_string(&member, data, n);
    member_ids.push_back(member);
  }
  CryptoPP::Integer envelope_count;
  n += get_integer(&envelope_count, data, n);
  member_envelopes.clear();
  for (int i = 0; i < checked_count(envelope_count, 1024); ++i) {
    KeyEnvelope envelope;
    n += get_string(&envelope.recipient_id, data, n);
    n += get_string(&envelope.wrapped_group_key, data, n);
    member_envelopes.push_back(std::move(envelope));
  }
  n += get_integer(&escrow_envelope_a, data, n);
  n += get_integer(&escrow_envelope_b, data, n);
  n += get_string(&creator_signature, data, n);
  return n;
}

void UserToServer_GroupSend_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_GroupSend_Message);
  put_string(group_id, data);
  put_string(iv, data);
  put_string(ciphertext, data);
  put_string(mac, data);
  put_string(signature, data);
}

int UserToServer_GroupSend_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_GroupSend_Message);
  int n = 1;
  n += get_string(&group_id, data, n);
  n += get_string(&iv, data, n);
  n += get_string(&ciphertext, data, n);
  n += get_string(&mac, data, n);
  n += get_string(&signature, data, n);
  return n;
}

void UserToServer_GroupFetch_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_GroupFetch_Message);
  put_string(group_id, data);
  put_integer(CryptoPP::Integer(since_id), data);
}

int UserToServer_GroupFetch_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_GroupFetch_Message);
  int n = 1;
  n += get_string(&group_id, data, n);
  CryptoPP::Integer since;
  n += get_integer(&since, data, n);
  since_id = since.ConvertToLong();
  return n;
}

void UserToServer_GroupClose_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_GroupClose_Message);
}

int UserToServer_GroupClose_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_GroupClose_Message);
  return 1;
}

void ServerToUser_GroupResult_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToUser_GroupResult_Message);
  put_bool(success, data);
  put_string(detail, data);
}

int ServerToUser_GroupResult_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToUser_GroupResult_Message);
  int n = 1;
  n += get_bool(&success, data, n);
  n += get_string(&detail, data, n);
  return n;
}

void ServerToUser_GroupMessages_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToUser_GroupMessages_Message);
  put_string(group_id, data);
  put_string(wrapped_group_key, data);
  put_integer(CryptoPP::Integer(messages.size()), data);
  for (const auto &message : messages) {
    put_integer(CryptoPP::Integer(message.message_id), data);
    put_string(message.sender_id, data);
    put_string(message.iv, data);
    put_string(message.ciphertext, data);
    put_string(message.mac, data);
    put_string(message.signature, data);
  }
}

int ServerToUser_GroupMessages_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToUser_GroupMessages_Message);
  int n = 1;
  n += get_string(&group_id, data, n);
  n += get_string(&wrapped_group_key, data, n);
  CryptoPP::Integer count;
  n += get_integer(&count, data, n);
  messages.clear();
  for (int i = 0; i < checked_count(count); ++i) {
    GroupChatMessage message;
    CryptoPP::Integer message_id;
    n += get_integer(&message_id, data, n);
    message.message_id = message_id.ConvertToLong();
    n += get_string(&message.sender_id, data, n);
    n += get_string(&message.iv, data, n);
    n += get_string(&message.ciphertext, data, n);
    n += get_string(&message.mac, data, n);
    n += get_string(&message.signature, data, n);
    messages.push_back(std::move(message));
  }
  return n;
}


// ================================================
// USER <=> USER MESSAGES
// ================================================

/**
 * serialize UserToUser_DHPublicValue_Message.
 */
void UserToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_DHPublicValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->public_value);
  put_string(value_string, data);

  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());

  put_string(this->user_signature, data);
}

/**
 * deserialize UserToUser_DHPublicValue_Message.
 */
int UserToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_DHPublicValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->public_value = string_to_byteblock(value_string);

  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  n += get_string(&this->user_signature, data, n);
  return n;
}

/**
 * serialize UserToUser_Message_Message.
 */
void UserToUser_Message_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_Message_Message);

  // Add fields.
  put_string(this->msg, data);
}

/**
 * deserialize UserToUser_Message_Message.
 */
int UserToUser_Message_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_Message_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->msg, data, n);
  return n;
}

// ================================================
// THRESHOLD ESCROW MESSAGES
// ================================================

void ElGamal_Ciphertext::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ElGamal_Ciphertext);
  put_integer(this->a, data);
  put_integer(this->b, data);
}

int ElGamal_Ciphertext::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ElGamal_Ciphertext);
  int n = 1;
  n += get_integer(&this->a, data, n);
  n += get_integer(&this->b, data, n);
  return n;
}

void PartialDecryption_Struct::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::PartialDecryption_Struct);
  put_integer(this->d, data);
  std::vector<unsigned char> ct_data;
  this->aggregate_ciphertext.serialize(ct_data);
  data.insert(data.end(), ct_data.begin(), ct_data.end());
}

int PartialDecryption_Struct::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::PartialDecryption_Struct);
  int n = 1;
  n += get_integer(&this->d, data, n);
  std::vector<unsigned char> slice(data.begin() + n, data.end());
  n += this->aggregate_ciphertext.deserialize(slice);
  return n;
}

void DecryptionZKP_Struct::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::DecryptionZKP_Struct);
  put_integer(this->u, data);
  put_integer(this->v, data);
  put_integer(this->s, data);
}

int DecryptionZKP_Struct::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::DecryptionZKP_Struct);
  int n = 1;
  n += get_integer(&this->u, data, n);
  n += get_integer(&this->v, data, n);
  n += get_integer(&this->s, data, n);
  return n;
}

void Escrow_PartialDecryption_Message::serialize(
    std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::Escrow_PartialDecryption_Message);
  put_string(this->escrow_id, data);
  put_string(this->group_id, data);
  std::vector<unsigned char> dec_data;
  this->dec.serialize(dec_data);
  data.insert(data.end(), dec_data.begin(), dec_data.end());
  std::vector<unsigned char> zkp_data;
  this->zkp.serialize(zkp_data);
  data.insert(data.end(), zkp_data.begin(), zkp_data.end());
}

int Escrow_PartialDecryption_Message::deserialize(
    std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::Escrow_PartialDecryption_Message);
  int n = 1;
  n += get_string(&this->escrow_id, data, n);
  n += get_string(&this->group_id, data, n);
  std::vector<unsigned char> slice1(data.begin() + n, data.end());
  n += this->dec.deserialize(slice1);
  std::vector<unsigned char> slice2(data.begin() + n, data.end());
  n += this->zkp.deserialize(slice2);
  return n;
}

// ================================================
// SIGNING HELPERS
// ================================================

/**
 * Concatenate a string and a RSA public key into vector of unsigned char
 */
std::vector<unsigned char>
concat_string_and_rsakey(std::string &s, CryptoPP::RSA::PublicKey &k) {
  // Concat s to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), s.begin(), s.end());

  // Concat k to vec
  std::string k_str;
  CryptoPP::StringSink ss(k_str);
  k.Save(ss);
  v.insert(v.end(), k_str.begin(), k_str.end());
  return v;
}

std::vector<unsigned char> concat_string_and_two_rsakeys(
    std::string &s, CryptoPP::RSA::PublicKey &signing_key,
    CryptoPP::RSA::PublicKey &encryption_key) {
  std::vector<unsigned char> result = concat_string_and_rsakey(s, signing_key);
  std::string encryption_key_data;
  CryptoPP::StringSink sink(encryption_key_data);
  encryption_key.Save(sink);
  result.insert(result.end(), encryption_key_data.begin(), encryption_key_data.end());
  return result;
}

/**
 * Concatenate two byteblocks into vector of unsigned char
 */
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2) {
  // Convert byteblocks to strings
  std::string b1_str = byteblock_to_string(b1);
  std::string b2_str = byteblock_to_string(b2);

  // Concat strings to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), b1_str.begin(), b1_str.end());
  v.insert(v.end(), b2_str.begin(), b2_str.end());
  return v;
}

/**
 * Concatenate a byteblock and certificate into vector of unsigned char
 */
std::vector<unsigned char>
concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                          Certificate_Message &cert) {
  // Convert byteblock to strings, serialize cert
  std::string b_str = byteblock_to_string(b);

  std::vector<unsigned char> cert_data;
  cert.serialize(cert_data);

  // Concat string and data to vec.
  std::vector<unsigned char> v;
  v.insert(v.end(), b_str.begin(), b_str.end());
  v.insert(v.end(), cert_data.begin(), cert_data.end());
  return v;
}

void EscrowToServer_Keygen_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_Keygen_Message);
  put_string(this->escrow_id, data);
  put_string(this->group_id, data);
  put_string(this->auth_tag, data);
}

int EscrowToServer_Keygen_Message::deserialize(std::vector<unsigned char> &data) {
  int n = 1;
  n += get_string(&this->escrow_id, data, n);
  n += get_string(&this->group_id, data, n);
  n += get_string(&this->auth_tag, data, n);
  return n;
}

void ServerToEscrow_DecryptRequest_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToEscrow_DecryptRequest_Message);
  put_string(this->group_id, data);
  this->ciphertext.serialize(data);
  put_string(this->requester_id, data);
  put_string(byteblock_to_string(this->requester_dh_pub), data);
  put_string(this->requester_mesh_mac, data);
}

int ServerToEscrow_DecryptRequest_Message::deserialize(std::vector<unsigned char> &data) {
  int n = 1;
  n += get_string(&this->group_id, data, n);
  std::vector<unsigned char> ciphertext_data(data.begin() + n, data.end());
  n += this->ciphertext.deserialize(ciphertext_data);
  n += get_string(&this->requester_id, data, n);
  std::string pub_str;
  n += get_string(&pub_str, data, n);
  this->requester_dh_pub = string_to_byteblock(pub_str);
  n += get_string(&this->requester_mesh_mac, data, n);
  return n;
}

void EscrowToServer_FlagGroup_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_FlagGroup_Message);
  put_string(this->escrow_id, data);
  put_string(this->group_id, data);
  put_string(byteblock_to_string(this->requester_dh_pub), data);
  put_string(this->mesh_mac, data);
  put_string(this->auth_tag, data);
}

int EscrowToServer_FlagGroup_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_FlagGroup_Message);
  int n = 1;
  n += get_string(&this->escrow_id, data, n);
  n += get_string(&this->group_id, data, n);
  std::string pub_str;
  n += get_string(&pub_str, data, n);
  this->requester_dh_pub = string_to_byteblock(pub_str);
  n += get_string(&this->mesh_mac, data, n);
  n += get_string(&this->auth_tag, data, n);
  return n;
}

void EscrowToServer_EncryptedPartial_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_EncryptedPartial_Message);
  put_string(this->from_id, data);
  put_string(this->group_id, data);
  put_string(byteblock_to_string(this->responder_dh_pub), data);
  put_string(this->iv, data);
  put_string(this->ciphertext, data);
  put_string(this->mac, data);
}

int EscrowToServer_EncryptedPartial_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_EncryptedPartial_Message);
  int n = 1;
  n += get_string(&this->from_id, data, n);
  n += get_string(&this->group_id, data, n);
  std::string pub_str;
  n += get_string(&pub_str, data, n);
  this->responder_dh_pub = string_to_byteblock(pub_str);
  n += get_string(&this->iv, data, n);
  n += get_string(&this->ciphertext, data, n);
  n += get_string(&this->mac, data, n);
  return n;
}

void ServerToEscrow_PartialBundle_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToEscrow_PartialBundle_Message);
  put_string(this->group_id, data);
  this->ciphertext.serialize(data);
  put_integer(CryptoPP::Integer(this->partials.size()), data);
  for (const auto &p : this->partials) {
    put_string(p.from_id, data);
    put_integer(p.partial_pk, data);
    put_string(p.responder_dh_pub, data);
    put_string(p.iv, data);
    put_string(p.ciphertext, data);
    put_string(p.mac, data);
  }
  put_integer(CryptoPP::Integer(this->messages.size()), data);
  for (const auto &m : this->messages) {
    put_integer(CryptoPP::Integer(m.message_id), data);
    put_string(m.sender_id, data);
    put_string(m.iv, data);
    put_string(m.ciphertext, data);
    put_string(m.mac, data);
    put_string(m.signature, data);
  }
  put_integer(CryptoPP::Integer(this->sender_certificates.size()), data);
  for (auto &certificate : this->sender_certificates) {
    certificate.serialize(data);
  }
}

int ServerToEscrow_PartialBundle_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToEscrow_PartialBundle_Message);
  int n = 1;
  n += get_string(&this->group_id, data, n);
  std::vector<unsigned char> ciphertext_data(data.begin() + n, data.end());
  n += this->ciphertext.deserialize(ciphertext_data);
  CryptoPP::Integer partial_count;
  n += get_integer(&partial_count, data, n);
  this->partials.clear();
  for (int i = 0; i < checked_count(partial_count); ++i) {
    EncryptedPartialEntry p;
    n += get_string(&p.from_id, data, n);
    n += get_integer(&p.partial_pk, data, n);
    n += get_string(&p.responder_dh_pub, data, n);
    n += get_string(&p.iv, data, n);
    n += get_string(&p.ciphertext, data, n);
    n += get_string(&p.mac, data, n);
    this->partials.push_back(std::move(p));
  }
  CryptoPP::Integer message_count;
  n += get_integer(&message_count, data, n);
  this->messages.clear();
  for (int i = 0; i < checked_count(message_count); ++i) {
    GroupChatMessage m;
    CryptoPP::Integer message_id;
    n += get_integer(&message_id, data, n);
    m.message_id = message_id.ConvertToLong();
    n += get_string(&m.sender_id, data, n);
    n += get_string(&m.iv, data, n);
    n += get_string(&m.ciphertext, data, n);
    n += get_string(&m.mac, data, n);
    n += get_string(&m.signature, data, n);
    this->messages.push_back(std::move(m));
  }
  CryptoPP::Integer certificate_count;
  n += get_integer(&certificate_count, data, n);
  this->sender_certificates.clear();
  for (int i = 0; i < checked_count(certificate_count); ++i) {
    Certificate_Message certificate;
    std::vector<unsigned char> certificate_data(data.begin() + n, data.end());
    n += certificate.deserialize(certificate_data);
    this->sender_certificates.push_back(std::move(certificate));
  }
  return n;
}

void EscrowToServer_DecryptReady_Message::serialize(
    std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_DecryptReady_Message);
  put_string(this->escrow_id, data);
  put_string(this->auth_tag, data);
}

int EscrowToServer_DecryptReady_Message::deserialize(
    std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_DecryptReady_Message);
  int n = 1;
  n += get_string(&this->escrow_id, data, n);
  n += get_string(&this->auth_tag, data, n);
  return n;
}

void EscrowToServer_DHPublicValue_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_DHPublicValue_Message);
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

int EscrowToServer_DHPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_DHPublicValue_Message);
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

void ServerToEscrow_DHPublicValue_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToEscrow_DHPublicValue_Message);
  std::string server_public_string = byteblock_to_string(this->server_public_value);
  std::string escrow_public_string = byteblock_to_string(this->escrow_public_value);
  put_string(server_public_string, data);
  put_string(escrow_public_string, data);
  put_string(this->server_signature, data);
}

int ServerToEscrow_DHPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToEscrow_DHPublicValue_Message);
  std::string server_public_string;
  std::string escrow_public_string;
  int n = 1;
  n += get_string(&server_public_string, data, n);
  n += get_string(&escrow_public_string, data, n);
  n += get_string(&this->server_signature, data, n);

  this->server_public_value = string_to_byteblock(server_public_string);
  this->escrow_public_value = string_to_byteblock(escrow_public_string);
  return n;
}

// --- ServerToEscrow_DKGStart_Message ---

void ServerToEscrow_DKGStart_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToEscrow_DKGStart_Message);
  put_string(this->group_id, data);
  put_integer(CryptoPP::Integer(this->n), data);
  put_integer(CryptoPP::Integer(this->t), data);
  // Serialize vector of escrow_ids
  put_integer(CryptoPP::Integer(this->escrow_ids.size()), data);
  for (const auto &id : this->escrow_ids) {
    put_string(id, data);
  }
}

int ServerToEscrow_DKGStart_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToEscrow_DKGStart_Message);
  int n_bytes = 1;
  n_bytes += get_string(&this->group_id, data, n_bytes);
  CryptoPP::Integer n_int, t_int, count_int;
  n_bytes += get_integer(&n_int, data, n_bytes);
  this->n = n_int.ConvertToLong();
  n_bytes += get_integer(&t_int, data, n_bytes);
  this->t = t_int.ConvertToLong();
  n_bytes += get_integer(&count_int, data, n_bytes);
  int count = checked_count(count_int, 16);
  this->escrow_ids.clear();
  for (int i = 0; i < count; i++) {
    std::string id;
    n_bytes += get_string(&id, data, n_bytes);
    this->escrow_ids.push_back(id);
  }
  return n_bytes;
}

// --- DKG_FeldmanCommitment ---

void DKG_FeldmanCommitment::serialize(std::vector<unsigned char> &data) {
  // No message type byte — this is a sub-struct, not a top-level message.
  // When used as a standalone message, the parent adds the type byte.
  put_string(this->dealer_id, data);
  put_integer(CryptoPP::Integer(this->commitments.size()), data);
  for (const auto &c : this->commitments) {
    put_integer(c, data);
  }
}

int DKG_FeldmanCommitment::deserialize(std::vector<unsigned char> &data) {
  int n = 0;
  n += get_string(&this->dealer_id, data, n);
  CryptoPP::Integer count_int;
  n += get_integer(&count_int, data, n);
  int count = checked_count(count_int, 16);
  this->commitments.clear();
  for (int i = 0; i < count; i++) {
    CryptoPP::Integer c;
    n += get_integer(&c, data, n);
    this->commitments.push_back(c);
  }
  return n;
}

// --- EscrowToServer_DKGCommitment_Message ---

void EscrowToServer_DKGCommitment_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_DKGCommitment_Message);
  put_string(this->escrow_id, data);
  // Serialize the commitment sub-struct inline
  this->commitment.serialize(data);
}

int EscrowToServer_DKGCommitment_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_DKGCommitment_Message);
  int n = 1;
  n += get_string(&this->escrow_id, data, n);
  std::vector<unsigned char> slice(data.begin() + n, data.end());
  n += this->commitment.deserialize(slice);
  return n;
}

// --- ServerToEscrow_DKGAllCommitments_Message ---

void ServerToEscrow_DKGAllCommitments_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToEscrow_DKGAllCommitments_Message);
  put_integer(CryptoPP::Integer(this->all_commitments.size()), data);
  for (auto &c : this->all_commitments) {
    c.serialize(data);
  }
}

int ServerToEscrow_DKGAllCommitments_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToEscrow_DKGAllCommitments_Message);
  int n = 1;
  CryptoPP::Integer count_int;
  n += get_integer(&count_int, data, n);
  int count = checked_count(count_int, 16);
  this->all_commitments.clear();
  for (int i = 0; i < count; i++) {
    DKG_FeldmanCommitment c;
    std::vector<unsigned char> slice(data.begin() + n, data.end());
    n += c.deserialize(slice);
    this->all_commitments.push_back(c);
  }
  return n;
}

// --- DKG_DHPublicValue ---

void DKG_DHPublicValue::serialize(std::vector<unsigned char> &data) {
  put_string(this->from_id, data);
  put_string(this->to_id, data);
  std::string pub_str = byteblock_to_string(this->public_value);
  put_string(pub_str, data);
}

int DKG_DHPublicValue::deserialize(std::vector<unsigned char> &data) {
  int n = 0;
  n += get_string(&this->from_id, data, n);
  n += get_string(&this->to_id, data, n);
  std::string pub_str;
  n += get_string(&pub_str, data, n);
  this->public_value = string_to_byteblock(pub_str);
  return n;
}

// --- EscrowToServer_DKGDHPublicValues_Message ---

void EscrowToServer_DKGDHPublicValues_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_DKGDHPublicValues_Message);
  put_string(this->from_id, data);
  put_integer(CryptoPP::Integer(this->values.size()), data);
  for (auto &v : this->values) {
    v.serialize(data);
  }
}

int EscrowToServer_DKGDHPublicValues_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_DKGDHPublicValues_Message);
  int n = 1;
  n += get_string(&this->from_id, data, n);
  CryptoPP::Integer count_int;
  n += get_integer(&count_int, data, n);
  int count = checked_count(count_int, 16);
  this->values.clear();
  for (int i = 0; i < count; i++) {
    DKG_DHPublicValue v;
    std::vector<unsigned char> slice(data.begin() + n, data.end());
    n += v.deserialize(slice);
    this->values.push_back(v);
  }
  return n;
}

// --- ServerToEscrow_DKGDHDelivery_Message ---

void ServerToEscrow_DKGDHDelivery_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToEscrow_DKGDHDelivery_Message);
  put_integer(CryptoPP::Integer(this->values.size()), data);
  for (auto &v : this->values) {
    v.serialize(data);
  }
}

int ServerToEscrow_DKGDHDelivery_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToEscrow_DKGDHDelivery_Message);
  int n = 1;
  CryptoPP::Integer count_int;
  n += get_integer(&count_int, data, n);
  int count = checked_count(count_int, 16);
  this->values.clear();
  for (int i = 0; i < count; i++) {
    DKG_DHPublicValue v;
    std::vector<unsigned char> slice(data.begin() + n, data.end());
    n += v.deserialize(slice);
    this->values.push_back(v);
  }
  return n;
}

// --- DKG_EncryptedShare ---

void DKG_EncryptedShare::serialize(std::vector<unsigned char> &data) {
  put_string(this->from_id, data);
  put_string(this->to_id, data);
  put_string(this->iv, data);
  put_string(this->ciphertext, data);
  put_string(this->mac, data);
}

int DKG_EncryptedShare::deserialize(std::vector<unsigned char> &data) {
  int n = 0;
  n += get_string(&this->from_id, data, n);
  n += get_string(&this->to_id, data, n);
  n += get_string(&this->iv, data, n);
  n += get_string(&this->ciphertext, data, n);
  n += get_string(&this->mac, data, n);
  return n;
}

// --- EscrowToServer_DKGShareBundle_Message ---

void EscrowToServer_DKGShareBundle_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_DKGShareBundle_Message);
  put_string(this->from_id, data);
  put_integer(CryptoPP::Integer(this->shares.size()), data);
  for (auto &s : this->shares) {
    s.serialize(data);
  }
}

int EscrowToServer_DKGShareBundle_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_DKGShareBundle_Message);
  int n = 1;
  n += get_string(&this->from_id, data, n);
  CryptoPP::Integer count_int;
  n += get_integer(&count_int, data, n);
  int count = checked_count(count_int, 16);
  this->shares.clear();
  for (int i = 0; i < count; i++) {
    DKG_EncryptedShare s;
    std::vector<unsigned char> slice(data.begin() + n, data.end());
    n += s.deserialize(slice);
    this->shares.push_back(s);
  }
  return n;
}

// --- ServerToEscrow_DKGShareDelivery_Message ---

void ServerToEscrow_DKGShareDelivery_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToEscrow_DKGShareDelivery_Message);
  put_integer(CryptoPP::Integer(this->shares.size()), data);
  for (auto &s : this->shares) {
    s.serialize(data);
  }
}

int ServerToEscrow_DKGShareDelivery_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToEscrow_DKGShareDelivery_Message);
  int n = 1;
  CryptoPP::Integer count_int;
  n += get_integer(&count_int, data, n);
  int count = checked_count(count_int, 16);
  this->shares.clear();
  for (int i = 0; i < count; i++) {
    DKG_EncryptedShare s;
    std::vector<unsigned char> slice(data.begin() + n, data.end());
    n += s.deserialize(slice);
    this->shares.push_back(s);
  }
  return n;
}

// --- EscrowToServer_DKGComplete_Message ---

void EscrowToServer_DKGComplete_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::EscrowToServer_DKGComplete_Message);
  put_string(this->escrow_id, data);
  put_integer(this->partial_pk, data);
}

int EscrowToServer_DKGComplete_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::EscrowToServer_DKGComplete_Message);
  int n = 1;
  n += get_string(&this->escrow_id, data, n);
  n += get_integer(&this->partial_pk, data, n);
  return n;
}

// --- UserToServer_GroupMembershipRequest_Message ---

void UserToServer_GroupMembershipRequest_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_GroupMembershipRequest_Message);
  put_string(this->user_id, data);
}

int UserToServer_GroupMembershipRequest_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_GroupMembershipRequest_Message);
  int n = 1;
  n += get_string(&this->user_id, data, n);
  return n;
}

// --- ServerToUser_GroupMembershipResponse_Message ---

void ServerToUser_GroupMembershipResponse_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToUser_GroupMembershipResponse_Message);
  put_integer(CryptoPP::Integer(this->group_ids.size()), data);
  for (const auto &g : this->group_ids) {
    put_string(g, data);
  }
}

int ServerToUser_GroupMembershipResponse_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToUser_GroupMembershipResponse_Message);
  int n = 1;
  CryptoPP::Integer count;
  n += get_integer(&count, data, n);
  this->group_ids.clear();
  for (int i = 0; i < checked_count(count); ++i) {
    std::string g;
    n += get_string(&g, data, n);
    this->group_ids.push_back(g);
  }
  return n;
}

// --- UserToServer_GetRegisteredUsers_Message ---

void UserToServer_GetRegisteredUsers_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::UserToServer_GetRegisteredUsers_Message);
  put_string(this->user_id, data);
}

int UserToServer_GetRegisteredUsers_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::UserToServer_GetRegisteredUsers_Message);
  int n = 1;
  n += get_string(&this->user_id, data, n);
  return n;
}

// --- ServerToUser_GetRegisteredUsers_Response_Message ---

void ServerToUser_GetRegisteredUsers_Response_Message::serialize(std::vector<unsigned char> &data) {
  data.push_back((char)MessageType::ServerToUser_GetRegisteredUsers_Response_Message);
  put_integer(CryptoPP::Integer(this->user_ids.size()), data);
  for (const auto &u : this->user_ids) {
    put_string(u, data);
  }
}

int ServerToUser_GetRegisteredUsers_Response_Message::deserialize(std::vector<unsigned char> &data) {
  assert(data[0] == MessageType::ServerToUser_GetRegisteredUsers_Response_Message);
  int n = 1;
  CryptoPP::Integer count;
  n += get_integer(&count, data, n);
  this->user_ids.clear();
  for (int i = 0; i < checked_count(count); ++i) {
    std::string u;
    n += get_string(&u, data, n);
    this->user_ids.push_back(u);
  }
  return n;
}
