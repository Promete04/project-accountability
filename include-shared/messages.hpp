#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/rsa.h>

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  HMACTagged_Wrapper = 0,
  Certificate_Message = 1,
  UserToServer_DHPublicValue_Message = 2,
  ServerToUser_DHPublicValue_Message = 3,
  UserToServer_IDPrompt_Message = 4,
  ServerToUser_Salt_Message = 5,
  UserToServer_HashedAndSaltedPassword_Message = 6,
  ServerToUser_PRGSeed_Message = 7,
  UserToServer_PRGValue_Message = 8,
  UserToServer_VerificationKey_Message = 9,
  ServerToUser_IssuedCertificate_Message = 10,
  UserToUser_DHPublicValue_Message = 11,
  UserToUser_Message_Message = 12,
  ElGamal_Ciphertext = 13,
  PartialDecryption_Struct = 14,
  DecryptionZKP_Struct = 15,
  Escrow_PartialDecryption_Message = 16,
  EscrowToServer_Keygen_Message = 17,
  ServerToEscrow_DecryptRequest_Message = 19,
  EscrowToServer_DHPublicValue_Message = 20,
  ServerToEscrow_DHPublicValue_Message = 21,
  // DKG messages
  ServerToEscrow_DKGStart_Message = 22,
  EscrowToServer_DKGCommitment_Message = 23,
  ServerToEscrow_DKGAllCommitments_Message = 24,
  EscrowToServer_DKGDHPublicValues_Message = 25,
  ServerToEscrow_DKGDHDelivery_Message = 26,
  EscrowToServer_DKGShareBundle_Message = 27,
  ServerToEscrow_DKGShareDelivery_Message = 28,
  EscrowToServer_DKGComplete_Message = 29,
  EscrowToServer_DecryptReady_Message = 30,
  UserToServer_GroupCreate_Message = 31,
  UserToServer_GroupSend_Message = 32,
  UserToServer_GroupFetch_Message = 33,
  UserToServer_GroupClose_Message = 34,
  ServerToUser_GroupResult_Message = 35,
  ServerToUser_GroupMessages_Message = 36,
  UserToServer_CertificateRequest_Message = 37,
  ServerToUser_CertificateResponse_Message = 38,
  UserToServer_ElectionKeyRequest_Message = 39,
  ServerToUser_ElectionKeyResponse_Message = 40,
  UserToServer_GroupDKGStart_Message = 41,
  ServerToUser_GroupDKGStatus_Message = 42,
  // Escrow-initiated group flagging: the requesting escrow recovers the group
  // key itself, so the server never sees a plaintext partial decryption.
  EscrowToServer_FlagGroup_Message = 43,
  EscrowToServer_EncryptedPartial_Message = 44,
  ServerToEscrow_PartialBundle_Message = 45,
  // A user asks which groups it belongs to; the server answers from the
  // authenticated session id (see server HandleGroupRequest).
  UserToServer_GroupMembershipRequest_Message = 46,
  ServerToUser_GroupMembershipResponse_Message = 47,
  UserToServer_GetRegisteredUsers_Message = 48,
  ServerToUser_GetRegisteredUsers_Response_Message = 49,
};
};

MessageType::T get_message_type(std::vector<unsigned char> &data);


// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// serializers.
int put_bool(bool b, std::vector<unsigned char> &data);
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// deserializers
int get_bool(bool *b, std::vector<unsigned char> &data, int idx);
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Certificate_Message : public Serializable {
  std::string id;
  CryptoPP::RSA::PublicKey verification_key;
  CryptoPP::RSA::PublicKey encryption_key;
  std::string server_signature; // computed on id + verification_key

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// USER <=> SERVER MESSAGES
// ================================================

struct UserToServer_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock server_public_value;
  CryptoPP::SecByteBlock user_public_value;
  std::string server_signature; // computed on server_value + user_value

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_IDPrompt_Message : public Serializable {
  std::string id;
  bool new_user;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_Salt_Message : public Serializable {
  std::string salt;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_HashedAndSaltedPassword_Message : public Serializable {
  std::string hspw;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_PRGSeed_Message : public Serializable {
  CryptoPP::SecByteBlock seed;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_PRGValue_Message : public Serializable {
  CryptoPP::SecByteBlock value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_VerificationKey_Message : public Serializable {
  CryptoPP::RSA::PublicKey verification_key;
  CryptoPP::RSA::PublicKey encryption_key;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_IssuedCertificate_Message : public Serializable {
  Certificate_Message certificate;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_CertificateRequest_Message : public Serializable {
  std::string user_id;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_CertificateResponse_Message : public Serializable {
  bool found;
  Certificate_Message certificate;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_ElectionKeyRequest_Message : public Serializable {
  std::string group_id;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_ElectionKeyResponse_Message : public Serializable {
  bool available;
  std::string group_id;
  CryptoPP::Integer public_key;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// The first group-create attempt uses this lightweight request to reserve the
// group ID and start its escrow DKG. Once the DKG is ready, the normal signed
// GroupCreate message carries the encrypted group-key envelopes.
struct UserToServer_GroupDKGStart_Message : public Serializable {
  std::string group_id;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_GroupDKGStatus_Message : public Serializable {
  bool ready = false;
  bool started = false;
  std::string group_id;
  std::string detail;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_GroupCreate_Message : public Serializable {
  std::string group_id;
  std::vector<std::string> member_ids;
  struct KeyEnvelope {
    std::string recipient_id;
    std::string wrapped_group_key;
  };
  std::vector<KeyEnvelope> member_envelopes;
  CryptoPP::Integer escrow_envelope_a;
  CryptoPP::Integer escrow_envelope_b;
  std::string creator_signature;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_GroupSend_Message : public Serializable {
  std::string group_id;
  std::string iv;
  std::string ciphertext;
  std::string mac;
  std::string signature;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_GroupFetch_Message : public Serializable {
  std::string group_id;
  // Only messages with id > since_id are returned; 0 fetches the full history.
  int since_id = 0;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_GroupClose_Message : public Serializable {
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_GroupResult_Message : public Serializable {
  bool success;
  std::string detail;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct GroupChatMessage {
  int message_id = 0;
  std::string sender_id;
  std::string iv;
  std::string ciphertext;
  std::string mac;
  std::string signature;
};

// Canonical, length-prefixed bytes covered by a sender's RSA-PSS signature.
// The DB-assigned message ID is deliberately excluded: it does not exist when
// the sender creates the signature.
std::vector<unsigned char> group_message_signature_input(
    const std::string &group_id, const std::string &sender_id,
    const std::string &iv, const std::string &ciphertext,
    const std::string &mac);

struct ServerToUser_GroupMessages_Message : public Serializable {
  std::string group_id;
  std::string wrapped_group_key;
  std::vector<GroupChatMessage> messages;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_GroupMembershipRequest_Message : public Serializable {
  std::string user_id;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_GroupMembershipResponse_Message : public Serializable {
  std::vector<std::string> group_ids;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_GetRegisteredUsers_Message : public Serializable {
  std::string user_id;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_GetRegisteredUsers_Response_Message : public Serializable {
  std::vector<std::string> user_ids;
  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// USER <=> USER MESSAGES
// ================================================

struct UserToUser_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;
  Certificate_Message certificate;
  std::string user_signature; // computed on public_value + certificate

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToUser_Message_Message : public Serializable {
  std::string msg;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// THRESHOLD ESCROW MESSAGES
// ================================================

// Struct for an ElGamal ciphertext (a, b) := (g^r, pk^r * m)
struct ElGamal_Ciphertext : public Serializable {
  CryptoPP::Integer a;
  CryptoPP::Integer b;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// Struct for a pd of `aggregate_ciphertext` (d) = (a^{sk_i})
struct PartialDecryption_Struct : public Serializable {
  CryptoPP::Integer d;
  ElGamal_Ciphertext aggregate_ciphertext;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// Struct for a pd zkp of vote (a, b): (u, v, s) = (g^r, a^r, s)
struct DecryptionZKP_Struct : public Serializable {
  CryptoPP::Integer u;
  CryptoPP::Integer v;
  CryptoPP::Integer s;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Escrow_PartialDecryption_Message : public Serializable {
  std::string escrow_id;
  std::string group_id;
  PartialDecryption_Struct dec;
  DecryptionZKP_Struct zkp;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct EscrowToServer_Keygen_Message : public Serializable {
  std::string escrow_id;
  std::string group_id;
  std::string auth_tag;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToEscrow_DecryptRequest_Message : public Serializable {
  std::string group_id;
  ElGamal_Ciphertext ciphertext;
  // The escrow that initiated the flag. Responders encrypt their partial to
  // requester_dh_pub so only the requester — never the server — can read it.
  std::string requester_id;
  CryptoPP::SecByteBlock requester_dh_pub;
  // HMAC from the requesting escrow's mesh key over the requester, group and
  // DH public value. Responders verify it before producing a partial.
  std::string requester_mesh_mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// An escrow asks the server to coordinate a threshold decryption of a group's
// key, carrying the ephemeral DH public value responders will encrypt to.
struct EscrowToServer_FlagGroup_Message : public Serializable {
  std::string escrow_id;
  std::string group_id;
  CryptoPP::SecByteBlock requester_dh_pub;
  std::string mesh_mac;
  std::string auth_tag;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// A responder's partial decryption, encrypted under the DH secret shared with
// the requesting escrow. The server relays this blob without reading it.
struct EscrowToServer_EncryptedPartial_Message : public Serializable {
  std::string from_id;
  std::string group_id;
  CryptoPP::SecByteBlock responder_dh_pub;
  std::string iv;         // byteblock_to_string of the AES IV
  std::string ciphertext; // AES(K, serialized Escrow_PartialDecryption_Message)
  std::string mac;        // HMAC over responder metadata + ciphertext

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// One collected encrypted partial as delivered to the requesting escrow. The
// server attaches partial_pk (g^{z_i}) so the requester can verify the ZKP.
struct EncryptedPartialEntry {
  std::string from_id;
  CryptoPP::Integer partial_pk;
  std::string responder_dh_pub; // byteblock_to_string
  std::string iv;
  std::string ciphertext;
  std::string mac;
};

// Everything the requesting escrow needs to recover the group key locally and
// decrypt the group's stored messages.
struct ServerToEscrow_PartialBundle_Message : public Serializable {
  std::string group_id;
  ElGamal_Ciphertext ciphertext; // the group's escrow envelope (a, b)
  std::vector<EncryptedPartialEntry> partials;
  std::vector<GroupChatMessage> messages;
  // Certificates are sent once per sender so the recovering escrow can verify
  // message signatures without the group key or a user login session.
  std::vector<Certificate_Message> sender_certificates;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// Sent after the authenticated server-channel handshake when an escrow is
// available to process one pending decryption request.
struct EscrowToServer_DecryptReady_Message : public Serializable {
  std::string escrow_id;
  std::string auth_tag;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct EscrowToServer_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToEscrow_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock server_public_value;
  CryptoPP::SecByteBlock escrow_public_value;
  std::string server_signature; // computed on server_value + escrow_value

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};


// ================================================
// SIGNING HELPERS
// ================================================

std::vector<unsigned char>
concat_string_and_rsakey(std::string &s, CryptoPP::RSA::PublicKey &k);
std::vector<unsigned char> concat_string_and_two_rsakeys(
    std::string &s, CryptoPP::RSA::PublicKey &signing_key,
    CryptoPP::RSA::PublicKey &encryption_key);
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2);
std::vector<unsigned char> concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                                                     Certificate_Message &cert);

// ================================================
// DKG (Distributed Key Generation) MESSAGES
// ================================================

struct ServerToEscrow_DKGStart_Message : public Serializable {
  std::string group_id;
  int n;
  int t;
  std::vector<std::string> escrow_ids;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct DKG_FeldmanCommitment : public Serializable {
  std::string dealer_id;
  std::vector<CryptoPP::Integer> commitments; // G^{c_k} for k=0..t-1

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct EscrowToServer_DKGCommitment_Message : public Serializable {
  std::string escrow_id;
  DKG_FeldmanCommitment commitment;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToEscrow_DKGAllCommitments_Message : public Serializable {
  std::vector<DKG_FeldmanCommitment> all_commitments;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct DKG_DHPublicValue : public Serializable {
  std::string from_id;
  std::string to_id;
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct EscrowToServer_DKGDHPublicValues_Message : public Serializable {
  std::string from_id;
  std::vector<DKG_DHPublicValue> values;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToEscrow_DKGDHDelivery_Message : public Serializable {
  std::vector<DKG_DHPublicValue> values;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct DKG_EncryptedShare : public Serializable {
  std::string from_id;
  std::string to_id;
  std::string iv;
  std::string ciphertext; // AES-CBC encryption of f_i(j)
  std::string mac;        // HMAC over the share context + ciphertext

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct EscrowToServer_DKGShareBundle_Message : public Serializable {
  std::string from_id;
  std::vector<DKG_EncryptedShare> shares;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToEscrow_DKGShareDelivery_Message : public Serializable {
  std::vector<DKG_EncryptedShare> shares;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct EscrowToServer_DKGComplete_Message : public Serializable {
  std::string escrow_id;
  CryptoPP::Integer partial_pk; // G^{z_i}

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};
