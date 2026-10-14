#pragma once
#include <iostream>
#include <map>
#include <mutex>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <crypto++/integer.h>

struct UserRow {
  std::string user_id;
  std::string password_hash;
  std::string password_salt;
  std::string prg_seed;
  std::string certificate_data;
};

struct GroupRow {
  std::string group_id;
  std::string creator_id;
  CryptoPP::Integer escrow_a;
  CryptoPP::Integer escrow_b;
  std::string creator_signature;
};

struct GroupEnvelopeRow {
  std::string recipient_id;
  std::string wrapped_group_key;
};

struct GroupMessageRow {
  int id = 0;
  std::string sender_id;
  std::string iv;
  std::string ciphertext;
  std::string mac;
  std::string signature;
};

// The threshold public key and each escrow's verification key are retained per
// group so a restart never turns recovery back into a process-global key.
struct GroupDKGRow {
  std::string group_id;
  std::string creator_id;
  CryptoPP::Integer public_key;
};

class DBDriver {
public:
  DBDriver();
  int open(std::string dbpath);
  int close();

  void init_tables();
  void reset_tables();

  UserRow find_user(std::string user_id);
  UserRow insert_user(UserRow user);
  std::vector<std::string> get_users();
  bool update_user_certificate(const std::string &user_id,
                               const std::string &certificate_data);
  bool create_group(const GroupRow &group, const std::vector<std::string> &members,
                    const std::vector<GroupEnvelopeRow> &envelopes);
  bool store_group_dkg(const GroupDKGRow &dkg,
                       const std::map<std::string, CryptoPP::Integer> &partial_pks);
  bool get_group_dkg(const std::string &group_id, GroupDKGRow &dkg);
  bool get_group_dkg_partial_key(const std::string &group_id,
                                 const std::string &escrow_id,
                                 CryptoPP::Integer &partial_pk);
  bool get_group(const std::string &group_id, GroupRow &group);
  bool get_group_envelope(const std::string &group_id, const std::string &user_id,
                          GroupEnvelopeRow &envelope);
  bool is_group_member(const std::string &group_id, const std::string &user_id);
  std::vector<std::string> get_user_groups(const std::string &user_id);
  bool add_group_message(const std::string &group_id, const GroupMessageRow &message);
  std::vector<GroupMessageRow> get_group_messages(const std::string &group_id,
                                                  int since_id = 0);
private:
  std::mutex mtx;
  sqlite3 *db;
};
