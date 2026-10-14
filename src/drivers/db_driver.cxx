#include <fstream>
#include <iostream>
#include <stdexcept>

#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

/**
 * Initialize DBDriver.
 */
DBDriver::DBDriver() {}

/**
 * Open a particular db file.
 */
int DBDriver::open(std::string dbpath) {
  return sqlite3_open(dbpath.c_str(), &this->db);
}

/**
 * Close db.
 */
int DBDriver::close() { return sqlite3_close(this->db); }

/**
 * Initialize tables.
 */
void DBDriver::init_tables() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string create_query = "CREATE TABLE IF NOT EXISTS user("
                             "user_id TEXT PRIMARY KEY NOT NULL, "
                             "password_hash TEXT NOT NULL, "
                             "password_salt TEXT NOT NULL, "
                             "prg_seed TEXT NOT NULL, "
                             "certificate_data BLOB);";
  char *err;
  int exit = sqlite3_exec(this->db, create_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }
  // Existing development databases predate certificates. Ignore the duplicate
  // column error when the migration has already been applied.
  sqlite3_exec(this->db, "ALTER TABLE user ADD COLUMN certificate_data BLOB",
               NULL, 0, &err);
  const char *group_tables[] = {
      "CREATE TABLE IF NOT EXISTS chat_group(group_id TEXT PRIMARY KEY, creator_id TEXT NOT NULL, escrow_a TEXT NOT NULL, escrow_b TEXT NOT NULL, creator_signature BLOB NOT NULL)",
      "CREATE TABLE IF NOT EXISTS group_member(group_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY(group_id, user_id))",
      "CREATE TABLE IF NOT EXISTS group_envelope(group_id TEXT NOT NULL, recipient_id TEXT NOT NULL, wrapped_group_key BLOB NOT NULL, PRIMARY KEY(group_id, recipient_id))",
      "CREATE TABLE IF NOT EXISTS group_message(id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT NOT NULL, sender_id TEXT NOT NULL, iv BLOB NOT NULL, ciphertext BLOB NOT NULL, mac BLOB NOT NULL, signature BLOB NOT NULL)",
      "CREATE TABLE IF NOT EXISTS group_dkg(group_id TEXT PRIMARY KEY, creator_id TEXT NOT NULL, public_key TEXT NOT NULL)",
      "CREATE TABLE IF NOT EXISTS group_dkg_escrow(group_id TEXT NOT NULL, escrow_id TEXT NOT NULL, partial_public_key TEXT NOT NULL, PRIMARY KEY(group_id, escrow_id))"};
  for (const char *query : group_tables) sqlite3_exec(this->db, query, NULL, 0, &err);

  // The earliest group prototype created chat_group with only group_id. Add
  // the later group-setup fields in place so a completed DKG remains usable
  // after upgrading instead of forcing the escrows to run it again.
  const char *chat_group_migrations[] = {
      "ALTER TABLE chat_group ADD COLUMN creator_id TEXT",
      "ALTER TABLE chat_group ADD COLUMN escrow_a TEXT",
      "ALTER TABLE chat_group ADD COLUMN escrow_b TEXT",
      "ALTER TABLE chat_group ADD COLUMN creator_signature BLOB"};
  for (const char *query : chat_group_migrations) {
    char *migration_err = nullptr;
    const int migration_rc =
        sqlite3_exec(this->db, query, NULL, 0, &migration_err);
    if (migration_rc != SQLITE_OK && migration_err != nullptr &&
        std::string(migration_err).find("duplicate column name") ==
            std::string::npos) {
      std::cerr << "Error migrating chat_group: " << migration_err
                << std::endl;
    }
    sqlite3_free(migration_err);
  }
  const char *group_message_migrations[] = {
      "ALTER TABLE group_message ADD COLUMN signature BLOB NOT NULL DEFAULT ''"};
  for (const char *query : group_message_migrations) {
    char *migration_err = nullptr;
    const int migration_rc =
        sqlite3_exec(this->db, query, NULL, 0, &migration_err);
    if (migration_rc != SQLITE_OK && migration_err != nullptr &&
        std::string(migration_err).find("duplicate column name") ==
            std::string::npos) {
      std::cerr << "Error migrating group_message: " << migration_err
                << std::endl;
    }
    sqlite3_free(migration_err);
  }
  // Development databases created before creator binding can be upgraded in
  // place. A duplicate-column error simply means the schema is current.
  sqlite3_exec(this->db, "ALTER TABLE group_dkg ADD COLUMN creator_id TEXT",
               NULL, 0, &err);
}

/**
 * Reset tables by dropping all.
 */
void DBDriver::reset_tables() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Get all table names
  std::vector<std::string> table_names;
  table_names = {"group_message", "group_envelope", "group_member", "chat_group",
                 "group_dkg_escrow", "group_dkg", "user"};

  sqlite3_stmt *stmt;
  // For each table, drop it
  for (std::string table : table_names) {
    std::string delete_query = "DELETE FROM " + table;
    sqlite3_prepare_v2(this->db, delete_query.c_str(), delete_query.length(),
                       &stmt, nullptr);
    char *err;
    int exit = sqlite3_exec(this->db, delete_query.c_str(), NULL, 0, &err);
    if (exit != SQLITE_OK) {
      std::cerr << "Error deleting table entries: " << err << std::endl;
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error resetting tables" << std::endl;
  }
}

/**
 * Find the given user. Returns an empty user if none was found.
 */
UserRow DBDriver::find_user(std::string user_id) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query =
      "SELECT user_id, password_hash, password_salt, prg_seed, certificate_data "
      "FROM user WHERE user_id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, user_id.c_str(), user_id.length(), SQLITE_STATIC);

  // Retreive user.
  UserRow user;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result;
      int num_bytes;
      switch (colIndex) {
      case 0:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        user.user_id = std::string((const char *)raw_result, num_bytes);
        break;
      case 1:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        user.password_hash = std::string((const char *)raw_result, num_bytes);
        break;
      case 2:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        user.password_salt = std::string((const char *)raw_result, num_bytes);
        break;
      case 3:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        user.prg_seed = std::string((const char *)raw_result, num_bytes);
        break;
      case 4:
        raw_result = sqlite3_column_blob(stmt, colIndex);
        num_bytes = sqlite3_column_bytes(stmt, colIndex);
        if (raw_result != nullptr)
          user.certificate_data = std::string((const char *)raw_result, num_bytes);
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding user " << std::endl;
  }
  return user;
}

/**
 * Insert the given user; prints an error if violated a primary key constraint.
 */
UserRow DBDriver::insert_user(UserRow user) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string insert_query = "INSERT INTO user(user_id, password_hash, "
                             "password_salt, prg_seed, certificate_data) VALUES(?, ?, ?, ?, ?);";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, user.user_id.c_str(), user.user_id.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, user.password_hash.c_str(),
                    user.password_hash.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, user.password_salt.c_str(),
                    user.password_salt.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, user.prg_seed.c_str(), user.prg_seed.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 5, user.certificate_data.data(),
                    user.certificate_data.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding user " << std::endl;
  }
  return user;
}

bool DBDriver::update_user_certificate(const std::string &user_id,
                                       const std::string &certificate_data) {
  std::unique_lock<std::mutex> lck(this->mtx);
  sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db,
      "UPDATE user SET certificate_data = ? WHERE user_id = ?", -1, &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, certificate_data.data(), certificate_data.size(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, user_id.c_str(), user_id.size(), SQLITE_TRANSIENT);
  bool updated = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(this->db) == 1;
  sqlite3_finalize(stmt);
  return updated;
}

bool DBDriver::create_group(const GroupRow &group,
                            const std::vector<std::string> &members,
                            const std::vector<GroupEnvelopeRow> &envelopes) {
  std::unique_lock<std::mutex> lock(this->mtx);
  if (members.empty() || members.size() != envelopes.size()) return false;
  sqlite3_exec(this->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
  bool ok = true;
  sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db,
                     "INSERT INTO chat_group(group_id, creator_id, escrow_a, "
                     "escrow_b, creator_signature) VALUES(?, ?, ?, ?, ?)",
                     -1, &stmt, nullptr);
  sqlite3_bind_text(stmt, 1, group.group_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, group.creator_id.c_str(), -1, SQLITE_TRANSIENT);
  std::string a = CryptoPP::IntToString(group.escrow_a), b = CryptoPP::IntToString(group.escrow_b);
  sqlite3_bind_text(stmt, 3, a.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, b.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 5, group.creator_signature.data(), group.creator_signature.size(), SQLITE_TRANSIENT);
  ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  for (size_t i = 0; ok && i < members.size(); ++i) {
    sqlite3_prepare_v2(this->db, "INSERT INTO group_member VALUES(?, ?)", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, group.group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, members[i].c_str(), -1, SQLITE_TRANSIENT);
    ok = sqlite3_step(stmt) == SQLITE_DONE; sqlite3_finalize(stmt);
    if (!ok || envelopes[i].recipient_id != members[i]) { ok = false; break; }
    sqlite3_prepare_v2(this->db, "INSERT INTO group_envelope VALUES(?, ?, ?)", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, group.group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, envelopes[i].recipient_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, envelopes[i].wrapped_group_key.data(), envelopes[i].wrapped_group_key.size(), SQLITE_TRANSIENT);
    ok = sqlite3_step(stmt) == SQLITE_DONE; sqlite3_finalize(stmt);
  }
  sqlite3_exec(this->db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  return ok;
}

bool DBDriver::store_group_dkg(
    const GroupDKGRow &dkg,
    const std::map<std::string, CryptoPP::Integer> &partial_pks) {
  if (dkg.group_id.empty() || partial_pks.empty()) return false;
  std::unique_lock<std::mutex> lock(this->mtx);
  sqlite3_exec(this->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
  bool ok = true;
  sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db,
      "INSERT INTO group_dkg(group_id, creator_id, public_key) VALUES(?, ?, ?)", -1, &stmt,
      nullptr);
  const std::string public_key = CryptoPP::IntToString(dkg.public_key);
  sqlite3_bind_text(stmt, 1, dkg.group_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, dkg.creator_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, public_key.c_str(), -1, SQLITE_TRANSIENT);
  ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);

  for (const auto &[escrow_id, partial_pk] : partial_pks) {
    if (!ok) break;
    sqlite3_prepare_v2(this->db,
        "INSERT INTO group_dkg_escrow(group_id, escrow_id, partial_public_key) "
        "VALUES(?, ?, ?)", -1, &stmt, nullptr);
    const std::string partial_key = CryptoPP::IntToString(partial_pk);
    sqlite3_bind_text(stmt, 1, dkg.group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, escrow_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, partial_key.c_str(), -1, SQLITE_TRANSIENT);
    ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
  }
  sqlite3_exec(this->db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
  return ok;
}

bool DBDriver::get_group_dkg(const std::string &group_id, GroupDKGRow &dkg) {
  std::unique_lock<std::mutex> lock(this->mtx);
  sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db,
      "SELECT creator_id, public_key FROM group_dkg WHERE group_id = ?", -1, &stmt,
      nullptr);
  sqlite3_bind_text(stmt, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
  const bool found = sqlite3_step(stmt) == SQLITE_ROW;
  if (found) {
    dkg.group_id = group_id;
    const auto *creator = sqlite3_column_text(stmt, 0);
    dkg.creator_id = creator == nullptr ? "" :
        reinterpret_cast<const char *>(creator);
    dkg.public_key = CryptoPP::Integer(
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1)));
  }
  sqlite3_finalize(stmt);
  return found;
}

bool DBDriver::get_group_dkg_partial_key(const std::string &group_id,
                                         const std::string &escrow_id,
                                         CryptoPP::Integer &partial_pk) {
  std::unique_lock<std::mutex> lock(this->mtx);
  sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db,
      "SELECT partial_public_key FROM group_dkg_escrow "
      "WHERE group_id = ? AND escrow_id = ?", -1, &stmt, nullptr);
  sqlite3_bind_text(stmt, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, escrow_id.c_str(), -1, SQLITE_TRANSIENT);
  const bool found = sqlite3_step(stmt) == SQLITE_ROW;
  if (found) {
    partial_pk = CryptoPP::Integer(
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
  }
  sqlite3_finalize(stmt);
  return found;
}

bool DBDriver::get_group(const std::string &id, GroupRow &group) {
  std::unique_lock<std::mutex> lock(this->mtx); sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db, "SELECT creator_id, escrow_a, escrow_b, creator_signature FROM chat_group WHERE group_id=?", -1, &stmt, nullptr);
  sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT); bool ok = sqlite3_step(stmt) == SQLITE_ROW;
  if (ok) { group.group_id=id; group.creator_id=(const char*)sqlite3_column_text(stmt,0); group.escrow_a=CryptoPP::Integer((const char*)sqlite3_column_text(stmt,1)); group.escrow_b=CryptoPP::Integer((const char*)sqlite3_column_text(stmt,2)); const char *p=(const char*)sqlite3_column_blob(stmt,3); group.creator_signature.assign(p, sqlite3_column_bytes(stmt,3)); }
  sqlite3_finalize(stmt); return ok;
}

bool DBDriver::get_group_envelope(const std::string &id, const std::string &user, GroupEnvelopeRow &row) {
  std::unique_lock<std::mutex> lock(this->mtx); sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db, "SELECT wrapped_group_key FROM group_envelope WHERE group_id=? AND recipient_id=?", -1, &stmt, nullptr);
  sqlite3_bind_text(stmt,1,id.c_str(),-1,SQLITE_TRANSIENT); sqlite3_bind_text(stmt,2,user.c_str(),-1,SQLITE_TRANSIENT); bool ok=sqlite3_step(stmt)==SQLITE_ROW;
  if(ok){ row.recipient_id=user; const char*p=(const char*)sqlite3_column_blob(stmt,0); row.wrapped_group_key.assign(p,sqlite3_column_bytes(stmt,0)); } sqlite3_finalize(stmt); return ok;
}

bool DBDriver::is_group_member(const std::string &id, const std::string &user) {
  std::unique_lock<std::mutex> lock(this->mtx); sqlite3_stmt *stmt=nullptr; sqlite3_prepare_v2(this->db,"SELECT 1 FROM group_member WHERE group_id=? AND user_id=?",-1,&stmt,nullptr); sqlite3_bind_text(stmt,1,id.c_str(),-1,SQLITE_TRANSIENT); sqlite3_bind_text(stmt,2,user.c_str(),-1,SQLITE_TRANSIENT); bool ok=sqlite3_step(stmt)==SQLITE_ROW; sqlite3_finalize(stmt); return ok;
}

std::vector<std::string> DBDriver::get_user_groups(const std::string &user) {
  std::unique_lock<std::mutex> lock(this->mtx); sqlite3_stmt *stmt=nullptr; sqlite3_prepare_v2(this->db,"SELECT group_id FROM group_member WHERE user_id=? ORDER BY group_id",-1,&stmt,nullptr); sqlite3_bind_text(stmt,1,user.c_str(),-1,SQLITE_TRANSIENT); std::vector<std::string> groups; while(sqlite3_step(stmt)==SQLITE_ROW){ groups.push_back((const char*)sqlite3_column_text(stmt,0)); } sqlite3_finalize(stmt); return groups;
}

bool DBDriver::add_group_message(const std::string &id, const GroupMessageRow &m) {
  std::unique_lock<std::mutex> lock(this->mtx);
  sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db,
                     "INSERT INTO group_message(group_id,sender_id,iv,ciphertext,mac,signature) VALUES(?,?,?,?,?,?)",
                     -1, &stmt, nullptr);
  sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, m.sender_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 3, m.iv.data(), m.iv.size(), SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 4, m.ciphertext.data(), m.ciphertext.size(),
                    SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 5, m.mac.data(), m.mac.size(), SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 6, m.signature.data(), m.signature.size(),
                    SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}


std::vector<GroupMessageRow> DBDriver::get_group_messages(const std::string &id, int since_id) {
  std::unique_lock<std::mutex> lock(this->mtx);
  sqlite3_stmt *stmt = nullptr;
  sqlite3_prepare_v2(this->db,
                     "SELECT id,sender_id,iv,ciphertext,mac,signature FROM group_message WHERE group_id=? AND id>? ORDER BY id",
                     -1, &stmt, nullptr);
  sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, since_id);
  std::vector<GroupMessageRow> rows;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    GroupMessageRow m;
    m.id = sqlite3_column_int(stmt, 0);
    m.sender_id = (const char *)sqlite3_column_text(stmt, 1);
    const char *p = (const char *)sqlite3_column_blob(stmt, 2);
    m.iv.assign(p, sqlite3_column_bytes(stmt, 2));
    p = (const char *)sqlite3_column_blob(stmt, 3);
    m.ciphertext.assign(p, sqlite3_column_bytes(stmt, 3));
    p = (const char *)sqlite3_column_blob(stmt, 4);
    m.mac.assign(p, sqlite3_column_bytes(stmt, 4));
    p = (const char *)sqlite3_column_blob(stmt, 5);
    m.signature.assign(p != nullptr ? p : "", sqlite3_column_bytes(stmt, 5));
    rows.push_back(std::move(m));
  }
  sqlite3_finalize(stmt);
  return rows;
}

/**
 * Get user ids
 */
std::vector<std::string> DBDriver::get_users() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string users_query = "SELECT user_id "
                            "FROM user";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, users_query.c_str(), users_query.length(), &stmt,
                     nullptr);

  // Retreive user.
  UserRow user;
  // Retreive user.
  std::vector<std::string> users;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const void *raw_result;
    int num_bytes;
    raw_result = sqlite3_column_blob(stmt, 0);
    num_bytes = sqlite3_column_bytes(stmt, 0);
    std::string username = std::string((const char *)raw_result, num_bytes);
    users.push_back(username);
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error getting users" << std::endl;
  }
  return users;
}
