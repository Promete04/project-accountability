#pragma once

#include <array>
#include <stdexcept>
#include <string>

#include "constants.hpp"

// Demo provisioning for the fixed escrow set.  In a deployed system these
// values belong in a protected provisioning store, not the source tree.  The
// Server-authentication secrets are deliberately distinct from the escrow-only
// mesh secret. The latter is provisioned in include/pkg/escrow_mesh.hpp and is
// deliberately never included by server code.
inline const std::array<std::string, THRESHOLD_N> &authorized_escrow_ids() {
  static const std::array<std::string, THRESHOLD_N> ids = {
      "1", "2", "3", "4", "5"};
  return ids;
}

inline bool is_authorized_escrow(const std::string &id) {
  for (const auto &authorized_id : authorized_escrow_ids()) {
    if (authorized_id == id)
      return true;
  }
  return false;
}

inline const std::string &escrow_server_auth_secret(const std::string &id) {
  static const std::array<std::string, THRESHOLD_N> secrets = {
      "escrow-server-auth-1-v1-2026",
      "escrow-server-auth-2-v1-2026",
      "escrow-server-auth-3-v1-2026",
      "escrow-server-auth-4-v1-2026",
      "escrow-server-auth-5-v1-2026",
  };
  const auto &ids = authorized_escrow_ids();
  for (size_t i = 0; i < ids.size(); ++i) {
    if (ids[i] == id)
      return secrets[i];
  }
  throw std::runtime_error("Unknown escrow ID.");
}
