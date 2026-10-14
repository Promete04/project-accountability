#pragma once

#include <string>

// Provision this only on escrow installations.  It is intentionally not
// included by server code: the server authenticates escrow identities with its
// own per-escrow secrets but must never hold the mesh secret.
inline const std::string &escrow_mesh_secret() {
  static const std::string secret = "escrow-only-dkg-mesh-v1-2026";
  return secret;
}
