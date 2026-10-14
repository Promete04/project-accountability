#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/modarith.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rsa.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/db_driver.hpp"

class VoteClient {
public:
  static ElGamal_Ciphertext Encrypt(CryptoPP::Integer m, CryptoPP::Integer pk);

  static std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
  PartialDecrypt(ElGamal_Ciphertext ciphertext, CryptoPP::Integer partial_pk,
                 CryptoPP::Integer sk);

  static bool
  VerifyPartialDecryptZKP(Escrow_PartialDecryption_Message escrow_msg,
                          CryptoPP::Integer pki);

  static CryptoPP::Integer
  CombineResults(ElGamal_Ciphertext ciphertext,
                 std::vector<Escrow_PartialDecryption_Message> all_partial_decryptions);
};
