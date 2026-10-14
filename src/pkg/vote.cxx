#include "../../include/pkg/vote.hpp"
#include "../../include-shared/logger.hpp"
#include "constants.hpp"
#include "drivers/crypto_driver.hpp"
#include "drivers/db_driver.hpp"
#include "messages.hpp"
#include "util.hpp"

namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Standard ElGamal encryption: (a, b) = (g^r, m * pk^r)
 */
ElGamal_Ciphertext VoteClient::Encrypt(CryptoPP::Integer m,
                                       CryptoPP::Integer pk) {

  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer min = CryptoPP::Integer::One();
  CryptoPP::Integer max = DL_Q - CryptoPP::Integer::One();
  CryptoPP::Integer r(prng, min, max);

  CryptoPP::Integer a = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
  CryptoPP::Integer pk_pow_r = CryptoPP::ModularExponentiation(pk, r, DL_P);
  CryptoPP::Integer b = CryptoPP::ModularMultiplication(m, pk_pow_r, DL_P);

  ElGamal_Ciphertext ct;
  ct.a = a;
  ct.b = b;
  return ct;
}

/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
VoteClient::PartialDecrypt(ElGamal_Ciphertext ciphertext,
                           CryptoPP::Integer partial_pk,
                           CryptoPP::Integer sk) {

  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer min = CryptoPP::Integer::One();
  CryptoPP::Integer max = DL_Q - CryptoPP::Integer::One();

  CryptoPP::Integer r(prng, min, max);

  PartialDecryption_Struct pd_s;
  pd_s.d = CryptoPP::ModularExponentiation(ciphertext.a, sk, DL_P);
  pd_s.aggregate_ciphertext = ciphertext;

  DecryptionZKP_Struct dz_s;

  dz_s.u = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
  dz_s.v = CryptoPP::ModularExponentiation(ciphertext.a, r, DL_P);

  CryptoPP::Integer sigma =
      hash_dec_zkp(partial_pk, ciphertext.a, pd_s.d, dz_s.u, dz_s.v);
  sigma = sigma % DL_Q;

  CryptoPP::Integer temp = CryptoPP::ModularMultiplication(sk, sigma, DL_Q);
  dz_s.s = (r + temp) % DL_Q;

  return {pd_s, dz_s};
}

/**
 * Verify partial decryption zkp.
 */
bool VoteClient::VerifyPartialDecryptZKP(
    Escrow_PartialDecryption_Message escrow_msg, CryptoPP::Integer pki) {

  CryptoPP::Integer s = escrow_msg.zkp.s;
  CryptoPP::Integer d_i = escrow_msg.dec.d;
  CryptoPP::Integer c1 = escrow_msg.dec.aggregate_ciphertext.a;
  CryptoPP::Integer u = escrow_msg.zkp.u; // A in the slides
  CryptoPP::Integer v = escrow_msg.zkp.v; // B in the slides

  CryptoPP::Integer sigma = hash_dec_zkp(pki, c1, d_i, u, v);
  sigma = sigma % DL_Q;

  CryptoPP::Integer right_1 = CryptoPP::ModularMultiplication(
      u, CryptoPP::ModularExponentiation(pki, sigma, DL_P), DL_P);

  if (ModularExponentiation(DL_G, s, DL_P) != right_1)
    return false;

  CryptoPP::Integer right_2 = CryptoPP::ModularMultiplication(
      v, CryptoPP::ModularExponentiation(d_i, sigma, DL_P), DL_P);

  if (CryptoPP::ModularExponentiation(c1, s, DL_P) != right_2)
    return false;

  return true;
}

/**
 * Combines partial decryptions and returns recovered plaintext m.
 */
CryptoPP::Integer VoteClient::CombineResults(
    ElGamal_Ciphertext ciphertext,
    std::vector<Escrow_PartialDecryption_Message> all_partial_decryptions) {

  CryptoPP::Integer combined_d = CryptoPP::Integer::One();
  CryptoDriver crypto_driver;

  std::vector<int> participants;
  for (const auto& msg : all_partial_decryptions) {
    participants.push_back(std::stoi(msg.escrow_id));
  }

  for (size_t i = 0; i < all_partial_decryptions.size(); i++) {
    int participant_idx = std::stoi(all_partial_decryptions[i].escrow_id);
    CryptoPP::Integer lambda_i = crypto_driver.ComputeLagrangeCoeff(participant_idx, participants);

    CryptoPP::Integer d_i = all_partial_decryptions[i].dec.d;
    CryptoPP::Integer d_i_pow_lambda = CryptoPP::ModularExponentiation(d_i, lambda_i, DL_P);

    combined_d = CryptoPP::ModularMultiplication(combined_d, d_i_pow_lambda, DL_P);
  }

  CryptoPP::Integer inv_c1_sk =
      CryptoPP::EuclideanMultiplicativeInverse(combined_d, DL_P);

  CryptoPP::Integer m =
      CryptoPP::ModularMultiplication(ciphertext.b, inv_c1_sk, DL_P);

  return m;
}
