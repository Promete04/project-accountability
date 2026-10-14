#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/osrng.h"
#include "crypto++/pssr.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/files.h>
#include <crypto++/queue.h>
#include <utility>
#include <vector>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Encrypts the given message using AES and tags the ciphertext with an
 * HMAC. Outputs an HMACTagged_Wrapper as bytes.
 */
std::vector<unsigned char>
CryptoDriver::encrypt_and_tag(SecByteBlock AES_key, SecByteBlock HMAC_key,
                              Serializable *message) {
  // Serialize given message.
  std::vector<unsigned char> plaintext;
  message->serialize(plaintext);

  // Encrypt the payload, generate iv to hmac.
  std::pair<std::string, SecByteBlock> encrypted =
      this->AES_encrypt(AES_key, chvec2str(plaintext));
  std::string to_tag = std::string((const char *)encrypted.second.data(),
                                   encrypted.second.size()) +
                       encrypted.first;

  // Generate HMAC on the payload.
  HMACTagged_Wrapper msg;
  msg.payload = str2chvec(encrypted.first);
  msg.iv = encrypted.second;
  msg.mac = this->HMAC_generate(HMAC_key, to_tag);

  // Serialize the HMAC and payload.
  std::vector<unsigned char> payload_data;
  msg.serialize(payload_data);
  return payload_data;
}

/**
 * @brief Verifies that the tagged HMAC is valid on the ciphertext and decrypts
 * the given message using AES. Takes in an HMACTagged_Wrapper as bytes.
 */
std::pair<std::vector<unsigned char>, bool>
CryptoDriver::decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                                 std::vector<unsigned char> ciphertext_data) {
  // Deserialize
  HMACTagged_Wrapper ciphertext;
  ciphertext.deserialize(ciphertext_data);

  // Verify HMAC
  std::string to_verify =
      std::string((const char *)ciphertext.iv.data(), ciphertext.iv.size()) +
      chvec2str(ciphertext.payload);
  bool valid = this->HMAC_verify(HMAC_key, to_verify, ciphertext.mac);
  if (!valid)
    return std::make_pair(std::vector<unsigned char>{}, false);

  // Decrypt only after authenticating the ciphertext (encrypt-then-MAC).
  std::string plaintext =
      this->AES_decrypt(AES_key, ciphertext.iv, chvec2str(ciphertext.payload));
  std::vector<unsigned char> plaintext_data = str2chvec(plaintext);
  return std::make_pair(plaintext_data, valid);
}

/**
 * @brief Generate DH keypair.
 */
std::tuple<DH, SecByteBlock, SecByteBlock> CryptoDriver::DH_initialize() {
  DH DH_obj(DL_P, DL_Q, DL_G);
  AutoSeededRandomPool prng;
  SecByteBlock DH_private_key(DH_obj.PrivateKeyLength());
  SecByteBlock DH_public_key(DH_obj.PublicKeyLength());
  DH_obj.GenerateKeyPair(prng, DH_private_key, DH_public_key);
  return std::make_tuple(DH_obj, DH_private_key, DH_public_key);
}

/**
 * @brief Generates a shared secret.
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  SecByteBlock shared_key(DH_obj.AgreedValueLength());
  if (!DH_obj.Agree(shared_key, DH_private_value, DH_other_public_value)) {
    throw std::runtime_error("Failed to generate shared key.");
  }
  return shared_key;
}

/**
 * @brief Generates AES key using HKDF with a salt.
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());

  SecByteBlock derived(AES::DEFAULT_KEYLENGTH);

  HKDF<SHA256> hdkf;

  hdkf.DeriveKey(derived, derived.size(), DH_shared_key, DH_shared_key.size(),
                 aes_salt, aes_salt.size(), NULL, 0);

  return derived;
}

/**
 * Computes the Lagrange coefficient l_i for interpolating f(0) over the given
 * participant x-coordinates, in the field Z_q.
 * TODO: Review
 * Changes:
 *   1. The result is now reduced mod q and its sign normalized before being
 *      returned. The committed version returned `numerator * inverse(...)`
 *      directly — an unreduced, possibly-negative value.
 *   2. Each -j and (i-j) factor is reduced into [0, q) before being multiplied
 *      in, and the denominator is reduced before the modular inverse. The
 *      committed version accumulated raw signed products, so a negative
 *      denominator could reach EuclideanMultiplicativeInverse, where a modular
 *      inverse is not well-defined.
 */
CryptoPP::Integer
CryptoDriver::ComputeLagrangeCoeff(int i,
                                   const std::vector<int> &participants) {
  auto mod_q = [](CryptoPP::Integer x) {
    x %= DL_Q;
    if (x.IsNegative())
      x += DL_Q;
    return x;
  };

  CryptoPP::Integer numerator(1);
  CryptoPP::Integer denominator(1);

  for (int j : participants) {
    if (i == j)
      continue;

    numerator = mod_q(numerator * mod_q(CryptoPP::Integer(-j)));
    denominator = mod_q(denominator * mod_q(CryptoPP::Integer(i - j)));
  }

  return mod_q(numerator * CryptoPP::EuclideanMultiplicativeInverse(denominator,
                                                                    DL_Q));
}

/**
 * @brief Encrypts the given plaintext.
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    CBC_Mode<AES>::Encryption encryptor;
    AutoSeededRandomPool prng;

    SecByteBlock iv(AES::BLOCKSIZE);

    encryptor.GetNextIV(prng, iv.data());
    encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

    std::string ciphertext;

    StringSource ss(
        plaintext, true,
        new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));

    return {ciphertext, iv};
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext.
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    CBC_Mode<AES>::Decryption decryptor;

    decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

    std::string plaintext;

    StringSource(
        ciphertext, true,
        new StreamTransformationFilter(decryptor, new StringSink(plaintext)));

    return plaintext;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt.
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  SecByteBlock derived(SHA256::BLOCKSIZE);
  HKDF<SHA256> hdkf;
  hdkf.DeriveKey(derived, derived.size(), DH_shared_key, DH_shared_key.size(),
                 hmac_salt, hmac_salt.size(), NULL, 0);
  return derived;
}

/**
 * @brief Given a ciphertext, generates an HMAC
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    HMAC<SHA256> hmac(key, key.size());
    std::string mac;
    StringSource ss(ciphertext, true,
                    new HashFilter(hmac, new StringSink(mac)));
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid.
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  try {
    HMAC<SHA256> hmac(key, key.size());
    StringSource ss(ciphertext + mac, true,
                    new HashVerificationFilter(hmac, NULL, flags));
    return true;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

/**
 * @brief Generates RSA public and private keys.
 */
std::pair<RSA::PrivateKey, RSA::PublicKey> CryptoDriver::RSA_generate_keys() {
  RSA::PrivateKey private_key;
  RSA::PublicKey public_key;
  AutoSeededRandomPool prng;
  private_key.GenerateRandomWithKeySize(prng, RSA_KEYSIZE);
  public_key.AssignFrom(private_key);
  if (!private_key.Validate(prng, 3) || !public_key.Validate(prng, 3)) {
    throw std::runtime_error("RSA key generation failed validation.");
  }
  return std::make_pair(private_key, public_key);
}

/**
 * @brief Sign the given message with the given key.
 */
std::string CryptoDriver::RSA_sign(const RSA::PrivateKey &signing_key,
                                   std::vector<unsigned char> message) {
  AutoSeededRandomPool rng;

  RSASS<PSS, SHA256>::Signer signer(signing_key);
  std::string msg = chvec2str(message);

  std::string signature;

  StringSource(msg, true,
               new SignerFilter(rng, signer, new StringSink(signature)));
  return signature;
}

/**
 * @brief Verify that signature is valid with the given key.
 */
bool CryptoDriver::RSA_verify(const RSA::PublicKey &verification_key,
                              std::vector<unsigned char> message,
                              std::string signature) {
  const int flags = SignatureVerificationFilter::PUT_RESULT |
                    SignatureVerificationFilter::SIGNATURE_AT_END;

  RSASS<PSS, SHA256>::Verifier verifier(verification_key);
  std::string msg = chvec2str(message);

  byte result = 0;
  try {
    StringSource(msg + signature, true,
                 new SignatureVerificationFilter(
                     verifier, new ArraySink(&result, 1), flags));
    return result != 0;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

/**
 * @brief Generate a pseudorandom value using AES_RNG given a seed and an iv.
 */
SecByteBlock CryptoDriver::prg(const SecByteBlock &seed, SecByteBlock iv,
                               int size) {
  OFB_Mode<AES>::Encryption prng;
  if (iv.size() < 16) {
    iv.CleanGrow(PRG_SIZE);
  }
  prng.SetKeyWithIV(seed, seed.size(), iv, iv.size());

  SecByteBlock prg_value(size);
  prng.GenerateBlock(prg_value, prg_value.size());
  return prg_value;
}

/**
 * @brief Gets the unix timestamp rounded to the second.
 */
Integer CryptoDriver::nowish() {
  uint64_t sec = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  Integer sec_int(sec);
  return sec_int;
}

/**
 * @brief Generates a random seed of size numBytes as a byte block.
 */
SecByteBlock CryptoDriver::png(int numBytes) {
  SecByteBlock seed(numBytes);
  OS_GenerateRandomBlock(false, seed, seed.size());
  return seed;
}

/**
 * @brief Generates a SHA-256 hash of msg.
 */
std::string CryptoDriver::hash(std::string msg) {
  SHA256 hash;
  std::string encodedHex;
  HexEncoder encoder(new StringSink(encodedHex));

  // Compute hash
  StringSource(msg, true, new HashFilter(hash, new StringSink(encodedHex)));
  return encodedHex;
}

/**
 * @brief Generate a random degree-(t-1) polynomial over Z_q.
 * Returns the vector of t coefficients [c_0, c_1, ..., c_{t-1}].
 * c_0 is the secret constant term (z_i for this dealer).
 */
std::vector<CryptoPP::Integer> CryptoDriver::DKG_generate_polynomial(int t) {
  AutoSeededRandomPool prng;
  std::vector<CryptoPP::Integer> coeffs(t);
  for (int i = 0; i < t; i++) {
    coeffs[i] = CryptoPP::Integer(prng, 1, DL_Q - 1);
  }
  return coeffs;
}

/**
 * @brief Evaluate polynomial at point x (mod q) using Horner's method.
 * poly(x) = c_0 + c_1*x + c_2*x^2 + ... + c_{t-1}*x^{t-1}
 */
CryptoPP::Integer CryptoDriver::DKG_evaluate_polynomial(
    const std::vector<CryptoPP::Integer> &coeffs, int x) {
  CryptoPP::Integer result = CryptoPP::Integer::Zero();
  CryptoPP::Integer x_int(x);

  // Horner's method: evaluate from highest degree down
  for (int i = coeffs.size() - 1; i >= 0; i--) {
    result = (result * x_int + coeffs[i]) % DL_Q;
  }
  // Ensure positive result
  if (result.IsNegative()) {
    result += DL_Q;
  }
  return result;
}

/**
 * @brief Compute Feldman commitments: G^{c_k} mod P for each coefficient c_k.
 */
std::vector<CryptoPP::Integer> CryptoDriver::DKG_feldman_commitments(
    const std::vector<CryptoPP::Integer> &coeffs) {
  std::vector<CryptoPP::Integer> commitments;
  commitments.reserve(coeffs.size());
  for (const auto &c : coeffs) {
    commitments.push_back(CryptoPP::ModularExponentiation(DL_G, c, DL_P));
  }
  return commitments;
}

/**
 * @brief Verify a received share f_i(j) against dealer i's Feldman commitments.
 * Checks: G^{share} == Π_{k=0}^{t-1} (commitment_k)^{j^k} mod P
 */
bool CryptoDriver::DKG_verify_share(int j, CryptoPP::Integer share,
    const std::vector<CryptoPP::Integer> &commitments) {
  // LHS: G^{share} mod P
  CryptoPP::Integer lhs = CryptoPP::ModularExponentiation(DL_G, share, DL_P);

  // RHS: product of commitment_k^{j^k} mod P
  CryptoPP::Integer rhs = CryptoPP::Integer::One();
  CryptoPP::Integer j_int(j);
  CryptoPP::Integer j_power = CryptoPP::Integer::One(); // j^0 = 1

  for (size_t k = 0; k < commitments.size(); k++) {
    CryptoPP::Integer term =
        CryptoPP::ModularExponentiation(commitments[k], j_power, DL_P);
    rhs = CryptoPP::ModularMultiplication(rhs, term, DL_P);
    j_power = (j_power * j_int) % DL_Q;
  }

  return lhs == rhs;
}
