#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptoPP/sha.h"

#include "./iterhash.hpp"


void cryptopp_sha(pybind11::module &m) {
    decl_IteratedHashWithStaticTransform<CryptoPP::SHA1>(m, "SHA1", R"(\\brief SHA-1 message digest
\\sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-1">SHA-1</a>
\\since SHA1 since Crypto++ 1.0, SHA2 since Crypto++ 4.0, ARMv8 SHA since
  Crypto++ 6.0, Intel SHA since Crypto++ 6.0)");
    decl_IteratedHashWithStaticTransform<CryptoPP::SHA256>(m, "SHA256", R"(\\brief SHA-256 message digest
\\sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-256">SHA-256</a>
\\since SHA2 since Crypto++ 4.0, ARMv8 SHA since Crypto++ 6.0,
  Intel SHA since Crypto++ 6.0, Power8 SHA since Crypto++ 6.1)");
    decl_IteratedHashWithStaticTransform<CryptoPP::SHA224>(m, "SHA224", R"(\\brief SHA-224 message digest
\\sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-224">SHA-224</a>
\\since SHA2 since Crypto++ 4.0, ARMv8 SHA since Crypto++ 6.0,
  Intel SHA since Crypto++ 6.0, Power8 SHA since Crypto++ 6.1)");
    decl_IteratedHashWithStaticTransform<CryptoPP::SHA512>(m, "SHA512", R"(\\brief SHA-512 message digest
\\sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-512">SHA-512</a>
\\since SHA2 since Crypto++ 4.0, Power8 SHA since Crypto++ 6.1)");
    decl_IteratedHashWithStaticTransform<CryptoPP::SHA384>(m, "SHA384", R"(\\brief SHA-384 message digest
\\sa <a href="http://www.weidai.com/scan-mirror/md.html#SHA-384">SHA-384</a>
\\since SHA2 since Crypto++ 4.0, Power8 SHA since Crypto++ 6.1)");
}
