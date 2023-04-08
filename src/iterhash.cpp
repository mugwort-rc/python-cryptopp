#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptoPP/iterhash.h"


void cryptopp_iterhash(pybind11::module &m) {
    pybind11::register_exception<CryptoPP::HashInputTooLong>(m, "HashInputTooLong");
}
