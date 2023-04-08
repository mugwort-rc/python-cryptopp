#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

extern void cryptopp_cryptlib(pybind11::module &m);
extern void cryptopp_iterhash(pybind11::module &m);
extern void cryptopp_sha(pybind11::module &m);
extern void cryptopp_filters(pybind11::module &m);
extern void cryptopp_hex(pybind11::module &m);

extern void cryptopp_utils(pybind11::module &m);


PYBIND11_MODULE(__cryptopp, m) {
    cryptopp_cryptlib(m);
    cryptopp_iterhash(m);
    cryptopp_sha(m);
    cryptopp_filters(m);
    cryptopp_hex(m);

    cryptopp_utils(m);
}
