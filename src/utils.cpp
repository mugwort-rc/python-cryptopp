#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptoPP/hex.h"



void cryptopp_utils(pybind11::module &m) {
    auto sub = m.def_submodule("utils");
    sub.def("hex_encode", [](const pybind11::bytes &data) {
        const std::string_view view = data;
        CryptoPP::HexEncoder encoder;
        encoder.Put(reinterpret_cast<const unsigned char *>(&view[0]), view.size());
        encoder.MessageEnd();
        const auto size = encoder.MaxRetrievable();
        if ( size <= 0 ) {
            return std::string();
        }
        std::string temp(size, 0);
        encoder.Get(reinterpret_cast<unsigned char *>(&temp[0]), size);
        return temp;
    });
}
