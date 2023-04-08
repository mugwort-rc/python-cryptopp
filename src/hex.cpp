#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptoPP/hex.h"


void cryptopp_hex(pybind11::module &m) {
    pybind11::class_<CryptoPP::HexEncoder, CryptoPP::SimpleProxyFilter>(m, "HexEncoder", "\\brief Converts given data to base 16")
        .def(pybind11::init<
            CryptoPP::BufferedTransformation *,
            bool,
            int,
            const std::string &,
            const std::string &>(),
            pybind11::arg("attachment") = nullptr,
            pybind11::arg("uppercase") = true,
            pybind11::arg("groupSize") = 0,
            pybind11::arg("separator") = std::string(),
            pybind11::arg("terminator") = std::string(),
            R"(\\brief Construct a HexEncoder
\\param attachment a BufferedTrasformation to attach to this object
\\param uppercase a flag indicating uppercase output
\\param groupSize the size of the output grouping
\\param separator the separator to use between groups
\\param terminator the terminator append after processing)"
        )
        .def("IsolatedInitialize", &CryptoPP::HexEncoder::IsolatedInitialize)
        ;
}
