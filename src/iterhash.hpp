#pragma once
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptoPP/iterhash.h"


template <class T>
inline void decl_IteratedHashWithStaticTransform(pybind11::module &m, const char *name, const char *docstring) {
    auto cls = pybind11::class_<T, CryptoPP::HashTransformation>(m, name, docstring)
        .def(pybind11::init<>())
        ;
}
