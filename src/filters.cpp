#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptoPP/hex.h"


void cryptopp_filters(pybind11::module &m) {
    pybind11::class_<CryptoPP::Filter, CryptoPP::BufferedTransformation>(m, "Filter", R"(\\brief Implementation of BufferedTransformation's attachment interface
\\details Filter is a cornerstone of the Pipeline trinity. Data flows from
 Sources, through Filters, and then terminates in Sinks. The difference
 between a Source and Filter is a Source \a pumps data, while a Filter does
 not. The difference between a Filter and a Sink is a Filter allows an
 attached transformation, while a Sink does not.
\\details See the discussion of BufferedTransformation in cryptlib.h for
 more details.)")
//        .def(pybind11::init<CryptoPP::BufferedTransformation *>(), pybind11::arg("attachment") = nullptr, R"(\\brief Construct a Filter
//\\param attachment an optional attached transformation
//\\details attachment can be NULL.)")
        .def("Attachable", &CryptoPP::Filter::Attachable, R"(\ \brief Determine if attachable
\\return true if the object allows attached transformations, false otherwise.
\\note Source and Filter offer attached transformations; while Sink does not.)")
        .def("AttachedTransformation", static_cast<CryptoPP::BufferedTransformation *(CryptoPP::Filter::*)()>(&CryptoPP::Filter::AttachedTransformation), R"(\\brief Retrieve attached transformation
\\return pointer to a BufferedTransformation if there is an attached transformation, NULL otherwise.)")
        .def("Detach", &CryptoPP::Filter::Detach, pybind11::arg("newAttachment") = nullptr, R"(\\brief Replace an attached transformation
\\param newAttachment an optional attached transformation
\\details newAttachment can be a single filter, a chain of filters or NULL.
 Pass NULL to remove an existing BufferedTransformation or chain of filters)")
        .def("TransferTo2", &CryptoPP::Filter::TransferTo2, pybind11::arg("target"), pybind11::arg("transferBytes"), pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, pybind11::arg("blocking") = true)
        .def("CopyRangeTo2", &CryptoPP::Filter::CopyRangeTo2, pybind11::arg("target"), pybind11::arg("begin"), pybind11::arg("end")=CryptoPP::LWORD_MAX, pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, pybind11::arg("blocking") = true)
        .def("Initialize", &CryptoPP::Filter::Initialize, pybind11::arg("parameters"), pybind11::arg("propagation") = -1)
        .def("Flush", &CryptoPP::Filter::Flush, pybind11::arg("hardFlush"), pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true)
        .def("MessageSeriesEnd", &CryptoPP::Filter::MessageSeriesEnd, pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true)
        ;

    pybind11::class_<CryptoPP::FilterWithBufferedInput, CryptoPP::Filter>(m, "FilterWithBufferedInput", R"(\\brief Divides an input stream into discrete blocks
\\details FilterWithBufferedInput divides the input stream into a first block, a number of
 middle blocks, and a last block. First and last blocks are optional, and middle blocks may
 be a stream instead (i.e. <tt>blockSize == 1</tt>).
\\sa AuthenticatedEncryptionFilter, AuthenticatedDecryptionFilter, HashVerificationFilter,
 SignatureVerificationFilter, StreamTransformationFilter)")
//        .def(pybind11::init<CryptoPP::BufferedTransformation *>(), pybind11::arg("attachment"), R"(\\brief Construct a FilterWithBufferedInput with an attached transformation
//\\param attachment an attached transformation)")
//        .def(pybind11::init<size_t, size_t, size_t, CryptoPP::BufferedTransformation *>(),
//            pybind11::arg("firstSize"), pybind11::arg("blockSize"), pybind11::arg("lastSize"), pybind11::arg("attachment"), R"(\\brief Construct a FilterWithBufferedInput with an attached transformation
//\\param firstSize the size of the first block
//\\param blockSize the size of middle blocks
//\\param lastSize the size of the last block
//\\param attachment an attached transformation
//\\details firstSize and lastSize may be 0. blockSize must be at least 1.)")
        .def("IsolatedInitialize", &CryptoPP::FilterWithBufferedInput::IsolatedInitialize, pybind11::arg("parameters"))
        .def("Put2", [](CryptoPP::FilterWithBufferedInput &self, const pybind11::bytes &inString, int messageEnd, bool blocking) {
            const std::string_view view = inString;
            self.Put2(reinterpret_cast<const unsigned char *>(&view[0]), view.size(), messageEnd, blocking);
        }, pybind11::arg("inString"), pybind11::arg("messageEnd"), pybind11::arg("blocking"))
        .def("PutModifiable2", [](CryptoPP::FilterWithBufferedInput &self, const pybind11::bytes &inString, int messageEnd, bool blocking) {
            const std::string_view view = inString;
            self.PutModifiable2(
                const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(&view[0])), view.size(), messageEnd, blocking);
        }, pybind11::arg("inString"), pybind11::arg("messageEnd"), pybind11::arg("blocking"))
        .def("IsolatedFlush", &CryptoPP::FilterWithBufferedInput::IsolatedFlush, pybind11::arg("hardFlush"), pybind11::arg("blocking"), R"(\\brief Flushes data buffered by this object, without signal propagation
\\param hardFlush indicates whether all data should be flushed
\\param blocking specifies whether the object should block when processing input
\\return true if the Flush was successful, false otherwise
\\details IsolatedFlush() calls ForceNextPut() if hardFlush is true
\\note  hardFlush must be used with care)")
        .def("ForceNextPut", &CryptoPP::FilterWithBufferedInput::ForceNextPut, R"(\\brief Flushes data buffered by this object
\\details The input buffer may contain more than blockSize bytes if <tt>lastSize != 0</tt>.
 ForceNextPut() forces a call to NextPut() if this is the case.)")
        ;

    pybind11::class_<CryptoPP::ProxyFilter, CryptoPP::FilterWithBufferedInput>(m, "ProxyFilter", R"(\\brief Base class for Filter classes that are proxies for a chain of other filters
\\since Crypto++ 4.0)")
//        .def(pybind11::init<
//            CryptoPP::BufferedTransformation *,
//            size_t,
//            size_t,
//            CryptoPP::BufferedTransformation *>(),
//            pybind11::arg("filter"),
//            pybind11::arg("filterSize"),
//            pybind11::arg("lastSize"),
//            pybind11::arg("attachment"),
//            R"(\\brief Construct a ProxyFilter
//\\param filter an output filter
//\\param firstSize the first Put size
//\\param lastSize the last Put size
//\\param attachment an attached transformation)"
//        )
        .def("IsolatedFlush", &CryptoPP::ProxyFilter::IsolatedFlush)
        .def("SetFilter", &CryptoPP::ProxyFilter::SetFilter)
        .def("NextPutMultiple", [](CryptoPP::ProxyFilter &self, const pybind11::bytes &s) {
            const std::string_view view = s;
            self.NextPutMultiple(reinterpret_cast<const unsigned char *>(&view[0]), view.size());
        }, pybind11::arg("s"))
        .def("NextPutModifiable", [](CryptoPP::ProxyFilter &self, const pybind11::bytes &inString) {
            const std::string_view view = inString;
            self.NextPutModifiable(
                const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(&view[0])), view.size());
        }, pybind11::arg("inString"))
        ;
    pybind11::class_<CryptoPP::SimpleProxyFilter, CryptoPP::ProxyFilter>(m, "SimpleProxyFilter", R"(\\brief Proxy filter that doesn't modify the underlying filter's input or output
\\since Crypto++ 5.0)")
        .def(pybind11::init<
            CryptoPP::BufferedTransformation *,
            CryptoPP::BufferedTransformation *>(),
            pybind11::arg("filter"),
            pybind11::arg("attachment"),
            R"(\\brief Construct a SimpleProxyFilter
\\param filter an output filter
\\param attachment an attached transformation)"
        )
        .def("FirstPut", [](CryptoPP::SimpleProxyFilter &self, const pybind11::bytes &inString) {
            const std::string_view view = inString;
            self.FirstPut(reinterpret_cast<const unsigned char *>(&view[0]));
        }, pybind11::arg("inString"))
        .def("LastPut", [](CryptoPP::SimpleProxyFilter &self, const pybind11::bytes &inString) {
            const std::string_view view = inString;
            self.LastPut(reinterpret_cast<const unsigned char *>(&view[0]), view.size());
        }, pybind11::arg("inString"), R"(\\brief Input the last block of data
\\param inString the input byte buffer
\\param length the size of the input buffer, in bytes
\\details LastPut() processes the last block of data and signals attached filters to do the same.
 LastPut() is always called. The pseudo algorithm for the logic is:
<pre>
    if totalLength < firstSize then length == totalLength
    else if totalLength <= firstSize+lastSize then length == totalLength-firstSize
    else lastSize <= length < lastSize+blockSize
</pre>)")
        ;
}
