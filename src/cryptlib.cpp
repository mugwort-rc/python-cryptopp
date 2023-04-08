#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "CryptoPP/cryptlib.h"


void cryptopp_cryptlib(pybind11::module &m) {
    pybind11::enum_<CryptoPP::CipherDir>(m, "CipherDir", R"(\\brief Specifies a direction for a cipher to operate
\\sa BlockTransformation::IsForwardTransformation(), BlockTransformation::IsPermutation(), BlockTransformation::GetCipherDirection())")
        .value("ENCRYPTION", CryptoPP::CipherDir::ENCRYPTION, "\\brief the cipher is performing encryption")
        .value("DECRYPTION", CryptoPP::CipherDir::DECRYPTION, "\\brief the cipher is performing decryption")
        .export_values()
        ;

    m.attr("INFINITE_TIME") = pybind11::cast<>(CryptoPP::INFINITE_TIME);

    pybind11::enum_<CryptoPP::ByteOrder>(m, "ByteOrder", "Provides the byte ordering\nBig-endian and little-endian modes are supported. Bi-endian and PDP-endian modes")
        .value("LITTLE_ENDIAN_ORDER", CryptoPP::ByteOrder::LITTLE_ENDIAN_ORDER, "byte order is little-endian")
        .value("BIG_ENDIAN_ORDER", CryptoPP::ByteOrder::BIG_ENDIAN_ORDER, "byte order is big-endian")
        .export_values()
        ;

    pybind11::register_exception<CryptoPP::Exception>(m, "CryptoPPException");
    pybind11::register_exception<CryptoPP::InvalidArgument>(m, "InvalidArgument");
    pybind11::register_exception<CryptoPP::InvalidDataFormat>(m, "InvalidDataFormat");
    pybind11::register_exception<CryptoPP::InvalidCiphertext>(m, "InvalidCiphertext");
    pybind11::register_exception<CryptoPP::NotImplemented>(m, "NotImplemented");
    pybind11::register_exception<CryptoPP::CannotFlush>(m, "CannotFlush");
    pybind11::register_exception<CryptoPP::OS_Error>(m, "OS_Error");

    pybind11::class_<CryptoPP::DecodingResult>(m, "DecodingResult", "\\brief Returns a decoding results")
        .def(pybind11::init<>(), R"(\\brief Constructs a DecodingResult
\\details isValidCoding is initialized to false and messageLength is
initialized to 0.)")
        .def(pybind11::init<size_t>(), R"(\\brief Constructs a DecodingResult
\\param len the message length
\\details isValidCoding is initialized to true.)", pybind11::arg("len"))
        .def("__eq__", &CryptoPP::DecodingResult::operator ==, R"(\\brief Compare two DecodingResult
\\param rhs the other DecodingResult
\\return true if either isValidCoding or messageLength is \\a not equal,
false otherwise)")
        .def("__ne__", &CryptoPP::DecodingResult::operator !=, R"(\\brief Compare two DecodingResult
\\param rhs the other DecodingResult
\\return true if either isValidCoding or messageLength is \\a not equal,
false otherwise
\\details Returns <tt>!operator==(rhs)</tt>.)")
        .def_readwrite("isValidCoding", &CryptoPP::DecodingResult::isValidCoding, "\\brief Flag to indicate the decoding is valid")
        .def_readwrite("messageLength", &CryptoPP::DecodingResult::messageLength, "\\brief Recovered message length if isValidCoding is true, undefined otherwise")
        ;

    pybind11::class_<CryptoPP::NameValuePairs>(m, "NameValuePairs", R"(\brief Interface for retrieving values given their names
\\details This class is used to safely pass a variable number of arbitrarily
 typed arguments to functions and to read values from keys and crypto parameters.
\\details To obtain an object that implements NameValuePairs for the purpose of
 parameter passing, use the MakeParameters() function.
\\details To get a value from NameValuePairs, you need to know the name and the
 type of the value. Call GetValueNames() on a NameValuePairs object to obtain a
 list of value names that it supports. then look at the Name namespace
 documentation to see what the type of each value is, or alternatively, call
 GetIntValue() with the value name, and if the type is not int, a
 ValueTypeMismatch exception will be thrown and you can get the actual type from
 the exception object.
\\sa NullNameValuePairs, g_nullNameValuePairs,
<A HREF="http://www.cryptopp.com/wiki/NameValuePairs">NameValuePairs</A> on the
Crypto++ wiki)")
        //.def("GetThisObject", &CryptoPP::NameValuePairs::GetThisObject)
        //.def("GetThisPointer", &CryptoPP::NameValuePairs::GetThisPointer)
        //.def("GetValue", &CryptoPP::NameValuePairs::GetValue)
        //.def("GetValueWithDefault", &CryptoPP::NameValuePairs::GetValueWithDefault)
        .def("GetValueNames", &CryptoPP::NameValuePairs::GetValueNames)
        .def("GetIntValue", [](CryptoPP::NameValuePairs &self, const char *name) -> pybind11::object {
            int value = 0;
            if ( ! self.GetIntValue(name, value) ) {
                // return None
                return pybind11::object();
            }
            return pybind11::cast<>(value);
        })
        .def("GetIntValueWithDefault", &CryptoPP::NameValuePairs::GetIntValueWithDefault)
        .def("GetWord64Value", [](CryptoPP::NameValuePairs &self, const char *name) -> pybind11::object {
            CryptoPP::word64 value = 0;
            if ( ! self.GetWord64Value(name, value) ) {
                // return None
                return pybind11::object();
            }
            return pybind11::cast<>(value);
        })
        .def("GetWord64ValueWithDefault", &CryptoPP::NameValuePairs::GetWord64ValueWithDefault)
        //.def("ThrowIfTypeMismatch", &CryptoPP::NameValuePairs::ThrowIfTypeMismatch)
        //.def("GetRequiredParameter", &CryptoPP::NameValuePairs::GetRequiredParameter)
        //.def("GetRequiredIntParameter", &CryptoPP::NameValuePairs::GetRequiredIntParameter)
        //.def("GetVoidValue", &CryptoPP::NameValuePairs::GetVoidValue)
        ;

    pybind11::register_exception<CryptoPP::NameValuePairs::ValueTypeMismatch>(m, "ValueTypeMismatch");

    m.attr("DEFAULT_CHANNEL") = CryptoPP::DEFAULT_CHANNEL;
    m.attr("AAD_CHANNEL") = CryptoPP::AAD_CHANNEL;
    //m.attr("g_nullNameValuePairs") = CryptoPP::g_nullNameValuePairs;

    pybind11::class_<CryptoPP::Clonable>(m, "Clonable", R"(\\brief Interface for cloning objects
\\note this is \\a not implemented by most classes
\\sa ClonableImpl, NotCopyable)")
        .def("Clone", &CryptoPP::Clonable::Clone, R"(\brief Copies  this object
\\return a copy of this object
\\throw NotImplemented
\\note this is \\a not implemented by most classes
\\sa NotCopyable)")
        ;

    pybind11::class_<CryptoPP::Algorithm, CryptoPP::Clonable>(m, "Algorithm", "\\brief Interface for all crypto algorithms")
        .def(pybind11::init<bool>(), pybind11::arg("checkSelfTestStatus")=true, R"(\\brief Interface for all crypto algorithms
\\param checkSelfTestStatus determines whether the object can proceed if the self
 tests have not been run or failed.
\\details When FIPS 140-2 compliance is enabled and checkSelfTestStatus == true,
 this constructor throws SelfTestFailure if the self test hasn't been run or fails.
\\details FIPS 140-2 compliance is disabled by default. It is only used by certain
 versions of the library when the library is built as a DLL on Windows. Also see
 CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2 in config.h.)")
        .def("AlgorithmName", &CryptoPP::Algorithm::AlgorithmName, R"(\\brief Provides the name of this algorithm
\\return the standard algorithm name
\\details The standard algorithm name can be a name like <tt>AES</tt> or <tt>AES/GCM</tt>.
 Some algorithms do not have standard names yet. For example, there is no standard
 algorithm name for Shoup's ECIES.
\\note AlgorithmName is not universally implemented yet.)")
        .def("AlgorithmProvider", &CryptoPP::Algorithm::AlgorithmProvider, R"(\\brief Retrieve the provider of this algorithm
\\return the algorithm provider
\\details The algorithm provider can be a name like "C++", "SSE", "NEON", "AESNI",
 "ARMv8" and "Power8". C++ is standard C++ code. Other labels, like SSE,
 usually indicate a specialized implementation using instructions from a higher
 instruction set architecture (ISA). Future labels may include external hardware
 like a hardware security module (HSM).
\\details Generally speaking Wei Dai's original IA-32 ASM code falls under "SSE2".
 Labels like "SSSE3" and "SSE4.1" follow after Wei's code and use intrinsics
 instead of ASM.
\\details Algorithms which combine different instructions or ISAs provide the
 dominant one. For example on x86 <tt>AES/GCM</tt> returns "AESNI" rather than
 "CLMUL" or "AES+SSE4.1" or "AES+CLMUL" or "AES+SSE4.1+CLMUL".
\\note Provider is not universally implemented yet.
\\since Crypto++ 8.0)")
        ;

/*

/// \brief Interface for algorithms that take byte strings as keys
/// \sa FixedKeyLength(), VariableKeyLength(), SameKeyLengthAs(), SimpleKeyingInterfaceImpl()
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE SimpleKeyingInterface
{
public:
	virtual ~SimpleKeyingInterface() {}

	/// \brief Returns smallest valid key length
	/// \return the minimum key length, in bytes
	virtual size_t MinKeyLength() const =0;

	/// \brief Returns largest valid key length
	/// \return the maximum key length, in bytes
	virtual size_t MaxKeyLength() const =0;

	/// \brief Returns default key length
	/// \return the default key length, in bytes
	virtual size_t DefaultKeyLength() const =0;

	/// \brief Returns a valid key length for the algorithm
	/// \param keylength the size of the key, in bytes
	/// \return the valid key length, in bytes
	/// \details keylength is provided in bytes, not bits. If keylength is less than MIN_KEYLENGTH,
	///  then the function returns MIN_KEYLENGTH. If keylength is greater than MAX_KEYLENGTH,
	///  then the function returns MAX_KEYLENGTH. if If keylength is a multiple of KEYLENGTH_MULTIPLE,
	///  then keylength is returned. Otherwise, the function returns a \a lower multiple of
	///  KEYLENGTH_MULTIPLE.
	virtual size_t GetValidKeyLength(size_t keylength) const =0;

	/// \brief Returns whether keylength is a valid key length
	/// \param keylength the requested keylength
	/// \return true if keylength is valid, false otherwise
	/// \details Internally the function calls GetValidKeyLength()
	virtual bool IsValidKeyLength(size_t keylength) const
		{return keylength == GetValidKeyLength(keylength);}

	/// \brief Sets or reset the key of this object
	/// \param key the key to use when keying the object
	/// \param length the size of the key, in bytes
	/// \param params additional initialization parameters to configure this object
	virtual void SetKey(const byte *key, size_t length, const NameValuePairs &params = g_nullNameValuePairs);

	/// \brief Sets or reset the key of this object
	/// \param key the key to use when keying the object
	/// \param length the size of the key, in bytes
	/// \param rounds the number of rounds to apply the transformation function,
	///  if applicable
	/// \details SetKeyWithRounds() calls SetKey() with a NameValuePairs
	///  object that only specifies rounds. rounds is an integer parameter,
	///  and <tt>-1</tt> means use the default number of rounds.
	void SetKeyWithRounds(const byte *key, size_t length, int rounds);

	/// \brief Sets or reset the key of this object
	/// \param key the key to use when keying the object
	/// \param length the size of the key, in bytes
	/// \param iv the initialization vector to use when keying the object
	/// \param ivLength the size of the iv, in bytes
	/// \details SetKeyWithIV() calls SetKey() with a NameValuePairs
	///  that only specifies IV. The IV is a byte buffer with size ivLength.
	///  ivLength is an integer parameter, and <tt>-1</tt> means use IVSize().
	void SetKeyWithIV(const byte *key, size_t length, const byte *iv, size_t ivLength);

	/// \brief Sets or reset the key of this object
	/// \param key the key to use when keying the object
	/// \param length the size of the key, in bytes
	/// \param iv the initialization vector to use when keying the object
	/// \details SetKeyWithIV() calls SetKey() with a NameValuePairs() object
	///  that only specifies iv. iv is a byte buffer, and it must have
	///  a size IVSize().
	void SetKeyWithIV(const byte *key, size_t length, const byte *iv)
		{SetKeyWithIV(key, length, iv, IVSize());}

	/// \brief Secure IVs requirements as enumerated values.
	/// \details Provides secure IV requirements as a monotonically increasing enumerated values.
	///  Requirements can be compared using less than (&lt;) and greater than (&gt;). For example,
	///  <tt>UNIQUE_IV &lt; RANDOM_IV</tt> and <tt>UNPREDICTABLE_RANDOM_IV &gt; RANDOM_IV</tt>.
	/// \details Objects that use SimpleKeyingInterface do not support an optional IV. That is,
	///	 an IV must be present or it must be absent. If you wish to support an optional IV then
	///  provide two classes - one with an IV and one without an IV.
	/// \sa IsResynchronizable(), CanUseRandomIVs(), CanUsePredictableIVs(), CanUseStructuredIVs()
	enum IV_Requirement {
		/// \brief The IV must be unique
		UNIQUE_IV = 0,
		/// \brief The IV must be random and possibly predictable
		RANDOM_IV,
		/// \brief The IV must be random and unpredictable
		UNPREDICTABLE_RANDOM_IV,
		/// \brief The IV is set by the object
		INTERNALLY_GENERATED_IV,
		/// \brief The object does not use an IV
		NOT_RESYNCHRONIZABLE
	};

	/// \brief Minimal requirement for secure IVs
	/// \return the secure IV requirement of the algorithm
	virtual IV_Requirement IVRequirement() const =0;

	/// \brief Determines if the object can be resynchronized
	/// \return true if the object can be resynchronized (i.e. supports initialization vectors), false otherwise
	/// \note If this function returns true, and no IV is passed to SetKey() and <tt>CanUseStructuredIVs()==true</tt>,
	///  an IV of all 0's will be assumed.
	bool IsResynchronizable() const {return IVRequirement() < NOT_RESYNCHRONIZABLE;}

	/// \brief Determines if the object can use random IVs
	/// \return true if the object can use random IVs (in addition to ones returned by GetNextIV), false otherwise
	bool CanUseRandomIVs() const {return IVRequirement() <= UNPREDICTABLE_RANDOM_IV;}

	/// \brief Determines if the object can use random but possibly predictable IVs
	/// \return true if the object can use random but possibly predictable IVs (in addition to ones returned by
	///  GetNextIV), false otherwise
	bool CanUsePredictableIVs() const {return IVRequirement() <= RANDOM_IV;}

	/// \brief Determines if the object can use structured IVs
	/// \return true if the object can use structured IVs, false otherwise
	/// \details CanUseStructuredIVs() indicates whether the object can use structured IVs; for example a counter
	///  (in addition to ones returned by GetNextIV).
	bool CanUseStructuredIVs() const {return IVRequirement() <= UNIQUE_IV;}

	/// \brief Returns length of the IV accepted by this object
	/// \return the size of an IV, in bytes
	/// \throw NotImplemented() if the object does not support resynchronization
	/// \details The default implementation throws NotImplemented
	virtual unsigned int IVSize() const
		{throw NotImplemented(GetAlgorithm().AlgorithmName() + ": this object doesn't support resynchronization");}

	/// \brief Provides the default size of an IV
	/// \return default length of IVs accepted by this object, in bytes
	unsigned int DefaultIVLength() const {return IVSize();}

	/// \brief Provides the minimum size of an IV
	/// \return minimal length of IVs accepted by this object, in bytes
	/// \throw NotImplemented() if the object does not support resynchronization
	virtual unsigned int MinIVLength() const {return IVSize();}

	/// \brief Provides the maximum size of an IV
	/// \return maximal length of IVs accepted by this object, in bytes
	/// \throw NotImplemented() if the object does not support resynchronization
	virtual unsigned int MaxIVLength() const {return IVSize();}

	/// \brief Resynchronize with an IV
	/// \param iv the initialization vector
	/// \param ivLength the size of the initialization vector, in bytes
	/// \details Resynchronize() resynchronizes with an IV provided by the caller. <tt>ivLength=-1</tt> means use IVSize().
	/// \throw NotImplemented() if the object does not support resynchronization
	virtual void Resynchronize(const byte *iv, int ivLength=-1) {
		CRYPTOPP_UNUSED(iv); CRYPTOPP_UNUSED(ivLength);
		throw NotImplemented(GetAlgorithm().AlgorithmName() + ": this object doesn't support resynchronization");
	}

	/// \brief Retrieves a secure IV for the next message
	/// \param rng a RandomNumberGenerator to produce keying material
	/// \param iv a block of bytes to receive the IV
	/// \details The IV must be at least IVSize() in length.
	/// \details This method should be called after you finish encrypting one message and are ready
	///  to start the next one. After calling it, you must call SetKey() or Resynchronize().
	///  before using this object again.
	/// \details Internally, the base class implementation calls RandomNumberGenerator's GenerateBlock()
	/// \note This method is not implemented on decryption objects.
	virtual void GetNextIV(RandomNumberGenerator &rng, byte *iv);

protected:
	/// \brief Returns the base class Algorithm
	/// \return the base class Algorithm
	virtual const Algorithm & GetAlgorithm() const =0;

	/// \brief Sets the key for this object without performing parameter validation
	/// \param key a byte buffer used to key the cipher
	/// \param length the length of the byte buffer
	/// \param params additional parameters passed as NameValuePairs
	/// \details key must be at least DEFAULT_KEYLENGTH in length.
	virtual void UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params) =0;

	/// \brief Validates the key length
	/// \param length the size of the keying material, in bytes
	/// \throw InvalidKeyLength if the key length is invalid
	void ThrowIfInvalidKeyLength(size_t length);

	/// \brief Validates the object
	/// \throw InvalidArgument if the IV is present
	/// \details Internally, the default implementation calls IsResynchronizable() and throws
	///  InvalidArgument if the function returns  true.
	/// \note called when no IV is passed
	void ThrowIfResynchronizable();

	/// \brief Validates the IV
	/// \param iv the IV with a length of IVSize, in bytes
	/// \throw InvalidArgument on failure
	/// \details Internally, the default implementation checks the iv. If iv is not NULL or nullptr,
	///  then the function succeeds. If iv is NULL, then IVRequirement is checked against
	///  UNPREDICTABLE_RANDOM_IV. If IVRequirement is UNPREDICTABLE_RANDOM_IV, then
	///  then the function succeeds. Otherwise, an exception is thrown.
	void ThrowIfInvalidIV(const byte *iv);

	/// \brief Validates the IV length
	/// \param length the size of an IV, in bytes
	/// \throw InvalidArgument if the IV length is invalid
	size_t ThrowIfInvalidIVLength(int length);

	/// \brief Retrieves and validates the IV
	/// \param params NameValuePairs with the IV supplied as a ConstByteArrayParameter
	/// \param size the length of the IV, in bytes
	/// \return a pointer to the first byte of the IV
	/// \throw InvalidArgument if the number of rounds are invalid
	const byte * GetIVAndThrowIfInvalid(const NameValuePairs &params, size_t &size);

	/// \brief Validates the key length
	/// \param length the size of the keying material, in bytes
	inline void AssertValidKeyLength(size_t length) const
		{CRYPTOPP_UNUSED(length); CRYPTOPP_ASSERT(IsValidKeyLength(length));}
};

/// \brief Interface for the data processing part of block ciphers
/// \details Classes derived from BlockTransformation are block ciphers
///  in ECB mode (for example the DES::Encryption class), which are stateless.
///  These classes should not be used directly, but only in combination with
///  a mode class (see CipherModeDocumentation in modes.h).
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE BlockTransformation : public Algorithm
{
public:
	virtual ~BlockTransformation() {}

	/// \brief Encrypt or decrypt a block
	/// \param inBlock the input message before processing
	/// \param outBlock the output message after processing
	/// \param xorBlock an optional XOR mask
	/// \details ProcessAndXorBlock encrypts or decrypts inBlock, xor with xorBlock, and write to outBlock.
	/// \details The size of the block is determined by the block cipher and its documentation. Use
	///  BLOCKSIZE at compile time, or BlockSize() at runtime.
	/// \note The message can be transformed in-place, or the buffers must \a not overlap
	/// \sa FixedBlockSize, BlockCipherFinal from seckey.h and BlockSize()
	virtual void ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const =0;

	/// \brief Encrypt or decrypt a block
	/// \param inBlock the input message before processing
	/// \param outBlock the output message after processing
	/// \details ProcessBlock encrypts or decrypts inBlock and write to outBlock.
	/// \details The size of the block is determined by the block cipher and its documentation.
	///  Use BLOCKSIZE at compile time, or BlockSize() at runtime.
	/// \sa FixedBlockSize, BlockCipherFinal from seckey.h and BlockSize()
	/// \note The message can be transformed in-place, or the buffers must \a not overlap
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{ProcessAndXorBlock(inBlock, NULLPTR, outBlock);}

	/// \brief Encrypt or decrypt a block in place
	/// \param inoutBlock the input message before processing
	/// \details ProcessBlock encrypts or decrypts inoutBlock in-place.
	/// \details The size of the block is determined by the block cipher and its documentation.
	///  Use BLOCKSIZE at compile time, or BlockSize() at runtime.
	/// \sa FixedBlockSize, BlockCipherFinal from seckey.h and BlockSize()
	void ProcessBlock(byte *inoutBlock) const
		{ProcessAndXorBlock(inoutBlock, NULLPTR, inoutBlock);}

	/// Provides the block size of the cipher
	/// \return the block size of the cipher, in bytes
	virtual unsigned int BlockSize() const =0;

	/// \brief Provides input and output data alignment for optimal performance.
	/// \return the input data alignment that provides optimal performance
	/// \sa GetAlignment() and OptimalBlockSize()
	virtual unsigned int OptimalDataAlignment() const;

	/// \brief Determines if the transformation is a permutation
	/// \return true if this is a permutation (i.e. there is an inverse transformation)
	virtual bool IsPermutation() const {return true;}

	/// \brief Determines if the cipher is being operated in its forward direction
	/// \return true if DIR is ENCRYPTION, false otherwise
	/// \sa IsForwardTransformation(), IsPermutation(), GetCipherDirection()
	virtual bool IsForwardTransformation() const =0;

	/// \brief Determines the number of blocks that can be processed in parallel
	/// \return the number of blocks that can be processed in parallel, for bit-slicing implementations
	/// \details Bit-slicing is often used to improve throughput and minimize timing attacks.
	virtual unsigned int OptimalNumberOfParallelBlocks() const {return 1;}

	/// \brief Bit flags that control AdvancedProcessBlocks() behavior
	enum FlagsForAdvancedProcessBlocks {
		/// \brief inBlock is a counter
		BT_InBlockIsCounter=1,
		/// \brief should not modify block pointers
		BT_DontIncrementInOutPointers=2,
		/// \brief Xor inputs before transformation
		BT_XorInput=4,
		/// \brief perform the transformation in reverse
		BT_ReverseDirection=8,
		/// \brief Allow parallel transformations
		BT_AllowParallel=16};

	/// \brief Encrypt and xor multiple blocks using additional flags
	/// \param inBlocks the input message before processing
	/// \param xorBlocks an optional XOR mask
	/// \param outBlocks the output message after processing
	/// \param length the size of the blocks, in bytes
	/// \param flags additional flags to control processing
	/// \details Encrypt and xor multiple blocks according to FlagsForAdvancedProcessBlocks flags.
	/// \note If BT_InBlockIsCounter is set, then the last byte of inBlocks may be modified.
	virtual size_t AdvancedProcessBlocks(const byte *inBlocks, const byte *xorBlocks, byte *outBlocks, size_t length, word32 flags) const;

	/// \brief Provides the direction of the cipher
	/// \return ENCRYPTION if IsForwardTransformation() is true, DECRYPTION otherwise
	/// \sa IsForwardTransformation(), IsPermutation()
	inline CipherDir GetCipherDirection() const {return IsForwardTransformation() ? ENCRYPTION : DECRYPTION;}
};

/// \brief Interface for the data processing portion of stream ciphers
/// \sa StreamTransformationFilter()
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE StreamTransformation : public Algorithm
{
public:
	virtual ~StreamTransformation() {}

	/// \brief Provides a reference to this object
	/// \return A reference to this object
	/// \details Useful for passing a temporary object to a function that takes a non-const reference
	StreamTransformation& Ref() {return *this;}

	/// \brief Provides the mandatory block size of the cipher
	/// \return The block size of the cipher if input must be processed in blocks, 1 otherwise
	/// \details Stream ciphers and some block ciphers modes of operation return 1. Modes that
	///  return 1 must be able to process a single byte at a time, like counter mode. If a
	///  mode of operation or block cipher cannot stream then it must not return 1.
	/// \details When filters operate the mode or cipher, ProcessData will be called with a
	///  string of bytes that is determined by MandatoryBlockSize and OptimalBlockSize. When a
	///  policy is set, like 16-byte strings for a 16-byte block cipher, the filter will buffer
	///  bytes until the specified number of bytes is available to the object.
	/// \sa ProcessData, ProcessLastBlock, MandatoryBlockSize, MinLastBlockSize, BlockPaddingSchemeDef, IsLastBlockSpecial
	virtual unsigned int MandatoryBlockSize() const {return 1;}

	/// \brief Provides the input block size most efficient for this cipher
	/// \return The input block size that is most efficient for the cipher
	/// \details The base class implementation returns MandatoryBlockSize().
	/// \note Optimal input length is
	///  <tt>n * OptimalBlockSize() - GetOptimalBlockSizeUsed()</tt> for any <tt>n \> 0</tt>.
	virtual unsigned int OptimalBlockSize() const {return MandatoryBlockSize();}

	/// \brief Provides the number of bytes used in the current block when processing at optimal block size.
	/// \return the number of bytes used in the current block when processing at the optimal block size
	virtual unsigned int GetOptimalBlockSizeUsed() const {return 0;}

	/// \brief Provides input and output data alignment for optimal performance
	/// \return the input data alignment that provides optimal performance
	/// \sa GetAlignment() and OptimalBlockSize()
	virtual unsigned int OptimalDataAlignment() const;

	/// \brief Encrypt or decrypt an array of bytes
	/// \param outString the output byte buffer
	/// \param inString the input byte buffer
	/// \param length the size of the input and output byte buffers, in bytes
	/// \details ProcessData is called with a string of bytes whose size depends on MandatoryBlockSize.
	///  Either <tt>inString == outString</tt>, or they must not overlap.
	/// \sa ProcessData, ProcessLastBlock, MandatoryBlockSize, MinLastBlockSize, BlockPaddingSchemeDef, IsLastBlockSpecial
	virtual void ProcessData(byte *outString, const byte *inString, size_t length) =0;

	/// \brief Encrypt or decrypt the last block of data
	/// \param outString the output byte buffer
	/// \param outLength the size of the output byte buffer, in bytes
	/// \param inString the input byte buffer
	/// \param inLength the size of the input byte buffer, in bytes
	/// \return the number of bytes used in outString
	/// \details ProcessLastBlock is used when the last block of data is special and requires handling
	///  by the cipher. The current implementation provides an output buffer with a size
	///  <tt>inLength+2*MandatoryBlockSize()</tt>. The return value allows the cipher to expand cipher
	///  text during encryption or shrink plain text during decryption.
	/// \details This member function is used by CBC-CTS and OCB modes.
	/// \sa ProcessData, ProcessLastBlock, MandatoryBlockSize, MinLastBlockSize, BlockPaddingSchemeDef, IsLastBlockSpecial
	virtual size_t ProcessLastBlock(byte *outString, size_t outLength, const byte *inString, size_t inLength);

	/// \brief Provides the size of the last block
	/// \return the minimum size of the last block
	/// \details MinLastBlockSize() returns the minimum size of the last block. 0 indicates the last
	///  block is not special.
	/// \details MandatoryBlockSize() enlists one of two behaviors. First, if MandatoryBlockSize()
	///  returns 1, then the cipher can be streamed and ProcessData() is called with the tail bytes.
	///  Second, if MandatoryBlockSize() returns non-0, then the string of bytes is padded to
	///  MandatoryBlockSize() according to the padding mode. Then, ProcessData() is called with the
	///  padded string of bytes.
	/// \details Some authenticated encryption modes are not expressed well with MandatoryBlockSize()
	///  and MinLastBlockSize(). For example, AES/OCB uses 16-byte blocks (MandatoryBlockSize = 16)
	///  and the last block requires special processing (MinLastBlockSize = 0). However, 0 is a valid
	///  last block size for OCB and the special processing is custom padding, and not standard PKCS
	///  padding. In response an unambiguous IsLastBlockSpecial() was added.
	/// \sa ProcessData, ProcessLastBlock, MandatoryBlockSize, MinLastBlockSize, BlockPaddingSchemeDef, IsLastBlockSpecial
	virtual unsigned int MinLastBlockSize() const {return 0;}

	/// \brief Determines if the last block receives special processing
	/// \return true if the last block reveives special processing, false otherwise.
	/// \details Some authenticated encryption modes are not expressed well with
	///  MandatoryBlockSize() and MinLastBlockSize(). For example, AES/OCB uses
	///  16-byte blocks (MandatoryBlockSize = 16) and the last block requires special processing
	///  (MinLastBlockSize = 0). However, 0 is a valid last block size for OCB and the special
	///  processing is custom padding, and not standard PKCS padding. In response an
	///  unambiguous IsLastBlockSpecial() was added.
	/// \details When IsLastBlockSpecial() returns false nothing special happens. All the former
	///  rules and behaviors apply. This is the default behavior of IsLastBlockSpecial().
	/// \details When IsLastBlockSpecial() returns true four things happen. First, MinLastBlockSize = 0
	///  means 0 is a valid block size that should be processed. Second, standard block cipher padding is
	///  \a not \a applied. Third, the caller supplies an outString is larger than inString by
	///  <tt>2*MandatoryBlockSize()</tt>. That is, there's a reserve available when processing the last block.
	///  Fourth, the cipher is responsible for finalization like custom padding. The cipher will tell
	///  the library how many bytes were processed or used by returning the appropriate value from
	///  ProcessLastBlock().
	/// \details The return value of ProcessLastBlock() indicates how many bytes were written to
	///  <tt>outString</tt>. A filter pipelining data will send <tt>outString</tt> and up to <tt>outLength</tt>
	///  to an <tt>AttachedTransformation()</tt> for additional processing. Below is an example of the code
	///  used in <tt>StreamTransformationFilter::LastPut</tt>.
	/// <pre>  if (m_cipher.IsLastBlockSpecial())
	///   {
	///     size_t reserve = 2*m_cipher.MandatoryBlockSize();
	///     space = HelpCreatePutSpace(*AttachedTransformation(), DEFAULT_CHANNEL, length+reserve);
	///     length = m_cipher.ProcessLastBlock(space, length+reserve, inString, length);
	///     AttachedTransformation()->Put(space, length);
	///     return;
	///   }</pre>
	/// \sa ProcessData, ProcessLastBlock, MandatoryBlockSize, MinLastBlockSize, BlockPaddingSchemeDef, IsLastBlockSpecial
	/// \since Crypto++ 6.0
	virtual bool IsLastBlockSpecial() const {return false;}

	/// \brief Encrypt or decrypt a string of bytes
	/// \param inoutString the string to process
	/// \param length the size of the inoutString, in bytes
	/// \details Internally, the base class implementation calls ProcessData().
	inline void ProcessString(byte *inoutString, size_t length)
		{ProcessData(inoutString, inoutString, length);}

	/// \brief Encrypt or decrypt a string of bytes
	/// \param outString the output string to process
	/// \param inString the input string to process
	/// \param length the size of the input and output strings, in bytes
	/// \details Internally, the base class implementation calls ProcessData().
	inline void ProcessString(byte *outString, const byte *inString, size_t length)
		{ProcessData(outString, inString, length);}

	/// \brief Encrypt or decrypt a byte
	/// \param input the input byte to process
	/// \details Internally, the base class implementation calls ProcessData() with a size of 1.
	inline byte ProcessByte(byte input)
		{ProcessData(&input, &input, 1); return input;}

	/// \brief Determines whether the cipher supports random access
	/// \return true if the cipher supports random access, false otherwise
	virtual bool IsRandomAccess() const =0;

	/// \brief Seek to an absolute position
	/// \param pos position to seek
	/// \throw NotImplemented
	/// \details The base class implementation throws NotImplemented. The function
	///  \ref CRYPTOPP_ASSERT "asserts" IsRandomAccess() in debug builds.
	virtual void Seek(lword pos)
	{
		CRYPTOPP_UNUSED(pos);
		CRYPTOPP_ASSERT(!IsRandomAccess());
		throw NotImplemented("StreamTransformation: this object doesn't support random access");
	}

	/// \brief Determines whether the cipher is self-inverting
	/// \return true if the cipher is self-inverting, false otherwise
	/// \details IsSelfInverting determines whether this transformation is
	///  self-inverting (e.g. xor with a keystream).
	virtual bool IsSelfInverting() const =0;

	/// \brief Determines if the cipher is being operated in its forward direction
	/// \return true if DIR is ENCRYPTION, false otherwise
	/// \sa IsForwardTransformation(), IsPermutation(), GetCipherDirection()
	virtual bool IsForwardTransformation() const =0;
};

*/

    pybind11::class_<CryptoPP::HashTransformation, CryptoPP::Algorithm>(m, "HashTransformation", R"(\\brief Interface for hash functions and data processing part of MACs
\details HashTransformation objects are stateful. They are created in an initial state,
 change state as Update() is called, and return to the initial
 state when Final() is called. This interface allows a large message to
 be hashed in pieces by calling Update() on each piece followed by
 calling Final().
\\sa HashFilter(), HashVerificationFilter())")
        .def("Ref", &CryptoPP::HashTransformation::Ref, R"(\\brief Provides a reference to this object
\\return A reference to this object
\\details Useful for passing a temporary object to a function that takes a non-const reference)")
        .def("Update", [](CryptoPP::HashTransformation &self, const pybind11::bytes &data) {
            std::string_view view = data;
            self.Update(reinterpret_cast<const unsigned char *>(&view[0]), view.size());
        }, pybind11::arg("input"), R"(\\brief Updates a hash with additional input
\\param input the additional input as a buffer
\\param length the size of the buffer, in bytes)")
        /// \brief Request space which can be written into by the caller
        /// \param size the requested size of the buffer
        /// \details The purpose of this method is to help avoid extra memory allocations.
        /// \details size is an \a IN and \a OUT parameter and used as a hint. When the call is made,
        ///  size is the requested size of the buffer. When the call returns, size is the size of
        ///  the array returned to the caller.
        /// \details The base class implementation sets size to 0 and returns NULL or nullptr.
        /// \note Some objects, like ArraySink, cannot create a space because its fixed.
        //.def("CreateUpdateSpace", &CryptoPP::HashTransformation::CreateUpdateSpace)
        .def("Final", [](CryptoPP::HashTransformation &self) {
            std::string temp(self.DigestSize(), 0);
            self.Final(reinterpret_cast<unsigned char *>(&temp[0]));
            return pybind11::bytes(temp);
        }, R"(\\brief Computes the hash of the current message
\\param digest a pointer to the buffer to receive the hash
\\details Final() restarts the hash for a new message.
\\pre <tt>COUNTOF(digest) <= DigestSize()</tt> or <tt>COUNTOF(digest) <= HASH::DIGESTSIZE</tt> ensures
 the output byte buffer is large enough for the digest.)")
        .def("Restart", &CryptoPP::HashTransformation::Restart, R"(\\brief Restart the hash
\\details Discards the current state, and restart for a new message)")
        .def("DigestSize", &CryptoPP::HashTransformation::DigestSize, R"(Provides the digest size of the hash
\\return the digest size of the hash.)")
        .def("TagSize", &CryptoPP::HashTransformation::TagSize, R"(Provides the tag size of the hash
\\return the tag size of the hash.
\\details Same as DigestSize().)")
        .def("BlockSize", &CryptoPP::HashTransformation::BlockSize, R"(\\brief Provides the block size of the compression function
\\return block size of the compression function, in bytes
\\details BlockSize() will return 0 if the hash is not block based
 or does not have an equivalent block size. For example, Keccak
 and SHA-3 do not have a block size, but they do have an equivalent
 block size called rate expressed as <tt>r</tt>.)")
        .def("OptimalBlockSize", &CryptoPP::HashTransformation::OptimalBlockSize, R"(\\brief Provides the input block size most efficient for this hash.
\\return The input block size that is most efficient for the cipher
\\details The base class implementation returns MandatoryBlockSize().
\\details Optimal input length is
 <tt>n * OptimalBlockSize() - GetOptimalBlockSizeUsed()</tt> for any <tt>n \> 0</tt>.)")
        .def("OptimalDataAlignment", &CryptoPP::HashTransformation::OptimalDataAlignment, R"(\\brief Provides input and output data alignment for optimal performance
\\return the input data alignment that provides optimal performance
\\sa GetAlignment() and OptimalBlockSize())")
        .def("CalculateDigest", [](CryptoPP::HashTransformation &self, const pybind11::bytes &data) {
            std::string temp(self.DigestSize(), 0);
            const std::string_view view = data;
            self.CalculateDigest(reinterpret_cast<unsigned char *>(&temp[0]), reinterpret_cast<const unsigned char *>(&view[0]), view.size());
            return pybind11::bytes(temp);
        }, pybind11::arg("input"), R"(\\brief Updates the hash with additional input and computes the hash of the current message
\\param digest a pointer to the buffer to receive the hash
\\param input the additional input as a buffer
\\param length the size of the buffer, in bytes
\\details Use this if your input is in one piece and you don't want to call Update()
 and Final() separately
\\details CalculateDigest() restarts the hash for the next message.
\\pre <tt>COUNTOF(digest) == DigestSize()</tt> or <tt>COUNTOF(digest) == HASH::DIGESTSIZE</tt> ensures
 the output byte buffer is a valid size.)")
        .def("Verify", [](CryptoPP::HashTransformation &self, const pybind11::bytes digest) {
            const std::string_view view = digest;
            return self.Verify(reinterpret_cast<const unsigned char *>(&view[0]));
        }, pybind11::arg("digest"), R"(\\brief Verifies the hash of the current message
\\param digest a pointer to the buffer of an \a existing hash
\\return \p true if the existing hash matches the computed hash, \p false otherwise
\\throw InvalidArgument() if the existing hash's size exceeds DigestSize()
\\details Verify() performs a bitwise compare on the buffers using VerifyBufsEqual(), which is
 a constant time comparison function. digestLength cannot exceed DigestSize().
\\details Verify() restarts the hash for the next message.
\\pre <tt>COUNTOF(digest) == DigestSize()</tt> or <tt>COUNTOF(digest) == HASH::DIGESTSIZE</tt> ensures
 the input byte buffer is a valid size.)")
        .def("VerifyDigest", [](CryptoPP::HashTransformation &self, const pybind11::bytes &digest, const pybind11::bytes &data) {
            const std::string_view digest_view = digest;
            const std::string_view input_view = data;
            return self.VerifyDigest(reinterpret_cast<const unsigned char *>(&digest_view[0]), reinterpret_cast<const unsigned char *>(&input_view[0]), input_view.size());
        }, pybind11::arg("digest"), pybind11::arg("input"), R"(\\brief Updates the hash with additional input and verifies the hash of the current message
\\param digest a pointer to the buffer of an \a existing hash
\\param input the additional input as a buffer
\\param length the size of the buffer, in bytes
\\return \p true if the existing hash matches the computed hash, \p false otherwise
\\throw InvalidArgument() if the existing hash's size exceeds DigestSize()
\\details Use this if your input is in one piece and you don't want to call Update()
 and Verify() separately
\\details VerifyDigest() performs a bitwise compare on the buffers using VerifyBufsEqual(),
 which is a constant time comparison function.
\\details VerifyDigest() restarts the hash for the next message.
\\pre <tt>COUNTOF(digest) == DigestSize()</tt> or <tt>COUNTOF(digest) == HASH::DIGESTSIZE</tt> ensures
 the output byte buffer is a valid size.)")
        .def("TruncatedFinal", [](CryptoPP::HashTransformation &self, size_t digestSize) {
            std::string temp(digestSize, 0);
            self.TruncatedFinal(reinterpret_cast<unsigned char *>(&temp[0]), digestSize);
            return pybind11::bytes(temp);
        }, pybind11::arg("digestSize"), R"(\\brief Computes the hash of the current message
\\param digest a pointer to the buffer to receive the hash
\\param digestSize the size of the truncated digest, in bytes
\\details TruncatedFinal() calls Final() and then copies digestSize bytes to digest.
 The hash is restarted the hash for the next message.
\\pre <tt>COUNTOF(digest) <= DigestSize()</tt> or <tt>COUNTOF(digest) <= HASH::DIGESTSIZE</tt> ensures
 the output byte buffer is a valid size.)")
        .def("CalculateTruncatedDigest", [](CryptoPP::HashTransformation &self, size_t digestSize, const pybind11::bytes &data) {
            std::string temp(digestSize, 0);
            std::string_view view = data;
            self.CalculateTruncatedDigest(reinterpret_cast<unsigned char *>(&temp[0]), digestSize, reinterpret_cast<const unsigned char *>(&view[0]), view.size());
        }, pybind11::arg("digestSize"), pybind11::arg("input"), R"(\\brief Updates the hash with additional input and computes the hash of the current message
\\param digest a pointer to the buffer to receive the hash
\\param digestSize the length of the truncated hash, in bytes
\\param input the additional input as a buffer
\\param length the size of the buffer, in bytes
\\details Use this if your input is in one piece and you don't want to call Update()
 and CalculateDigest() separately.
\\details CalculateTruncatedDigest() restarts the hash for the next message.
\\pre <tt>digestSize <= DigestSize()</tt> or <tt>digestSize <= HASH::DIGESTSIZE</tt> ensures
 the output byte buffer is a valid size.)")
        .def("TruncatedVerify", [](CryptoPP::HashTransformation &self, const pybind11::bytes &digest) {
            const std::string_view view = digest;
            return self.TruncatedVerify(reinterpret_cast<const unsigned char *>(&view[0]), view.size());
        }, pybind11::arg("digest"), R"(\\brief Verifies the hash of the current message
\\param digest a pointer to the buffer of an \a existing hash
\\param digestLength the size of the truncated hash, in bytes
\\return \p true if the existing hash matches the computed hash, \p false otherwise
\\throw InvalidArgument() if digestLength exceeds DigestSize()
\\details TruncatedVerify() is a truncated version of Verify(). It can operate on a
 buffer smaller than DigestSize(). However, digestLength cannot exceed DigestSize().
\\details Verify() performs a bitwise compare on the buffers using VerifyBufsEqual(), which is
 a constant time comparison function. digestLength cannot exceed DigestSize().
\\details TruncatedVerify() restarts the hash for the next message.
\\pre <tt>digestLength <= DigestSize()</tt> or <tt>digestLength <= HASH::DIGESTSIZE</tt> ensures
 the input byte buffer is a valid size.)")
        .def("VerifyTruncatedDigest", [](CryptoPP::HashTransformation &self, const pybind11::bytes &digest, const pybind11::bytes &data) {
            const std::string_view digest_view = digest;
            const std::string_view input_view = data;
            return self.VerifyTruncatedDigest(reinterpret_cast<const unsigned char *>(&digest_view[0]), digest_view.size(), reinterpret_cast<const unsigned char *>(&input_view[0]), input_view.size());
        }, pybind11::arg("digest"), pybind11::arg("input"), R"(\\brief Updates the hash with additional input and verifies the hash of the current message
\\param digest a pointer to the buffer of an \a existing hash
\\param digestLength the size of the truncated hash, in bytes
\\param input the additional input as a buffer
\\param length the size of the buffer, in bytes
\\return \p true if the existing hash matches the computed hash, \p false otherwise
\\throw InvalidArgument() if digestLength exceeds DigestSize()
\\details Use this if your input is in one piece and you don't want to call Update()
 and TruncatedVerify() separately.
\\details VerifyTruncatedDigest() is a truncated version of VerifyDigest(). It can operate
 on a buffer smaller than DigestSize(). However, digestLength cannot exceed DigestSize().
\\details VerifyTruncatedDigest() restarts the hash for the next message.
\\pre <tt>digestLength <= DigestSize()</tt> or <tt>digestLength <= HASH::DIGESTSIZE</tt> ensures
 the input byte buffer is a valid size.)")
        ;

/*

/// \brief Interface for one direction (encryption or decryption) of a block cipher
/// \details These objects usually should not be used directly. See BlockTransformation for more details.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE BlockCipher : public SimpleKeyingInterface, public BlockTransformation
{
protected:
	const Algorithm & GetAlgorithm() const {return *this;}
};

/// \brief Interface for one direction (encryption or decryption) of a stream cipher or cipher mode
/// \details These objects usually should not be used directly. See StreamTransformation for more details.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE SymmetricCipher : public SimpleKeyingInterface, public StreamTransformation
{
protected:
	const Algorithm & GetAlgorithm() const {return *this;}
};

/// \brief Interface for message authentication codes
/// \details These objects usually should not be used directly. See HashTransformation for more details.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE MessageAuthenticationCode : public SimpleKeyingInterface, public HashTransformation
{
protected:
	const Algorithm & GetAlgorithm() const {return *this;}
};

/// \brief Interface for authenticated encryption modes of operation
/// \details AuthenticatedSymmetricCipher() provides the interface for one direction
///  (encryption or decryption) of a stream cipher or block cipher mode with authentication. The
///  StreamTransformation() part of this interface is used to encrypt or decrypt the data. The
///  MessageAuthenticationCode() part of the interface is used to input additional authenticated
///  data (AAD), which is MAC'ed but not encrypted. The MessageAuthenticationCode() part is also
///  used to generate and verify the MAC.
/// \details Crypto++ provides four authenticated encryption modes of operation - CCM, EAX, GCM
///  and OCB mode. All modes implement AuthenticatedSymmetricCipher() and the motivation for
///  the API, like calling AAD a &quot;header&quot;, can be found in Bellare, Rogaway and
///  Wagner's <A HREF="http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf">The EAX Mode of
///  Operation</A>. The EAX paper suggested a basic API to help standardize AEAD schemes in
///  software and promote adoption of the modes.
/// \sa <A HREF="http://www.cryptopp.com/wiki/Authenticated_Encryption">Authenticated
///  Encryption</A> on the Crypto++ wiki.
/// \since Crypto++ 5.6.0
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AuthenticatedSymmetricCipher : public MessageAuthenticationCode, public StreamTransformation
{
public:
	virtual ~AuthenticatedSymmetricCipher() {}

	/// \brief Exception thrown when the object is in the wrong state for the operation
	/// \details this indicates that a member function was called in the wrong state, for example trying to encrypt
	///  a message before having set the key or IV
	class BadState : public Exception
	{
	public:
		explicit BadState(const std::string &name, const char *message) : Exception(OTHER_ERROR, name + ": " + message) {}
		explicit BadState(const std::string &name, const char *function, const char *state) : Exception(OTHER_ERROR, name + ": " + function + " was called before " + state) {}
	};

	/// \brief Provides the maximum length of AAD that can be input
	/// \return the maximum length of AAD that can be input before the encrypted data
	virtual lword MaxHeaderLength() const =0;

	/// \brief Provides the maximum length of encrypted data
	/// \return the maximum length of encrypted data
	virtual lword MaxMessageLength() const =0;

	/// \brief Provides the maximum length of AAD
	/// \return the maximum length of AAD that can be input after the encrypted data
	virtual lword MaxFooterLength() const {return 0;}

	/// \brief Determines if data lengths must be specified prior to inputting data
	/// \return true if the data lengths are required before inputting data, false otherwise
	/// \details if this function returns true, SpecifyDataLengths() must be called before attempting to input data.
	///  This is the case for some schemes, such as CCM.
	/// \sa SpecifyDataLengths()
	virtual bool NeedsPrespecifiedDataLengths() const {return false;}

	/// \brief Prescribes the data lengths
	/// \param headerLength size of data before message is input, in bytes
	/// \param messageLength size of the message, in bytes
	/// \param footerLength size of data after message is input, in bytes
	/// \details SpecifyDataLengths() only needs to be called if NeedsPrespecifiedDataLengths() returns <tt>true</tt>.
	///  If <tt>true</tt>, then <tt>headerLength</tt> will be validated against <tt>MaxHeaderLength()</tt>,
	///  <tt>messageLength</tt> will be validated against <tt>MaxMessageLength()</tt>, and
	///  <tt>footerLength</tt> will be validated against <tt>MaxFooterLength()</tt>.
	/// \sa NeedsPrespecifiedDataLengths()
	void SpecifyDataLengths(lword headerLength, lword messageLength, lword footerLength=0);

	/// \brief Encrypts and calculates a MAC in one call
	/// \param ciphertext the encryption buffer
	/// \param mac the mac buffer
	/// \param macSize the size of the MAC buffer, in bytes
	/// \param iv the iv buffer
	/// \param ivLength the size of the IV buffer, in bytes
	/// \param header the AAD buffer
	/// \param headerLength the size of the AAD buffer, in bytes
	/// \param message the message buffer
	/// \param messageLength the size of the messagetext buffer, in bytes
	/// \details EncryptAndAuthenticate() encrypts and generates the MAC in one call. The function
	///  truncates the MAC if <tt>macSize < TagSize()</tt>.
	virtual void EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *message, size_t messageLength);

	/// \brief Decrypts and verifies a MAC in one call
	/// \param message the decryption buffer
	/// \param mac the mac buffer
	/// \param macSize the size of the MAC buffer, in bytes
	/// \param iv the iv buffer
	/// \param ivLength the size of the IV buffer, in bytes
	/// \param header the AAD buffer
	/// \param headerLength the size of the AAD buffer, in bytes
	/// \param ciphertext the ciphertext buffer
	/// \param ciphertextLength the size of the ciphertext buffer, in bytes
	/// \return true if the MAC is valid and the decoding succeeded, false otherwise
	/// \details DecryptAndVerify() decrypts and verifies the MAC in one call.
	/// <tt>message</tt> is a decryption buffer and should be at least as large as the ciphertext buffer.
	/// \details The function returns true iff MAC is valid. DecryptAndVerify() assumes the MAC
	///  is truncated if <tt>macLength < TagSize()</tt>.
	virtual bool DecryptAndVerify(byte *message, const byte *mac, size_t macSize, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *ciphertext, size_t ciphertextLength);

	/// \brief Provides the name of this algorithm
	/// \return the standard algorithm name
	/// \details The standard algorithm name can be a name like \a AES or \a AES/GCM. Some algorithms
	///  do not have standard names yet. For example, there is no standard algorithm name for
	///  Shoup's ECIES.
	virtual std::string AlgorithmName() const;

	/// \brief Retrieve the provider of this algorithm
	/// \return the algorithm provider
	/// \details The algorithm provider can be a name like "C++", "SSE", "NEON", "AESNI",
	///  "ARMv8" and "Power8". C++ is standard C++ code. Other labels, like SSE,
	///  usually indicate a specialized implementation using instructions from a higher
	///  instruction set architecture (ISA). Future labels may include external hardware
	///  like a hardware security module (HSM).
	/// \details Generally speaking Wei Dai's original IA-32 ASM code falls under "SSE2".
	///  Labels like "SSSE3" and "SSE4.1" follow after Wei's code and use intrinsics
	///  instead of ASM.
	/// \details Algorithms which combine different instructions or ISAs provide the
	///  dominant one. For example on x86 <tt>AES/GCM</tt> returns "AESNI" rather than
	///  "CLMUL" or "AES+SSE4.1" or "AES+CLMUL" or "AES+SSE4.1+CLMUL".
	/// \note Provider is not universally implemented yet.
	/// \since Crypto++ 8.0
	virtual std::string AlgorithmProvider() const {return "C++";}

protected:
	const Algorithm & GetAlgorithm() const
		{return *static_cast<const MessageAuthenticationCode *>(this);}
	virtual void UncheckedSpecifyDataLengths(lword headerLength, lword messageLength, lword footerLength)
		{CRYPTOPP_UNUSED(headerLength); CRYPTOPP_UNUSED(messageLength); CRYPTOPP_UNUSED(footerLength);}
};

/// \brief Interface for random number generators
/// \details The library provides a number of random number generators, from software based
///  to hardware based generators.
/// \details All generated values are uniformly distributed over the range specified.
/// \since Crypto++ 3.1
/// \sa <A HREF="https://www.cryptopp.com/wiki/RandomNumberGenerator">RandomNumberGenerator</A>
///  on the Crypto++ wiki
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE RandomNumberGenerator : public Algorithm
{
public:
	virtual ~RandomNumberGenerator() {}

	/// \brief Update RNG state with additional unpredictable values
	/// \param input the entropy to add to the generator
	/// \param length the size of the input buffer
	/// \throw NotImplemented
	/// \details A generator may or may not accept additional entropy. Call CanIncorporateEntropy()
	///  to test for the ability to use additional entropy.
	/// \details If a derived class does not override IncorporateEntropy(), then the base class
	///  throws NotImplemented.
	virtual void IncorporateEntropy(const byte *input, size_t length)
	{
		CRYPTOPP_UNUSED(input); CRYPTOPP_UNUSED(length);
		throw NotImplemented("RandomNumberGenerator: IncorporateEntropy not implemented");
	}

	/// \brief Determines if a generator can accept additional entropy
	/// \return true if IncorporateEntropy() is implemented
	virtual bool CanIncorporateEntropy() const {return false;}

	/// \brief Generate new random byte and return it
	/// \return a random 8-bit byte
	/// \details Default implementation calls GenerateBlock() with one byte.
	/// \details All generated values are uniformly distributed over the range specified within the
	///  the constraints of a particular generator.
	virtual byte GenerateByte();

	/// \brief Generate new random bit and return it
	/// \return a random bit
	/// \details The default implementation calls GenerateByte() and return its lowest bit.
	/// \details All generated values are uniformly distributed over the range specified within the
	///  the constraints of a particular generator.
	virtual unsigned int GenerateBit();

	/// \brief Generate a random 32 bit word in the range min to max, inclusive
	/// \param min the lower bound of the range
	/// \param max the upper bound of the range
	/// \return a random 32-bit word
	/// \details The default implementation calls Crop() on the difference between max and
	///  min, and then returns the result added to min.
	/// \details All generated values are uniformly distributed over the range specified within the
	///  the constraints of a particular generator.
	virtual word32 GenerateWord32(word32 min=0, word32 max=0xffffffffUL);

	/// \brief Generate random array of bytes
	/// \param output the byte buffer
	/// \param size the length of the buffer, in bytes
	/// \details All generated values are uniformly distributed over the range specified within the
	///  the constraints of a particular generator.
	/// \note A derived generator \a must override either GenerateBlock() or
	///  GenerateIntoBufferedTransformation(). They can override both, or have one call the other.
	virtual void GenerateBlock(byte *output, size_t size);

	/// \brief Generate random bytes into a BufferedTransformation
	/// \param target the BufferedTransformation object which receives the bytes
	/// \param channel the channel on which the bytes should be pumped
	/// \param length the number of bytes to generate
	/// \details The default implementation calls GenerateBlock() and pumps the result into
	///  the DEFAULT_CHANNEL of the target.
	/// \details All generated values are uniformly distributed over the range specified within the
	///  the constraints of a particular generator.
	/// \note A derived generator \a must override either GenerateBlock() or
	///  GenerateIntoBufferedTransformation(). They can override both, or have one call the other.
	virtual void GenerateIntoBufferedTransformation(BufferedTransformation &target, const std::string &channel, lword length);

	/// \brief Generate and discard n bytes
	/// \param n the number of bytes to generate and discard
	virtual void DiscardBytes(size_t n);

	/// \brief Randomly shuffle the specified array
	/// \param begin an iterator to the first element in the array
	/// \param end an iterator beyond the last element in the array
	/// \details The resulting permutation is uniformly distributed.
	template <class IT> void Shuffle(IT begin, IT end)
	{
		// TODO: What happens if there are more than 2^32 elements?
		for (; begin != end; ++begin)
			std::iter_swap(begin, begin + GenerateWord32(0, static_cast<word32>(end-begin-1)));
	}
};

/// \brief Interface for key derivation functions
/// \since Crypto++ 7.0
/// \sa <A HREF="https://www.cryptopp.com/wiki/KeyDerivationFunction">KeyDerivationFunction</A>
///  on the Crypto++ wiki
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE KeyDerivationFunction : public Algorithm
{
public:
	virtual ~KeyDerivationFunction() {}

	/// \brief Provides the name of this algorithm
	/// \return the standard algorithm name
	virtual std::string AlgorithmName() const =0;

	/// \brief Determine minimum number of bytes
	/// \return Minimum number of bytes which can be derived
	virtual size_t MinDerivedKeyLength() const;

	/// \brief Determine maximum number of bytes
	/// \return Maximum number of bytes which can be derived
	virtual size_t MaxDerivedKeyLength() const;

	/// \brief Returns a valid key length for the derivation function
	/// \param keylength the size of the derived key, in bytes
	/// \return the valid key length, in bytes
	virtual size_t GetValidDerivedLength(size_t keylength) const =0;

	/// \brief Returns whether keylength is a valid key length
	/// \param keylength the requested keylength
	/// \return true if the derived keylength is valid, false otherwise
	/// \details Internally the function calls GetValidKeyLength()
	virtual bool IsValidDerivedLength(size_t keylength) const {
		return keylength == GetValidDerivedLength(keylength);
	}

	/// \brief Derive a key from a seed
	/// \param derived the derived output buffer
	/// \param derivedLen the size of the derived buffer, in bytes
	/// \param secret the seed input buffer
	/// \param secretLen the size of the secret buffer, in bytes
	/// \param params additional initialization parameters to configure this object
	/// \return the number of iterations performed
	/// \throw InvalidDerivedKeyLength if <tt>derivedLen</tt> is invalid for the scheme
	/// \details DeriveKey() provides a standard interface to derive a key from
	///  a secret seed and other parameters. Each class that derives from KeyDerivationFunction
	///  provides an overload that accepts most parameters used by the derivation function.
	/// \details the number of iterations performed by DeriveKey() may be 1. For example, a
	///  scheme like HKDF does not use the iteration count so it returns 1.
	virtual size_t DeriveKey(byte *derived, size_t derivedLen, const byte *secret, size_t secretLen, const NameValuePairs& params = g_nullNameValuePairs) const =0;

	/// \brief Set or change parameters
	/// \param params additional initialization parameters to configure this object
	/// \details SetParameters() is useful for setting common parameters when an object is
	///  reused. Some derivation function classes may choose to implement it.
	virtual void SetParameters(const NameValuePairs& params);

protected:
	/// \brief Returns the base class Algorithm
	/// \return the base class Algorithm
	virtual const Algorithm & GetAlgorithm() const =0;

	/// \brief Validates the derived key length
	/// \param length the size of the derived key material, in bytes
	/// \throw InvalidKeyLength if the key length is invalid
	void ThrowIfInvalidDerivedKeyLength(size_t length) const;
};

/// \brief Interface for password based key derivation functions
/// \since Crypto++ 7.0
struct PasswordBasedKeyDerivationFunction : public KeyDerivationFunction
{
};

/// \brief Random Number Generator that does not produce random numbers
/// \return reference that can be passed to functions that require a RandomNumberGenerator
/// \details NullRNG() returns a reference that can be passed to functions that require a
///  RandomNumberGenerator but don't actually use it. The NullRNG() throws NotImplemented
///  when a generation function is called.
/// \sa ClassNullRNG, PK_SignatureScheme::IsProbabilistic()
CRYPTOPP_DLL RandomNumberGenerator & CRYPTOPP_API NullRNG();

class WaitObjectContainer;
class CallStack;

/// \brief Interface for objects that can be waited on.
class CRYPTOPP_NO_VTABLE Waitable
{
public:
	virtual ~Waitable() {}

	/// \brief Maximum number of wait objects that this object can return
	/// \return the maximum number of wait objects
	virtual unsigned int GetMaxWaitObjectCount() const =0;

	/// \brief Retrieves waitable objects
	/// \param container the wait container to receive the references to the objects.
	/// \param callStack CallStack() object used to select waitable objects
	/// \details GetWaitObjects() is usually called in one of two ways. First, it can
	///  be called like <tt>something.GetWaitObjects(c, CallStack("my func after X", 0));</tt>.
	///  Second, if in an outer GetWaitObjects() method that itself takes a callStack
	///  parameter, it can be called like
	///  <tt>innerThing.GetWaitObjects(c, CallStack("MyClass::GetWaitObjects at X", &callStack));</tt>.
	virtual void GetWaitObjects(WaitObjectContainer &container, CallStack const& callStack) =0;

	/// \brief Wait on this object
	/// \return true if the wait succeeded, false otherwise
	/// \details Wait() is the same as creating an empty container, calling GetWaitObjects(), and then calling
	///  Wait() on the container.
	bool Wait(unsigned long milliseconds, CallStack const& callStack);
};

*/

    pybind11::class_<CryptoPP::BufferedTransformation, CryptoPP::Algorithm>(m, "BufferedTransformation", R"(\\brief Interface for buffered transformations
\\details BufferedTransformation is a generalization of BlockTransformation,
 StreamTransformation and HashTransformation.
\\details A buffered transformation is an object that takes a stream of bytes as input (this may
 be done in stages), does some computation on them, and then places the result into an internal
 buffer for later retrieval. Any partial result already in the output buffer is not modified
 by further input.
\\details If a method takes a "blocking" parameter, and you pass false for it, then the method
 will return before all input has been processed if the input cannot be processed without waiting
 (for network buffers to become available, for example). In this case the method will return true
 or a non-zero integer value. When this happens you must continue to call the method with the same
 parameters until it returns false or zero, before calling any other method on it or attached
 BufferedTransformation. The integer return value in this case is approximately
 the number of bytes left to be processed, and can be used to implement a progress bar.
\\details For functions that take a "propagation" parameter, <tt>propagation != 0</tt> means pass on
 the signal to attached BufferedTransformation objects, with propagation decremented at each
 step until it reaches <tt>0</tt>. <tt>-1</tt> means unlimited propagation.
\\details \a All of the retrieval functions, like Get() and GetWord32(), return the actual
 number of bytes retrieved, which is the lesser of the request number and MaxRetrievable().
\\details \a Most of the input functions, like Put() and PutWord32(), return the number of
 bytes remaining to be processed. A 0 value means all bytes were processed, and a non-0 value
 means bytes remain to be processed.
\\nosubgrouping)")
        //.def(pybind11::init<>(), "\\brief Construct a BufferedTransformation")
        .def("Ref", &CryptoPP::BufferedTransformation::Ref, R"(\\brief Provides a reference to this object
\\return A reference to this object
\\details Useful for passing a temporary object to a function that takes a non-const reference)")
        .def("Put", pybind11::overload_cast<CryptoPP::byte, bool>(&CryptoPP::BufferedTransformation::Put), pybind11::arg("inByte"), pybind11::arg("blocking") = true, R"(\\brief Input a byte for processing
\\param inByte the 8-bit byte (octet) to be processed.
\\param blocking specifies whether the object should block when processing input.
\\return the number of bytes that remain to be processed (i.e., bytes not processed).
 0 indicates all bytes were processed.
\\details <tt>Put(byte)</tt> calls <tt>Put(byte*, size_t)</tt>.)")
        .def("Put", [](CryptoPP::BufferedTransformation &self, const pybind11::bytes &inString, bool blocking) {
            const std::string_view view = inString;
            return self.Put(reinterpret_cast<const unsigned char *>(&view[0]), view.size(), blocking);
        }, pybind11::arg("inString"), pybind11::arg("blocking") = true, R"(\\brief Input a byte buffer for processing
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain to be processed (i.e., bytes not processed).
 0 indicates all bytes were processed.
\\details Internally, Put() calls Put2().)")
        .def("PutWord16", &CryptoPP::BufferedTransformation::PutWord16, pybind11::arg("value"), pybind11::arg("order")=CryptoPP::BIG_ENDIAN_ORDER, pybind11::arg("blocking") = true, R"(Input a 16-bit word for processing.
\\param value the 16-bit value to be processed
\\param order the ByteOrder of the value to be processed.
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain to be processed (i.e., bytes not processed).
 0 indicates all bytes were processed.)")
        .def("PutWord32", &CryptoPP::BufferedTransformation::PutWord32, pybind11::arg("value"), pybind11::arg("order")=CryptoPP::BIG_ENDIAN_ORDER, pybind11::arg("blocking") = true, R"(Input a 32-bit word for processing.
\\param value the 32-bit value to be processed.
\\param order the ByteOrder of the value to be processed.
\\param blocking specifies whether the object should block when processing input.
\\return the number of bytes that remain to be processed (i.e., bytes not processed).
 0 indicates all bytes were processed.)")
        .def("PutWord64", &CryptoPP::BufferedTransformation::PutWord64, pybind11::arg("value"), pybind11::arg("order")=CryptoPP::BIG_ENDIAN_ORDER, pybind11::arg("blocking") = true, R"(Input a 64-bit word for processing.
\\param value the 64-bit value to be processed.
\\param order the ByteOrder of the value to be processed.
\\param blocking specifies whether the object should block when processing input.
\\return the number of bytes that remain to be processed (i.e., bytes not processed).
 0 indicates all bytes were processed.)")
        /// \brief Request space which can be written into by the caller
        /// \param size the requested size of the buffer
        /// \return byte pointer to the space to input data
        /// \details The purpose of this method is to help avoid extra memory allocations.
        /// \details size is an \a IN and \a OUT parameter and used as a hint. When the call is made,
        ///  size is the requested size of the buffer. When the call returns, size is the size of
        ///  the array returned to the caller.
        /// \details The base class implementation sets size to 0 and returns NULL.
        /// \note Some objects, like ArraySink, cannot create a space because its fixed. In the case of
        /// an ArraySink, the pointer to the array is returned and the size is remaining size.
        //.def("CreatePutSpace", &CryptoPP::BufferedTransformation::CreatePutSpace)
        .def("CanModifyInput", &CryptoPP::BufferedTransformation::CanModifyInput, R"(\\brief Determines whether input can be modified by the callee
\\return true if input can be modified, false otherwise
\\details The base class implementation returns false.)")
        .def("PutModifiable", [](CryptoPP::BufferedTransformation &self, const pybind11::bytes inString, bool blocking) {
            const std::string_view view = inString;
            self.PutModifiable(
                const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(&view[0])), view.size(), blocking);
        }, pybind11::arg("inString"), pybind11::arg("blocking") = true, R"(\\brief Input multiple bytes that may be modified by callee.
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain to be processed (i.e., bytes not processed). 0 indicates all
 bytes were processed.)")
        .def("MessageEnd", &CryptoPP::BufferedTransformation::MessageEnd, pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true, R"(\\brief Signals the end of messages to the object
\\param propagation the number of attached transformations the MessageEnd() signal should be passed
\\param blocking specifies whether the object should block when processing input
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.)")
        .def("PutMessageEnd", [](CryptoPP::BufferedTransformation &self, const pybind11::bytes &inString, int propagation, bool blocking) {
            const std::string_view view = inString;
            return self.PutMessageEnd(reinterpret_cast<const unsigned char *>(&view[0]), view.size(), propagation, blocking);
        }, pybind11::arg("inString"), pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true, R"(\\brief Input multiple bytes for processing and signal the end of a message
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param propagation the number of attached transformations the MessageEnd() signal should be passed
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain to be processed (i.e., bytes not processed). 0 indicates all
 bytes were processed.
\\details Internally, PutMessageEnd() calls Put2() with a modified propagation to
 ensure all attached transformations finish processing the message.
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.)")
        .def("Put2", [](CryptoPP::BufferedTransformation &self, const pybind11::bytes &inString, int messageEnd, bool blocking) {
            const std::string_view view = inString;
            return self.Put2(reinterpret_cast<const unsigned char *>(&view[0]), view.size(), messageEnd, blocking);
        }, pybind11::arg("inString"), pybind11::arg("messageEnd"), pybind11::arg("blocking"), R"(\\brief Input multiple bytes for processing
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param messageEnd means how many filters to signal MessageEnd() to, including this one
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain to be processed (i.e., bytes not processed). 0 indicates all
 bytes were processed.
\\details Derived classes must implement Put2().)")
        .def("PutModifiable2", [](CryptoPP::BufferedTransformation &self, const pybind11::bytes &inString, int messageEnd, bool blocking) {
            const std::string_view view = inString;
            return self.PutModifiable2(
                const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(&view[0])), view.size(), messageEnd, blocking);
        }, R"(\\brief Input multiple bytes that may be modified by callee.
\\param inString the byte buffer to process.
\\param length the size of the string, in bytes.
\\param messageEnd means how many filters to signal MessageEnd() to, including this one.
\\param blocking specifies whether the object should block when processing input.
\\return the number of bytes that remain to be processed (i.e., bytes not processed). 0 indicates all
 bytes were processed.
\\details Internally, PutModifiable2() calls Put2().)")
        .def("GetMaxWaitObjectCount", &CryptoPP::BufferedTransformation::GetMaxWaitObjectCount, "\\brief Retrieves the maximum number of waitable objects")
//        .def("GetWaitObjects", &CryptoPP::BufferedTransformation::GetWaitObjects, pybind11::arg("container"), pybind11::arg("callStack"), R"(\\brief Retrieves waitable objects
//\\param container the wait container to receive the references to the objects
//\\param callStack CallStack() object used to select waitable objects
//\\details GetWaitObjects is usually called in one of two ways. First, it can
// be called like <tt>something.GetWaitObjects(c, CallStack("my func after X", 0));</tt>.
// Second, if in an outer GetWaitObjects() method that itself takes a callStack
// parameter, it can be called like
// <tt>innerThing.GetWaitObjects(c, CallStack("MyClass::GetWaitObjects at X", &callStack));</tt>.)")
        .def("IsolatedInitialize", &CryptoPP::BufferedTransformation::IsolatedInitialize, pybind11::arg("parameters"), R"(\\brief Initialize or reinitialize this object, without signal propagation
\\param parameters a set of NameValuePairs to initialize this object
\\throw NotImplemented
\\details IsolatedInitialize() is used to initialize or reinitialize an object using a variable
 number of arbitrarily typed arguments. The function avoids the need for multiple constructors providing
 all possible combintations of configurable parameters.
\\details IsolatedInitialize() does not call Initialize() on attached transformations. If initialization
 should be propagated, then use the Initialize() function.
\\details If a derived class does not override IsolatedInitialize(), then the base class throws
 NotImplemented.)")
        .def("IsolatedFlush", &CryptoPP::BufferedTransformation::IsolatedFlush, pybind11::arg("hardFlush"), pybind11::arg("blocking"), R"(\\brief Flushes data buffered by this object, without signal propagation
\\param hardFlush indicates whether all data should be flushed
\\param blocking specifies whether the object should block when processing input
\\return true if the flush was successful, false otherwise
\\note hardFlush must be used with care)")
        .def("IsolatedMessageSeriesEnd", &CryptoPP::BufferedTransformation::IsolatedMessageSeriesEnd, pybind11::arg("blocking"), R"(\\brief Marks the end of a series of messages, without signal propagation
\\param blocking specifies whether the object should block when completing the processing on
 the current series of messages
\\return true if the message was successful, false otherwise)")
        .def("Initialize", &CryptoPP::BufferedTransformation::Initialize, pybind11::arg("parameters"), pybind11::arg("propagation") = -1, R"(\\brief Initialize or reinitialize this object, with signal propagation
\\param parameters a set of NameValuePairs to initialize or reinitialize this object
\\param propagation the number of attached transformations the Initialize() signal should be passed
\\details Initialize() is used to initialize or reinitialize an object using a variable number of
 arbitrarily typed arguments. The function avoids the need for multiple constructors providing
 all possible combintations of configurable parameters.
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.)")
        .def("Flush", &CryptoPP::BufferedTransformation::Flush, pybind11::arg("hardFlush"), pybind11::arg("propacation") = -1, pybind11::arg("blocking") = true, R"(\\brief Flush buffered input and/or output, with signal propagation
\\param hardFlush is used to indicate whether all data should be flushed
\\param propagation the number of attached transformations the Flush()
 signal should be passed
\\param blocking specifies whether the object should block when processing input
\\return true if the flush was successful, false otherwise
\\details propagation count includes this object. Setting propagation to
 <tt>1</tt> means this object only. Setting propagation to <tt>-1</tt>
 means unlimited propagation.
\\note Hard flushes must be used with care. It means try to process and
 output everything, even if there may not be enough data to complete the
 action. For example, hard flushing a HexDecoder would cause an error if
 you do it after inputing an odd number of hex encoded characters.
\\note For some types of filters, like  ZlibDecompressor, hard flushes can
 only be done at "synchronization points". These synchronization points
 are positions in the data stream that are created by hard flushes on the
 corresponding reverse filters, in this example ZlibCompressor. This is
 useful when zlib compressed data is moved across a network in packets
 and compression state is preserved across packets, as in the SSH2 protocol.)")
        .def("MessageSeriesEnd", &CryptoPP::BufferedTransformation::MessageSeriesEnd, pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true, R"(\\brief Marks the end of a series of messages, with signal propagation
\\param propagation the number of attached transformations the MessageSeriesEnd() signal should be passed
\\param blocking specifies whether the object should block when processing input
\\return true if the message was successful, false otherwise
\\details Each object that receives the signal will perform its processing, decrement
 propagation, and then pass the signal on to attached transformations if the value is not 0.
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.
\\note There should be a MessageEnd() immediately before MessageSeriesEnd().)")
        .def("SetAutoSignalPropagation", &CryptoPP::BufferedTransformation::SetAutoSignalPropagation, pybind11::arg("propagation"), R"(\\brief Set propagation of automatically generated and transferred signals
\\param propagation then new value
\\details Setting propagation to <tt>0</tt> means do not automatically generate signals. Setting
 propagation to <tt>-1</tt> means unlimited propagation.)")
        .def("GetAutoSignalPropagation", &CryptoPP::BufferedTransformation::GetAutoSignalPropagation, R"(\\brief Retrieve automatic signal propagation value
\\return the number of attached transformations the signal is propagated to. 0 indicates
 the signal is only witnessed by this object)")
        .def("MaxRetrievable", &CryptoPP::BufferedTransformation::MaxRetrievable, R"(\\brief Provides the number of bytes ready for retrieval
\\return the number of bytes ready for retrieval
\\details The number of bytes available are dependent on the source. If an exact value is
 available, then the exact value is returned. The exact value can include 0 if the source
 is exhausted.
\\details Some stream-based sources do not allow seeking() on the underlying stream, such
 as some FileSource(). If the stream does not allow seeking() then MaxRetrievable()
 returns LWORD_MAX to indicate there are still bytes to be retrieved.)")
        .def("AnyRetrievable", &CryptoPP::BufferedTransformation::AnyRetrievable, R"(\\brief Determines whether bytes are ready for retrieval
\\return true if bytes are available for retrieval, false otherwise)")
        /// \brief Retrieve a 8-bit byte
        /// \param outByte the 8-bit value to be retrieved
        /// \return the number of bytes consumed during the call.
        /// \details Use the return value of Get to detect short reads.
        //.def("Get", &CryptoPP::BufferedTransformation::Get)
        .def("Get", [](CryptoPP::BufferedTransformation &self, size_t getMax) {
            std::string temp(getMax, 0);
            const auto size = self.Get(reinterpret_cast<unsigned char *>(&temp[0]), getMax);
            temp.resize(size);
            return pybind11::bytes(temp);
        }, pybind11::arg("getMax"), R"(\\brief Retrieve a block of bytes
\\param outString a block of bytes
\\param getMax the number of bytes to Get
\\return the number of bytes consumed during the call.
\\details Use the return value of Get to detect short reads.)")
        /// \brief Peek a 8-bit byte
        /// \param outByte the 8-bit value to be retrieved
        /// \return the number of bytes read during the call.
        /// \details Peek does not remove bytes from the object. Use the return value of
        ///  Get() to detect short reads.
        //.def("Peek", &CryptoPP::BufferedTransformation::Peek)
        .def("Peek", [](CryptoPP::BufferedTransformation &self, size_t peekMax) {
            std::string temp(peekMax, 0);
            const auto size = self.Peek(reinterpret_cast<unsigned char *>(&temp[0]), peekMax);
            temp.resize(size);
            return pybind11::bytes(temp);
        }, pybind11::arg("peekMax"), R"(\\brief Peek a block of bytes
\\param outString a block of bytes
\\param peekMax the number of bytes to Peek
\\return the number of bytes read during the call.
\\details Peek does not remove bytes from the object. Use the return value of
 Peek() to detect short reads.)")
        /// \brief Retrieve a 16-bit word
        /// \param value the 16-bit value to be retrieved
        /// \param order the ByteOrder of the value to be processed.
        /// \return the number of bytes consumed during the call.
        /// \details Use the return value of GetWord16() to detect short reads.
        //.def("GetWord16", &CryptoPP::BufferedTransformation::GetWord16)
        /// \brief Retrieve a 32-bit word
		/// \param value the 32-bit value to be retrieved
		/// \param order the ByteOrder of the value to be processed.
		/// \return the number of bytes consumed during the call.
		/// \details Use the return value of GetWord32() to detect short reads.
        .def("GetWord32", &CryptoPP::BufferedTransformation::GetWord32)
        /// \brief Retrieve a 64-bit word
		/// \param value the 64-bit value to be retrieved
		/// \param order the ByteOrder of the value to be processed.
		/// \return the number of bytes consumed during the call.
		/// \details Use the return value of GetWord64() to detect short reads.
		/// \since Crypto++ 8.3
        //.def("GetWord64", &CryptoPP::BufferedTransformation::GetWord64)
        /// \brief Peek a 16-bit word
		/// \param value the 16-bit value to be retrieved
		/// \param order the ByteOrder of the value to be processed.
		/// \return the number of bytes consumed during the call.
		/// \details Peek does not consume bytes in the stream. Use the return value
		///  of PeekWord16() to detect short reads.
        //.def("PeekWord16", &CryptoPP::BufferedTransformation::PeekWord16)
        /// \brief Peek a 32-bit word
		/// \param value the 32-bit value to be retrieved
		/// \param order the ByteOrder of the value to be processed.
		/// \return the number of bytes consumed during the call.
		/// \details Peek does not consume bytes in the stream. Use the return value
		///  of PeekWord32() to detect short reads.
        //.def("PeekWord32", &CryptoPP::BufferedTransformation::PeekWord32)
        /// \brief Peek a 64-bit word
		/// \param value the 64-bit value to be retrieved
		/// \param order the ByteOrder of the value to be processed.
		/// \return the number of bytes consumed during the call.
		/// \details Peek does not consume bytes in the stream. Use the return value
		///  of PeekWord64() to detect short reads.
		/// \since Crypto++ 8.3
        //.def("PeekWord64", &CryptoPP::BufferedTransformation::PeekWord64)
        /// \brief Transfer bytes from this object to another BufferedTransformation
		/// \param target the destination BufferedTransformation
		/// \param transferMax the number of bytes to transfer
		/// \param channel the channel on which the transfer should occur
		/// \return the number of bytes transferred during the call.
		/// \details TransferTo removes bytes from this object and moves them to the destination.
		/// \details The function always returns transferMax. If an accurate count is needed, then use TransferTo2().
        .def("TransferTo", &CryptoPP::BufferedTransformation::TransferTo, pybind11::arg("target"), pybind11::arg("transferMax") = CryptoPP::LWORD_MAX, pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL)
        .def("Skip", &CryptoPP::BufferedTransformation::Skip, pybind11::arg("skipMax") = CryptoPP::LWORD_MAX, R"(\\brief Discard skipMax bytes from the output buffer
\\param skipMax the number of bytes to discard
\\details Skip() discards bytes from the output buffer, which is the AttachedTransformation(), if present.
 The function always returns the parameter <tt>skipMax</tt>.
\\details If you want to skip bytes from a Source, then perform the following.
<pre>  StringSource ss(str, false, new Redirector(TheBitBucket()));
  ss.Pump(10);    // Skip 10 bytes from Source
  ss.Detach(new FilterChain(...));
  ss.PumpAll();
</pre>)")
        .def("CopyTo", &CryptoPP::BufferedTransformation::CopyTo, pybind11::arg("target"), pybind11::arg("copyMax") = CryptoPP::LWORD_MAX, pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, R"(\\brief Copy bytes from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param copyMax the number of bytes to copy
\\param channel the channel on which the transfer should occur
\\return the number of bytes copied during the call.
\\details CopyTo copies bytes from this object to the destination. The bytes are not removed from this object.
\\details The function always returns copyMax. If an accurate count is needed, then use CopyRangeTo2().)")
        .def("CopyRangeTo", &CryptoPP::BufferedTransformation::CopyRangeTo, pybind11::arg("target"), pybind11::arg("position"), pybind11::arg("copyMax") = CryptoPP::LWORD_MAX, pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, R"(\\brief Copy bytes from this object using an index to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param position the 0-based index of the byte stream to begin the copying
\\param copyMax the number of bytes to copy
\\param channel the channel on which the transfer should occur
\\return the number of bytes copied during the call.
\\details CopyTo copies bytes from this object to the destination. The bytes remain in this
 object. Copying begins at the index position in the current stream, and not from an absolute
 position in the stream.
\\details The function returns the new position in the stream after transferring the bytes starting at the index.)")
        .def("TotalBytesRetrievable", &CryptoPP::BufferedTransformation::TotalBytesRetrievable, R"(\\brief Provides the number of bytes ready for retrieval
\\return the number of bytes ready for retrieval)")
        .def("NumberOfMessages", &CryptoPP::BufferedTransformation::NumberOfMessages, R"(\\brief Provides the number of meesages processed by this object
\\return the number of meesages processed by this object
\\details NumberOfMessages returns number of times MessageEnd() has been
 received minus messages retrieved or skipped)")
        .def("AnyMessages", &CryptoPP::BufferedTransformation::AnyMessages, R"(\\brief Determines if any messages are available for retrieval
\\return true if <tt>NumberOfMessages() &gt; 0</tt>, false otherwise
\\details AnyMessages returns true if <tt>NumberOfMessages() &gt; 0</tt>)")
        .def("GetNextMessage", &CryptoPP::BufferedTransformation::GetNextMessage, R"(\\brief Start retrieving the next message
\\return true if a message is ready for retrieval
\\details GetNextMessage() returns true if a message is ready for retrieval; false
 if no more messages exist or this message is not completely retrieved.)")
        .def("SkipMessages", &CryptoPP::BufferedTransformation::SkipMessages, pybind11::arg("count") = UINT_MAX, R"(\\brief Skip a number of meessages
\\param count number of messages to skip
\\return 0 if the requested number of messages was skipped, non-0 otherwise
\\details SkipMessages() skips count number of messages. If there is an AttachedTransformation()
 then SkipMessages() is called on the attached transformation. If there is no attached
 transformation, then count number of messages are sent to TheBitBucket() using TransferMessagesTo().)")
        .def("TransferMessagesTo", &CryptoPP::BufferedTransformation::TransferMessagesTo, pybind11::arg("target"), pybind11::arg("count") = UINT_MAX, pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, R"(\\brief Transfer messages from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param count the number of messages to transfer
\\param channel the channel on which the transfer should occur
\\return the number of bytes that remain in the current transfer block (i.e., bytes not transferred)
\\details TransferMessagesTo2() removes messages from this object and moves them to the destination.
 If all bytes are not transferred for a message, then processing stops and the number of remaining
 bytes is returned. TransferMessagesTo() does not proceed to the next message.
\\details A return value of 0 indicates all messages were successfully transferred.)")
        .def("CopyMessagesTo", &CryptoPP::BufferedTransformation::CopyMessagesTo, pybind11::arg("target"), pybind11::arg("count") = UINT_MAX, pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, R"(\\brief Copy messages from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param count the number of messages to copy
\\param channel the channel on which the copy should occur
\\return the number of bytes that remain in the current transfer block (i.e., bytes not transferred)
\\details CopyMessagesTo copies messages from this object to the destination.
 If all bytes are not transferred for a message, then processing stops and the number of remaining
 bytes is returned. CopyMessagesTo() does not proceed to the next message.
\\details A return value of 0 indicates all messages were successfully copied.)")
        .def("SkipAll", &CryptoPP::BufferedTransformation::SkipAll, "\\brief Skip all messages in the series")
        .def("TransferAllTo", &CryptoPP::BufferedTransformation::TransferAllTo, pybind11::arg("target"), pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, R"(\\brief Transfer all bytes from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param channel the channel on which the transfer should occur
\\details TransferMessagesTo2() removes messages from this object and moves them to the destination.
 Internally TransferAllTo() calls TransferAllTo2().)")
        .def("CopyAllTo", &CryptoPP::BufferedTransformation::CopyAllTo, pybind11::arg("target"), pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, R"(\\brief Copy messages from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param channel the channel on which the transfer should occur
\\details CopyAllTo copies messages from this object and copies them to the destination.)")
        .def("GetNextMessageSeries", &CryptoPP::BufferedTransformation::GetNextMessageSeries, R"(\\brief Retrieve the next message in a series
\\return true if a message was retrieved, false otherwise
\\details Internally, the base class implementation returns false.)")
        .def("NumberOfMessagesInThisSeries", &CryptoPP::BufferedTransformation::NumberOfMessagesInThisSeries, R"(\\brief Provides the number of messages in a series
\\return the number of messages in this series)")
        .def("NumberOfMessageSeries", &CryptoPP::BufferedTransformation::NumberOfMessageSeries, R"(\\brief Provides the number of messages in a series
\\return the number of messages in this series)")
        .def("TransferTo2", &CryptoPP::BufferedTransformation::TransferTo2, pybind11::arg("target"), pybind11::arg("byteCount"), pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, pybind11::arg("blocking") = true, R"(\\brief Transfer bytes from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param byteCount the number of bytes to transfer
\\param channel the channel on which the transfer should occur
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain in the transfer block (i.e., bytes not transferred)
\\details TransferTo2() removes bytes from this object and moves them to the destination.
 Transfer begins at the index position in the current stream, and not from an absolute
 position in the stream.
\\details byteCount is an \a IN and \a OUT parameter. When the call is made,
 byteCount is the requested size of the transfer. When the call returns, byteCount is
 the number of bytes that were transferred.)")
        .def("CopyRangeTo2", &CryptoPP::BufferedTransformation::CopyRangeTo2, pybind11::arg("target"), pybind11::arg("begin"), pybind11::arg("end") = CryptoPP::LWORD_MAX, pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, pybind11::arg("blocking") = true, R"(\\brief Copy bytes from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param begin the 0-based index of the first byte to copy in the stream
\\param end the 0-based index of the last byte to copy in the stream
\\param channel the channel on which the transfer should occur
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain in the copy block (i.e., bytes not copied)
\\details CopyRangeTo2 copies bytes from this object to the destination. The bytes are not
 removed from this object. Copying begins at the index position in the current stream, and
 not from an absolute position in the stream.
\\details begin is an \\a IN and \\a OUT parameter. When the call is made, begin is the
 starting position of the copy. When the call returns, begin is the position of the first
 byte that was \\a not copied (which may be different than end). begin can be used for
 subsequent calls to CopyRangeTo2().)")
        .def("TransferMessagesTo2", &CryptoPP::BufferedTransformation::TransferMessagesTo2, pybind11::arg("target"), pybind11::arg("messageCount"), pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, pybind11::arg("blocking") = true, R"(\\brief Transfer messages from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param messageCount the number of messages to transfer
\\param channel the channel on which the transfer should occur
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain in the current transfer block (i.e., bytes not transferred)
\\details TransferMessagesTo2() removes messages from this object and moves them to the destination.
\\details messageCount is an \a IN and \a OUT parameter. When the call is made, messageCount is the
 the number of messages requested to be transferred. When the call returns, messageCount is the
 number of messages actually transferred.)")
        .def("TransferAllTo2", &CryptoPP::BufferedTransformation::TransferAllTo2, pybind11::arg("target"), pybind11::arg("channel") = CryptoPP::DEFAULT_CHANNEL, pybind11::arg("blocking") = true, R"(\\brief Transfer all bytes from this object to another BufferedTransformation
\\param target the destination BufferedTransformation
\\param channel the channel on which the transfer should occur
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain in the current transfer block (i.e., bytes not transferred)
\\details TransferMessagesTo2() removes messages from this object and moves them to the destination.)")
//        .def("ChannelPut", &CryptoPP::BufferedTransformation::ChannelPut, pybind11::arg("channel"), pybind11::arg("inByte"), pybind11::arg("blocking") = true, R"(\\brief Input a byte for processing on a channel
//\\param channel the channel to process the data.
//\\param inByte the 8-bit byte (octet) to be processed.
//\\param blocking specifies whether the object should block when processing input.
//\\return 0 indicates all bytes were processed during the call. Non-0 indicates the
//  number of bytes that were not processed.)")
        .def("ChannelPut", [](CryptoPP::BufferedTransformation &self, const std::string &channel, const pybind11::bytes inString, bool blocking) {
            const std::string_view view = inString;
            return self.ChannelPut(channel.c_str(), reinterpret_cast<const unsigned char *>(&view[0]), view.size(), blocking);
        }, pybind11::arg("channel"), pybind11::arg("inString"), pybind11::arg("blocking") = true, R"(\\brief Input a byte buffer for processing on a channel
\\param channel the channel to process the data
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param blocking specifies whether the object should block when processing input
\\return 0 indicates all bytes were processed during the call. Non-0 indicates the
 number of bytes that were not processed.)")
        .def("ChannelPutModifiable", [](CryptoPP::BufferedTransformation &self, const std::string &channel, const pybind11::bytes &inString, bool blocking) {
            const std::string_view view = inString;
            return self.ChannelPutModifiable(channel.c_str(), const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(&view[0])), view.size(), blocking);
        }, pybind11::arg("channel"), pybind11::arg("inString"), pybind11::arg("blocking") = true, R"(\\brief Input multiple bytes that may be modified by callee on a channel
\\param channel the channel to process the data.
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param blocking specifies whether the object should block when processing input
\\return 0 indicates all bytes were processed during the call. Non-0 indicates the
 number of bytes that were not processed.)")
        .def("ChannelPutWord16", &CryptoPP::BufferedTransformation::ChannelPutWord16, pybind11::arg("channels"), pybind11::arg("value"), pybind11::arg("order") = CryptoPP::BIG_ENDIAN_ORDER, pybind11::arg("blocking") = true, R"(\\brief Input a 16-bit word for processing on a channel.
\\param channel the channel to process the data.
\\param value the 16-bit value to be processed.
\\param order the ByteOrder of the value to be processed.
\\param blocking specifies whether the object should block when processing input.
\\return 0 indicates all bytes were processed during the call. Non-0 indicates the
 number of bytes that were not processed.)")
        .def("ChannelPutWord32", &CryptoPP::BufferedTransformation::ChannelPutWord32, pybind11::arg("channel"), pybind11::arg("value"), pybind11::arg("order") = CryptoPP::BIG_ENDIAN_ORDER, pybind11::arg("blocking") = true, R"(\\brief Input a 32-bit word for processing on a channel.
\\param channel the channel to process the data.
\\param value the 32-bit value to be processed.
\\param order the ByteOrder of the value to be processed.
\\param blocking specifies whether the object should block when processing input.
\\return 0 indicates all bytes were processed during the call. Non-0 indicates the
 number of bytes that were not processed.)")
        .def("ChannelPutWord64", &CryptoPP::BufferedTransformation::ChannelPutWord64, pybind11::arg("channel"), pybind11::arg("value"), pybind11::arg("order") = CryptoPP::BIG_ENDIAN_ORDER, pybind11::arg("blocking") = true, R"(\\brief Input a 64-bit word for processing on a channel.
\\param channel the channel to process the data.
\\param value the 64-bit value to be processed.
\\param order the ByteOrder of the value to be processed.
\\param blocking specifies whether the object should block when processing input.
\\return 0 indicates all bytes were processed during the call. Non-0 indicates the
 number of bytes that were not processed.)")
        .def("ChannelMessageEnd", &CryptoPP::BufferedTransformation::ChannelMessageEnd, pybind11::arg("channel"), pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true, R"(\\brief Signal the end of a message
\\param channel the channel to process the data.
\\param propagation the number of attached transformations the ChannelMessageEnd() signal should be passed
\\param blocking specifies whether the object should block when processing input
\\return 0 indicates all bytes were processed during the call. Non-0 indicates the
 number of bytes that were not processed.
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.)")
        .def("ChannelPutMessageEnd", [](CryptoPP::BufferedTransformation &self, const std::string &channel, const pybind11::bytes &inString, int propagation, bool blocking) {
            const std::string_view view = inString;
            return self.ChannelPutMessageEnd(channel.c_str(), reinterpret_cast<const unsigned char *>(&view[0]), view.size(), propagation, blocking);
        }, pybind11::arg("channel"), pybind11::arg("inString"), pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true, R"(\\brief Input multiple bytes for processing and signal the end of a message
\\param channel the channel to process the data.
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param propagation the number of attached transformations the ChannelPutMessageEnd() signal should be passed
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain to be processed (i.e., bytes not processed)
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.)")
        /// \brief Request space which can be written into by the caller
        /// \param channel the channel to process the data
        /// \param size the requested size of the buffer
        /// \return a pointer to a memory block with length size
        /// \details The purpose of this method is to help avoid extra memory allocations.
        /// \details size is an \a IN and \a OUT parameter and used as a hint. When the call is made,
        ///  size is the requested size of the buffer. When the call returns, size is the size of
        ///  the array returned to the caller.
        /// \details The base class implementation sets size to 0 and returns NULL.
        /// \note Some objects, like ArraySink(), cannot create a space because its fixed. In the case of
        ///  an ArraySink(), the pointer to the array is returned and the size is remaining size.
        //.def("ChannelCreatePutSpace", &CryptoPP::BufferedTransformation::ChannelCreatePutSpace)
        .def("ChannelPut2", [](CryptoPP::BufferedTransformation &self, const std::string &channel, const pybind11::bytes &inString, int messageEnd, bool blocking) {
            const std::string_view view = inString;
            return self.ChannelPut2(channel.c_str(), reinterpret_cast<const unsigned char *>(&view[0]), view.size(), messageEnd, blocking);
        }, pybind11::arg("channel"), pybind11::arg("inString"), pybind11::arg("messageEnd"), pybind11::arg("blocking"), R"(\\brief Input multiple bytes for processing on a channel.
\\param channel the channel to process the data.
\\param inString the byte buffer to process.
\\param length the size of the string, in bytes.
\\param messageEnd means how many filters to signal MessageEnd() to, including this one.
\\param blocking specifies whether the object should block when processing input.
\\return the number of bytes that remain to be processed (i.e., bytes not processed))")
        .def("ChannelPutModifiable2", [](CryptoPP::BufferedTransformation &self, const std::string &channel, const pybind11::bytes &inString, int messageEnd, bool blocking) {
            const std::string_view view = inString;
            return self.ChannelPutModifiable2(channel.c_str(), const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(&view[0])), view.size(), messageEnd, blocking);
        }, pybind11::arg("channel"), pybind11::arg("inString"), pybind11::arg("messageEnd"), pybind11::arg("blocking"), R"(\\brief Input multiple bytes that may be modified by callee on a channel
\\param channel the channel to process the data
\\param inString the byte buffer to process
\\param length the size of the string, in bytes
\\param messageEnd means how many filters to signal MessageEnd() to, including this one
\\param blocking specifies whether the object should block when processing input
\\return the number of bytes that remain to be processed (i.e., bytes not processed))")
        .def("ChannelFlush", &CryptoPP::BufferedTransformation::ChannelFlush, pybind11::arg("channel"), pybind11::arg("hardFlush"), pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true, R"(\\brief Flush buffered input and/or output on a channel
\\param channel the channel to flush the data
\\param hardFlush is used to indicate whether all data should be flushed
\\param propagation the number of attached transformations the ChannelFlush() signal should be passed
\\param blocking specifies whether the object should block when processing input
\\return true of the Flush was successful
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.)")
        .def("ChannelMessageSeriesEnd", &CryptoPP::BufferedTransformation::ChannelMessageSeriesEnd, pybind11::arg("channel"), pybind11::arg("propagation") = -1, pybind11::arg("blocking") = true, R"(\\brief Marks the end of a series of messages on a channel
\\param channel the channel to signal the end of a series of messages
\\param propagation the number of attached transformations the ChannelMessageSeriesEnd() signal should be passed
\\param blocking specifies whether the object should block when processing input
\\return true if the message was successful, false otherwise
\\details Each object that receives the signal will perform its processing, decrement
 propagation, and then pass the signal on to attached transformations if the value is not 0.
\\details propagation count includes this object. Setting propagation to <tt>1</tt> means this
 object only. Setting propagation to <tt>-1</tt> means unlimited propagation.
\\note There should be a MessageEnd() immediately before MessageSeriesEnd().)")
        .def("SetRetrievalChannel", &CryptoPP::BufferedTransformation::SetRetrievalChannel, pybind11::arg("channel"), R"(\\brief Sets the default retrieval channel
\\param channel the channel to signal the end of a series of messages
\\note this function may not be implemented in all objects that should support it.)")
        .def("Attachable", &CryptoPP::BufferedTransformation::Attachable, R"(\\brief Determines whether the object allows attachment
\\return true if the object allows an attachment, false otherwise
\\details Sources and Filters will returns true, while Sinks and other objects will return false.)")
        .def("AttachedTransformation", static_cast<CryptoPP::BufferedTransformation *(CryptoPP::BufferedTransformation::*)()>(&CryptoPP::BufferedTransformation::AttachedTransformation), R"(\\brief Returns the object immediately attached to this object
\\return the attached transformation
\\details AttachedTransformation() returns NULL if there is no attachment. The non-const
 version of AttachedTransformation() always returns NULL.)")
        .def("Detach", &CryptoPP::BufferedTransformation::Detach, pybind11::arg("newAttach") = nullptr, R"(\\brief Delete the current attachment chain and attach a new one
\\param newAttachment the new BufferedTransformation to attach
\\throw NotImplemented
\\details Detach() deletes the current attachment chain and replace it with an optional newAttachment
\\details If a derived class does not override Detach(), then the base class throws
 NotImplemented.)")
        .def("Attach", &CryptoPP::BufferedTransformation::Attach, pybind11::arg("newAttachment"), R"(\\brief Add newAttachment to the end of attachment chain
\\param newAttachment the attachment to add to the end of the chain)")
        ;

    pybind11::register_exception<CryptoPP::BufferedTransformation::BlockingInputOnly>(m, "BlockingInputOnly");
    pybind11::register_exception<CryptoPP::BufferedTransformation::NoChannelSupport>(m, "NoChannelSupport");
    pybind11::register_exception<CryptoPP::BufferedTransformation::InvalidChannelName>(m, "InvalidChannelName");

    m.def("TheBitBucket", &CryptoPP::TheBitBucket, R"(\\brief An input discarding BufferedTransformation
\\return a reference to a BufferedTransformation object that discards all input)");

/*

/// \brief Interface for crypto material
/// \details CryptoMaterial() is an interface for crypto material, such as
///  public keys, private keys and crypto parameters. Derived classes generally
///  do not offer public methods such as GenerateRandom() and
///  GenerateRandomWithKeySize().
/// \sa GeneratableCryptoMaterial()
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CryptoMaterial : public NameValuePairs
{
public:
	/// Exception thrown when invalid crypto material is detected
	class CRYPTOPP_DLL InvalidMaterial : public InvalidDataFormat
	{
	public:
		explicit InvalidMaterial(const std::string &s) : InvalidDataFormat(s) {}
	};

	virtual ~CryptoMaterial() {}

	/// \brief Assign values to this object
	/// \details This function can be used to create a public key from a private key.
	virtual void AssignFrom(const NameValuePairs &source) =0;

	/// \brief Check this object for errors
	/// \param rng a RandomNumberGenerator for objects which use randomized testing
	/// \param level the level of thoroughness
	/// \return true if the tests succeed, false otherwise
	/// \details There are four levels of thoroughness:
	///   <ul>
	///   <li>0 - using this object won't cause a crash or exception
	///   <li>1 - this object will probably function, and encrypt, sign, other operations correctly
	///   <li>2 - ensure this object will function correctly, and perform reasonable security checks
	///   <li>3 - perform reasonable security checks, and do checks that may take a long time
	///   </ul>
	/// \details Level 0 does not require a RandomNumberGenerator. A NullRNG() can be used for level 0.
	///  Level 1 may not check for weak keys and such. Levels 2 and 3 are recommended.
	/// \sa ThrowIfInvalid()
	virtual bool Validate(RandomNumberGenerator &rng, unsigned int level) const =0;

	/// \brief Check this object for errors
	/// \param rng a RandomNumberGenerator for objects which use randomized testing
	/// \param level the level of thoroughness
	/// \throw InvalidMaterial
	/// \details Internally, ThrowIfInvalid() calls Validate() and throws InvalidMaterial() if validation fails.
	/// \sa Validate()
	virtual void ThrowIfInvalid(RandomNumberGenerator &rng, unsigned int level) const
		{if (!Validate(rng, level)) throw InvalidMaterial("CryptoMaterial: this object contains invalid values");}

	/// \brief Saves a key to a BufferedTransformation
	/// \param bt the destination BufferedTransformation
	/// \throw NotImplemented
	/// \details Save() writes the material to a BufferedTransformation.
	/// \details If the material is a key, then the key is written with ASN.1 DER encoding. The key
	///  includes an object identifier with an algorithm id, like a subjectPublicKeyInfo.
	/// \details A "raw" key without the "key info" can be saved using a key's DEREncode() method.
	/// \details If a derived class does not override Save(), then the base class throws
	///  NotImplemented().
	virtual void Save(BufferedTransformation &bt) const
		{CRYPTOPP_UNUSED(bt); throw NotImplemented("CryptoMaterial: this object does not support saving");}

	/// \brief Loads a key from a BufferedTransformation
	/// \param bt the source BufferedTransformation
	/// \throw KeyingErr
	/// \details Load() attempts to read material from a BufferedTransformation. If the
	///  material is a key that was generated outside the library, then the following
	///  usually applies:
	///   <ul>
	///   <li>the key should be ASN.1 BER encoded
	///   <li>the key should be a "key info"
	///   </ul>
	/// \details "key info" means the key should have an object identifier with an algorithm id,
	///  like a subjectPublicKeyInfo.
	/// \details To read a "raw" key without the "key info", then call the key's BERDecode() method.
	/// \note Load() generally does not check that the key is valid. Call Validate(), if needed.
	virtual void Load(BufferedTransformation &bt)
		{CRYPTOPP_UNUSED(bt); throw NotImplemented("CryptoMaterial: this object does not support loading");}

	/// \brief Determines whether the object supports precomputation
	/// \return true if the object supports precomputation, false otherwise
	/// \sa Precompute()
	virtual bool SupportsPrecomputation() const {return false;}

	/// \brief Perform precomputation
	/// \param precomputationStorage the suggested number of objects for the precompute table
	/// \throw NotImplemented
	/// \details The exact semantics of Precompute() varies, but it typically means calculate
	///  a table of n objects that can be used later to speed up computation.
	/// \details If a derived class does not override Precompute(), then the base class throws
	///  NotImplemented.
	/// \sa SupportsPrecomputation(), LoadPrecomputation(), SavePrecomputation()
	virtual void Precompute(unsigned int precomputationStorage) {
		CRYPTOPP_UNUSED(precomputationStorage); CRYPTOPP_ASSERT(!SupportsPrecomputation());
		throw NotImplemented("CryptoMaterial: this object does not support precomputation");
	}

	/// \brief Retrieve previously saved precomputation
	/// \param storedPrecomputation BufferedTransformation with the saved precomputation
	/// \throw NotImplemented
	/// \sa SupportsPrecomputation(), Precompute()
	virtual void LoadPrecomputation(BufferedTransformation &storedPrecomputation)
		{CRYPTOPP_UNUSED(storedPrecomputation); CRYPTOPP_ASSERT(!SupportsPrecomputation()); throw NotImplemented("CryptoMaterial: this object does not support precomputation");}

	/// \brief Save precomputation for later use
	/// \param storedPrecomputation BufferedTransformation to write the precomputation
	/// \throw NotImplemented
	/// \sa SupportsPrecomputation(), Precompute()
	virtual void SavePrecomputation(BufferedTransformation &storedPrecomputation) const
		{CRYPTOPP_UNUSED(storedPrecomputation); CRYPTOPP_ASSERT(!SupportsPrecomputation()); throw NotImplemented("CryptoMaterial: this object does not support precomputation");}

	/// \brief Perform a quick sanity check
	/// \details DoQuickSanityCheck() is for internal library use, and it should not be called by library users.
	void DoQuickSanityCheck() const	{ThrowIfInvalid(NullRNG(), 0);}

#if defined(__SUNPRO_CC)
	// Sun Studio 11/CC 5.8 workaround: it generates incorrect code
	// when casting to an empty virtual base class. JW, 2018: It is
	// still a problem in Sun Studio 12.6/CC 5.15 on i386. Just enable
	// it everywhere in case it affects SPARC (which we don't test).
	char m_sunCCworkaround;
#endif
};

/// \brief Interface for crypto material
/// \details GeneratableCryptoMaterial() is an interface for crypto material,
///  such as private keys and crypto parameters. Derived classes offer public
///  methods such as GenerateRandom() and GenerateRandomWithKeySize().
/// \sa CryptoMaterial()
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE GeneratableCryptoMaterial : virtual public CryptoMaterial
{
public:
	virtual ~GeneratableCryptoMaterial() {}

	/// \brief Generate a random key or crypto parameters
	/// \param rng a RandomNumberGenerator to produce keying material
	/// \param params additional initialization parameters
	/// \throw KeyingErr if a key can't be generated or algorithm parameters are invalid
	/// \details If a derived class does not override GenerateRandom(), then the base class throws
	///  NotImplemented.
	virtual void GenerateRandom(RandomNumberGenerator &rng, const NameValuePairs &params = g_nullNameValuePairs) {
		CRYPTOPP_UNUSED(rng); CRYPTOPP_UNUSED(params);
		throw NotImplemented("GeneratableCryptoMaterial: this object does not support key/parameter generation");
	}

	/// \brief Generate a random key or crypto parameters
	/// \param rng a RandomNumberGenerator to produce keying material
	/// \param keySize the size of the key, in bits
	/// \throw KeyingErr if a key can't be generated or algorithm parameters are invalid
	/// \details GenerateRandomWithKeySize calls GenerateRandom() with a NameValuePairs
	///  object with only "KeySize"
	void GenerateRandomWithKeySize(RandomNumberGenerator &rng, unsigned int keySize);
};

/// \brief Interface for public keys
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PublicKey : virtual public CryptoMaterial
{
};

/// \brief Interface for private keys
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PrivateKey : public GeneratableCryptoMaterial
{
};

/// \brief Interface for crypto parameters
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CryptoParameters : public GeneratableCryptoMaterial
{
};

/// \brief Interface for certificates
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE Certificate : virtual public CryptoMaterial
{
};

/// \brief Interface for asymmetric algorithms
/// \details BERDecode() and DEREncode() were removed under Issue 569
///  and Commit 9b174e84de7a. Programs should use <tt>AccessMaterial().Load(bt)</tt>
///  or <tt>GetMaterial().Save(bt)</tt> instead.
/// \sa <A HREF="https://github.com/weidai11/cryptopp/issues/569">Issue 569</A>
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AsymmetricAlgorithm : public Algorithm
{
public:
	virtual ~AsymmetricAlgorithm() {}

	/// \brief Retrieves a reference to CryptoMaterial
	/// \return a reference to the crypto material
	virtual CryptoMaterial & AccessMaterial() =0;

	/// \brief Retrieves a reference to CryptoMaterial
	/// \return a const reference to the crypto material
	virtual const CryptoMaterial & GetMaterial() const =0;

#if 0
	/// \brief Loads this object from a BufferedTransformation
	/// \param bt a BufferedTransformation object
	/// \details Use of BERDecode() changed to Load() at Issue 569.
	/// \deprecated for backwards compatibility, calls <tt>AccessMaterial().Load(bt)</tt>
	void BERDecode(BufferedTransformation &bt)
		{AccessMaterial().Load(bt);}

	/// \brief Saves this object to a BufferedTransformation
	/// \param bt a BufferedTransformation object
	/// \details Use of DEREncode() changed to Save() at Issue 569.
	/// \deprecated for backwards compatibility, calls GetMaterial().Save(bt)
	void DEREncode(BufferedTransformation &bt) const
		{GetMaterial().Save(bt);}
#endif
};

/// \brief Interface for asymmetric algorithms using public keys
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PublicKeyAlgorithm : public AsymmetricAlgorithm
{
public:
	virtual ~PublicKeyAlgorithm() {}

	// VC60 workaround: no co-variant return type

	/// \brief Retrieves a reference to a Public Key
	/// \return a reference to the public key
	CryptoMaterial & AccessMaterial()
		{return AccessPublicKey();}
	/// \brief Retrieves a reference to a Public Key
	/// \return a const reference the public key
	const CryptoMaterial & GetMaterial() const
		{return GetPublicKey();}

	/// \brief Retrieves a reference to a Public Key
	/// \return a reference to the public key
	virtual PublicKey & AccessPublicKey() =0;
	/// \brief Retrieves a reference to a Public Key
	/// \return a const reference the public key
	virtual const PublicKey & GetPublicKey() const
		{return const_cast<PublicKeyAlgorithm *>(this)->AccessPublicKey();}
};

/// \brief Interface for asymmetric algorithms using private keys
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PrivateKeyAlgorithm : public AsymmetricAlgorithm
{
public:
	virtual ~PrivateKeyAlgorithm() {}

	/// \brief Retrieves a reference to a Private Key
	/// \return a reference the private key
	CryptoMaterial & AccessMaterial() {return AccessPrivateKey();}
	/// \brief Retrieves a reference to a Private Key
	/// \return a const reference the private key
	const CryptoMaterial & GetMaterial() const {return GetPrivateKey();}

	/// \brief Retrieves a reference to a Private Key
	/// \return a reference the private key
	virtual PrivateKey & AccessPrivateKey() =0;
	/// \brief Retrieves a reference to a Private Key
	/// \return a const reference the private key
	virtual const PrivateKey & GetPrivateKey() const {return const_cast<PrivateKeyAlgorithm *>(this)->AccessPrivateKey();}
};

/// \brief Interface for key agreement algorithms
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE KeyAgreementAlgorithm : public AsymmetricAlgorithm
{
public:
	virtual ~KeyAgreementAlgorithm() {}

	/// \brief Retrieves a reference to Crypto Parameters
	/// \return a reference the crypto parameters
	CryptoMaterial & AccessMaterial() {return AccessCryptoParameters();}
	/// \brief Retrieves a reference to Crypto Parameters
	/// \return a const reference the crypto parameters
	const CryptoMaterial & GetMaterial() const {return GetCryptoParameters();}

	/// \brief Retrieves a reference to Crypto Parameters
	/// \return a reference the crypto parameters
	virtual CryptoParameters & AccessCryptoParameters() =0;
	/// \brief Retrieves a reference to Crypto Parameters
	/// \return a const reference the crypto parameters
	virtual const CryptoParameters & GetCryptoParameters() const {return const_cast<KeyAgreementAlgorithm *>(this)->AccessCryptoParameters();}
};

/// \brief Interface for public-key encryptors and decryptors
/// \details This class provides an interface common to encryptors and decryptors
///  for querying their plaintext and ciphertext lengths.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_CryptoSystem
{
public:
	virtual ~PK_CryptoSystem() {}

	/// \brief Provides the maximum length of plaintext for a given ciphertext length
	/// \return the maximum size of the plaintext, in bytes
	/// \details This function returns 0 if ciphertextLength is not valid (too long or too short).
	virtual size_t MaxPlaintextLength(size_t ciphertextLength) const =0;

	/// \brief Calculate the length of ciphertext given length of plaintext
	/// \return the maximum size of the ciphertext, in bytes
	/// \details This function returns 0 if plaintextLength is not valid (too long).
	virtual size_t CiphertextLength(size_t plaintextLength) const =0;

	/// \brief Determines whether this object supports the use of a named parameter
	/// \param name the name of the parameter
	/// \return true if the parameter name is supported, false otherwise
	/// \details Some possible parameter names: EncodingParameters(), KeyDerivationParameters()
	///  and others Parameters listed in argnames.h
	virtual bool ParameterSupported(const char *name) const =0;

	/// \brief Provides the fixed ciphertext length, if one exists
	/// \return the fixed ciphertext length if one exists, otherwise 0
	/// \details "Fixed" here means length of ciphertext does not depend on length of plaintext.
	///  In this case, it usually does depend on the key length.
	virtual size_t FixedCiphertextLength() const {return 0;}

	/// \brief Provides the maximum plaintext length given a fixed ciphertext length
	/// \return maximum plaintext length given the fixed ciphertext length, if one exists,
	///  otherwise return 0.
	/// \details FixedMaxPlaintextLength(0 returns the maximum plaintext length given the fixed ciphertext
	///  length, if one exists, otherwise return 0.
	virtual size_t FixedMaxPlaintextLength() const {return 0;}
};

/// \brief Interface for public-key encryptors
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Encryptor : public PK_CryptoSystem, public PublicKeyAlgorithm
{
public:
	/// \brief Exception thrown when trying to encrypt plaintext of invalid length
	class CRYPTOPP_DLL InvalidPlaintextLength : public Exception
	{
	public:
		InvalidPlaintextLength() : Exception(OTHER_ERROR, "PK_Encryptor: invalid plaintext length") {}
	};

	/// \brief Encrypt a byte string
	/// \param rng a RandomNumberGenerator derived class
	/// \param plaintext the plaintext byte buffer
	/// \param plaintextLength the size of the plaintext byte buffer
	/// \param ciphertext a byte buffer to hold the encrypted string
	/// \param parameters a set of NameValuePairs to initialize this object
	/// \pre <tt>CiphertextLength(plaintextLength) != 0</tt> ensures the plaintext isn't too large
	/// \pre <tt>COUNTOF(ciphertext) == CiphertextLength(plaintextLength)</tt> ensures the output
	///  byte buffer is large enough.
	/// \sa PK_Decryptor
	virtual void Encrypt(RandomNumberGenerator &rng,
		const byte *plaintext, size_t plaintextLength,
		byte *ciphertext, const NameValuePairs &parameters = g_nullNameValuePairs) const =0;

	/// \brief Create a new encryption filter
	/// \param rng a RandomNumberGenerator derived class
	/// \param attachment an attached transformation
	/// \param parameters a set of NameValuePairs to initialize this object
	/// \details \p attachment can be \p NULL. The caller is responsible for deleting the returned pointer.
	///  Encoding parameters should be passed in the "EP" channel.
	virtual BufferedTransformation * CreateEncryptionFilter(RandomNumberGenerator &rng,
		BufferedTransformation *attachment=NULLPTR, const NameValuePairs &parameters = g_nullNameValuePairs) const;
};

/// \brief Interface for public-key decryptors
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Decryptor : public PK_CryptoSystem, public PrivateKeyAlgorithm
{
public:
	virtual ~PK_Decryptor() {}

	/// \brief Decrypt a byte string
	/// \param rng a RandomNumberGenerator derived class
	/// \param ciphertext the encrypted byte buffer
	/// \param ciphertextLength the size of the encrypted byte buffer
	/// \param plaintext a byte buffer to hold the decrypted string
	/// \param parameters a set of NameValuePairs to initialize this object
	/// \return the result of the decryption operation
	/// \details If DecodingResult::isValidCoding is true, then DecodingResult::messageLength
	///  is valid and holds the actual length of the plaintext recovered. The result is undefined
	///  if decryption failed. If DecodingResult::isValidCoding is false, then DecodingResult::messageLength
	///  is undefined.
	/// \pre <tt>COUNTOF(plaintext) == MaxPlaintextLength(ciphertextLength)</tt> ensures the output
	///  byte buffer is large enough
	/// \sa PK_Encryptor
	virtual DecodingResult Decrypt(RandomNumberGenerator &rng,
		const byte *ciphertext, size_t ciphertextLength,
		byte *plaintext, const NameValuePairs &parameters = g_nullNameValuePairs) const =0;

	/// \brief Create a new decryption filter
	/// \param rng a RandomNumberGenerator derived class
	/// \param attachment an attached transformation
	/// \param parameters a set of NameValuePairs to initialize this object
	/// \return the newly created decryption filter
	/// \note the caller is responsible for deleting the returned pointer
	virtual BufferedTransformation * CreateDecryptionFilter(RandomNumberGenerator &rng,
		BufferedTransformation *attachment=NULLPTR, const NameValuePairs &parameters = g_nullNameValuePairs) const;

	/// \brief Decrypt a fixed size ciphertext
	/// \param rng a RandomNumberGenerator derived class
	/// \param ciphertext the encrypted byte buffer
	/// \param plaintext a byte buffer to hold the decrypted string
	/// \param parameters a set of NameValuePairs to initialize this object
	/// \return the result of the decryption operation
	/// \details If DecodingResult::isValidCoding is true, then DecodingResult::messageLength
	///  is valid and holds the actual length of the plaintext recovered. The result is undefined
	///  if decryption failed. If DecodingResult::isValidCoding is false, then DecodingResult::messageLength
	///  is undefined.
	/// \pre <tt>COUNTOF(plaintext) == MaxPlaintextLength(ciphertextLength)</tt> ensures the output
	///  byte buffer is large enough
	/// \sa PK_Encryptor
	DecodingResult FixedLengthDecrypt(RandomNumberGenerator &rng, const byte *ciphertext, byte *plaintext, const NameValuePairs &parameters = g_nullNameValuePairs) const
		{return Decrypt(rng, ciphertext, FixedCiphertextLength(), plaintext, parameters);}
};

/// \brief Interface for public-key signers and verifiers
/// \details This class provides an interface common to signers and verifiers for querying scheme properties
/// \sa DL_SignatureSchemeBase, TF_SignatureSchemeBase, DL_SignerBase, TF_SignerBase
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_SignatureScheme
{
public:
	/// \brief Exception throw when the private or public key has a length that can't be used
	/// \details InvalidKeyLength() may be thrown by any function in this class if the private
	///  or public key has a length that can't be used
	class CRYPTOPP_DLL InvalidKeyLength : public Exception
	{
	public:
		InvalidKeyLength(const std::string &message) : Exception(OTHER_ERROR, message) {}
	};

	/// \brief Exception throw when the private or public key is too short to sign or verify
	/// \details KeyTooShort() may be thrown by any function in this class if the private or public
	///  key is too short to sign or verify anything
	class CRYPTOPP_DLL KeyTooShort : public InvalidKeyLength
	{
	public:
		KeyTooShort() : InvalidKeyLength("PK_Signer: key too short for this signature scheme") {}
	};

	virtual ~PK_SignatureScheme() {}

	/// \brief Provides the signature length if it only depends on the key
	/// \return the signature length if it only depends on the key, in bytes
	/// \details SignatureLength() returns the signature length if it only depends on the key, otherwise 0.
	virtual size_t SignatureLength() const =0;

	/// \brief Provides the maximum signature length produced given the length of the recoverable message part
	/// \param recoverablePartLength the length of the recoverable message part, in bytes
	/// \return the maximum signature length produced for a given length of recoverable message part, in bytes
	/// \details MaxSignatureLength() returns the maximum signature length produced given the length of the
	///  recoverable message part.
	virtual size_t MaxSignatureLength(size_t recoverablePartLength = 0) const
		{CRYPTOPP_UNUSED(recoverablePartLength); return SignatureLength();}

	/// \brief Provides the length of longest message that can be recovered
	/// \return the length of longest message that can be recovered, in bytes
	/// \details MaxRecoverableLength() returns the length of longest message that can be recovered, or 0 if
	///  this signature scheme does not support message recovery.
	virtual size_t MaxRecoverableLength() const =0;

	/// \brief Provides the length of longest message that can be recovered from a signature of given length
	/// \param signatureLength the length of the signature, in bytes
	/// \return the length of longest message that can be recovered from a signature of given length, in bytes
	/// \details MaxRecoverableLengthFromSignatureLength() returns the length of longest message that can be
	///  recovered from a signature of given length, or 0 if this signature scheme does not support message
	///  recovery.
	virtual size_t MaxRecoverableLengthFromSignatureLength(size_t signatureLength) const =0;

	/// \brief Determines whether a signature scheme requires a random number generator
	/// \return true if the signature scheme requires a RandomNumberGenerator() to sign
	/// \details if IsProbabilistic() returns false, then NullRNG() can be passed to functions that take
	///  RandomNumberGenerator().
	virtual bool IsProbabilistic() const =0;

	/// \brief Determines whether the non-recoverable message part can be signed
	/// \return true if the non-recoverable message part can be signed
	virtual bool AllowNonrecoverablePart() const =0;

	/// \brief Determines whether the signature must be input before the message
	/// \return true if the signature must be input before the message during verifcation
	/// \details if SignatureUpfront() returns true, then you must input the signature before the message
	///  during verification. Otherwise you can input the signature at anytime.
	virtual bool SignatureUpfront() const {return false;}

	/// \brief Determines whether the recoverable part must be input before the non-recoverable part
	/// \return true if the recoverable part must be input before the non-recoverable part during signing
	/// \details RecoverablePartFirst() determines whether you must input the recoverable part before the
	///  non-recoverable part during signing
	virtual bool RecoverablePartFirst() const =0;
};

/// \brief Interface for accumulating messages to be signed or verified
/// \details Only Update() should be called from the PK_MessageAccumulator() class. No other functions
///  inherited from HashTransformation, like DigestSize() and TruncatedFinal(), should be called.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_MessageAccumulator : public HashTransformation
{
public:
	/// \warning DigestSize() should not be called on PK_MessageAccumulator
	unsigned int DigestSize() const
		{throw NotImplemented("PK_MessageAccumulator: DigestSize() should not be called");}

	/// \warning TruncatedFinal() should not be called on PK_MessageAccumulator
	void TruncatedFinal(byte *digest, size_t digestSize)
	{
		CRYPTOPP_UNUSED(digest); CRYPTOPP_UNUSED(digestSize);
		throw NotImplemented("PK_MessageAccumulator: TruncatedFinal() should not be called");
	}
};

/// \brief Interface for public-key signers
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Signer : public PK_SignatureScheme, public PrivateKeyAlgorithm
{
public:
	virtual ~PK_Signer() {}

	/// \brief Create a new HashTransformation to accumulate the message to be signed
	/// \param rng a RandomNumberGenerator derived class
	/// \return a pointer to a PK_MessageAccumulator
	/// \details NewSignatureAccumulator() can be used with all signing methods. Sign() will automatically delete the
	///  accumulator pointer. The caller is responsible for deletion if a method is called that takes a reference.
	virtual PK_MessageAccumulator * NewSignatureAccumulator(RandomNumberGenerator &rng) const =0;

	/// \brief Input a recoverable message to an accumulator
	/// \param messageAccumulator a reference to a PK_MessageAccumulator
	/// \param recoverableMessage a pointer to the recoverable message part to be signed
	/// \param recoverableMessageLength the size of the recoverable message part
	virtual void InputRecoverableMessage(PK_MessageAccumulator &messageAccumulator, const byte *recoverableMessage, size_t recoverableMessageLength) const =0;

	/// \brief Sign and delete the messageAccumulator
	/// \param rng a RandomNumberGenerator derived class
	/// \param messageAccumulator a pointer to a PK_MessageAccumulator derived class
	/// \param signature a block of bytes for the signature
	/// \return actual signature length
	/// \details Sign() deletes the messageAccumulator, even if an exception is thrown.
	/// \pre <tt>COUNTOF(signature) == MaxSignatureLength()</tt>
	virtual size_t Sign(RandomNumberGenerator &rng, PK_MessageAccumulator *messageAccumulator, byte *signature) const;

	/// \brief Sign and restart messageAccumulator
	/// \param rng a RandomNumberGenerator derived class
	/// \param messageAccumulator a pointer to a PK_MessageAccumulator derived class
	/// \param signature a block of bytes for the signature
	/// \param restart flag indicating whether the messageAccumulator should be restarted
	/// \return actual signature length
	/// \pre <tt>COUNTOF(signature) == MaxSignatureLength()</tt>
	virtual size_t SignAndRestart(RandomNumberGenerator &rng, PK_MessageAccumulator &messageAccumulator, byte *signature, bool restart=true) const =0;

	/// \brief Sign a message
	/// \param rng a RandomNumberGenerator derived class
	/// \param message a pointer to the message
	/// \param messageLen the size of the message to be signed
	/// \param signature a block of bytes for the signature
	/// \return actual signature length
	/// \pre <tt>COUNTOF(signature) == MaxSignatureLength()</tt>
	virtual size_t SignMessage(RandomNumberGenerator &rng, const byte *message, size_t messageLen, byte *signature) const;

	/// \brief Sign a recoverable message
	/// \param rng a RandomNumberGenerator derived class
	/// \param recoverableMessage a pointer to the recoverable message part to be signed
	/// \param recoverableMessageLength the size of the recoverable message part
	/// \param nonrecoverableMessage a pointer to the non-recoverable message part to be signed
	/// \param nonrecoverableMessageLength the size of the non-recoverable message part
	/// \param signature a block of bytes for the signature
	/// \return actual signature length
	/// \pre <tt>COUNTOF(signature) == MaxSignatureLength(recoverableMessageLength)</tt>
	virtual size_t SignMessageWithRecovery(RandomNumberGenerator &rng, const byte *recoverableMessage, size_t recoverableMessageLength,
		const byte *nonrecoverableMessage, size_t nonrecoverableMessageLength, byte *signature) const;
};

/// \brief Interface for public-key signature verifiers
/// \details The Recover* functions throw NotImplemented if the signature scheme does not support
///  message recovery.
/// \details The Verify* functions throw InvalidDataFormat if the scheme does support message
///  recovery and the signature contains a non-empty recoverable message part. The
///  Recover* functions should be used in that case.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE PK_Verifier : public PK_SignatureScheme, public PublicKeyAlgorithm
{
public:
	virtual ~PK_Verifier() {}

	/// \brief Create a new HashTransformation to accumulate the message to be verified
	/// \return a pointer to a PK_MessageAccumulator
	/// \details NewVerificationAccumulator() can be used with all verification methods. Verify() will automatically delete
	///  the accumulator pointer. The caller is responsible for deletion if a method is called that takes a reference.
	virtual PK_MessageAccumulator * NewVerificationAccumulator() const =0;

	/// \brief Input signature into a message accumulator
	/// \param messageAccumulator a pointer to a PK_MessageAccumulator derived class
	/// \param signature the signature on the message
	/// \param signatureLength the size of the signature
	virtual void InputSignature(PK_MessageAccumulator &messageAccumulator, const byte *signature, size_t signatureLength) const =0;

	/// \brief Check whether messageAccumulator contains a valid signature and message
	/// \param messageAccumulator a pointer to a PK_MessageAccumulator derived class
	/// \return true if the signature is valid, false otherwise
	/// \details Verify() deletes the messageAccumulator, even if an exception is thrown.
	virtual bool Verify(PK_MessageAccumulator *messageAccumulator) const;

	/// \brief Check whether messageAccumulator contains a valid signature and message, and restart messageAccumulator
	/// \param messageAccumulator a reference to a PK_MessageAccumulator derived class
	/// \return true if the signature is valid, false otherwise
	/// \details VerifyAndRestart() restarts the messageAccumulator
	virtual bool VerifyAndRestart(PK_MessageAccumulator &messageAccumulator) const =0;

	/// \brief Check whether input signature is a valid signature for input message
	/// \param message a pointer to the message to be verified
	/// \param messageLen the size of the message
	/// \param signature a pointer to the signature over the message
	/// \param signatureLen the size of the signature
	/// \return true if the signature is valid, false otherwise
	virtual bool VerifyMessage(const byte *message, size_t messageLen,
		const byte *signature, size_t signatureLen) const;

	/// \brief Recover a message from its signature
	/// \param recoveredMessage a pointer to the recoverable message part to be verified
	/// \param messageAccumulator a pointer to a PK_MessageAccumulator derived class
	/// \return the result of the verification operation
	/// \details Recover() deletes the messageAccumulator, even if an exception is thrown.
	/// \pre <tt>COUNTOF(recoveredMessage) == MaxRecoverableLengthFromSignatureLength(signatureLength)</tt>
	virtual DecodingResult Recover(byte *recoveredMessage, PK_MessageAccumulator *messageAccumulator) const;

	/// \brief Recover a message from its signature
	/// \param recoveredMessage a pointer to the recoverable message part to be verified
	/// \param messageAccumulator a pointer to a PK_MessageAccumulator derived class
	/// \return the result of the verification operation
	/// \details RecoverAndRestart() restarts the messageAccumulator
	/// \pre <tt>COUNTOF(recoveredMessage) == MaxRecoverableLengthFromSignatureLength(signatureLength)</tt>
	virtual DecodingResult RecoverAndRestart(byte *recoveredMessage, PK_MessageAccumulator &messageAccumulator) const =0;

	/// \brief Recover a message from its signature
	/// \param recoveredMessage a pointer for the recovered message
	/// \param nonrecoverableMessage a pointer to the non-recoverable message part to be signed
	/// \param nonrecoverableMessageLength the size of the non-recoverable message part
	/// \param signature the signature on the message
	/// \param signatureLength the size of the signature
	/// \return the result of the verification operation
	/// \pre <tt>COUNTOF(recoveredMessage) == MaxRecoverableLengthFromSignatureLength(signatureLength)</tt>
	virtual DecodingResult RecoverMessage(byte *recoveredMessage,
		const byte *nonrecoverableMessage, size_t nonrecoverableMessageLength,
		const byte *signature, size_t signatureLength) const;
};

/// \brief Interface for domains of simple key agreement protocols
/// \details A key agreement domain is a set of parameters that must be shared
///  by two parties in a key agreement protocol, along with the algorithms
///  for generating key pairs and deriving agreed values.
/// \since Crypto++ 3.0
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE SimpleKeyAgreementDomain : public KeyAgreementAlgorithm
{
public:
	virtual ~SimpleKeyAgreementDomain() {}

	/// \brief Provides the size of the agreed value
	/// \return size of agreed value produced in this domain
	virtual unsigned int AgreedValueLength() const =0;

	/// \brief Provides the size of the private key
	/// \return size of private keys in this domain
	virtual unsigned int PrivateKeyLength() const =0;

	/// \brief Provides the size of the public key
	/// \return size of public keys in this domain
	virtual unsigned int PublicKeyLength() const =0;

	/// \brief Generate private key in this domain
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer for the generated private key in this domain
	/// \pre <tt>COUNTOF(privateKey) == PrivateKeyLength()</tt>
	virtual void GeneratePrivateKey(RandomNumberGenerator &rng, byte *privateKey) const =0;

	/// \brief Generate a public key from a private key in this domain
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer with the previously generated private key
	/// \param publicKey a byte buffer for the generated public key in this domain
	/// \pre <tt>COUNTOF(publicKey) == PublicKeyLength()</tt>
	virtual void GeneratePublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const =0;

	/// \brief Generate a private/public key pair
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer for the generated private key in this domain
	/// \param publicKey a byte buffer for the generated public key in this domain
	/// \details GenerateKeyPair() is equivalent to calling GeneratePrivateKey() and then GeneratePublicKey().
	/// \pre <tt>COUNTOF(privateKey) == PrivateKeyLength()</tt>
	/// \pre <tt>COUNTOF(publicKey) == PublicKeyLength()</tt>
	virtual void GenerateKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	/// \brief Derive agreed value
	/// \param agreedValue a byte buffer for the shared secret
	/// \param privateKey a byte buffer with your private key in this domain
	/// \param otherPublicKey a byte buffer with the other party's public key in this domain
	/// \param validateOtherPublicKey a flag indicating if the other party's public key should be validated
	/// \return true upon success, false in case of failure
	/// \details Agree() derives an agreed value from your private keys and couterparty's public keys.
	/// \details The other party's public key is validated by default. If you have previously validated the
	///  static public key, use <tt>validateStaticOtherPublicKey=false</tt> to save time.
	/// \pre <tt>COUNTOF(agreedValue) == AgreedValueLength()</tt>
	/// \pre <tt>COUNTOF(privateKey) == PrivateKeyLength()</tt>
	/// \pre <tt>COUNTOF(otherPublicKey) == PublicKeyLength()</tt>
	virtual bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const =0;
};

/// \brief Interface for domains of authenticated key agreement protocols
/// \details In an authenticated key agreement protocol, each party has two
///  key pairs. The long-lived key pair is called the static key pair,
///  and the short-lived key pair is called the ephemeral key pair.
/// \since Crypto++ 3.0
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE AuthenticatedKeyAgreementDomain : public KeyAgreementAlgorithm
{
public:
	virtual ~AuthenticatedKeyAgreementDomain() {}

	/// \brief Provides the size of the agreed value
	/// \return size of agreed value produced in this domain
	virtual unsigned int AgreedValueLength() const =0;

	/// \brief Provides the size of the static private key
	/// \return size of static private keys in this domain
	virtual unsigned int StaticPrivateKeyLength() const =0;

	/// \brief Provides the size of the static public key
	/// \return size of static public keys in this domain
	virtual unsigned int StaticPublicKeyLength() const =0;

	/// \brief Generate static private key in this domain
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer for the generated private key in this domain
	/// \pre <tt>COUNTOF(privateKey) == PrivateStaticKeyLength()</tt>
	virtual void GenerateStaticPrivateKey(RandomNumberGenerator &rng, byte *privateKey) const =0;

	/// \brief Generate a static public key from a private key in this domain
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer with the previously generated private key
	/// \param publicKey a byte buffer for the generated public key in this domain
	/// \pre <tt>COUNTOF(publicKey) == PublicStaticKeyLength()</tt>
	virtual void GenerateStaticPublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const =0;

	/// \brief Generate a static private/public key pair
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer for the generated private key in this domain
	/// \param publicKey a byte buffer for the generated public key in this domain
	/// \details GenerateStaticKeyPair() is equivalent to calling GenerateStaticPrivateKey() and then GenerateStaticPublicKey().
	/// \pre <tt>COUNTOF(privateKey) == PrivateStaticKeyLength()</tt>
	/// \pre <tt>COUNTOF(publicKey) == PublicStaticKeyLength()</tt>
	virtual void GenerateStaticKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	/// \brief Provides the size of ephemeral private key
	/// \return the size of ephemeral private key in this domain
	virtual unsigned int EphemeralPrivateKeyLength() const =0;

	/// \brief Provides the size of ephemeral public key
	/// \return the size of ephemeral public key in this domain
	virtual unsigned int EphemeralPublicKeyLength() const =0;

	/// \brief Generate ephemeral private key
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer for the generated private key in this domain
	/// \pre <tt>COUNTOF(privateKey) == PrivateEphemeralKeyLength()</tt>
	virtual void GenerateEphemeralPrivateKey(RandomNumberGenerator &rng, byte *privateKey) const =0;

	/// \brief Generate ephemeral public key
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer for the generated private key in this domain
	/// \param publicKey a byte buffer for the generated public key in this domain
	/// \pre <tt>COUNTOF(publicKey) == PublicEphemeralKeyLength()</tt>
	virtual void GenerateEphemeralPublicKey(RandomNumberGenerator &rng, const byte *privateKey, byte *publicKey) const =0;

	/// \brief Generate private/public key pair
	/// \param rng a RandomNumberGenerator derived class
	/// \param privateKey a byte buffer for the generated private key in this domain
	/// \param publicKey a byte buffer for the generated public key in this domain
	/// \details GenerateEphemeralKeyPair() is equivalent to calling GenerateEphemeralPrivateKey() and then GenerateEphemeralPublicKey()
	virtual void GenerateEphemeralKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	/// \brief Derive agreed value
	/// \param agreedValue a byte buffer for the shared secret
	/// \param staticPrivateKey a byte buffer with your static private key in this domain
	/// \param ephemeralPrivateKey a byte buffer with your ephemeral private key in this domain
	/// \param staticOtherPublicKey a byte buffer with the other party's static public key in this domain
	/// \param ephemeralOtherPublicKey a byte buffer with the other party's ephemeral public key in this domain
	/// \param validateStaticOtherPublicKey a flag indicating if the other party's public key should be validated
	/// \return true upon success, false in case of failure
	/// \details Agree() derives an agreed value from your private keys and couterparty's public keys.
	/// \details The other party's ephemeral public key is validated by default. If you have previously validated
	///  the static public key, use <tt>validateStaticOtherPublicKey=false</tt> to save time.
	/// \pre <tt>COUNTOF(agreedValue) == AgreedValueLength()</tt>
	/// \pre <tt>COUNTOF(staticPrivateKey) == StaticPrivateKeyLength()</tt>
	/// \pre <tt>COUNTOF(ephemeralPrivateKey) == EphemeralPrivateKeyLength()</tt>
	/// \pre <tt>COUNTOF(staticOtherPublicKey) == StaticPublicKeyLength()</tt>
	/// \pre <tt>COUNTOF(ephemeralOtherPublicKey) == EphemeralPublicKeyLength()</tt>
	virtual bool Agree(byte *agreedValue,
		const byte *staticPrivateKey, const byte *ephemeralPrivateKey,
		const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
		bool validateStaticOtherPublicKey=true) const =0;
};


/// \brief Exception thrown when an ASN.1 BER decoing error is encountered
class CRYPTOPP_DLL BERDecodeErr : public InvalidArgument
{
public:
	BERDecodeErr() : InvalidArgument("BER decode error") {}
	BERDecodeErr(const std::string &s) : InvalidArgument(s) {}
};

/// \brief Interface for encoding and decoding ASN1 objects
/// \details Each class that derives from ASN1Object should provide a serialization format
///  that controls subobject layout. Most of the time the serialization format is
///  taken from a standard, like P1363 or an RFC.
class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE ASN1Object
{
public:
	virtual ~ASN1Object() {}

	/// \brief Decode this object from a BufferedTransformation
	/// \param bt BufferedTransformation object
	/// \details Uses Basic Encoding Rules (BER)
	virtual void BERDecode(BufferedTransformation &bt) =0;

	/// \brief Encode this object into a BufferedTransformation
	/// \param bt BufferedTransformation object
	/// \details Uses Distinguished Encoding Rules (DER)
	virtual void DEREncode(BufferedTransformation &bt) const =0;

	/// \brief Encode this object into a BufferedTransformation
	/// \param bt BufferedTransformation object
	/// \details Uses Basic Encoding Rules (BER).
	/// \details This may be useful if DEREncode() would be too inefficient.
	virtual void BEREncode(BufferedTransformation &bt) const {DEREncode(bt);}
};


*/

    m.def("LibraryVersion", &CryptoPP::LibraryVersion, R"(\\brief Specifies the build-time version of the library
\\return integer representing the build-time version
\\details LibraryVersion can help detect inadvertent mixing and matching of library
 versions. When using Crypto++ distributed by a third party, LibraryVersion()
 records the version of the shared object that was built by the third party.
 The LibraryVersion() record resides in <tt>cryptlib.o</tt> on Unix compatibles
 and <tt>cryptlib.obj</tt> on Windows. It does not change when an app links
 to the library.
\\details LibraryVersion() is declared with C linkage (<tt>extern "C"</tt>) within the
 CryptoPP namespace to help programs locate the symbol. If the symbol is present, then
 the library version is 5.7 or above. If it is missing, then the library version is
 5.6.5 or below.
\\details The function could be used as shown below.
<pre>  if (LibraryVersion() != HeaderVersion())
  {
     cout << "Potential version mismatch" << endl;

     const int lmaj = (LibraryVersion() / 100U) % 10;
     const int lmin = (LibraryVersion() / 10U) % 10;
     const int hmaj = (HeaderVersion() / 100U) % 10;
     const int hmin = (HeaderVersion() / 10U) % 10;

     if(lmaj != hmaj)
        cout << "Major version mismatch" << endl;
     else if(lmin != hmin)
        cout << "Minor version mismatch" << endl;
  }
</pre>
\\sa HeaderVersion(), <A HREF="http://github.com/weidai11/cryptopp/issues/371">GitHub Issue 371</A>.
\\since Crypto++ 6.0)");

    m.def("HeaderVersion", &CryptoPP::HeaderVersion, R"(\\brief Specifies the runtime version of the library
\\return integer representing the runtime version
\\details HeaderVersion() can help detect inadvertent mixing and matching of library
 versions. When using Crypto++ distributed by a third party, HeaderVersion()
 records the version of the headers used by the app when the app is compiled.
\\details HeaderVersion() is declared with C linkage (<tt>extern "C"</tt>) within the
 CryptoPP namespace to help programs locate the symbol. If the symbol is present, then
 the library version is 5.7 or above. If it is missing, then the library version is
 5.6.5 or below.
\\details The function could be used as shown below.
<pre>  if (LibraryVersion() != HeaderVersion())
  {
     cout << "Potential version mismatch" << endl;

     const int lmaj = (LibraryVersion() / 100U) % 10;
     const int lmin = (LibraryVersion() / 10U) % 10;
     const int hmaj = (HeaderVersion() / 100U) % 10;
     const int hmin = (HeaderVersion() / 10U) % 10;

     if(lmaj != hmaj)
        cout << "Major version mismatch" << endl;
     else if(lmin != hmin)
        cout << "Minor version mismatch" << endl;
  }
</pre>
\\sa LibraryVersion(), <A HREF="http://github.com/weidai11/cryptopp/issues/371">GitHub Issue 371</A>.
\\since Crypto++ 6.0)");
}
