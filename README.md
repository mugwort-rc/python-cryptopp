# python-cryptopp

## Install

```
pip install git+https://github.com/mugwort-rc/python-cryptopp
```

## License

This library provided under the same Boost Software License as the original library.

## Usage

### SHA1

```python
>>> import cryptopp
>>> hash = cryptopp.SHA1()
>>> print("Name:", hash.AlgorithmName())
Name: SHA-1
>>> print("Digest size:", hash.DigestSize())
Digest size: 20
>>> print("Block size:", hash.BlockSize())
Block size: 64
>>> msg = b"Yoda said, Do or do not. There is no try."
>>> hash.Update(msg)
>>> digest = hash.Final()
>>> print("Message:", msg)
Message: b'Yoda said, Do or do not. There is no try.'
>>> print("Digest:", cryptopp.utils.hex_encode(digest))
Digest: 05C0042DF9A7793B7BDE3AB9724C08CF37398652
>>> hash = cryptopp.SHA1()
>>> hash.Update(msg)
>>> digest = hash.TruncatedFinal(hash.DigestSize()//2)
>>> print("Digest:", cryptopp.utils.hex_encode(digest))
Digest: 05C0042DF9A7793B7BDE
```
