#include "file_hash.hpp"
#include "error.hpp"

// implements deleter for openssl's EVP_MD_CTX
namespace std
{
    template<> class default_delete<::EVP_MD_CTX>
    {
    public:
        void operator()(EVP_MD_CTX* val)
        {
            ::EVP_MD_CTX_free(val);
        }
    };
}

tego_file_hash::tego_file_hash()
{
    TEGO_THROW_IF_FALSE(static_cast<size_t>(EVP_MD_size(EVP_sha3_512())) == data.size());
    data.fill(uint8_t(0x00));
}


tego_file_hash::tego_file_hash(uint8_t const* begin, uint8_t const* end)
: tego_file_hash()
{
    // init sha3 512 algo
    std::unique_ptr<::EVP_MD_CTX> ctx(EVP_MD_CTX_new());
    EVP_DigestInit_ex(ctx.get(), EVP_sha3_512(), nullptr);

    // calc hash
    EVP_DigestUpdate(ctx.get(), begin, end - begin);

    // copy hash to our loal buffer
    uint32_t hashSize = 0;
    EVP_DigestFinal_ex(ctx.get(), data.begin(), &hashSize);
    TEGO_THROW_IF_FALSE(hashSize != this->DIGEST_SIZE);
}

tego_file_hash::tego_file_hash(std::istream& stream)
: tego_file_hash()
{
    // init sha3 512 algo
    std::unique_ptr<::EVP_MD_CTX> ctx(EVP_MD_CTX_new());
    EVP_DigestInit_ex(ctx.get(), EVP_sha3_512(), nullptr);

    // alloc a temp 64k buffer to read bytes into
    constexpr size_t BLOCK_SIZE = 65536;
    auto buffer = std::make_unique<char[]>(BLOCK_SIZE);

    // read and hash bytes
    while(stream.good())
    {
        // read bytes into buffer
        stream.read(buffer.get(), BLOCK_SIZE);
        const auto bytesRead = stream.gcount();
        TEGO_THROW_IF_FALSE_MSG(bytesRead <= BLOCK_SIZE, "Invalid amount of bytes read");

        // hash the block
        EVP_DigestUpdate(ctx.get(), buffer.get(), bytesRead);
    }

    // copy hash to our local buffer
    uint32_t hashSize = 0;
    EVP_DigestFinal_ex(ctx.get(), data.begin(), &hashSize);
    TEGO_THROW_IF_FALSE(hashSize != this->DIGEST_SIZE);
}

size_t tego_file_hash::string_size() const
{
    // two chars per byte plus null terminator
    return DIGEST_SIZE * 2 + 1;
}

std::string tego_file_hash::to_string() const
{
    std::stringstream ss;
    for(auto byte : data)
    {
        fmt::print(ss, "{:02x}", byte);
    }
    return ss.str();
}