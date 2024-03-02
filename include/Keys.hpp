#ifndef BKCRACK_KEYS_HPP
#define BKCRACK_KEYS_HPP

#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"

/// Keys defining the cipher state
class Keys
{
public:
    /// Construct default state
    Keys() = default;

    /// Construct keys from given components
    Keys(std::uint32_t x, std::uint32_t y, std::uint32_t z);

    /// Construct keys associated to the given password
    explicit Keys(const std::string& password);

    /// Update the state with a plaintext byte
    void update(std::uint8_t p)
    {
        x = Crc32Tab::crc32(x, p);
        y = (y + lsb(x)) * MultTab::mult + 1;
        z = Crc32Tab::crc32(z, msb(y));
    }

    /// Update the state forward to a target offset
    void update(const std::vector<std::uint8_t>& ciphertext, std::size_t current, std::size_t target);

    /// Update the state backward with a ciphertext byte
    void updateBackward(std::uint8_t c)
    {
        z = Crc32Tab::crc32inv(z, msb(y));
        y = (y - 1) * MultTab::multInv - lsb(x);
        x = Crc32Tab::crc32inv(x, c ^ getK());
    }

    /// Update the state backward with a plaintext byte
    void updateBackwardPlaintext(std::uint8_t p)
    {
        z = Crc32Tab::crc32inv(z, msb(y));
        y = (y - 1) * MultTab::multInv - lsb(x);
        x = Crc32Tab::crc32inv(x, p);
    }

    /// Update the state backward to a target offset
    void updateBackward(const std::vector<std::uint8_t>& ciphertext, std::size_t current, std::size_t target);

    /// \return X value
    auto getX() const -> std::uint32_t
    {
        return x;
    }

    /// \return Y value
    auto getY() const -> std::uint32_t
    {
        return y;
    }

    /// \return Z value
    auto getZ() const -> std::uint32_t
    {
        return z;
    }

    /// \return the keystream byte derived from the keys
    auto getK() const -> std::uint8_t
    {
        return KeystreamTab::getByte(z);
    }

private:
    std::uint32_t x = 0x12345678;
    std::uint32_t y = 0x23456789;
    std::uint32_t z = 0x34567890;
};

#endif // BKCRACK_KEYS_HPP
