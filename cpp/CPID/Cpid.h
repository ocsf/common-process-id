#pragma once

// SPDX-License-Identifier: Apache-2.0

#include <guiddef.h>
#include <cstdint>
#include <string>

using cpid_t = GUID;

class Cpid
{
protected:

#pragma pack(push, 1)
    struct digest_input_content_t
    {
        GUID     machine_guid;
        uint64_t system_creation_time_windows_ticks;
        uint64_t process_creation_time_windows_ticks;
        uint64_t pid;
    };
#pragma pack(pop)

    static_assert(40 == sizeof(digest_input_content_t), "Windows digest_input_content_t size should be 40 bytes");

public:
    // A read-only instance of the cpid_t structure whose value are all zeroes.
    static constexpr cpid_t Empty = { };

public:
    // Delete the constructor to prevent instantiation.
    Cpid() = delete;

    // Initializes static Cpid class.
    static bool Startup();
    // Releases the resources used by the static Cpid class.
    static void Shutdown();
    // This function performs a CPID calculation to test whether its internal functions produce an expected result.
    static bool SelfTest();

    // Derives a CPID (pronounced "see-pid") from the specified process information for the current Windows computer.
    static bool Derive(uint64_t processCreationTime, uint32_t processId, cpid_t* cpid);
    // Derives a CPID (pronounced "see-pid") using the specified system and process information.
    static bool Derive2(const GUID& machineGuid, uint64_t systemCreationTime, uint64_t processCreationTime, uint64_t processId, cpid_t* cpid);

    // Compares two cpid_t values and returns an integer that indicates their relative position in the sort order.
    static int Compare(const cpid_t& cpidA, const cpid_t& cpidB) noexcept;
    // Determines whether two specified CPID values are the same.
    static bool Equals(const cpid_t& cpidA, const cpid_t& cpidB) noexcept;
    static size_t GetHashCode(cpid_t cpid) noexcept;
    // Returns the string representation of the specified cpid_t structure.
    static std::string ToString(const cpid_t& cpid);
    // Converts the string representation of a CPID to the equivalent cpid_t structure.
    static bool TryParse(const std::string& str, cpid_t* cpid);

protected:
    // Computes the SHA256 hash of the specified input per CPID specification.
    static bool ComputeSha256Hash(const digest_input_content_t* input, uint8_t digest[32]);
    static bool GetMachineGuid(GUID* machineGuid);
    static bool GetProcessCreationTime(uint32_t processId, uint64_t* creationTime);

protected:
    // static internal variables
    static GUID     s_machineGuid;
    static uint64_t s_systemCreationTime;
    static void*    s_bcrypt;
};


// less-than operator for use in STL map and set
inline bool operator<(const cpid_t& cpidA, const cpid_t& cpidB) noexcept
{
    return (Cpid::Compare(cpidA, cpidB) < 0);
}


// hash operator for use in STL unordered_map and unordered_set
namespace std
{
    template <>
    struct hash<cpid_t>
    {
        inline std::size_t operator()(const cpid_t& cpid) const noexcept
        {
            return Cpid::GetHashCode(cpid);
        }
    };
}
