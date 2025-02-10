//
//	Cpid.cpp
// 
//	Provides methods to derive the Common Process Identifier (CPID pronounced "see-pid") as specified by OCSF.
//
//	Reference:
//	https://github.com/ocsf/common-process-id
//
// 
//	Author(s):
//	ing. E.J. Loman (ByteJams B.V.)
//---------------------------------------------------------------------------------------------------------------------
#include "Cpid.h"
#include <Windows.h>
#include <assert.h>

#pragma comment(lib, "Bcrypt.lib")


//---------------------------------------------------------------------------------------------------------------------
// 
//	Static class variables
// 
//---------------------------------------------------------------------------------------------------------------------
GUID	 Cpid::s_machineGuid = { };
uint64_t Cpid::s_systemCreationTime = 0;
void*    Cpid::s_bcrypt = nullptr;


//---------------------------------------------------------------------------------------------------------------------
// 
//	Startup
// 
//	Initializes static Cpid class by performing the following actions:
// 
//	1) Retrieving the MachineGuid of the current Windows system.
//	2) Retrieving the creation time of the System process (PID 4).
//	3) Opening a SHA256 provider, used for deriving CPID values.
// 
//	Calling this method is optional. The Derive() method also ensure that the required system information for 
//	deriving CPID values on the current Windows system is available.
// 
//	Returns	: true when the static class was successfully initialized.
//			  false when failed or when the caller was not running with elevated privileges.
// 
//	Remarks	: Note that the caller must run with elevated privileges.
//			  This because CPID uses the creation time of the PID 4 system process of the current Windows system.
// 
//	See also: Shutdown()
//			  Selftest()
//			  Derive()
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::Startup()
{
	if (!GetMachineGuid(&s_machineGuid))
	{
		return false; // failed to get the MachineGuid
	}
	if (!GetProcessCreationTime(4, &s_systemCreationTime))
	{
		return false; // failed to get the creation time of the System(4) process	
	}

	if (s_bcrypt == nullptr)
	{
		NTSTATUS status = BCryptOpenAlgorithmProvider(
			(BCRYPT_ALG_HANDLE*)&s_bcrypt, BCRYPT_SHA256_ALGORITHM, NULL, 0);

		if (!BCRYPT_SUCCESS(status))
		{
			return false; // failed to open SHA256 provider
		}
	}

	return true;
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	Shutdown
// 
//	Releases the resources used by the static Cpid class.
// 
//	This function method closes the SHA256 provider that was opened by the Startup() or Derive() methods.
//	In addition it erases the MachineGuid and SystemCreationTime variables that are used internally.
// 
//	See also: Startup()
// 
//---------------------------------------------------------------------------------------------------------------------
void Cpid::Shutdown()
{
	if (s_bcrypt)
	{
		BCryptCloseAlgorithmProvider(s_bcrypt, 0);
		s_bcrypt = nullptr;
	}

	memset(&s_machineGuid, 0, sizeof(s_machineGuid));

	s_systemCreationTime = 0;

	return;
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	Compare
// 
//	Compares two cpid_t values and returns an integer that indicates their relative position in the sort order.
// 
//	Returns	: < 0 cpidA precedes cpidB in the sort order.
//		        0 cpidA occurs in the same position as cpidB in the sort order.
//			  > 0 cpidA follows cpidB in the sort order.
// 
//---------------------------------------------------------------------------------------------------------------------
int Cpid::Compare(const cpid_t& cpidA, const cpid_t& cpidB) noexcept
{
	if (cpidA.Data1 < cpidB.Data1)
	{
		return -1;
	}
	if (cpidA.Data1 > cpidB.Data1)
	{
		return 1;
	}
	if (cpidA.Data2 < cpidB.Data2)
	{
		return -1;
	}
	if (cpidA.Data2 > cpidB.Data2)
	{
		return 1;
	}
	if (cpidA.Data3 < cpidB.Data3)
	{
		return -1;
	}
	if (cpidA.Data3 > cpidB.Data3)
	{
		return 1;
	}
	return (std::memcmp(cpidA.Data4, cpidB.Data4, sizeof(cpidA.Data4)));
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	ComputeSha256Hash
// 
//	Computes the SHA256 hash of the specified input per CPID specification.
// 
//	Params	: input  [in]  pointer to a digest_input_content_t that is to be hashed
//			  digest [out] pointer to a buffer that receives the 32 bytes of the sha256 digest 
// 
//	Returns	: true when the SHA256 digest was successfully computed; false otherwise.
// 
//	See also: https://github.com/ocsf/common-process-id/blob/main/specification.md
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::ComputeSha256Hash(const digest_input_content_t* input, uint8_t digest[32])
{
	if (s_bcrypt == nullptr)
	{
		NTSTATUS status = BCryptOpenAlgorithmProvider(
			(BCRYPT_ALG_HANDLE*)&s_bcrypt, BCRYPT_SHA256_ALGORITHM, NULL, 0);

		if (!BCRYPT_SUCCESS(status))
		{
			return false;
		}
	}

	DWORD hashObjectSize = 0;
	DWORD resultLength = 0;
	BCRYPT_HASH_HANDLE hHash = nullptr;

	NTSTATUS status = BCryptGetProperty(
		s_bcrypt, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(hashObjectSize), &resultLength, 0);

	if (BCRYPT_SUCCESS(status))
	{
		uint8_t* hashObject = static_cast<uint8_t*>(malloc(hashObjectSize));

		if (hashObject == nullptr)
		{
			status = STATUS_NO_MEMORY;
		}
		else
		{
			status = BCryptCreateHash(s_bcrypt, &hHash, hashObject, hashObjectSize, nullptr, 0, 0);

			if (BCRYPT_SUCCESS(status))
			{
				status = BCryptHashData(hHash, (PUCHAR)input, sizeof(digest_input_content_t), 0);

				if (BCRYPT_SUCCESS(status))
				{
					status = BCryptFinishHash(hHash, digest, 32, 0);
				}
				BCryptDestroyHash(hHash);
			}

			free(hashObject);
		}
	}

	return BCRYPT_SUCCESS(status);
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	Derive
//
//	Derives a CPID (pronounced "see-pid") from the specified process information for the current Windows computer.
// 
//	Params	: processCreationTime [in] The creation time of the process.
//			  processId           [in] The process ID of the process.
//			  cpid                [out] Receives the Cpid derived from the specified process information.
// 
//	Returns	: true if the CPID was successfully derived; false otherwise.
// 
//	Remarks	: Note that the caller must run with elevated privileges.
//			  This because CPID uses the creation time of the PID 4 system process of the current Windows system.
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::Derive(uint64_t processCreationTime, uint32_t processId, cpid_t* cpid)
{
	if (s_systemCreationTime == 0)
	{
		if (!Startup())
		{
			return false;
		}
	}

	return Derive2(s_machineGuid, s_systemCreationTime, processCreationTime, processId, cpid);
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	Derive2
// 
//	Derives a CPID (pronounced "see-pid") using the specified system and process information.
// 
//	Params	: machineGuid         [in] The MachineGuid of the Windows computer on which the specified process runs.
//			  systemCreationTime  [in] The creation time of the PID 4 process of the specified Windows computer.
//			  processCreationTime [in] The creation time of the process that runs on the specified Windows computer
//			  processId			  [in] The process ID of the process that runs on the specified Windows computer.
//			  cpid                [out] Receives the Cpid derived from the specified system and process information.
// 
//	Returns	: true if the CPID was successfully derived of the specified information; false otherwise.
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::Derive2(
	const GUID& machineGuid,
	uint64_t systemCreationTime,
	uint64_t processCreationTime,
	uint64_t processId,
	cpid_t* cpid)
{
	digest_input_content_t input;

	input.machine_guid                        = machineGuid;
	input.system_creation_time_windows_ticks  = systemCreationTime;
	input.process_creation_time_windows_ticks = processCreationTime;
	input.pid                                 = processId;

	uint8_t digest[32];
	if (!Cpid::ComputeSha256Hash(&input, digest))
	{
		return false; // failed
	}

	//
	//	Take the first 16-bytes of the SHA256 digest and turn it into a CPID (UUIDv8)
	//
	digest[7] = (digest[7] & 0x0F) | (0x8 << 4);	// set the version (Version 8)
	digest[8] = (digest[8] & 0x3F) | (0x80);		// set the variant

	cpid->Data1 =
		(static_cast<uint32_t>(digest[3]) << 24) |
		(static_cast<uint32_t>(digest[2]) << 16) |
		(static_cast<uint32_t>(digest[1]) <<  8) |
		(static_cast<uint32_t>(digest[0]));

	cpid->Data2 =
		(static_cast<uint16_t>(digest[5]) << 8) |
		(static_cast<uint16_t>(digest[4]));

	cpid->Data3 =
		(static_cast<uint16_t>(digest[7]) << 8) |
		(static_cast<uint16_t>(digest[6]));

	std::memcpy(cpid->Data4, &digest[8], sizeof(cpid->Data4));

	return true;
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	Equals
// 
//	Determines whether two specified CPID values are the same.
// 
//	Returns	: true if cpidA is the same as cpidB; false otherwise
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::Equals(const cpid_t& cpidA, const cpid_t& cpidB) noexcept
{
	if ((cpidA.Data1 == cpidB.Data1) &&
		(cpidA.Data2 == cpidB.Data2) &&
		(cpidA.Data3 == cpidB.Data3))
	{
		return (std::memcmp(cpidA.Data4, cpidB.Data4, sizeof(cpidA.Data4)) == 0);
	}
	return false;
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	GetHashCode
// 
//	Returns a hash that can be used in STL unordered_map and unordered_set containers.
// 
//---------------------------------------------------------------------------------------------------------------------
size_t Cpid::GetHashCode(cpid_t cpid) noexcept
{
#ifdef _WIN64

	uint64_t data4;
	std::memcpy(&data4, cpid.Data4, sizeof(data4));

	uint64_t data123 = 
		(static_cast<uint64_t>(cpid.Data1) << 32) |
		(static_cast<uint64_t>(cpid.Data2) << 16) |
		(static_cast<uint64_t>(cpid.Data3));

	return static_cast<size_t>(data123 ^ data4);

#else

	uint32_t data4a;
	uint32_t data4b;
	std::memcpy(&data4a, &cpid.Data4[0], sizeof(data4a));
	std::memcpy(&data4b, &cpid.Data4[4], sizeof(data4b));

	uint32_t data23 = 
		(static_cast<uint32_t>(cpid.Data2) << 16) |
		(static_cast<uint32_t>(cpid.Data3));

	return static_cast<size_t>(cpid.Data1 ^ data23 ^ data4a ^ data4b);

#endif
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	ToString
// 
//	Returns the string representation of the specified cpid_t structure.
// 
//	Params	: cpid [in] the CPID value to convert into a string
// 
//	Returns	: The value of the specified cpid, represented as a series of lowercase hexadecimal digits in the format 
//			  00000000-0000-0000-0000-000000000000
// 
//---------------------------------------------------------------------------------------------------------------------
std::string Cpid::ToString(const cpid_t& cpid)
{
	char buffer[37];

	snprintf(buffer, sizeof(buffer),
		"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		cpid.Data1,
		cpid.Data2,
		cpid.Data3,
		cpid.Data4[0],
		cpid.Data4[1],
		cpid.Data4[2],
		cpid.Data4[3],
		cpid.Data4[4],
		cpid.Data4[5],
		cpid.Data4[6],
		cpid.Data4[7]);

	return std::string(buffer);
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	TryParse
// 
//	Converts the string representation of a CPID to the equivalent cpid_t structure.
//	
//	Params	: str  [in]  the string representation of a CPID
//			  cpid [out] receives the cpid_t structure that contains the value that was parsed.

//	Returns	: true if the parse operation was successful; false otherwise.
// 
//	Remarks	: The only format accepted is 00000000-0000-0000-0000-000000000000
//			  Coincidentally, this is also the formatted output by the Cpid::ToString() method.
// 
//	See also: ToString()
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::TryParse(const std::string& str, cpid_t* cpid)
{
	static const uint8_t hex2bin[] =
	{
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
		0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  0,  0,  0,  0,  0,  0,	// 0x30 = '0', '1', '2', '3', '4', '5', ...
		0, 10, 11, 12, 13, 14, 15,  0,  0,  0,  0,  0,  0,  0,  0,  0,	// 0x40 = '@', 'A', 'B', 'C', 'D', 'E', 'F'
		0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
		0, 10, 11, 12, 13, 14, 15										// 0x60 = '`', 'a', 'b', 'c', 'd', 'e', 'f'
	};

	if (str.length() != 36)
	{
		return false;
	}
	
	if ((str [8] != '-') ||
		(str[13] != '-') ||
		(str[18] != '-') ||
		(str[23] != '-'))
	{
		return false;			// at least one delimiter is not on its expected place
	}

	for (int i = 0; i < 36; i++)
	{
		if ((i ==  8) || 
			(i == 13) || 
			(i == 18) || 
			(i == 23)) 
		{
			continue;			// skip the delimiter
		}
		if (str[i] > 'f')
		{
			return false;		// invalid character; would go outside of hex2bin array
		}
		if (hex2bin[str[i]] == 0)
		{
			if (str[i] != '0')
			{
				return false;	// invalid character; slot holds a zero that isn't the '0' character
			}
		}
	}

	cpid->Data1 = 
		(hex2bin[str[0]] << 28 | hex2bin[str[1]] << 24 | hex2bin[str[2]] << 20 | hex2bin[str[3]] << 16 |
         hex2bin[str[4]] << 12 | hex2bin[str[5]] <<  8 | hex2bin[str[6]] <<  4 | hex2bin[str[7]]);

	cpid->Data2    = hex2bin[str[ 9]] << 12 | hex2bin[str[10]] << 8 | hex2bin[str[11]] << 4 | hex2bin[str[12]];
	cpid->Data3    = hex2bin[str[14]] << 12 | hex2bin[str[15]] << 8 | hex2bin[str[16]] << 4 | hex2bin[str[17]];
	cpid->Data4[0] = hex2bin[str[19]] <<  4 | hex2bin[str[20]];
	cpid->Data4[1] = hex2bin[str[21]] <<  4 | hex2bin[str[22]];
	cpid->Data4[2] = hex2bin[str[24]] <<  4 | hex2bin[str[25]];
	cpid->Data4[3] = hex2bin[str[26]] <<  4 | hex2bin[str[27]];
	cpid->Data4[4] = hex2bin[str[28]] <<  4 | hex2bin[str[29]];
	cpid->Data4[5] = hex2bin[str[30]] <<  4 | hex2bin[str[31]];
	cpid->Data4[6] = hex2bin[str[32]] <<  4 | hex2bin[str[33]];
	cpid->Data4[7] = hex2bin[str[34]] <<  4 | hex2bin[str[35]];

	return true;
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	SelfTest
// 
//	This function performs a CPID calculation to test whether its internal functions produce an expected result.
// 
//	Returns	: true when the function passed its selftest; false when the selftest failed.
// 
//	Remarks	:
// 
//	The Common Process Id specification lists the example below and this selftest function tests this result.
// 
//	|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
//	| windows machine guid                 | b3b44fe1-8a3b-4191-a91e-d3581e766fac |
//	| system (PID 4) process creation time | 133494576686106382                   |
//	| process creation time                | 133494576996587731                   |
//	| process identifier                   | 4992                                 |
//	|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
//
//	Following the above process gives ec88c71a-1d67-853c-a76c-3f10f2acdb6e.
// 
//	See also:
//	https://github.com/ocsf/common-process-id/blob/main/specification.md
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::SelfTest()
{
	const GUID machineGuid = { 0xb3b44fe1, 0x8a3b, 0x4191, { 0xa9, 0x1e, 0xd3, 0x58, 0x1e, 0x76, 0x6f, 0xac } };
	const uint64_t systemCreationTime  = 133494576686106382;
	const uint64_t processCreationTime = 133494576996587731;
	const uint64_t processId = 4992;

	const cpid_t expected = { 0xec88c71a, 0x1d67, 0x853c, { 0xa7, 0x6c, 0x3f, 0x10, 0xf2, 0xac, 0xdb, 0x6e } };

	cpid_t cpid;
	if (!Derive2(machineGuid, systemCreationTime, processCreationTime, processId, &cpid))
	{
		return false; // failed to derive the CPID value
	}

	return (cpid == expected);
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	GetMachineId
// 
//	Params	: machineGuid [out] receives the MachineGuid of the current Windows computer.
// 
//	Returns	: true when successful; false otherwise.
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::GetMachineGuid(GUID* machineGuid)
{
	char str[40];
	DWORD size = sizeof(str);

	LSTATUS status = RegGetValueA(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Cryptography",
		"MachineGuid",
		RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
		nullptr,
		str,
		&size);

	if (status != ERROR_SUCCESS)
	{
		return false; // failed to get MachineGuid from Windows registry
	}

	cpid_t cpid;
	if (!Cpid::TryParse(str, &cpid))
	{
		return false; // failed to parse the string as a cpid_t or GUID
	}

	machineGuid->Data1 = cpid.Data1;
	machineGuid->Data2 = cpid.Data2;
	machineGuid->Data3 = cpid.Data3;
	std::memcpy(&machineGuid->Data4, cpid.Data4, sizeof(machineGuid->Data4));

	return true;
}


//---------------------------------------------------------------------------------------------------------------------
// 
//	GetProcessCreationTime
// 
//	Retrieves the creation time of an existing process.
// 
//	Params	: processId           [in]  The process ID of the process whose timing information is sought.
//			  processCreationTime [out] Receives the creation time of the process.
// 
//	Returns	: true when the creation time was successfully returned; false otherwise.
// 
//---------------------------------------------------------------------------------------------------------------------
bool Cpid::GetProcessCreationTime(uint32_t processId, uint64_t* processCreationTime)
{
	bool returnValue = false;

	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);

	if (hProcess != nullptr)
	{
		FILETIME ct, et, kt, ut;

		BOOL success = ::GetProcessTimes(hProcess, &ct, &et, &kt, &ut);

		if (success)
		{
			ULARGE_INTEGER li;
			li.LowPart = ct.dwLowDateTime;
			li.HighPart = ct.dwHighDateTime;

			(*processCreationTime) = li.QuadPart;

			returnValue = true;
		}

		CloseHandle(hProcess);
	}

	return returnValue;
}
