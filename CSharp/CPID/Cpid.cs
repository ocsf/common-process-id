using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace OCSF
{
    public readonly struct Cpid : IComparable<Cpid>, IEquatable<Cpid>
    {
        /// <summary>
        /// A read-only instance of the <see cref="OCSF.Cpid">Cpid</see> structure whose value are all zeroes.
        /// </summary>
        public readonly static Cpid Empty;

        private static Guid s_machineGuid = Guid.Empty;
        private static long s_systemCreationTime = 0;

        /// <summary>
        /// We store the Cpid value in a Guid structure so that we can conveniently use its many functions.
        /// </summary>
        private readonly Guid _guid;

        /// <summary>
        /// Initializes a new instance of the Cpid structure that equals to <see cref="Cpid.Empty">Empty</see>.
        /// </summary>
        public Cpid()
        {
            _guid = Guid.Empty;
        }

        /// <summary>
        /// Initializes a new instance of the Cpid structure by using the specifed Guid value.
        /// </summary>
        /// <param name="guid"></param>
        /// <seealso cref="ToGuid()"/>
        public Cpid(Guid guid)
        {
            _guid = guid;
        }

        /// <summary>
        /// Initializes a new instance of the Cpid structure by using the value represented by the specified read-only span of bytes.
        /// </summary>
        /// <param name="bytes"></param>
        /// <seealso cref="ToByteArray()"/>
        /// <exception cref="ArgumentException"></exception>
        public Cpid(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 16)
            {
                throw new ArgumentException("Invalid array length", "bytes");
            }

            _guid = new Guid(bytes);
        }


        /// <summary>
        /// Computes the SHA256 hash of the specified input per CPID specification.
        /// </summary>
        /// <seealso href="https://github.com/ocsf/common-process-id/blob/main/specification.md"/>
        private static byte[] ComputeSha256Hash(digest_input_content_t input)
        {
            //
            // From the specification:
            //
            // The digest input format is not important for the final identifier if it is formatted consistently.
            // Therefore, the input format can be optimized for easy and efficient implementation. One such optimization
            // is using platform-native memory representations. This choice removes endianness considerations from
            // endpoint software implementations, maximizing the chance of correct implementation. Additionally,
            // performance benefits are possible since conversion operations are minimized, and native implementations
            // can use packed (no padding) structs as the digest input buffer. Another optimization is using 64-bit
            // integers so the packed representations of digest input structs match default compiler packing behavior
            // on 64-bit platforms when optimizing for performance.
            //
            Span<byte> buffer = stackalloc byte[40];

            MemoryMarshal.Write(buffer, input);

            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(buffer.ToArray());
            }
        }


        /// <summary>
        /// Derives a CPID (pronounced "see-pid") from the specified process information for the current Windows computer.
        /// </summary>
        /// <param name="processStartTime">The DateTime when the process was created. This is typically Process.StartTime.</param>
        /// <param name="processId">The process ID of the process.</param>
        /// <returns>The Cpid structure derived from the specified process information for the current computer.</returns>
        /// <remarks>Note that the caller must run with elevated privileges because CPID uses the creation time of the PID 4 system process on this Windows system.</remarks>
        /// <exception cref="Exception"/>
        public static Cpid Derive(DateTime processStartTime, int processId)
        {
            return Derive((ulong)processStartTime.ToFileTimeUtc(), (ulong)processId);
        }


        /// <summary>
        /// Derives a CPID (pronounced "see-pid") from specified process information for the current Windows computer.
        /// </summary>
        /// <param name="processCreationTimeInTicks">The creation time of the process, in ticks.</param>
        /// <param name="processId">The process ID of the process.</param>
        /// <remarks>Note that the caller must run with elevated privileges because CPID uses the creation time of the PID 4 system process on this Windows system.</remarks>
        /// <exception cref="Exception"/>
        public static Cpid Derive(long processCreationTimeInTicks, int processId)
        {
            return Derive((ulong)processCreationTimeInTicks, (ulong)processId);
        }


        /// <summary>
        /// Derives a CPID (pronounced "see-pid") from specified process information for the current Windows computer.
        /// </summary>
        /// <param name="processCreationTimeInTicks">The creation time of the process, in ticks.</param>
        /// <param name="processId">The process ID of the process.</param>
        /// <returns>The Cpid structure derived from the specified process information for the current computer.</returns>
        /// <remarks>Note that the caller must run with elevated privileges because CPID uses the creation time of the PID 4 system process on this Windows system.</remarks>
        /// <exception cref="Exception"/>
        public static Cpid Derive(ulong processCreationTimeInTicks, ulong processId)
        {
            if (s_systemCreationTime == 0)
            {
                using (Process process = Process.GetProcessById(4))
                {
                    s_systemCreationTime = process.StartTime.ToFileTimeUtc();
                }
            }
            if (s_machineGuid == Guid.Empty)
            {
                using (RegistryKey? key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography", false))
                {
                    if (key == null)
                    {
                        throw new Exception("Unable to access MachineGuid");
                    }

                    object? value = key.GetValue("MachineGuid");

                    if (!(value is string machineGuid))
                    {
                        throw new Exception("MachineGuid is missing");
                    }

                    s_machineGuid = Guid.Parse(machineGuid);
                }
            }

            return Derive2(s_machineGuid, (ulong)s_systemCreationTime, processCreationTimeInTicks, processId);
        }


        /// <summary>
        /// Derives a CPID (pronounced "see-pid") using the specified system and process information.
        /// </summary>
        /// <param name="machineGuid">The MachineGuid of the Windows computer on which the specified process runs.</param>
        /// <param name="systemCreationTimeInTicks">The creation time of the System (PID 4) process of the specified Windows computer, in ticks.</param>
        /// <param name="processCreationTimeInTicks">The creation time of the process that runs on the specified Windows computer, in ticks.</param>
        /// <param name="pid">The process ID of the process that runs on the specified Windows computer.</param>
        /// <returns>The Cpid structure derived from the specified system and process information.</returns>
        /// <exception cref="Exception"></exception>
        public static Cpid Derive2(
            Guid machineGuid, 
            ulong systemCreationTimeInTicks, 
            ulong processCreationTimeInTicks, 
            ulong pid)
        {
            digest_input_content_t input = new digest_input_content_t();

            input.machine_guid                        = machineGuid;
            input.system_creation_time_windows_ticks  = systemCreationTimeInTicks;
            input.process_creation_time_windows_ticks = processCreationTimeInTicks;
            input.pid                                 = pid;

            byte[] bytes = ComputeSha256Hash(input);

            if (bytes.Length != 32)
            {
                throw new Exception("SHA256 digest failed");
            }

            bytes[7] = (byte)((bytes[7] & 0x0F) | (0x8 << 4));  // set the version (Version 8)
            bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);        // set the variant

            return new Cpid(bytes.AsSpan(0, 16));
        }

        public override int GetHashCode() => _guid.GetHashCode();

        public int CompareTo(Cpid other) => _guid.CompareTo(other._guid);

        public bool Equals(Cpid other) => _guid.Equals(other._guid);

        public override bool Equals(object? obj) =>
            obj is Cpid other && Equals(other) ||
            obj is Guid guid && _guid.Equals(guid);


        /// <summary>
        /// Converts the string representation of a CPID to the equivalent Cpid structure.
        /// </summary>
        /// <param name="input">The string to convert.</param>
        /// <returns>A structure that contains the value that was parsed.</returns>
        /// <exception cref="FormatException">input is not in a recognized format.</exception>
        /// <seealso cref="TryParse(string, out Cpid)"/>
        /// <seealso cref="ToString()"/>
        public static Cpid Parse(string input)
        {
            Guid guid;
            if (!Guid.TryParseExact(input, "D", out guid))
            {
                throw new FormatException($"Bad format: {input}");
            }
            return new Cpid(guid);
        }


        /// <summary>
        /// Converts the string representation of a CPID to the equivalent Cpid structure, provided that the string is in the correct format.
        /// </summary>
        /// <param name="input">The string to convert.</param>
        /// <returns>true if the parse operation was successful; false otherwise.</returns>
        /// <seealso cref="TryParse(string, out Cpid)"/>
        /// <seealso cref="ToString()"/>
        public static bool TryParse(string input, out Cpid result) 
        {
            Guid guid;
            if (!Guid.TryParseExact(input, "D", out guid))
            {
                result = Cpid.Empty;
                return false;
            }

            result = new Cpid(guid);
            return true;
        }


        /// <summary>
        /// Performs a selftest to see if the internal functions of the Cpid class produce an expected predefined result.
        /// </summary>
        /// <returns>true if the selftest was successful; false otherwise.</returns>
        /// <seealso cref="Derive(Guid, ulong, ulong, ulong)"/>
        /// <example>
        ///	|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        ///	| windows machine guid                 | b3b44fe1-8a3b-4191-a91e-d3581e766fac |
        ///	| system (PID 4) process creation time | 133494576686106382                   |
        ///	| process creation time                | 133494576996587731                   |
        ///	| process identifier                   | 4992                                 |
        ///	|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        ///
        ///	Following the above process gives ec88c71a-1d67-853c-a76c-3f10f2acdb6e.
        /// </example>
        /// <seealso href="https://github.com/ocsf/common-process-id/blob/main/specification.md"/>
        public static bool SelfTest()
        {
            //
            //  The following ensures that the digest_input_content_t is exactly 40 bytes.
            //  Sadly there is no way to do this at compile time.
            //
            int size = Marshal.SizeOf<digest_input_content_t>();
            if (size != 40)
            {
                
                throw new Exception("Windows digest_input_content_t size should be 40 bytes");
            }

            //
            // Check against the reference value mentioned in the specification.
            //
            Cpid cpid = Cpid.Derive2(
                new Guid("b3b44fe1-8a3b-4191-a91e-d3581e766fac"),
                133494576686106382,
                133494576996587731,
                4992);

            Guid expected = new Guid("ec88c71a-1d67-853c-a76c-3f10f2acdb6e");

            return (cpid == expected);
        }


        /// <summary>
        /// Returns a 16-element byte array that contains the value of this instance.
        /// </summary>
        public byte[] ToByteArray() => _guid.ToByteArray();


        /// <summary>
        /// Returns the Guid representation of the value of this instance of the Cpid structure.
        /// </summary>
        public Guid ToGuid() => _guid;


        /// <summary>
        /// Returns the string representation of the value of this instance of the Cpid structure.
        /// </summary>
        /// <returns>The value of this Cpid, represented as a series of lowercase hexadecimal digits in the format 00000000-0000-0000-0000-000000000000</returns>
        public override string ToString() => _guid.ToString("D", null);


        public static bool operator ==(Cpid left, Cpid right) => left.Equals(right);
        public static bool operator !=(Cpid left, Cpid right) => !(left == right);
        public static bool operator <(Cpid left, Cpid right) => left.CompareTo(right) < 0;
        public static bool operator >(Cpid left, Cpid right) => left.CompareTo(right) > 0;
        public static bool operator <=(Cpid left, Cpid right) => left.CompareTo(right) <= 0;
        public static bool operator >=(Cpid left, Cpid right) => left.CompareTo(right) >= 0;
        public static bool operator ==(Cpid left, Guid right) => left.Equals(right);
        public static bool operator !=(Cpid left, Guid right) => !(left == right);


        [SuppressMessage("Style", "IDE1006:Naming Styles", Justification = "The name adheres to the specification.")]
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct digest_input_content_t
        {
            public Guid machine_guid;
            public ulong system_creation_time_windows_ticks;
            public ulong process_creation_time_windows_ticks;
            public ulong pid;
        }
    }
}
