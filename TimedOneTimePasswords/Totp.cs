using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TimedOneTimePasswords
{

    /// <summary>
    /// Represents a time-based one-time password (TOTP) based 
    /// on a base32-encoded secret
    /// </summary>
    public sealed class Totp
    {
        private static readonly DateTime m_unixEpoch =
            new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private const int FREQUENCY_SECONDS = 30;

        private readonly string m_authenticationCode;
        private readonly DateTime m_expiry;

        public Totp(string base32Secret)
        {
            byte[] secretBytes = Base32.ToByteArray(base32Secret);

            DateTime utcNow = DateTime.UtcNow;
            long unixNow = ToUnixTime(utcNow);
            long timestamp = Convert.ToInt64(unixNow / FREQUENCY_SECONDS);
            byte[] timestampBytes = BitConverter.GetBytes(timestamp).ToArray();
            // IBM PC architecture is little endian
            Array.Reverse(timestampBytes);

            using (HMACSHA1 hmac = new HMACSHA1(secretBytes))
            {
                byte[] hmacBytes = hmac.ComputeHash(timestampBytes);
                int offset = hmacBytes.Last() & 0x0F;

                int firstByte = (hmacBytes[offset + 0] & 0x7F) << 24;
                int secondByte = hmacBytes[offset + 1] << 16;
                int thirdByte = hmacBytes[offset + 2] << 8;
                int fourthByte = hmacBytes[offset + 3];

                int authenticationCode =
                    (firstByte | secondByte | thirdByte | fourthByte) % 1000000;

                // pad with leading zeroes
                m_authenticationCode = authenticationCode.ToString().PadLeft(6, '0');
                m_expiry = GetExpiry(utcNow);
            }
        }

        /// <summary>
        /// The 6-digit authentication code itself
        /// </summary>
        public string AuthenticationCode { get { return m_authenticationCode; } }

        /// <summary>
        /// Expiration date of this authentication code in UTC time
        /// </summary>
        public DateTime ExpiryUtc { get { return m_expiry; } }

        /// <summary>
        /// True when this authentication code is expired
        /// </summary>
        public bool IsExpired
        {
            get
            {
                return DateTime.UtcNow > m_expiry;
            }
        }

        /// <summary>
        /// The length of the maximum validity period for an authentication code
        /// </summary>
        public static readonly TimeSpan MaxLifetime = TimeSpan.FromSeconds(FREQUENCY_SECONDS);

        public override string ToString()
        {
            string expiry = m_expiry.ToString("hh:mm:ss.fff");
            return "Authentication code: " + m_authenticationCode +
                " (expires at " + expiry + " UTC)";
        }

        // Helper - get expiration based on the generation time
        private static DateTime GetExpiry(DateTime generationTimeUtc)
        {
            long unixNow = ToUnixTime(generationTimeUtc);
            long secondsToExpiry = FREQUENCY_SECONDS - unixNow % FREQUENCY_SECONDS;
            DateTime expiry = generationTimeUtc + TimeSpan.FromSeconds(secondsToExpiry);

            if (expiry.Second % FREQUENCY_SECONDS == 0)
            {
                // mark last second of the interval as the expiry second
                expiry = expiry - TimeSpan.FromSeconds(1);
            }

            // set milliseconds to 999
            expiry = new DateTime(
                expiry.Year,
                expiry.Month,
                expiry.Day,
                expiry.Hour,
                expiry.Minute,
                expiry.Second, 999
                );
            return expiry;
        }

        // Helper - convert a date/time to a unix date stamp
        private static long ToUnixTime(DateTime dateTime)
        {
            double unixSeconds = (dateTime - m_unixEpoch).TotalSeconds;
            return Convert.ToInt64(Math.Round(unixSeconds));
        }
    }
}
