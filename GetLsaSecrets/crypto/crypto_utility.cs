using System;
using System.Runtime.InteropServices;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace utilities
{
    class MD4
    {
        public static string hex_to_ntlm(string hex)
        {
            // Convert hex string to byte array
            byte[] decodedBytes = ConvertHexStringToByteArray(hex);

            // Compute MD4 hash
            byte[] hash = ComputeMD4Hash(decodedBytes);
            Console.WriteLine(hash);

            // Convert hash to hex string and print
            Console.WriteLine(BitConverter.ToString(hash).Replace("-", "").ToLower());
            string hash2 = BitConverter.ToString(hash).Replace("-", "").ToLower();
            return hash2;
        }

        // Helper function to convert hex string to byte array
        static byte[] ConvertHexStringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];

            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

        // Compute MD4 hash using BouncyCastle
        static byte[] ComputeMD4Hash(byte[] input)
        {
            MD4Digest md4 = new MD4Digest();
            md4.BlockUpdate(input, 0, input.Length);

            byte[] result = new byte[md4.GetDigestSize()];
            md4.DoFinal(result, 0);

            return result;
        }

    }
}
