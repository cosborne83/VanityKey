using System;
using System.IO;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace VanityKey
{
    internal class Program
    {
        private const int MinKeyLength = 512;

        private static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("VanityKey.exe <key-length> <prefix-string> <output-file>");
                return;
            }

            if (!int.TryParse(args[0], out var keyLength) || keyLength < MinKeyLength)
            {
                Console.WriteLine("Invalid key length, must be >= {0}", MinKeyLength);
                return;
            }

            if (keyLength % 16 != 0)
            {
                Console.WriteLine("Invalid key length, must be divisible by 16");
                return;
            }

            var text = args[1];
            if (text.Length == 0)
            {
                Console.WriteLine("No prefix specified");
                return;
            }

            text = "AA/" + text;
            switch (text.Length % 4)
            {
                case 0:
                    text += "/w==";
                    break;
                case 1:
                    text += "/w=";
                    break;
                case 2:
                    text += "/w";
                    break;
                case 3:
                    text += "/";
                    break;
            }

            byte[] prefix;
            try
            {
                prefix = Convert.FromBase64String(text);
            }
            catch
            {
                Console.WriteLine("Prefix must be composed only of Base64 non-padding characters (A-z, a-z, 0-9, / and +)");
                return;
            }

            var rand = new SecureRandom();
            var realPrefix = new BigInteger(prefix, 1, prefix.Length - 1);
            var primeLength = keyLength >> 1;
            var realPrefixBitLength = (prefix.Length - 1) * 8;
            var shiftBits = keyLength - realPrefixBitLength;
            var appendPrefixBitLength = primeLength - realPrefixBitLength;
            var s = realPrefix.ShiftLeft(appendPrefixBitLength).Or(new BigInteger(appendPrefixBitLength, rand));
            var prefixBitLengthK = s.ToByteArray().Length * 8;
            var suffixBitLengthL = keyLength - prefixBitLengthK;
            var n1 = s.Multiply(BigInteger.Two.Pow(suffixBitLengthL));
            while (true)
            {
                var p = new BigInteger(suffixBitLengthL, 100, rand);
                var q = n1.Divide(p);
                q = q.Add(q.Mod(BigInteger.Two).Equals(BigInteger.Zero) ? BigInteger.One : BigInteger.Two);
                while (!q.IsProbablePrime(100))
                {
                    q = q.Add(BigInteger.Two);
                }

                var n = p.Multiply(q);
                if (!n.ShiftRight(shiftBits).Equals(realPrefix)) continue;

                //Console.WriteLine("p = {0}", p.ToString(16));
                //Console.WriteLine("q = {0}", q.ToString(16));
                //Console.WriteLine("n = {0}", n.ToString(16));

                var e = BigInteger.ValueOf(0x010001);

                using (var writer = new StreamWriter(args[2]))
                {
                    ExportPrivateKey(n, e, p, q, writer);
                }

                var header = new byte[]
                {
                    0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1
                };

                var modulus = n.ToByteArrayUnsigned();
                var modulusLength = modulus.Length;
                var pubkey = new byte[header.Length + 4 + modulusLength];
                Array.Copy(header, pubkey, header.Length);
                var offset = header.Length;
                pubkey[offset++] = (byte)((modulusLength >> 24) & 0xff);
                pubkey[offset++] = (byte)((modulusLength >> 16) & 0xff);
                pubkey[offset++] = (byte)((modulusLength >> 8) & 0xff);
                pubkey[offset++] = (byte)(modulusLength & 0xff);
                Array.Copy(modulus, 0, pubkey, offset, modulusLength);
                Console.WriteLine("ssh-rsa " + Convert.ToBase64String(pubkey));
                break;
            }
        }

        private static void ExportPrivateKey(BigInteger n, BigInteger e, BigInteger p, BigInteger q, TextWriter outputStream)
        {
            var modulus = n.ToByteArrayUnsigned();
            var exponent = e.ToByteArrayUnsigned();
            var p1 = p.Subtract(BigInteger.One);
            var q1 = q.Subtract(BigInteger.One);
            var phi = p1.Multiply(q1);
            var d = e.ModInverse(phi);
            var dp = d.Mod(p1);
            var dq = d.Mod(q1);
            var inverseQ = q.ModInverse(p);

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, modulus);
                    EncodeIntegerBigEndian(innerWriter, exponent);
                    EncodeIntegerBigEndian(innerWriter, d.ToByteArrayUnsigned());
                    EncodeIntegerBigEndian(innerWriter, p.ToByteArrayUnsigned());
                    EncodeIntegerBigEndian(innerWriter, q.ToByteArrayUnsigned());
                    EncodeIntegerBigEndian(innerWriter, dp.ToByteArrayUnsigned());
                    EncodeIntegerBigEndian(innerWriter, dq.ToByteArrayUnsigned());
                    EncodeIntegerBigEndian(innerWriter, inverseQ.ToByteArrayUnsigned());
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
    }
}
