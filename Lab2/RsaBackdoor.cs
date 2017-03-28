using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Math;
using Chaos.NaCl;

namespace Lab2
{
    static class RsaBackdoor
    {
        public static Rsa Inject(int e, int keyLen, int certainty, byte[] publicKey)
        {
            byte[] privateData = new byte[MontgomeryCurve25519.PrivateKeySizeInBytes];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            // Генерируем секретное значение для инициализации ГПСЧ
            rng.GetBytes(privateData);

            // Создаём полезную нагрузку, шифруя seed
            byte[] payload = MontgomeryCurve25519.GetPublicKey(privateData);
            byte[] seed = MontgomeryCurve25519.KeyExchange(publicKey, privateData);

            Rsa rsa = new Rsa(e, keyLen, certainty, new Random(seed.PackToInt()));
            Rsa.RsaParams rsap = rsa.Params;

            // Вшиваем полезную нагрузку в модуль n
            byte[] mod = rsap.n.ToByteArray();
            Replace(mod, payload, 80);
            BigInteger n = new BigInteger(mod);

            // q = NextPrime(n' / p)
            rsap.q = (n.Divide(rsap.p)).NextProbablePrime();    

            if (rsap.p.CompareTo(rsap.q) < 0)   // Если q больше p, меняем их местами
            {
                BigInteger tmp = rsap.p;
                rsap.p = rsap.q;
                rsap.q = tmp;
            }

            // Заново считаем остальные параметры
            rsa.GenerateKeys(rsap.p, rsap.q);
            return rsa;
        }

        public static Rsa Extract(int e, BigInteger mod, int certainty, byte[] privateKey)
        {
            byte[] modulus = mod.ToByteArray();
            byte[] payload = new byte[MontgomeryCurve25519.PublicKeySizeInBytes];

            // Вытаскиваем полезную нагрузку и расшифровываем seed
            Array.Copy(modulus, 80, payload, 0, 32);
            byte[] seed = MontgomeryCurve25519.KeyExchange(payload, privateKey);

            Rsa rsa = new Rsa(e, mod.BitLength, certainty, new Random(seed.PackToInt()));
            Rsa.RsaParams rsap = rsa.Params;

            // Вшиваем полезную нагрузку в модуль n
            modulus = rsap.n.ToByteArray();
            Replace(modulus, payload, 80);
            BigInteger n = new BigInteger(modulus);

            // q = NextPrime(n' / p)
            rsap.q = (n.Divide(rsap.p)).NextProbablePrime();

            if (rsap.p.CompareTo(rsap.q) < 0)   // Если q больше p, меняем их местами
            {
                BigInteger tmp = rsap.p;
                rsap.p = rsap.q;
                rsap.q = tmp;
            }

            // Заново считаем остальные параметры
            rsa.GenerateKeys(rsap.p, rsap.q);
            return rsa;
        }

        private static int PackToInt(this byte[] bytes)
        {
            if (bytes.Length % 4 != 0)
                throw new ArgumentException("bytes length must be a multiple of 4");

            int tmp, res = 0;

            for (int i = 0; i < bytes.Length / 4; i += 4)
            {
                tmp = bytes[i];
                tmp <<= 8;
                tmp += bytes[i + 1];
                tmp <<= 8;
                tmp += bytes[i + 2];
                tmp <<= 8;
                tmp += bytes[i + 3];
                res ^= tmp;
            }

            return res;
        }

        private static void Replace(byte[] origin, byte[] replace, int offset)
        {
            for (int i = 0; i < replace.Length; i++)
                origin[i + offset] = replace[i];
        }
    }
}
