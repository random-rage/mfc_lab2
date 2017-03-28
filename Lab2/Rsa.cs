using System;
using Org.BouncyCastle.Math;

namespace Lab2
{
    class Rsa
    {
        public struct RsaParams
        {
            public BigInteger p, q, 
                              e, d, n, 
                              dP, dQ, qInv;
        }

        private RsaParams _p;
        private bool _optimize;

        public RsaParams Params
        {
            get { return _p; }
            set { _p = value; }
        }

        public Rsa(bool optimize = true)
        {
            _optimize = optimize;
        }

        public Rsa(int e, int keyLen, int certainty, Random rnd, bool optimize = true)
        {
            BigInteger p, q;                    // Секретные значения p и q
            int comp;                           // Переменная для сравнения

            _optimize = optimize;
            _p.e = BigInteger.ValueOf(e);       // Устанавливаем экспоненту

            do
            {
                // Генерируем p и q
                p = new BigInteger(keyLen / 2, certainty, rnd);
                q = new BigInteger(keyLen / 2, certainty, rnd);

                comp = p.CompareTo(q);    // Сравниваем p и q

                if (comp == 0)                  // Если они равны, генерируем заново
                    continue;
                else if (comp < 0)              // Если q больше p, меняем их местами
                {
                    BigInteger tmp = p;
                    p = q;
                    q = tmp;
                }
            }
            while (GenerateKeys(p, q));
        }

        public bool GenerateKeys(BigInteger p, BigInteger q)
        {
            BigInteger p1, q1,          // (p - 1) и (q - 1)
                       f, gcd;          // Значение функции Эйлера от n и НОД(e, f)

            p1 = p.Subtract(BigInteger.One);
            q1 = q.Subtract(BigInteger.One);

            // Вычисляем значение функции Эйлера от n
            f = p1.Multiply(q1);

            gcd = f.Gcd(_p.e);                  // Вычисляем НОД(e, f)

            // Если общих делителей у e и f (кроме 1) нет, завершаем генерацию
            if (gcd.CompareTo(BigInteger.One) != 0)
                return true;

            _p.p = p;
            _p.q = q;
            _p.n = p.Multiply(q);               // Вычисляем n = p * q
            _p.d = _p.e.ModInverse(f);          // Вычисляем d = e^(-1) mod f

            if (_optimize)
            {
                // Вычисляем вспомогательные параметры
                _p.dP = _p.d.Mod(p1);
                _p.dQ = _p.d.Mod(q1);
                _p.qInv = q.ModInverse(p);
            }

            return false;
        }

        public BigInteger Encrypt(BigInteger m)
        {
            // Если пришло отрицательное число - кидаем исключение
            if (m.SignValue < 0)
                throw new ArgumentOutOfRangeException("m", "Message must be in range [0..N-1]");

            // Шифруем "число" только при условии, что оно меньше модуля
            if (m.CompareTo(_p.n) < 0)
                return m.ModPow(_p.e, _p.n);
            else
                throw new ArgumentOutOfRangeException("m", "Message must be less than N");
        }

        public BigInteger Decrypt(BigInteger c)
        {
            // Если пришло отрицательное число - кидаем исключение
            if (c.SignValue < 0)
                throw new ArgumentOutOfRangeException("c", "Ciphertext must be in range [0..N-1]");

            // Расшифровываем "число" только при условии, что оно меньше модуля
            if (c.CompareTo(_p.n) >= 0)
                throw new ArgumentOutOfRangeException("c", "Ciphertext must be less than N");

            // Использовать оптимизацию с китайской теоремой об остатках?
            if (_optimize)
            {
                BigInteger m1 = c.ModPow(_p.dP, _p.p);                  // c ^ (dP) mod p
                BigInteger m2 = c.ModPow(_p.dQ, _p.q);                  // c ^ (dQ) mod q
                BigInteger dM;

                if (m1.CompareTo(m2) < 0)                               // m1 < m2 ?
                {
                    BigInteger[] divRem = _p.q.DivideAndRemainder(_p.p);    // q / p

                    if (divRem[1].SignValue != 0)                       // [q / p]
                        divRem[0].Add(BigInteger.One);

                    dM = divRem[0].Multiply(_p.p);                      // [q / p] * p
                    dM = dM.Add(m1);                                    // m1 + [q / p] * p
                    dM = dM.Subtract(m2);                               // (m1 + [q / p] * p) - m2
                }
                else
                    dM = m1.Subtract(m2);

                BigInteger h = (_p.qInv.Multiply(dM)).Mod(_p.p);        // (qInv * dM) mod p

                return (h.Multiply(_p.q)).Add(m2);                      // m = hq + m2
            }
            else
                return c.ModPow(_p.d, _p.n);
        }
    }
}
