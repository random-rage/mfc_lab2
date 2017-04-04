using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;

namespace Lab2
{
    static class Program
    {
        static readonly BigInteger E = BigInteger.ValueOf(65537);
        static readonly BigInteger M = BigInteger.ValueOf(1234567890);

        static void Main(string[] args)
        {
            BigInteger e, n, m;
            Rsa hacked;
            
            #region Factorization
            Console.Write("=== Factorization attack ===\nEnter N to factorize: ");
            hacked = FactorizationAttack(E, new BigInteger(Console.ReadLine()));
            Console.WriteLine("Factorization result:\np = {0}\nq = {1}", 
                              hacked.Params.p, hacked.Params.q);
            #endregion
            
            #region Wiener
            Console.Write("\n=== Wiener attack ===\nEnter E: ");
            e = new BigInteger(Console.ReadLine());
            Console.Write("Enter N: ");

            hacked = WienerAttack(e, new BigInteger(Console.ReadLine()));
            if (hacked.Params.d == null)
                Console.WriteLine("Wiener attack failed");
            else
                Console.WriteLine("Result:\nd = {0}", hacked.Params.d);
            #endregion
            
            #region Re-encryption
            Console.Write("\n=== Re-encryption attack ===\nEnter E: ");
            e = new BigInteger(Console.ReadLine());
            Console.Write("Enter N: ");
            n = new BigInteger(Console.ReadLine());
            Console.Write("Enter ciphertext: ");

            m = ReencryptionAttack(e, n, new BigInteger(Console.ReadLine()));
            Console.WriteLine("Result:\nm = {0}", m);
            #endregion
            
            #region Common module
            Console.Write("\n=== Common module attack ===\nEnter E1: ");
            e = new BigInteger(Console.ReadLine());
            Console.Write("Enter E2: ");
            BigInteger e2 = new BigInteger(Console.ReadLine());
            Console.Write("Enter N: ");
            n = new BigInteger(Console.ReadLine());
            Console.Write("Enter C1: ");
            BigInteger c = new BigInteger(Console.ReadLine());
            Console.Write("Enter C2: ");

            m = CommonModuleAttack(e, e2, n, c, new BigInteger(Console.ReadLine()));
            if (m.SignValue == 0)
                Console.WriteLine("Common module attack failed, GCD(e1, e2) != 1");
            else
                Console.WriteLine("Result:\nm = {0}", m);
            #endregion

            Console.WriteLine("\nDone!");
            Console.ReadKey();
        }

        // Вычисляет корень по методу Ньютона
        static BigInteger Root(this BigInteger n, int e)
        {
            BigInteger G = n.ShiftRight((n.BitLength + 1) / e * (e - 1));
            BigInteger LastG, E = BigInteger.ValueOf(e);
            BigInteger E1 = E.Subtract(BigInteger.One);
            int i;

            while (true)
            {
                LastG = G;
                G = n.Divide(G.Pow(e - 1)).Add(G.Multiply(E1)).Divide(E);
                i = G.CompareTo(LastG);

                if (i == 0)
                    return G;

                if (i < 0)
                {
                    if (
                        (LastG.Subtract(G).CompareTo(BigInteger.One) == 0) &&
                        (G.Multiply(G).CompareTo(n) < 0 && LastG.Multiply(LastG).CompareTo(n) > 0)
                       )
                        return G;
                }
                else
                {
                    if (
                        (G.Subtract(LastG).CompareTo(BigInteger.One) == 0) &&
                        (LastG.Multiply(LastG).CompareTo(n) < 0 && G.Multiply(G).CompareTo(n) > 0)
                       ) 
                        return LastG;
                }
            }
        }
        
        static Rsa FactorizationAttack(BigInteger e, BigInteger n)
        {
            BigInteger t = n.Root(2);           // Предположение t[i]
            BigInteger sqr, root;               // Квадрат и корень для проверки на полный квадрат

            do
            {
                t = t.Add(BigInteger.One);
                sqr = t.Square().Subtract(n);   // t[i]^2 - n
                //            ___________
                // Вычисляем √ t[i]^2 - n
                root = sqr.Root(2);
            }
            while (root.Pow(2).CompareTo(sqr) != 0);    // Проверяем на полный квадрат

            Rsa rsa = new Rsa(e);
            rsa.GenerateKeys(t.Add(root), t.Subtract(root));
            return rsa;
        }

        // Представляет p/q как непрерывную дробь
        static IEnumerable<BigInteger> ContinuedFraction(BigInteger p, BigInteger q)
        {
            BigInteger n, t;
            while (q.SignValue > 0)
            {
                n = p.Divide(q);
                yield return n;
                t = q;
                q = p.Subtract(q.Multiply(n));
                p = t;
            }
        }

        // Возвращает знаменатель подходящих дробей для разложения
        static IEnumerable<BigInteger> Convergents(IEnumerable<BigInteger> conFrac)
        {
            BigInteger s = BigInteger.One;
            BigInteger q = BigInteger.Zero;
            BigInteger t;

            foreach (BigInteger c in conFrac)
            {
                t = s;
                s = q;
                q = c.Multiply(q).Add(t);
                yield return q;
            }
        }

        static Rsa WienerAttack(BigInteger e, BigInteger n)
        {
            // Вычисляем максимально допустимое D для атаки
            BigInteger maxD = n.Root(4);

            // Берём случайное число битности N, но меньше N
            BigInteger m = BigInteger.One.ShiftLeft(n.BitLength - 1).Add(BigInteger.One);

            // Шифруем его для дальнейшей проверки
            BigInteger c = m.ModPow(e, n);

            Rsa rsa = new Rsa(e, false);
            Rsa.RsaParams newParams = rsa.Params;
            newParams.n = n;

            // Перечисляем знаменатели подходящих дробей
            foreach (BigInteger d in Convergents(ContinuedFraction(e, n)))
            {
                if (d.CompareTo(maxD) > 0)          // Проверяем, не ушли ли мы далеко
                    break;

                // Пробуем расшифровать наше случайное сообщение
                if (c.ModPow(d, n).CompareTo(m) == 0)
                {
                    newParams.d = d;
                    rsa.Params = newParams;
                    break;              // Выходим из цикла, если расшифрование удалось
                }
            }
            return rsa;
        }

        static BigInteger ReencryptionAttack(BigInteger e, BigInteger n, BigInteger c)
        {
            BigInteger prev = c.ModPow(e, n);
            BigInteger m = prev.ModPow(e, n);

            while (m.CompareTo(c) != 0)
            {
                prev = m;
                m = prev.ModPow(e, n);
            }
            return prev;
        }

        // Возвращает НОД(a, b) и находит r, s такие, что a*r + b*s = НОД(a, b)
        static BigInteger ExtendedEuclid(BigInteger a, BigInteger b, 
                                         out BigInteger r, out BigInteger s)
        {
            BigInteger u = a;
            BigInteger v = b;
            BigInteger u1 = BigInteger.One;
            BigInteger v1 = BigInteger.Zero;
            BigInteger tmp;

            while (v.SignValue > 0)
            {
                BigInteger[] q = u.DivideAndRemainder(v);

                tmp = v1.Multiply(q[0]);
                BigInteger tn = u1.Subtract(tmp);
                u1 = v1;
                v1 = tn;

                u = v;
                v = q[1];
            }
            r = u1;

            tmp = u1.Multiply(a);
            tmp = u.Subtract(tmp);
            s = tmp.Divide(b);

            return u;
        }

        static BigInteger CommonModuleAttack(BigInteger e1, BigInteger e2, 
                                             BigInteger n, 
                                             BigInteger c1, BigInteger c2)
        {
            BigInteger r, s;
            BigInteger gcd = ExtendedEuclid(e1, e2, out r, out s);

            // Если НОД(e1, e2) != 1, нет смысла продолжать
            if (gcd.CompareTo(BigInteger.One) != 0)
                return BigInteger.Zero;

            BigInteger y1 = c1.ModPow(r, n);
            BigInteger y2 = c2.ModPow(s, n);

            return y1.Multiply(y2).Mod(n);
        }

        static void SpeedTest(int bits, int certainty)
        {
            BigInteger p, q, n, e, e1, e2, c1, c2, m;
            Random rnd = new Random();
            DateTime start;

            Console.WriteLine("=== Speed test {0} bits ===", bits);
            
            #region Factorization
            q = new BigInteger(bits / 2, certainty, rnd);
            p = q.NextProbablePrime();
            n = p.Multiply(q);

            start = DateTime.Now;
            FactorizationAttack(E, n);
            Console.WriteLine("\nFactorization attack: {0} ms", (DateTime.Now - start).TotalMilliseconds);
            #endregion

            #region Wiener
            e = new BigInteger(bits / 4 - 1, certainty, rnd);
            Rsa rsa = new Rsa(e, bits, certainty, rnd, false);

            start = DateTime.Now;
            BigInteger d = WienerAttack(rsa.Params.d, rsa.Params.n).Params.d;
            Console.WriteLine("\nWiener attack: {0} ms", (DateTime.Now - start).TotalMilliseconds);
            if (d == null || e.CompareTo(d) != 0)
                Console.WriteLine("Wiener attack failed");
            else
                Console.WriteLine("Wiener attack success");
            #endregion
            
            #region Common module
            e1 = new BigInteger(bits / 2, certainty, rnd);
            e2 = e1.NextProbablePrime();
            Rsa rsa1 = new Rsa(e1, bits, certainty, rnd, false);
            Rsa rsa2 = new Rsa(e2);
            rsa2.GenerateKeys(rsa1.Params.p, rsa1.Params.q);
            c1 = rsa1.Encrypt(M);
            c2 = rsa2.Encrypt(M);

            start = DateTime.Now;
            m = CommonModuleAttack(e1, e2, rsa2.Params.n, c1, c2);
            Console.WriteLine("\nCommon module attack: {0} ms", (DateTime.Now - start).TotalMilliseconds);
            Console.WriteLine("Common module attack {0}", 
                (m.SignValue != 0 && m.CompareTo(M) == 0) ? "success" : "failed");
            #endregion
        }
    }
}
