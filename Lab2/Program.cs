using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;

namespace Lab2
{
    static class Program
    {
        const int E = 65537;

        static void Main(string[] args)
        {
            BigInteger e, n, m;
            Rsa hacked;
            
            #region Factorization
            Console.Write("=== Factorization attack ===\nEnter N to factorize: ");
            hacked = FactorizationAttack
                (
                    BigInteger.ValueOf(E),
                    new BigInteger(Console.ReadLine())
                );
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
            
            #region Shared module
            Console.Write("\n=== Shared module attack ===\nEnter E1: ");
            e = new BigInteger(Console.ReadLine());
            Console.Write("Enter E2: ");
            BigInteger e2 = new BigInteger(Console.ReadLine());
            Console.Write("Enter N: ");
            n = new BigInteger(Console.ReadLine());
            Console.Write("Enter C1: ");
            BigInteger c = new BigInteger(Console.ReadLine());
            Console.Write("Enter C2: ");

            m = SharedModuleAttack(e, e2, n, c, new BigInteger(Console.ReadLine()));
            if (m.SignValue == 0)
                Console.WriteLine("Shared module attack failed, GCD(e1, e2) != 1");
            else
                Console.WriteLine("Result:\nm = {0}", m);
            #endregion

            Console.WriteLine("\nDone!");
            Console.ReadKey();
        }

        // Вычисляет квадратный корень по методу Ньютона
        static BigInteger Sqrt(this BigInteger n)
        {
            BigInteger G = n.ShiftRight((n.BitLength + 1) / 2);
            BigInteger LastG;
            int i;

            while (true)
            {
                LastG = G;
                G = n.Divide(G).Add(G).ShiftRight(1);
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
            BigInteger t = n.Sqrt();            // Предположение t[i]
            double root;                        // Корень для проверки на полный квадрат

            do
            {
                t = t.Add(BigInteger.One);
                //            ___________
                // Вычисляем √ t[i]^2 - n
                root = Math.Sqrt(double.Parse(t.Square().Subtract(n).ToString()));
            }
            while (root - Math.Truncate(root) > double.Epsilon);

            BigInteger delta = BigInteger.ValueOf((int)root);

            Rsa rsa = new Rsa(e);
            rsa.GenerateKeys(t.Add(delta), t.Subtract(delta));
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
            BigInteger maxD = n.Sqrt().Sqrt().Divide(BigInteger.Three);

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

        static BigInteger SharedModuleAttack(BigInteger e1, BigInteger e2, 
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
    }
}
