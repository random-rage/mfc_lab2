using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab2
{
    static class Program
    {
        const int E = 65537;

        static void Main(string[] args)
        {
            Rsa hacked;

            #region Bad params
            Console.Write("=== Bad params attack ===\nEnter N to factorize: ");
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
            BigInteger e = new BigInteger(Console.ReadLine());
            Console.Write("Enter N: ");

            hacked = WienerAttack(e, new BigInteger(Console.ReadLine()));
            if (hacked.Params.d == null)
                Console.WriteLine("Wiener attack failed");
            else
                Console.WriteLine("Result:\nd = {0}", hacked.Params.d);
            #endregion

            Console.WriteLine("Done!");
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
    }
}
