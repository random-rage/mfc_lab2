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
        const int KEY_SIZE = 2048;
        const int CERTAINTY = 200;
        const int SEED = 1635901897;

        static void Main(string[] args)
        {
            Console.Write("Enter N to factorize: ");
            Rsa hacked = FactorizationAttack(E, ulong.Parse(Console.ReadLine()).ToBigInt());
            Console.WriteLine("Factorization result:\np = {0}\nq = {1}", 
                              hacked.Params.p, hacked.Params.q);



            Console.WriteLine("Done!");
            Console.ReadKey();
        }

        public static BigInteger ToBigInt(this ulong n)
        {
            return new BigInteger(1, BitConverter.GetBytes(n).Reverse().ToArray());
        }

        public static BigInteger Sqrt(this BigInteger n)
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

        static Rsa FactorizationAttack(int e, BigInteger n)
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
    }
}
