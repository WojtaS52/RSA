using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

/*
 * 
 * Autorzy: Wojciech Świderski 242551, Mateusz Rybicki 242518
 * Program: Implementacja RSA w C#
 * Przedmiot: Podstawy kryptografii
 * Rok: 2022/23, semestr 4
 * 
 */

namespace WpfApp3
{
    public class RSA
    {
        
        private BigInteger _p;
        private BigInteger _q;
        private BigInteger _n;
        private BigInteger _Euler;
        private BigInteger _e = 65537;
        private BigInteger _d;
        private int bitLength;

        public BigInteger N
        {
            get { return _n; }
        }

        public BigInteger E
        {
            get { return _e; }
        }

        public BigInteger D
        {
            get { return _d; }
        }

        public BigInteger Euler
        {
            get { return _Euler; }
        }

        public RSA(int bitLength)
        {
            this.bitLength = bitLength;
        }

        public void GenerateKeys()
        {
            Random random = new Random();
            _q = GenerateProbablePrime(bitLength, random);
            _p = GenerateProbablePrime(bitLength, random);
            _n = _p * _q;
            _Euler = (_p - BigInteger.One) * (_q - BigInteger.One);
            _d = EuclideanAlgorithmExtended(_e, _Euler);
        }
        //enkrypcja
        public BigInteger Encrypt(BigInteger message, BigInteger e, BigInteger n)
        {
            return BigInteger.ModPow(message, e, n);
        }
        //dekrypcja
        public BigInteger Decrypt(BigInteger cipher, BigInteger d, BigInteger n)
        {
            return BigInteger.ModPow(cipher, d, n);

        }
        //po nazwie chyba wiadomo co :>
        public static bool IsProbablePrime(BigInteger n, int k)
        {
            if (n <= 1 || n == 4)
                return false;
            if (n <= 3)
                return true;

            int s = 0;
            BigInteger d = n - 1;
            while (d % 2 == 0)
            {
                s++;
                d /= 2;
            }

            for (int i = 0; i < k; i++)
            {
                Random random = new Random();
                BigInteger a = RandomInRange(2, n - 2, random);
                BigInteger x = BigInteger.ModPow(a, d, n);

                if (x == 1 || x == n - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == 1)
                        return false;
                    if (x == n - 1)
                        break;
                }

                if (x != n - 1)
                    return false;
            }

            return true;
        }

        public static BigInteger RandomInRange(BigInteger min, BigInteger max, Random random)
        {
            byte[] maxBytes = max.ToByteArray();
            byte[] minBytes = min.ToByteArray();

         

            int maxLength = maxBytes.Length;
            byte[] randomBytes = new byte[maxLength];

            random.NextBytes(randomBytes);

            BigInteger randomNumber = new BigInteger(randomBytes);

            // ensure the random number is within the range [min, max]
            BigInteger diff = max - min;
            BigInteger randomValueInRange = (randomNumber % diff) + min;

            return randomValueInRange;
        }

        //generowanie liczb pierwszych
        public static BigInteger GenerateProbablePrime(int bitLength, Random random)
        {
            while (true)
            {
                BigInteger prime = GenerateRandom(bitLength, random);
                if (prime.IsEven)
                {
                    prime += 1;
                }
                if (IsProbablePrime(prime,10))
                {
                    return prime;
                }
            }
        }
        public static BigInteger GenerateRandom(int bitLength, Random random)
        {
            byte[] bytes = new byte[bitLength / 8 + 1];
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= 0x7F; // ensure highest bit is 0 to make positive
            return new BigInteger(bytes);
        }
        //rozszerzony algorytm euklidesa
        public static BigInteger EuclideanAlgorithmExtended(BigInteger a, BigInteger b)
        {
            BigInteger u = BigInteger.One, w = a, x = BigInteger.Zero, z = b, q, tmp;
            while (w != BigInteger.Zero)
            {
                if (w < z)
                {
                    tmp = u;
                    u = x;
                    x = tmp;

                    tmp = w;
                    w = z;
                    z = tmp;
                }
                q = w / z;
                u -= q * x;
                w -= q * z;
            }
            if (z == BigInteger.One)
            {
                if (x < BigInteger.Zero)
                {
                    x += b;
                }
                return x;
            }
            return x;
        }

        //nwd jest w biginteger ale jakos dziwnie dzialał
        public static BigInteger EuclideanAlgorithm(BigInteger a, BigInteger b)
        {
            BigInteger tmp;
            while (b != BigInteger.Zero)
            {
                tmp = a % b;
                a = b;
                b = tmp;
            }
            return a;
        }

        public static bool IsPrime(BigInteger a, BigInteger b)
        {
            return EuclideanAlgorithm(a, b) == BigInteger.One;
        }

        public static BigInteger GenerateCoprimeNumber(BigInteger max)
        {
            BigInteger tmp = max / 3;
            while (!IsPrime(max, tmp))
            {
                tmp++;
            }
            return tmp;
        }



        // zero padding to 16 bytes 
        public byte[] zeroPadding(byte[] array)
        {
            int pom = (array.Length) % 16;
            int lastN = pom;

            if (lastN == 0)
            {
                return array;
            }

            int temp = array.Length;
            int addedBytes = 16 - lastN;
            byte[] completedArray = new byte[addedBytes + temp];

            System.Array.Copy(array, 0, completedArray, 0, temp);

            completedArray[temp] = (byte)0xFF; // 0xFF is maximum size of bytes

            for (int i = temp + 1; i < (addedBytes + array.Length); i++)
            {
                completedArray[i] = (byte)0x00;

            }

            return completedArray;
        }
        // remove adding zeros
        // array to nasza ta tablica
        public byte[] removeAddedZeros(byte[] array)
        {
            int digit0 = 0;


            int len = array.Length - 1;
            int i = len;
            int condition = array.Length - 16;

            //idziemy jakby od przedostatniego bajtu bo na ostatnim jest ta liczba tych 0 
            while (i >= condition)
            {

                if (array[i] == 0)
                {
                    digit0 += 1; // inkremetnacja
                }
                else if (array[i] != 0)
                {
                    break;
                }
                i--; // deikrementacja

            }

            if (digit0 != 0 || array[len] == (byte)0xFF)
            {
                digit0 = digit0 + 1;
            }

            byte[] firstForm = new byte[len - digit0 + 1];


            for (int j = 0; j < len - digit0 + 1; j++)
            {
                firstForm[j] = array[j];


            }

            return firstForm;
        }

        //dajemy dane do bloków i dodajemy 1 zeby biginteger tego nie usunał
        public byte[] getDataFromBlock(byte[] array, int digit)
        {
            byte[] new_tab = new byte[17];
            new_tab[16] = 1;
            int i = 0;

            while (i < 16)
            {
                new_tab[i] = array[16 * digit + i];
                i += 1;
            }

            return new_tab;
        }
        // odczytujemy dane z bloków, plus odejmujemy nasza 1
        public byte[] readDataFromBlock(byte[] array, int digit)
        {
            byte[] new_tab = new byte[16];
            int i = 0;

            while (i < 16)
            {
                new_tab[i] = array[17 * digit + i];
                i += 1;
            }

            return new_tab;
        }

        public void filesWrite(string path, List<BigInteger> buff)
        {
            //if (!File.Exists(path))
            {
                // Create a file to write to.
                using (StreamWriter sw = File.CreateText(path))
                {
                    for(int i = 0; i < buff.Count; i++)
                    {
                        sw.WriteLine(buff[i].ToString());
                    }
                }
            }
        }

        public void filesWrite(string path, string messege)
        {
             // Create a file to write to.
             using (StreamWriter sw = File.CreateText(path))
             {
                 sw.WriteLine(messege);
             }
        }

        public List<string> filesRead(string path)
        {
            List<string> list = new List<string>();
            // Open the file to read from.
            using (StreamReader sr = File.OpenText(path))
            {
                string s;
                while ((s = sr.ReadLine()) != null)
                {
                    list.Add(s);
                }
            }
            return list;
        }

        public List<BigInteger> StringToBigIntConversion(List<string> list)
        {
            List<BigInteger> cipher = new List<BigInteger>();
            for(int i=0; i < list.Count; i++)
            {
                cipher.Add(BigInteger.Parse(list[i]));
            }
            return cipher;
        }
    }
}
