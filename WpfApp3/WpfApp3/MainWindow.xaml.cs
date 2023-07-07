using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using static System.Runtime.InteropServices.JavaScript.JSType;


namespace WpfApp3
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        List<BigInteger> buff = new List<BigInteger>();
        List<byte> buffor = new List<byte>();
        List<byte> bufforCompare = new List<byte>();
        List<byte> checkEncrypt = new List<byte>();
        List<byte> checkDecrypt = new List<byte>();
        List<byte[]> checkBlocks = new List<byte[]>();
        List<byte[]> resultToByteArrayCheck = new List<byte[]>();
        List<byte[]> resultToByteArrayCheckDECRYPT = new List<byte[]>();
        List<byte[]> checkChunkz = new List<byte[]>();

        public bool isFile = false;
        public int keySize = 256;
        //BigInteger[] buffer;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void RadioButton_Checked(object sender, RoutedEventArgs e)
        {

        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {

             
           RSA log = new RSA(keySize);
           log.GenerateKeys();
           nPrivate.Text = log.N.ToString();
           nPublic.Text = log.N.ToString();
           ePrivate.Text = log.E.ToString();
           dPublic.Text = log.D.ToString();
            

          
        }
        //enkrypcja
        private void encrypt_btn_Click(object sender, RoutedEventArgs e)
        {


            buff.Clear();
            string nKey = nPublic.Text;
            string eKey = ePrivate.Text;
            BigInteger BiPublicN = BigInteger.Parse(nKey);
            BigInteger BiPrivateE = BigInteger.Parse(eKey);

            RSA log = new RSA(keySize);

            // new
            DecryptTextBox.Text = "";
            byte[] data;
            BigInteger result = new BigInteger(0);
            if(isFile)
            {
                data = buffor.ToArray();
            }
            else
            {
                data = Encoding.UTF8.GetBytes(EncryptTextBox.Text);
            }
            //data = Encoding.UTF8.GetBytes(EncryptTextBox.Text);
            data = log.zeroPadding(data);

            string helper = "";
            for(int i =0; i < data.Length / 16; i++)
            {
                byte[] block = log.getDataFromBlock(data, i);
                checkBlocks.Add(block);
                BigInteger toCipher = new BigInteger(block);
                result = log.Encrypt(toCipher, BiPrivateE, BiPublicN);
                resultToByteArrayCheck.Add(result.ToByteArray());
                checkEncrypt.AddRange(result.ToByteArray());
                buff.Add(result);
                helper += result.ToString();
                helper += 0x255;
            }
            log.filesWrite("buff.txt", buff);
            DecryptTextBox.Text = helper;
            //byte[] byt = StringToByteArray(helper);
        }

        //dekrypcja
        private void decrypt_btn_Click(object sender, RoutedEventArgs e)
        {
            buffor.Clear();
            EncryptTextBox.Text = ""; 
            RSA log = new RSA(keySize);

            if(buff.Count <= 0)
            {
                buff = log.StringToBigIntConversion(log.filesRead("buff.txt"));
            }

            BigInteger cipher;

            // get n public and d public keys and convert it into BigInteger
            string nKey = nPrivate.Text;
            string dKey = dPublic.Text;
            BigInteger BiPrivateN = BigInteger.Parse(nKey);
            BigInteger BiPublicD = BigInteger.Parse(dKey);

            BigInteger decryptedCipher;
            string helper = "";
            for (int j = 0; j<buff.Count; j++)
            {   
                cipher = buff[j];
                checkDecrypt.AddRange(buff[j].ToByteArray());
                decryptedCipher = log.Decrypt(cipher, BiPublicD, BiPrivateN);
                resultToByteArrayCheckDECRYPT.Add(decryptedCipher.ToByteArray());
                //byte[] bytes = Convert.FromHexString(decryptedCipher.ToString().Replace("-", ""));
                byte[] bytes = decryptedCipher.ToByteArray();
                    bool flag = false;
                    if (bytes.Length < 17)
                    {
                        bytes = log.zeroPadding(bytes);
                        byte[] bytes2 = new byte[17];
                        for (int i = 0; i < bytes.Length; i++)
                        {
                            bytes2[i] = bytes[i];
                        }
                        bytes2[16] = 0x00;
                        bytes = bytes2;
                        flag = true;
                    }
                    
                    byte[] chunk;
                    for (int i = 0; i < bytes.Length / 17; i++)
                    {
                        chunk = log.readDataFromBlock(bytes, i);
                        checkChunkz.Add(chunk);
                    if (flag)
                        {
                            chunk = log.removeAddedZeros(chunk);
                        }
                    //buffor.AddRange(chunk);
                    //EncryptTextBox.Text += Encoding.UTF8.GetString(chunk);
                    string converting = BitConverter.ToString(chunk).Replace("-","");
                    helper += converting;
                }             
            }
            byte[] readText = Convert.FromHexString(helper);
            readText = log.removeAddedZeros(readText);
            buffor.AddRange(readText);
            EncryptTextBox.Text += Encoding.UTF8.GetString(readText);
        }
        static string BytesToStringConverted(byte[] bytes)
        {
            using (var stream = new MemoryStream(bytes))
            {
                using (var streamReader = new StreamReader(stream))
                {
                    return streamReader.ReadToEnd();
                }
            }
        }

        public static string ConvertHex(System.String hexString)
        {
            try
            {
                string ascii = string.Empty;

                for (int i = 0; i < hexString.Length; i += 2)
                {
                    System.String hs = string.Empty;

                    hs = hexString.Substring(i, 2);
                    uint decval = System.Convert.ToUInt32(hs, 16);
                    char character = System.Convert.ToChar(decval);
                    ascii += character;

                }

                return ascii;
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }

            return string.Empty;
        }

        public static byte[] StringToByteArray(System.String hex)
        {
            int NumberChars = hex.Length / 2;
            byte[] bytes = new byte[NumberChars];
            using (var sr = new StringReader(hex))
            {
                for (int i = 0; i < NumberChars; i++)
                    bytes[i] =
                      Convert.ToByte(new string(new char[2] { (char)sr.Read(), (char)sr.Read() }), 16);
            }
            return bytes;
        }

        private void SaveToFileEncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            for(int i=0; i<buffor.Count; i++)
            {
                if(bufforCompare.Count> 0)
                {
                    if (buffor[i] != bufforCompare[i])
                    {
                        byte error1 = buffor[i];
                        byte error2 = bufforCompare[i];
                        return;
                    }
                }
            }
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            if (saveFileDialog.ShowDialog() == true)
            {
                byte[] bytes = buffor.ToArray();

                //byte[] bytes = Encoding.UTF8.GetBytes(EncryptTextBox.Text);
                File.WriteAllBytes(saveFileDialog.FileName, bytes);

            }
        }

        private void SaveDecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(DecryptTextBox.Text);
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            if (saveFileDialog.ShowDialog() == true)
            {
                File.WriteAllBytes(saveFileDialog.FileName, bytes);
            }
        }

        /*
         * 
         * Autorzy: Wojciech Świderski 242551, Mateusz Rybicki 242518
         * Program: Implementacja RSA w C#
         * Przedmiot: Podstawy kryptografii
         * Rok: 2022/23, semestr 4
         * 
         */


        private void LoadEncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                byte[] cos = File.ReadAllBytes(ofd.FileName);
                buffor.AddRange(cos);
                bufforCompare.AddRange(cos);
                EncryptTextBox.Text = Encoding.UTF8.GetString(cos);
            }
        }

        private void LoadDecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                byte[] cos = File.ReadAllBytes(ofd.FileName);
                DecryptTextBox.Text = BitConverter.ToString(cos).Replace("-", "");
                //DecryptTextBox.Text = Encoding.UTF8.GetString(cos);
            }
        }



        //wybor dlugosci klucza
        private void radio_128bit_Checked(object sender, RoutedEventArgs e)
        {
            keySize = 1024;
        }

        private void radio256bit_Checked(object sender, RoutedEventArgs e)
        {
            keySize = 256;
        }

        private void radio_512bit_Checked(object sender, RoutedEventArgs e)
        {
            keySize = 512;
        }
        //wybor czy plik czy text
        private void text_radio_btn_Checked(object sender, RoutedEventArgs e)
        {

            isFile = false;
        }

        private void file_radio_btn_Checked(object sender, RoutedEventArgs e)
        {
            buffor.Clear();
            isFile = true;
        }
    }


}
