using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Loopback
{
    public class LoopUtil
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_APP_CONTAINER
        {
            internal IntPtr appContainerSid;
            internal IntPtr userSid;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string appContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string displayName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string description;
            public INET_FIREWALL_AC_CAPABILITIES capabilities;
            public INET_FIREWALL_AC_BINARIES binaries;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string workingDirectory;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string packageFullName;

            public struct INET_FIREWALL_AC_CAPABILITIES
            {
                public uint count;
                public IntPtr capabilities;
            }

            public struct INET_FIREWALL_AC_BINARIES
            {
                public uint count;
                public IntPtr binaries;
            }
        }

        // Call this API to load the current list of LoopUtil-enabled AppContainers
        [DllImport("FirewallAPI.dll")]
        internal static extern uint NetworkIsolationGetAppContainerConfig(out uint pdwCntACs, out IntPtr appContainerSids);

        // Call this API to set the LoopUtil-exemption list 
        [DllImport("FirewallAPI.dll")]
        private static extern uint NetworkIsolationSetAppContainerConfig(uint pdwCntACs, SID_AND_ATTRIBUTES[] appContainerSids);

        // Use this API to convert a string SID into an actual SID 
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool ConvertStringSidToSid(string strSid, out IntPtr pSid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        // Call this API to enumerate all of the AppContainers on the system 
        [DllImport("FirewallAPI.dll")]
        internal static extern uint NetworkIsolationEnumAppContainers(uint Flags, out uint pdwCntPublicACs, out IntPtr ppACs);

        public class AppContainer
        {
            IntPtr Prt { get; set; }
            public String DisplayName { get; set; }
            public String StringSid { get; set; }
            public bool LoopUtil { get; set; }

            internal AppContainer(string displayName, IntPtr sid, IEnumerable<string> sids)
            {
                DisplayName = displayName;
                ConvertSidToStringSid(sid, out string tempSid);
                StringSid = tempSid;

                ConvertSidToStringSid(sid, out string right);
                LoopUtil = sids.Contains(right);
            }
        }

        public List<AppContainer> Apps = new List<AppContainer>();

        public LoopUtil()
        {
            LoadApps();
        }

        public void LoadApps()
        {
            Apps.Clear();

            NetworkIsolationEnumAppContainers(0x2, out uint size, out IntPtr arrayValue);
            var fullList = Base<INET_FIREWALL_APP_CONTAINER>(size, arrayValue);

            NetworkIsolationGetAppContainerConfig(out size, out arrayValue);
            var sids = Base<SID_AND_ATTRIBUTES>(size, arrayValue)
                .Select(x => { ConvertSidToStringSid(x.Sid, out string left); return left; });

            Apps.AddRange(fullList.Select(PI_app => new AppContainer(PI_app.displayName, PI_app.appContainerSid, sids)));
        }

        IEnumerable<T> Base<T>(uint size, IntPtr arrayValue)
        {
            var structSize = Marshal.SizeOf(typeof(T));
            for (var i = 0; i < size; i++, arrayValue += structSize)
            {
                yield return Marshal.PtrToStructure<T>(arrayValue);
            }
        }

        public bool SaveLoopbackState()
        {
            var arr = new List<SID_AND_ATTRIBUTES>(Apps.Where(x => x.LoopUtil)
                .Select(x => new SID_AND_ATTRIBUTES
                {
                    Attributes = 0,
                    Sid = Converter(x.StringSid)
                }));
            return NetworkIsolationSetAppContainerConfig((uint)arr.Count, arr.ToArray()) == 0;

            IntPtr Converter(string sid)
            {
                ConvertStringSidToSid(sid, out IntPtr ptr);
                return ptr;
            }
        }
    }
}
