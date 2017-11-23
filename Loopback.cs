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
        internal struct INET_FIREWALL_AC_CAPABILITIES
        {
            public uint count;
            public IntPtr capabilities; //SID_AND_ATTRIBUTES
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_AC_BINARIES
        {
            public uint count;
            public IntPtr binaries;
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
            internal INET_FIREWALL_AC_CAPABILITIES capabilities;
            internal INET_FIREWALL_AC_BINARIES binaries;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string workingDirectory;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string packageFullName;
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
            public String DisplayName { get; set; }
            public String StringSid { get; set; }
            public bool LoopUtil { get; set; }

            internal AppContainer(INET_FIREWALL_APP_CONTAINER PI_app, List<SID_AND_ATTRIBUTES> _AppListEnabled)
            {
                DisplayName = PI_app.displayName;
                ConvertSidToStringSid(PI_app.appContainerSid, out string tempSid);
                StringSid = tempSid;

                ConvertSidToStringSid(PI_app.appContainerSid, out string right);
                LoopUtil = _AppListEnabled.Count(x => Convert(x) == right) > 0;

                string Convert(SID_AND_ATTRIBUTES sid)
                {
                    ConvertSidToStringSid(sid.Sid, out string left);
                    return left;
                }
            }
        }

        internal List<INET_FIREWALL_APP_CONTAINER> AppListFull;
        public List<AppContainer> Apps = new List<AppContainer>();

        public LoopUtil()
        {
            LoadApps();
        }

        public void LoadApps()
        {
            Apps.Clear();

            IntPtr arrayValue = IntPtr.Zero;
            NetworkIsolationEnumAppContainers(0x2, out uint size, out arrayValue);
            AppListFull = Base<INET_FIREWALL_APP_CONTAINER>(size, arrayValue);

            arrayValue = IntPtr.Zero;
            NetworkIsolationGetAppContainerConfig(out size, out arrayValue);
            var appListEnabled = Base<SID_AND_ATTRIBUTES>(size, arrayValue);

            Apps.AddRange(AppListFull.Select(PI_app => new AppContainer(PI_app, appListEnabled)));
        }

        List<T> Base<T>(uint size, IntPtr arrayValue)
        {
            var list = new List<T>();
            var structSize = Marshal.SizeOf(typeof(T));
            for (var i = 0; i < size; i++)
            {
                var cur = (T)Marshal.PtrToStructure(arrayValue, typeof(T));
                list.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + structSize);
            }
            return list;
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
