using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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

        // Call this API to free the memory returned by the Enumeration API 
        [DllImport("FirewallAPI.dll")]
        internal static extern void NetworkIsolationFreeAppContainers(IntPtr pACs);

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
        static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
            out IntPtr ptrSid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        // Use this API to convert a string reference (e.g. "@{blah.pri?ms-resource://whatever}") into a plain string 
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf);

        // Call this API to enumerate all of the AppContainers on the system 
        [DllImport("FirewallAPI.dll")]
        internal static extern uint NetworkIsolationEnumAppContainers(uint Flags, out uint pdwCntPublicACs, out IntPtr ppACs);

        //http://msdn.microsoft.com/en-gb/library/windows/desktop/hh968116.aspx
        enum NETISO_FLAG
        {
            NETISO_FLAG_FORCE_COMPUTE_BINARIES = 0x1,
            NETISO_FLAG_MAX = 0x2
        }

        public class AppContainer
        {
            public String AppContainerName { get; set; }
            public String DisplayName { get; set; }
            public String WorkingDirectory { get; set; }
            public String StringSid { get; set; }
            public List<uint> Capabilities { get; set; }
            public bool LoopUtil { get; set; }

            public AppContainer(String _appContainerName, String _displayName, String _workingDirectory, IntPtr _sid)
            {
                AppContainerName = _appContainerName;
                DisplayName = _displayName;
                WorkingDirectory = _workingDirectory;
                ConvertSidToStringSid(_sid, out string tempSid);
                StringSid = tempSid;
            }
        }

        internal List<INET_FIREWALL_APP_CONTAINER> _AppListFull;
        internal List<SID_AND_ATTRIBUTES> _AppListEnabled;
        public List<AppContainer> Apps = new List<AppContainer>();
        internal IntPtr _pACs;

        public LoopUtil()
        {
            LoadApps();
        }

        public void LoadApps()
        {
            Apps.Clear();
            _pACs = IntPtr.Zero;
            _AppListFull = PI_NetworkIsolationEnumAppContainers();
            _AppListEnabled = PI_NetworkIsolationGetAppContainerConfig();
            foreach (var PI_app in _AppListFull)
            {
                AppContainer app = new AppContainer(PI_app.appContainerName, PI_app.displayName, PI_app.workingDirectory, PI_app.appContainerSid);

                var app_capabilities = GetCapabilites(PI_app.capabilities);
                if (app_capabilities.Count > 0)
                {
                    IntPtr arrayValue = IntPtr.Zero;
                }
                app.LoopUtil = CheckLoopback(PI_app.appContainerSid);
                Apps.Add(app);
            }
        }

        private bool CheckLoopback(IntPtr intPtr)
        {
            foreach (SID_AND_ATTRIBUTES item in _AppListEnabled)
            {
                ConvertSidToStringSid(item.Sid, out string left);
                ConvertSidToStringSid(intPtr, out string right);

                if (left == right)
                {
                    return true;
                }
            }
            return false;
        }

        private static List<SID_AND_ATTRIBUTES> GetCapabilites(INET_FIREWALL_AC_CAPABILITIES cap)
        {
            List<SID_AND_ATTRIBUTES> mycap = new List<SID_AND_ATTRIBUTES>();
            IntPtr arrayValue = cap.capabilities;

            var structSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (var i = 0; i < cap.count; i++)
            {
                var cur = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(arrayValue, typeof(SID_AND_ATTRIBUTES));
                mycap.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + structSize);
            }

            return mycap;
        }

        private static List<SID_AND_ATTRIBUTES> PI_NetworkIsolationGetAppContainerConfig()
        {
            IntPtr arrayValue = IntPtr.Zero;
            uint size = 0;
            var list = new List<SID_AND_ATTRIBUTES>();

            // Pin down variables
            GCHandle handle_pdwCntPublicACs = GCHandle.Alloc(size, GCHandleType.Pinned);
            GCHandle handle_ppACs = GCHandle.Alloc(arrayValue, GCHandleType.Pinned);

            uint retval = NetworkIsolationGetAppContainerConfig(out size, out arrayValue);

            var structSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (var i = 0; i < size; i++)
            {
                var cur = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(arrayValue, typeof(SID_AND_ATTRIBUTES));
                list.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + structSize);
            }

            //release pinned variables.
            handle_pdwCntPublicACs.Free();
            handle_ppACs.Free();

            return list;
        }

        private List<INET_FIREWALL_APP_CONTAINER> PI_NetworkIsolationEnumAppContainers()
        {
            IntPtr arrayValue = IntPtr.Zero;
            uint size = 0;
            var list = new List<INET_FIREWALL_APP_CONTAINER>();

            // Pin down variables
            GCHandle handle_pdwCntPublicACs = GCHandle.Alloc(size, GCHandleType.Pinned);
            GCHandle handle_ppACs = GCHandle.Alloc(arrayValue, GCHandleType.Pinned);

            uint retval = NetworkIsolationEnumAppContainers((Int32)NETISO_FLAG.NETISO_FLAG_MAX, out size, out arrayValue);
            _pACs = arrayValue; //store the pointer so it can be freed when we close the form

            var structSize = Marshal.SizeOf(typeof(INET_FIREWALL_APP_CONTAINER));
            for (var i = 0; i < size; i++)
            {
                var cur = (INET_FIREWALL_APP_CONTAINER)Marshal.PtrToStructure(arrayValue, typeof(INET_FIREWALL_APP_CONTAINER));
                list.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + structSize);
            }

            //release pinned variables.
            handle_pdwCntPublicACs.Free();
            handle_ppACs.Free();

            return list;
        }

        public bool SaveLoopbackState()
        {
            var countEnabled = Apps.Count(x => x.LoopUtil);
            SID_AND_ATTRIBUTES[] arr = new SID_AND_ATTRIBUTES[countEnabled];
            int count = 0;

            for (int i = 0; i < Apps.Count; i++)
            {
                if (Apps[i].LoopUtil)
                {
                    arr[count].Attributes = 0;
                    ConvertStringSidToSid(Apps[i].StringSid, out IntPtr ptr);
                    arr[count].Sid = ptr;
                    count++;
                }
            }

            return NetworkIsolationSetAppContainerConfig((uint)countEnabled, arr) == 0;
        }

        public void FreeResources()
        {
            NetworkIsolationFreeAppContainers(_pACs);
        }
    }
}
