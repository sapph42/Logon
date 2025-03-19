using System.Runtime.InteropServices;

#nullable enable
namespace EudLogger.Classes;
internal class HardwareStats {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public class MEMORYSTATUSEX {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
        public MEMORYSTATUSEX() {
            this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        }
    }

    [return: MarshalAs(UnmanagedType.Bool)]
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool GlobalMemoryStatusEx(
        [In, Out] MEMORYSTATUSEX lpBuffer
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetLogicalProcessorInformation(
        IntPtr Buffer,
        ref uint ReturnLength
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct CACHE_DESCRIPTOR {
        public byte Level;
        public byte Associativity;
        public ushort LineSize;
        public uint Size;
        public PROCESSOR_CACHE_TYPE Type;
    }

    public enum PROCESSOR_CACHE_TYPE {
        Unified = 0,
        Instruction = 1,
        Data = 2,
        Trace = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
        public UIntPtr ProcessorMask;
        public LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
        public ProcessorRelationUnion RelationUnion;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ProcessorRelationUnion {
        [FieldOffset(0)] public CACHE_DESCRIPTOR Cache;
        [FieldOffset(0)] public uint NumaNodeNumber;
        [FieldOffset(0)] public byte ProcessorCoreFlags;
        [FieldOffset(0)] private UInt64 Reserved1;
        [FieldOffset(8)] private UInt64 Reserved2;
    }

    public enum LOGICAL_PROCESSOR_RELATIONSHIP : uint {
        RelationProcessorCore    = 0,
        RelationNumaNode         = 1,
        RelationCache            = 2,
        RelationProcessorPackage = 3,
        RelationGroup            = 4,
        RelationAll              = 0xffff
    }

    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    public static SYSTEM_LOGICAL_PROCESSOR_INFORMATION[]? GetLogicalProcessorInformation() {
        uint ReturnLength = 0;
        GetLogicalProcessorInformation(IntPtr.Zero, ref ReturnLength);
        if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER) {
            IntPtr Ptr = Marshal.AllocHGlobal((int)ReturnLength);
            try {
                if (GetLogicalProcessorInformation(Ptr, ref ReturnLength)) {
                    int size = Marshal.SizeOf(typeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
                    int len = (int)ReturnLength / size;
                    SYSTEM_LOGICAL_PROCESSOR_INFORMATION[] Buffer = new SYSTEM_LOGICAL_PROCESSOR_INFORMATION[len];
                    IntPtr Item = Ptr;
                    for (int i = 0; i < len; i++) {
                        Buffer[i] = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION)Marshal.PtrToStructure(Item, typeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
                        Item = (IntPtr)(Item.ToInt64() + (long)size);
                    }
                    return Buffer;
                }
            } finally {
                Marshal.FreeHGlobal(Ptr);
            }
        }
        return null;
    }

    public static uint GetNumberOfSetBits(ulong value) {
        uint num = 0;
        while (value > 0) {
            if ((value & 1) == 1)
                num++;
            value >>= 1;
        }
        return num;
    }

    public static ulong GetTotalMem() {
        var memoryStatus = new MEMORYSTATUSEX();
        if (GlobalMemoryStatusEx(memoryStatus)) {
            return memoryStatus.ullTotalPhys;
        } else {
            return 0;
        }
    }

    [DllImport("kernel32")]
    extern static UInt64 GetTickCount64();

    public static TimeSpan GetUpTime() {
        return TimeSpan.FromMilliseconds(GetTickCount64());
    }
    [DllImport("tbs.dll", SetLastError = true)]
    private static extern int Tbsi_GetTpmVersionInfo(out TPMVersionInfo versionInfo);

    [StructLayout(LayoutKind.Sequential)]
    public struct TPMVersionInfo {
        public uint Major;
        public uint Minor;
        public uint Build;
        public uint Revision;
    }

    public static TPMVersionInfo GetTPMVersion() {
        int result = Tbsi_GetTpmVersionInfo(out TPMVersionInfo versionInfo);
        if (result != 0) {
            throw new Exception($"Failed to retrieve TPM version. Error code: {result}");
        }
        return versionInfo;
    }
}
