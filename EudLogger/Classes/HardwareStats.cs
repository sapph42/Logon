using System.Runtime.InteropServices;
using System.Runtime.Remoting.Contexts;
using Microsoft.Extensions.Logging;

#nullable enable
namespace SapphTools.Logging.Classes;
internal class HardwareStats {
#pragma warning disable IDE0044 // Suppress Add readonly modifier for unmanaged code
    #region P/Invoke Helper Classes, Structs, Enums and Consts

    private const int ERROR_INSUFFICIENT_BUFFER = 122;

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

    [StructLayout(LayoutKind.Sequential)]
    public struct TPMVersionInfo {
        public uint Major;
        public uint Minor;
        public uint Build;
        public uint Revision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TbsContextParams {
        public uint version;
        public uint flags;
    }
    public enum LOGICAL_PROCESSOR_RELATIONSHIP : uint {
        RelationProcessorCore = 0,
        RelationNumaNode = 1,
        RelationCache = 2,
        RelationProcessorPackage = 3,
        RelationGroup = 4,
        RelationAll = 0xffff
    }
    #endregion
    #region P/Invoke Methods
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

    [DllImport("kernel32")]
    extern static UInt64 GetTickCount64();

    [DllImport("tbs.dll", SetLastError = true)]
    private static extern int Tbsip_Submit_Command(
        IntPtr context,          // TBS context handle
        uint locality,           // TPM locality (0 for default)
        uint priority,           // Command priority
        byte[] commandBuffer,    // TPM command to send
        uint commandBufferLength,
        byte[] responseBuffer,   // Buffer for TPM response
        ref uint responseBufferLength
    );

    [DllImport("tbs.dll", SetLastError = true)]
    private static extern int Tbsi_Context_Create(
        ref TbsContextParams contextParams,
        out IntPtr context
    );

    [DllImport("tbs.dll", SetLastError = true)]
    private static extern int Tbsip_Context_Close(IntPtr context);
    #endregion
#pragma warning restore IDE0044 // Add readonly modifier
    #region P/Invoke Wrappers
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
    public static TimeSpan GetUpTime() {
        return TimeSpan.FromMilliseconds(GetTickCount64());
    }
    private static IntPtr CreateTbsContext() {
        var contextParams = new TbsContextParams { version = 1, flags = 0 };
        IntPtr context;

        int result = Tbsi_Context_Create(ref contextParams, out context);

        return context;
    }
    public static string? GetTPMVersion(ILogger Logger) {
        //This magic number is the command to retrieve TPMVersion info encoding in TPMCommand format
        IntPtr context = IntPtr.Zero;
        try {
            byte[] getVersionCommand = new byte[] { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x00 };

            byte[] responseBuffer = new byte[64];
            uint responseBufferLength = (uint)responseBuffer.Length;

            context = CreateTbsContext();

            int result = Tbsip_Submit_Command(
                context,
                0,  // Locality
                1,  // Priority
                getVersionCommand,
                (uint)getVersionCommand.Length,
                responseBuffer,
                ref responseBufferLength
            );

            if (result != 0) {
                Logger.Log(LogLevel.Error, $"Failed to retrieve TPM version. Result: {result}");
                return null;
            }

            Array.Resize(ref responseBuffer, (int)responseBufferLength);

            if (responseBuffer.Length < 10) {
                Logger.Log(LogLevel.Error, $"Failed to retrieve TPM version. Response buffer too short.");
                return null;
            }

            uint firmwareMajor = BitConverter.ToUInt16(responseBuffer, 8);
            uint firmwareMinor = BitConverter.ToUInt16(responseBuffer, 10);

            string version = $"{firmwareMajor}.{firmwareMinor}";
            Logger.Log(LogLevel.Information, new EventId(), $"GetTPMVersion: TPMVer: {version}", null, (message, exception) => "");
            return version;
        } catch (Exception ex) {
            Logger.Log(LogLevel.Debug, "Failed to retrieve TPM version.", ex);
            return null;
        } finally {
            Tbsip_Context_Close(context);
        }
    }
    #endregion
}
