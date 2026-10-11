using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ElectionGuard.Verifier.UnitTests;

/// <summary>
/// Starts a process on Windows with DETACHED_PROCESS, so that it has no console at all, with its
/// standard output and error redirected to pipes: the situation of a program started from Git Bash or
/// a service, where Console.OutputEncoding cannot be set (S10b-E review round 3).
/// <see cref="System.Diagnostics.Process"/> cannot do this: CreateNoWindow still gives the child a
/// console of its own, only without a window.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class DetachedProcess
{
    private const int DetachedProcessFlag = 0x00000008;
    private const int StartfUseStdHandles = 0x00000100;
    private const int HandleFlagInherit = 0x00000001;
    private const uint Infinite = 0xFFFFFFFF;
    private const uint WaitTimeout = 0x00000102;

    /// <summary>Runs <paramref name="file"/> with <paramref name="arguments"/>; returns its exit code, standard output bytes and standard error text.</summary>
    public static (int ExitCode, byte[] Output, string Error) Run(string file, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        var inherit = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), InheritHandle = 1 };
        Check(CreatePipe(out var outRead, out var outWrite, ref inherit, 0));
        Check(CreatePipe(out var errRead, out var errWrite, ref inherit, 0));
        using (outRead)
        using (errRead)
        {
            // The parent's ends must not be inherited, or the pipes never reach end of file.
            Check(SetHandleInformation(outRead, HandleFlagInherit, 0));
            Check(SetHandleInformation(errRead, HandleFlagInherit, 0));

            var startup = new StartupInfo
            {
                Size = Marshal.SizeOf<StartupInfo>(),
                Flags = StartfUseStdHandles,
                StdInput = IntPtr.Zero,
                StdOutput = outWrite.DangerousGetHandle(),
                StdError = errWrite.DangerousGetHandle(),
            };

            var commandLine = new StringBuilder(string.Join(" ", new[] { file }.Concat(arguments).Select(Quote)));
            bool started = CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, DetachedProcessFlag, IntPtr.Zero, null, ref startup, out var info);
            int startError = Marshal.GetLastWin32Error();

            // The child holds its own copies of the write ends now.
            outWrite.Dispose();
            errWrite.Dispose();
            if (!started)
            {
                throw new Win32Exception(startError, $"CreateProcess failed for {file}.");
            }

            try
            {
                var output = Task.Run(() => ReadAll(outRead));
                var error = Task.Run(() => Encoding.UTF8.GetString(ReadAll(errRead)));
                uint waited = WaitForSingleObject(info.Process, timeout == Timeout.InfiniteTimeSpan ? Infinite : (uint)timeout.TotalMilliseconds);
                if (waited == WaitTimeout)
                {
                    TerminateProcess(info.Process, 1);
                    throw new TimeoutException($"{file} did not exit within {timeout}.");
                }

                Check(GetExitCodeProcess(info.Process, out int exitCode));
                return (exitCode, output.GetAwaiter().GetResult(), error.GetAwaiter().GetResult());
            }
            finally
            {
                CloseHandle(info.Process);
                CloseHandle(info.Thread);
            }
        }
    }

    private static byte[] ReadAll(SafeFileHandle handle)
    {
        using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>Quotes one argument by the rules CommandLineToArgvW reads (backslashes doubled before a quote).</summary>
    private static string Quote(string argument)
    {
        var quoted = new StringBuilder("\"");
        int backslashes = 0;
        foreach (char c in argument)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }

            quoted.Append('\\', c == '"' ? 2 * backslashes + 1 : backslashes);
            backslashes = 0;
            quoted.Append(c);
        }

        return quoted.Append('\\', 2 * backslashes).Append('"').ToString();
    }

    private static void Check(bool succeeded)
    {
        if (!succeeded)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2Size;
        public IntPtr Reserved2;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public int ProcessId;
        public int ThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle readPipe, out SafeFileHandle writePipe, ref SecurityAttributes attributes, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, int mask, int flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string? applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, int creationFlags, IntPtr environment, string? currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out int exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, int exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
