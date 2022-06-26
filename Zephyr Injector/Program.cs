using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel;







public class BasicInject
{
    public static string dllName = "not";

    
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    // privileges
    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    // used for memory allocation
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;

    public static int Main()



    {

        //Opening Minecraft

        Console.Title = "DLL Injector for Minecraft";
        if (File.Exists("dllPath.txt"))
        {
            Console.WriteLine("Starting Minecraft");
            var process = new Process();
            var startInfo = new ProcessStartInfo
            {
                WindowStyle = ProcessWindowStyle.Normal,
                FileName = "explorer.exe",
                Arguments = "shell:appsFolder\\Microsoft.MinecraftUWP_8wekyb3d8bbwe!App",
            };
            process.StartInfo = startInfo;
            process.Start();
            Console.WriteLine("Waiting to Minecraft can be Injectable");
            Thread.Sleep(50000);
            Console.WriteLine("Injecting...");
        }


        try
        {


            dllName = File.ReadAllText("dllPath.txt");
        }
        catch
        {
            File.WriteAllText("dllPath.txt", "Remove this text and put your dll path <<<<<");
            File.WriteAllText("temp.bat", "@echo off & echo This Window will be closed when you exit from the notepad & title You can close this window & dllPath.txt");
            Process.Start("temp.bat");
            Thread.Sleep(1000);
            File.Delete("temp.bat");
            
            Environment.Exit(0);
        }


        // the target process - I'm using a dummy process for this
        // if you don't have one, open Task Manager and choose wisely

        Process targetProcess = Process.GetProcessesByName("Minecraft.Windows")[0];
        

        // geting the handle of the process - with required privileges
        IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

        // searching for the address of LoadLibraryA and storing it in a pointer
        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

        // name of the dll we want to inject
        

        // alocating some memory on the target process - enough to store the name of the dll
        // and storing its address in a pointer
        IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        // writing the name of the dll there
        UIntPtr bytesWritten;
        WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

        // creating a thread that will call LoadLibraryA with allocMemAddress as argument
        CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        Console.WriteLine("Injected!");
        
        return 0;
    }
    
}