REQUIRES C++20

Process::
    - Open a process by process id, process name, or window name.
    - Read an object from memory.
    - Read an array from memory.
    - Reads to protected memory.
    - Write an object to memory.
    - Write an array to memory.
    - Writes to protected memory.
    - Simple DLL using GetProcAddress and CreateRemoteThread.
TODO:  
    - Add some error info.

Image:: (adapted from https://www.x86matthew.com/view_post?id=add_exe_import)
    - Add DLL imports to EXE files.
TODO:
    - Split data members into structs, crowding the class at the moment.
    - Get data from loaded image.



https://what-when-how.com/windows-forensic-analysis/executable-file-analysis-windows-forensic-analysis-part-2/
https://learn.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN