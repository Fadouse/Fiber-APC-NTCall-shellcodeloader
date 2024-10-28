# FiberAPCNTshellcodeloader

fiberAPCNTshellcodeloader is a C++ project designed to load and execute shellcode using APC (Asynchronous Procedure Call) injection. This project demonstrates advanced techniques for memory allocation, shellcode decryption, and execution using Windows NT functions.

## Features

- **Shellcode Loading**: Load encrypted shellcode from a file.
- **Memory Allocation**: Allocate memory using NT functions.
- **Shellcode Decryption**: Decrypt shellcode using XOR encryption.
- **APC Injection**: Inject and execute shellcode using APC.

## Prerequisites

- Windows operating system
- CMake 3.29 or higher
- Visual Studio or any other C++ compiler

## Building the Project

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/fiberAPCNTshellcodeloader.git
    cd fiberAPCNTshellcodeloader
    ```

2. Create a build directory and navigate into it:
    ```sh
    mkdir build
    cd build
    ```

3. Run CMake to generate the build files:
    ```sh
    cmake ..
    ```

4. Build the project:
    ```sh
    cmake --build .
    ```

## Usage

1. Prepare your encrypted shellcode and save it as `encrypted_shellcode.data`.

2. Run the executable:
    ```sh
    ./fiberAPCNTshellcodeloader
    ```

## Detection and Bypass

- **VirusTotal Detection**: This project has a detection rate of 6 on VirusTotal. You can view the detailed report [here](https://www.virustotal.com/gui/file/514ae9d173b5a701fd51ff0f70dcc9c823cfe842aa80efb13db91d7bdf0f2aa8/detection).
- **Bypass**: Successfully bypasses 360 Total Security and Huorong (火绒).

## Disclaimer

This project is for educational purposes only. Use it responsibly and only in environments where you have explicit permission to test.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
