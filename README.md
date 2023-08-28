# fridard

## Compile

### prerequisite
* Go to latest [frida release page](https://github.com/frida/frida/releases/tag/16.1.3) and download a __frida-core-devkit-x.y.z-windows-x86_64.tar.xz__ and extract `frida-core.h` and `frida-core.lib`, place them in `frida/` directory.
* spdlog is used to generate logs, use `git submodule init && git submodule update` to clone them.
* You can use `npm install --save @types/frida-gum` to enable syntax highlighting when writing rule files
* The instrumentation file (main.js) uses several WS2 helper functions written in `ws2helper.c`. Use VS shell for developer to run compile.bat to compile the diresed `ws2helper.dll` in place. 
  
Use latest visual studio to open `.sln` to compile.
The compiled binary is `mfrida.exe`.

## Usage

```
.\mfrida.exe <pid1> <pid2> <pid3> ...
```

**Rules should be placed with the directory of you running the exe, the name is `main.js`**.

**`ws2helper.dll` should be placed alongside with `main.js`**.

Sample rule file is provided in **scripts/main.ts**

A single rule file for all targeted processes is supported now.

**Child gating is enabled, which means frida will automatically attach child processes created by processes under instrumenting.**
