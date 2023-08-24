let thread_modules = Process.enumerateModules()
let this_module = thread_modules[0]
let base_address = this_module.base;

let WS2_LIB_NAME = "ws2_32.dll"

let logger=console;

Interceptor.attach(Module.getExportByName('kernel32.dll', 'CreateFileW'), {
  onEnter(args) {
    logger.log(`[*] CreateFileW(\"${args[0].readUtf16String()}\")`);
  }
});

Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, "WSAStartup"), {
  onLeave(args) {
    logger.log("new socket prepared to initialize");
  }
})

Interceptor.attach(Module.getExportByName('kernel32.dll', 'CloseHandle'), {
  onEnter(args) {
    console.log(`[*] CloseHandle(${args[0]})`);
  //   console.log('CCCryptorCreate called from:\n' +
  //   Thread.backtrace(this.context, Backtracer.ACCURATE)
  //   .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }
});