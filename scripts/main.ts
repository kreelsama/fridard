let thread_modules = Process.enumerateModules()
let this_module = thread_modules[0]

console.log(JSON.stringify(this_module))
console.log("name: " + this_module.name)
console.log("base address: " + this_module.base)

Interceptor.attach(Module.getExportByName('kernel32.dll', 'CreateFileW'), {
  onEnter(args) {
    console.log(`[**] CreateFileW(\"${args[0].readUtf16String()}\")`);
  }
});

Interceptor.attach(Module.getExportByName('kernel32.dll', 'CloseHandle'), {
  onEnter(args) {
    console.log(`[**] CloseHandle(${args[0]})`);
  //   console.log('CCCryptorCreate called from:\n' +
  //   Thread.backtrace(this.context, Backtracer.ACCURATE)
  //   .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }
});