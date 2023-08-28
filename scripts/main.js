let thread_modules = Process.enumerateModules()
let this_module = thread_modules[0]
let base_address = this_module.base;

let WS2_LIB_NAME = "WS2_32.dll"

let logger=console;

var ushort_size = 0;


const local_module = Module.load("D:\\Dev\\frida\\scripts\\ws2helper.dll");
const get_addr_info = new NativeFunction(local_module.getExportByName("get_address_info"), 'int', ['pointer', 'pointer']);
const get_addr_info_from_addrinfo = new NativeFunction(local_module.getExportByName("get_address_info_from_addrinfo"), 'int', ['pointer', 'pointer']);
// const get_connect_state = new NativeFunction(local_module.getExportByName("get_connect_state"), 'int', [ ]);
const pid = Process.id;

// {724：{fd:724, status="local"|"remote", ip= null |"1.2.3.4", type="tcp" | "tcp6" | "udp" | "udp6", local_port = 0, remote_port = 0 }, ...}
var socket_map = new Map();
// {"yuhangji.cn": "1.2.3.4", ...}
var hostname_map = new Map();

let sockaddr_serialize = function (sockaddr) {
  let raddr_buf = Memory.alloc(100);
  let port = get_addr_info(sockaddr, raddr_buf);
  let raddr = raddr_buf.readCString();
  if(port == 0){
    port = null;
  }
  if (raddr.length == 0){
    raddr = null;
  }
  return {ip:raddr, port:port};
};

let addrinfo_serialize = function (addrinfo) {
  let raddr_buf = Memory.alloc(100);
  let port = get_addr_info_from_addrinfo(addrinfo, raddr_buf);
  let raddr = raddr_buf.readCString();
  if(port == 0)
    port = null;
  if(raddr.length == 0) {
    raddr = null;
  }
  return {ip:raddr, port:port};
};

let fd_serialize = function (fd) {
  let socktype = Socket.type(fd);
  let address = {ip:null, port:null};
  if (socktype == null)
    return address;
  
  let remote_address = Socket.peerAddress(fd);
  if (remote_address === null)
    return address;
  return remote_address;
};

let get_desc_or_map = function (fd) {
  let desc = socket_map.get(fd);
  if ( desc ) {
    return {...desc};
  }
  
  let socktype = Socket.type(fd);
  if(socktype == null){
    // fd is invalid
    return
  }

  let remote_addr = Socket.peerAddress(fd);
  let local_addr = Socket.localAddress(fd);
  let conn_status = "remote"
  if (remote_addr === null){
    remote_addr = {ip:null, port:null};
    conn_status = "local";
  }
  
  if (local_addr == null){
    local_addr = {ip:null, port:null};
  }

  desc = {
    fd: fd, 
    type: socktype, 
    remote_addr:
    {
      ip:   remote_addr.ip, 
      port: remote_addr.port,
    },
    local_addr: 
    {
      ip:    local_addr.ip,
      port:  local_addr.port,
    },
    status: conn_status
  }

  socket_map.set(fd, desc);
  
  return {...desc};
}

let transmitter = function (data, ctx) {
  data.pid = pid;
  if(ctx){
    let callstack = Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
    data.callstack = callstack;
  }

  if(data.remote_addr.ip) {
    let hostname = hostname_map.get(data.remote_addr.ip)
    if(hostname)
      data.remote_addr.hostname = hostname
  }

  console.log(JSON.stringify(data))
}

/*
INT WSAAPI getaddrinfo(
  [in, optional] PCSTR           pNodeName,
  [in, optional] PCSTR           pServiceName,
  [in, optional] const ADDRINFOA *pHints,
  [out]          PADDRINFOA      *ppResult
);
*/
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'getaddrinfo'), {
  // DNS request happens here
  onEnter(args) {
    this.hostname = args[0].readCString();
    this.service_name = args[1].readCString();
    this.resptr = args[3];
  },
  onLeave(retargs) {
    if(retargs.toInt32() != 0){
      return;
    }
    this.remote_address = addrinfo_serialize(this.resptr);
    hostname_map.set(this.remote_address.ip, this.hostname) //  only map hostname to IP
    // console.log(`Queried addrinfo of ${this.hostname}:${this.service_name}, got address ${this.remote_address.ip}:${this.remote_address.port}`);
  }
})


/*
SOCKET WSAAPI socket(
  [in] int af,
  [in] int type,
  [in] int protocol
);
*/
const address_families = ['UNSPEC', 'UNIX', 'INET', 'IMPLINK', 'PUP', 'CHAOS', 'NS', 'IPX', 'ISO', 'OSI', 'ECMA', 'DATAKIT', 'CCITT',
  'SNA', 'DECnet', 'DLI', 'LAT', 'HYLINK', 'APPLETALK', 'NETBIOS', 'VOICEVIEW', 'FIREFOX', 'UNKNOWN1', 'BAN', 'ATM', 'INET6', 
  'CLUSTER', '12844', 'IRDA', 'NETDES']
const socket_types = ['TCP', 'UDP', 'RAW', 'RDM', 'SEQPACKET']
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'socket'), {
  onEnter(args) {
    this.af = args[0].toUInt32();
    this.type = args[1].toUInt32();
    this.protocol = args[2].toUInt32();
  },
  onLeave(retargs) {
    let fd = retargs.toInt32()
    if(fd > 0){
      let desc = get_desc_or_map(fd)
      desc.function = 'socket'
      transmitter(desc, this.context)
      // console.log(`new socket ${fd} with type=${socktype} created`);
    }
  }
})

/*
int bind(
  [in] SOCKET         s,
       const sockaddr *addr,
  [in] int            namelen
);
*/
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'connect'), {
  // TODO: ConnectEx hook
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.remote_address = sockaddr_serialize(args[1]);
  },
  onLeave(retargs) {
    socket_map.delete(this.fd);
    let desc = get_desc_or_map(this.fd);
    desc.function = 'connect'
    transmitter(desc)
    // console.log(`Connect success for ${address.ip}:${address.port}, with local address ${laddress.ip}:${laddress.port}`);
  }
})

/*
int bind(
  [in] SOCKET         s,
       const sockaddr *addr,
  [in] int            namelen
);
*/
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'bind'), {
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.local_address = sockaddr_serialize(args[1]);
  },
  onLeave(retargs) {
    if(retargs.toInt32() == 0){
      let desc = get_desc_or_map(this.fd);
      desc.local_addr.ip = this.local_address.ip;
      desc.local_addr.port = this.local_address.port;
      desc.status = "local";
      socket_map.set(this.fd, desc)
      desc.function = 'bind'
      transmitter(desc)
      // console.log(`Program binded to ${this.local_address}`)
    }
  }
})

/*
SOCKET WSAAPI accept(
  [in]      SOCKET   s,
  [out]     sockaddr *addr,
  [in, out] int      *addrlen
);
*/
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'accept'), {
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.remote_addr_ptr = args[1];
  },
  onLeave(retargs) {
    if(retargs.toInt32() <= 0){
      return;
    }
    let new_fd = retargs.toInt32();
    let desc = get_desc_or_map(new_fd)
    desc.function = 'accept'
    transmitter(desc)
    // console.log(`Accpeted request from ${this.remote_address} with socket ${this.remote_fd}`);
  }
})

/**
int send(
  [in] SOCKET         s,
  [in] const char     *buf,
  [in] int            len,
  [in] int            flags,
);
 */
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'send'), {
  onEnter(args) {
    this.fd = args[0].toInt32()
    this.remote_address = fd_serialize(this.fd);
    this.sendbuf = args[1];
    // this.sendmsg = args[1].readCString(args[2].toInt32());
  },
  onLeave(retargs){
    let nBytes = retargs.toInt32();
    if(nBytes > 0){
      let desc = get_desc_or_map(this.fd)
      desc.msg = this.sendbuf.readCString(nBytes);
      desc.function = 'send'
      transmitter(desc);
      // console.log(`send buf to ${this.remote_address}`, "data:", this.sendmsg);
    }
    else if (nBytes < 0){ 
      // send failed: socket crash unexpectedly
      // possibly because an interruption. clean the record anyway.
      socket_map.delete(this.fd);
    } 
    else { // nBytes == 0: sth went wrong but socket survived
      // pass
    }
  }
})

/**
int sendto(
  [in] SOCKET         s,
  [in] const char     *buf,
  [in] int            len,
  [in] int            flags,
  [in] const sockaddr *to,
  [in] int            tolen
);
 */
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'sendto'), {
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.remote_address = fd_serialize(this.fd); // already 
    if(args[4] != null){
      this.remote_address = sockaddr_serialize(args[4]);
    }
    this.sendmsg = args[1].readCString(args[2].toInt32());
  },
  onLeave(retargs){
    let nBytes = retargs.toInt32();
    if(nBytes > 0){
      let desc = get_desc_or_map(this.fd);
      desc.remote_addr = this.remote_address;
      desc.function = "sendto"
      transmitter(desc)
      // console.log(`send buf to ${this.remote_address}`, "data:", this.sendmsg);
    }
    else if (nBytes < 0){ 
      // send failed: socket crash unexpectedly
      // possibly because an interruption. clean the record anyway.
      socket_map.delete(this.fd);
    } 
    else { // nBytes == 0: sth went wrong but socket survived
      // pass
    }
  }
})

/**
int closesocket(
  [in] SOCKET s
);
 */
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'closesocket'), {
  onEnter(args) {
    this.fd = args[0].toInt32();
  },
  onLeave(retargs){
    // clean the socket record anyway
    let desc = socket_map.get(this.fd);
    if(desc) {
      desc.function = "closesocket"
      transmitter(desc);
      socket_map.delete(this.fd);        
    // console.log(`socket ${this.fd} conncting to ${this.address} closed. `);
    }
  }
})

/**
int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
 */
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'recv'), {
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.address = fd_serialize(this.fd);
    this.recvbufptr = args[1];
    this.recvbuflen = args[2].toInt32();
  },
  onLeave(retargs){
    let nBytes = retargs.toInt32();
    if(nBytes > 0){
      let desc = get_desc_or_map(this.fd)
      desc.msg =  this.recvbufptr.readCString(nBytes)
      desc.function = 'recv'
      transmitter(desc)
      // console.log(`received buf from ${this.address}`, "data:",);
    }
    else if (nBytes < 0){
      socket_map.delete(this.fd)
    }
    else {
      // sth went wrong, but ignoring
    }
  }
})

/*
int recvfrom(
  [in]                SOCKET   s,
  [out]               char     *buf,
  [in]                int      len,
  [in]                int      flags,
  [out]               sockaddr *from,
  [in, out, optional] int      *fromlen
);
*/
Interceptor.attach(Module.getExportByName(WS2_LIB_NAME, 'recvfrom'), {
  onEnter(args) {
    this.fd = args[0].toInt32();
    this.local_address = fd_serialize(this.fd);
    this.recvbufptr = args[1];
    this.recvbuflen = args[2].toInt32();
    this.remote_address_ptr = args[4];
  },
  onLeave(retargs){
    let nBytes = retargs.toInt32();
    if(nBytes > 0){
      let desc = get_desc_or_map(this.fd);
      desc.remote_addr = sockaddr_serialize(this.remote_address_ptr);
      desc.msg = this.recvbufptr.readCString(nBytes);
      desc.function = 'recvfrom'
      desc.status = 'remote'
      transmitter(desc)
      // console.log(`received buf from ${this.address}`, "data:", this.recvbufptr.readCString(nBytes));
    }
    else if (nBytes < 0){ 
      // send failed: socket crash unexpectedly
      // possibly because an interruption. clean the record anyway.
      socket_map.delete(this.fd);
    } 
    else { // nBytes == 0: sth went wrong but socket survived
      // pass
    }
  }
})
