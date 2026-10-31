// SOVEREIGN - Raw AF_PACKET Network Interceptor
// Compile: rustc -O main.rs -o sovereign
// Run: sudo ./sovereign eth0

use std::env;
use std::ffi::CString;
use std::io;
use std::mem;
use std::os::raw::{c_char, c_int, c_short, c_uint, c_void};
use std::ptr;

const AF_PACKET: c_int = 17;
const SOCK_RAW: c_int = 3;
const ETH_P_ALL: c_short = 0x0003;
const SOL_PACKET: c_int = 263;
const PACKET_ADD_MEMBERSHIP: c_int = 1;
const PACKET_MR_PROMISC: c_int = 1;

#[repr(C)]
struct SockAddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

#[repr(C)]
struct PacketMreq {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

#[repr(C)]
struct IfReq {
    ifr_name: [c_char; 16],
    ifr_ifindex: c_int,
    _pad: [u8; 16],
}

extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: u32) -> c_int;
    fn recvfrom(fd: c_int, buf: *mut c_void, len: usize, flags: c_int, addr: *mut c_void, addrlen: *mut u32) -> isize;
    fn close(fd: c_int) -> c_int;
    fn ioctl(fd: c_int, request: u64, ...) -> c_int;
}

fn get_interface_index(fd: c_int, ifname: &str) -> io::Result<i32> {
    let mut req = IfReq {
        ifr_name: [0; 16],
        ifr_ifindex: 0,
        _pad: [0; 16],
    };
    let cname = CString::new(ifname).unwrap();
    let bytes = cname.as_bytes();
    for i in 0..bytes.len().min(15) {
        req.ifr_name[i] = bytes[i] as c_char;
    }
    // SIOCGIFINDEX = 0x8933
    let rc = unsafe { ioctl(fd, 0x8933, &mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(req.ifr_ifindex)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: sudo {} <interface>", args[0]);
        eprintln!("Example: sudo {} eth0", args[0]);
        std::process::exit(1);
    }

    let ifname = &args[1];

    unsafe {
        // 1. Создаем сырой сокет (перехват ВСЕХ пакетов)
        let fd = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as c_int);
        if fd < 0 {
            eprintln!("[!] Failed to create raw socket. Are you root?");
            return Err(io::Error::last_os_error());
        }

        // 2. Получаем индекс интерфейса
        let ifindex = get_interface_index(fd, ifname)?;

        // 3. Биндимся к интерфейсу
        let mut addr = SockAddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let rc = bind(fd, &addr as *const _ as *const c_void, mem::size_of::<SockAddrLl>() as u32);
        if rc < 0 {
            eprintln!("[!] Failed to bind to interface {}", ifname);
            return Err(io::Error::last_os_error());
        }

        // 4. Включаем Promiscuous Mode (режим прослушивания)
        let mreq = PacketMreq {
            mr_ifindex: ifindex,
            mr_type: PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        let rc = setsockopt(
            fd,
            SOL_PACKET,
            PACKET_ADD_MEMBERSHIP,
            &mreq as *const _ as *const c_void,
            mem::size_of::<PacketMreq>() as u32,
        );
        if rc < 0 {
            eprintln!("[!] Failed to set promiscuous mode.");
        }

        println!("[SOVEREIGN] Interceptor initialized on {}", ifname);
        println!("[SOVEREIGN] Capturing all raw traffic. Press Ctrl+C to stop.\n");

        let mut buf = vec![0u8; 65536];
        
        // Бесконечный цикл перехвата
        loop {
            let mut addr_len = mem::size_of::<SockAddrLl>() as u32;
            let n = recvfrom(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut addr as *mut _ as *mut c_void,
                &mut addr_len,
            );

            if n > 0 {
                let packet = &buf[..n as usize];
                
                // Парсинг Ethernet заголовка (14 байт)
                if packet.len() >= 14 {
                    let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
                    
                    // Проверяем, что это IPv4 (0x0800)
                    if eth_type == 0x0800 && packet.len() >= 34 {
                        let ip_header = &packet[14..];
                        let version = ip_header[0] >> 4;
                        
                        if version == 4 {
                            let src_ip = format!("{}.{}.{}.{}", ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
                            let dst_ip = format!("{}.{}.{}.{}", ip_header[16], ip_header[17], ip_header[18], ip_header[19]);
                            let protocol = ip_header[9];
                            let proto_name = match protocol {
                                1 => "ICMP",
                                6 => "TCP",
                                17 => "UDP",
                                _ => "OTHER",
                            };
                            
                            // Вывод только TCP/UDP для чистоты
                            if protocol == 6 || protocol == 17 {
                                let ttl = ip_header[8];
                                println!("[+] {} -> {} | {} | TTL: {} | Size: {}", src_ip, dst_ip, proto_name, ttl, n);
                            }
                        }
                    }
                }
            }
        }
    }
}
