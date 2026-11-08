// 仿投毒 build.rs:构建期外联(全部无害,只碰本机/保留域)。
// 期望:enforce 下 ① 域名解析被掐(failed to lookup)、② 本机 connect 得 os error 13;
//       audit 下照常发生但证据记 audit-deny。cargo 生态的"安装期"= build.rs 运行期。
use std::net::{TcpStream, ToSocketAddrs};

fn main() {
    match ("c2.evil.example", 4444u16).to_socket_addrs() {
        Ok(addrs) => println!("[cargo-evil] c2 resolve: {} addrs", addrs.count()),
        Err(e) => println!("[cargo-evil] c2 resolve: {e}"),
    }
    match TcpStream::connect("127.0.0.1:9999") {
        Ok(_) => println!("[cargo-evil] c2 connect: OK"),
        Err(e) => println!("[cargo-evil] c2 connect: {e}"),
    }
}
