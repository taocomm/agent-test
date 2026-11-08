# 仿投毒 sdist:setup.py 在构建后端里执行 = pypi 生态的"安装期任意代码执行"窗口。
# 全部动作无害:本机不存在端口 + 保留 example 域。
# 期望:enforce 下解析被掐(gaierror)、本机 connect 得 EPERM;audit 下照常发生但证据 audit-deny。
import socket
from setuptools import setup

print("[pypi-evil] build hook alive", flush=True)
try:
    ip = socket.gethostbyname("c2.evil.example")
    print(f"[pypi-evil] c2 resolve: {ip}", flush=True)
except OSError as e:
    print(f"[pypi-evil] c2 resolve: {e}", flush=True)
try:
    socket.create_connection(("127.0.0.1", 9999), timeout=2)
    print("[pypi-evil] c2 connect: OK", flush=True)
except OSError as e:
    print(f"[pypi-evil] c2 connect: {e}", flush=True)

setup(name="pypi-evil", version="0.1.0", py_modules=[])
