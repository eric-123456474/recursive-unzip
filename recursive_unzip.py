"""
@ ScriptName : ZIP 递归解压脚本
@ Description : 自动处理「ZIP 里套 ZIP、层数未知」的嵌套压缩包。
                特性：队列展开所有分支、按文件头识别 ZIP（兼容伪装扩展名）、
                自动尝试文件名密码、修复中文文件名乱码、兼容中文密码、
                可选支持 WinZip AES 加密（pip install pyzipper）。
"""

import os
import zipfile

try:
    import pyzipper  # 可选依赖：安装后支持 WinZip AES 加密的 ZIP
except ImportError:
    pyzipper = None

# 文件名密码都不对时最后尝试的常见弱口令，可按需自行增删
COMMON_PASSWORDS = [
    'password', '123456', '12345678', '123456789',
    '000000', '111111', 'admin', 'root',
]

# 解压成功后是否删除已处理完的 ZIP（默认 False，保留原件更安全）
DELETE_AFTER_EXTRACT = False


def is_zip(path):
    """通过文件头 PK 判断，而不是只看 .zip 扩展名（兼容无后缀/伪装文件）"""
    try:
        with open(path, 'rb') as f:
            return f.read(2) == b'PK'
    except OSError:
        return False


def fix_filename(info):
    """修复未设置 UTF-8 标志位时的中文文件名乱码（Windows 下常见）"""
    name = info.filename
    if not (info.flag_bits & 0x800):
        try:
            name = name.encode('cp437').decode('gbk')
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return name.replace('/', os.sep)


def build_passwords(zip_path, internal_names):
    """生成候选密码：压缩包自身文件名的各种变形 + 内部文件名 + 常见弱口令"""
    full = os.path.basename(zip_path)
    base = os.path.splitext(full)[0]
    candidates = [None]  # 先试无密码：压缩包可能根本没加密
    candidates += [
        base,          # 文件名（不含扩展名）
        full,          # 文件名（含扩展名）
        base.lower(),  # 全小写
        base.upper(),  # 全大写
        base[::-1],    # 反转
    ]
    # CTF 常见套路：内部 ZIP 的文件名就是外层密码
    for name in internal_names[:3]:
        candidates.append(os.path.splitext(os.path.basename(name))[0])
    candidates += COMMON_PASSWORDS

    # 去重并保持顺序
    seen = set()
    result = []
    for p in candidates:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def open_zip(path):
    """优先用 pyzipper（支持 AES），否则用标准库"""
    if pyzipper is not None:
        return pyzipper.AESZipFile(path)
    return zipfile.ZipFile(path)


def extract_one_entry(zf, info, dest, real_name, passwords):
    """用候选密码逐个尝试解压单个条目，成功返回 (密码, 输出路径)，失败返回 (None, None)"""
    out_path = os.path.join(dest, real_name)
    os.makedirs(os.path.dirname(out_path) or dest, exist_ok=True)

    # 避免不同层的同名文件互相覆盖
    if os.path.exists(out_path):
        root, ext = os.path.splitext(out_path)
        k = 1
        while os.path.exists(f'{root}_{k}{ext}'):
            k += 1
        out_path = f'{root}_{k}{ext}'

    for pwd in passwords:
        encodings = ('utf-8', 'gbk') if pwd else (None,)
        for enc in encodings:
            try:
                kwargs = {'pwd': pwd.encode(enc)} if pwd else {}
                with zf.open(info, **kwargs) as src, open(out_path, 'wb') as dst:
                    dst.write(src.read())
                return pwd, out_path
            except RuntimeError:
                continue  # 密码错误或 CRC 校验失败，换下一个候选
            except NotImplementedError:
                print('    [!] 该条目使用了 AES 等标准库不支持的加密，'
                      '请先执行: pip install pyzipper')
                return None, None
    return None, None


def extract_archive(zip_path, dest):
    """解压一个压缩包，返回解出的全部文件的绝对路径列表"""
    with open_zip(zip_path) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        real_names = [fix_filename(i) for i in infos]
        passwords = build_passwords(zip_path, real_names)

        results = []
        for info, real_name in zip(infos, real_names):
            pwd, out_path = extract_one_entry(zf, info, dest, real_name, passwords)
            if out_path:
                tag = f'密码: {pwd}' if pwd else '无密码'
                print(f'    [+] {real_name}  ({tag})')
                results.append(out_path)
            else:
                print(f'    [-] {real_name}  解压失败：所有候选密码均不正确')
        return results


def recursive_extract(file_path):
    file_path = os.path.abspath(file_path)
    work_dir = os.path.dirname(file_path)
    extract_root = os.path.join(work_dir, '_extracted')

    queue = [file_path]   # 待处理文件队列，可同时展开多个嵌套分支
    layer = 0
    finals = []

    while queue:
        cur = queue.pop(0)

        if not os.path.exists(cur):
            print(f'[!] 文件不存在，跳过: {cur}')
            continue
        if not is_zip(cur):
            finals.append(cur)
            continue

        layer += 1
        # 每个压缩包解压到独立编号目录，避免不同层同名文件互相覆盖
        base = os.path.splitext(os.path.basename(cur))[0]
        dest = os.path.join(extract_root, f'{layer:03d}_{base}')
        os.makedirs(dest, exist_ok=True)
        print(f'[{layer}] 解压: {cur}')
        print(f'    -> {dest}')

        try:
            produced = extract_archive(cur, dest)
        except zipfile.BadZipFile:
            print('    [!] 不是有效的 ZIP（可能是 RAR/7z 或文件已损坏），该分支停止')
            finals.append(cur)
            continue

        if DELETE_AFTER_EXTRACT and produced:
            os.remove(cur)
        queue.extend(produced)

    print('\n=== 递归结束，最终文件（非 ZIP）===')
    for f in finals:
        print('  ' + f)
    if not finals:
        print('  （没有得到最终文件，请检查上面的失败提示）')
    return finals


if __name__ == '__main__':
    path = input('请输入要解压的 ZIP 文件路径（可直接拖拽文件到窗口）: ').strip()
    # 去掉拖拽文件时自动带上的引号
    if len(path) >= 2 and path[0] == path[-1] and path[0] in ('"', "'"):
        path = path[1:-1]
    recursive_extract(path)
