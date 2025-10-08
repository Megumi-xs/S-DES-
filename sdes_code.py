import queue
import threading


class S_DES:
    def __init__(self):
        # 置换表定义
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]
        self.P = [2, 4, 3, 1]
        self.PC1 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.PC2 = [6, 3, 7, 4, 8, 5, 10, 9]
        # S盒定义
        self.S1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
        self.S2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]

    def permute(self, block, table):
        """根据置换表对数据块进行置换"""
        return [block[i - 1] for i in table]

    def left_shift(self, bits, n=1):
        """将位列表向左循环移位n次"""
        return bits[n:] + bits[:n]

    def generate_keys(self, key):
        """生成两个子密钥K1和K2（10位密钥输入）"""
        key = key[:10] if len(key) >= 10 else key + [0] * (10 - len(key))
        key_permuted = self.permute(key, self.PC1)
        left, right = key_permuted[:5], key_permuted[5:]

        # 生成K1（左移1位）
        left1 = self.left_shift(left)
        right1 = self.left_shift(right)
        k1 = self.permute(left1 + right1, self.PC2)

        # 生成K2（左移2位）
        left2 = self.left_shift(left1, 2)
        right2 = self.left_shift(right1, 2)
        k2 = self.permute(left2 + right2, self.PC2)

        return k1, k2

    def f_function(self, right, subkey):
        """轮函数f：扩展置换→异或→S盒替换→P盒置换"""
        expanded = self.permute(right, self.EP)
        xor_result = [expanded[i] ^ subkey[i] for i in range(8)]
        left_s, right_s = xor_result[:4], xor_result[4:]

        # S1盒替换
        row1 = left_s[0] * 2 + left_s[3]
        col1 = left_s[1] * 2 + left_s[2]
        s1_out = self.bin_list(self.S1[row1][col1], 2)

        # S2盒替换
        row2 = right_s[0] * 2 + right_s[3]
        col2 = right_s[1] * 2 + right_s[2]
        s2_out = self.bin_list(self.S2[row2][col2], 2)

        return self.permute(s1_out + s2_out, self.P)

    def encrypt_block(self, plaintext_block, key):
        """加密单个8位数据块"""
        ip_result = self.permute(plaintext_block, self.IP)
        left, right = ip_result[:4], ip_result[4:]
        k1, k2 = self.generate_keys(key)

        # 第一轮（K1）
        f_out = self.f_function(right, k1)
        new_left = [left[i] ^ f_out[i] for i in range(4)]
        left, right = right, new_left

        # 第二轮（K2）
        f_out = self.f_function(right, k2)
        new_left = [left[i] ^ f_out[i] for i in range(4)]

        return self.permute(new_left + right, self.IP_inv)

    def decrypt_block(self, ciphertext_block, key):
        """解密单个8位数据块（子密钥顺序与加密相反）"""
        ip_result = self.permute(ciphertext_block, self.IP)
        left, right = ip_result[:4], ip_result[4:]
        k1, k2 = self.generate_keys(key)

        # 第一轮（K2）
        f_out = self.f_function(right, k2)
        new_left = [left[i] ^ f_out[i] for i in range(4)]
        left, right = right, new_left

        # 第二轮（K1）
        f_out = self.f_function(right, k1)
        new_left = [left[i] ^ f_out[i] for i in range(4)]

        return self.permute(new_left + right, self.IP_inv)

    @staticmethod
    def bin_list(n, length):
        """将整数转换为指定长度的二进制列表（高位在前）"""
        return [(n >> i) & 1 for i in reversed(range(length))]

    @staticmethod
    def text_to_bits(text):
        """将文本转换为比特列表（每个字符8位二进制）"""
        bits = []
        for char in text:
            char_bits = [(ord(char) >> i) & 1 for i in reversed(range(8))]
            bits.extend(char_bits)
        return bits

    @staticmethod
    def bits_to_text(bits):
        """将比特列表转换为文本（每8位对应一个字符）"""
        text = ""
        if len(bits) % 8 != 0:
            return text
        for i in range(0, len(bits), 8):
            char_code = 0
            for bit in bits[i:i + 8]:
                char_code = (char_code << 1) | bit
            text += chr(char_code)
        return text

    def encrypt_text(self, plaintext, key):
        """加密任意长度文本（自动按8位分块，不足补0）"""
        plain_bits = self.text_to_bits(plaintext)
        cipher_bits = []
        for i in range(0, len(plain_bits), 8):
            block = plain_bits[i:i + 8]
            while len(block) < 8:
                block.append(0)
            cipher_bits.extend(self.encrypt_block(block, key))
        return self.bits_to_text(cipher_bits)

    def decrypt_text(self, ciphertext, key):
        """解密任意长度文本（与加密分块逻辑对应）"""
        cipher_bits = self.text_to_bits(ciphertext)
        plain_bits = []
        for i in range(0, len(cipher_bits), 8):
            block = cipher_bits[i:i + 8]
            while len(block) < 8:
                block.append(0)
            plain_bits.extend(self.decrypt_block(block, key))
        return self.bits_to_text(plain_bits)

    def brute_force_worker(self, start, end, plain_bits, cipher_bits, found_keys, running_flag, progress_queue, thread_id):
        """暴力破解工作线程：检查指定范围的10位密钥"""
        checked = 0
        total = end - start

        for i in range(start, end):
            if not running_flag[0]:
                progress_queue.put((thread_id, total - checked))
                return

            # 转换整数为10位二进制密钥
            key_str = format(i, '010b')
            key_bits = [int(c) for c in key_str]

            # 验证密钥是否匹配（加密明文对比密文）
            try:
                if self.encrypt_block(plain_bits, key_bits) == cipher_bits:
                    found_keys.append(key_str)
            except Exception:
                continue

            # 上报进度（每10个密钥一次）
            checked += 1
            if checked % 10 == 0:
                progress_queue.put((thread_id, 10))

        # 上报剩余进度
        remaining = total % 10
        if remaining > 0:
            progress_queue.put((thread_id, remaining))

    def brute_force(self, plaintext, ciphertext, max_threads=4, progress_callback=None, stop_callback=None):
        """暴力破解入口：多线程管理+进度监控（输入为8位二进制字符串）"""
        # 输入验证
        if len(plaintext) != 8 or not all(c in ['0', '1'] for c in plaintext):
            raise ValueError("明文必须是8位二进制字符串（仅含0和1）")
        if len(ciphertext) != 8 or not all(c in ['0', '1'] for c in ciphertext):
            raise ValueError("密文必须是8位二进制字符串（仅含0和1）")

        # 转换为比特列表
        plain_bits = [int(c) for c in plaintext]
        cipher_bits = [int(c) for c in ciphertext]

        # 共享变量初始化
        found_keys = []
        running_flag = [True]
        progress_queue = queue.Queue()
        total_keys = 1024  # 10位密钥共2^10=1024种可能
        processed_keys = 0

        # 进度监控线程
        def progress_monitor():
            nonlocal processed_keys
            while running_flag[0]:
                try:
                    _, count = progress_queue.get(timeout=0.1)
                    processed_keys += count
                    progress = min((processed_keys / total_keys) * 100, 100)
                    if progress_callback:
                        progress_callback(progress)
                except queue.Empty:
                    continue
            if progress_callback:
                progress_callback(100)

        monitor_thread = threading.Thread(target=progress_monitor, daemon=True)
        monitor_thread.start()

        # 分割密钥范围并启动工作线程
        keys_per_thread = total_keys // max_threads
        threads = []
        for i in range(max_threads):
            start = i * keys_per_thread
            end = (i + 1) * keys_per_thread if i < max_threads - 1 else total_keys

            thread = threading.Thread(
                target=self.brute_force_worker,
                args=(start, end, plain_bits, cipher_bits, found_keys, running_flag, progress_queue, i),
                daemon=True
            )
            threads.append(thread)
            thread.start()

        # 等待线程完成或停止
        try:
            while running_flag[0] and any(t.is_alive() for t in threads):
                if stop_callback and stop_callback():
                    running_flag[0] = False
        except KeyboardInterrupt:
            running_flag[0] = False

        # 清理并返回结果（去重+排序）
        running_flag[0] = False
        monitor_thread.join(timeout=1)
        return sorted(list(set(found_keys)))
