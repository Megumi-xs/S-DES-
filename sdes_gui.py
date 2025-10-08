import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from sdes_code import S_DES  # 导入核心算法类


class S_DES_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES加密解密程序")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # 初始化核心算法实例
        self.sdes = S_DES()

        # 样式配置
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("微软雅黑", 10))
        self.style.configure("TButton", font=("微软雅黑", 10))
        self.style.configure("TEntry", font=("微软雅黑", 10))

        # 输入验证命令（限制二进制输入长度）
        self.vcmd_8bit = self.root.register(self._check_8bit_input)
        self.vcmd_10bit = self.root.register(self._check_10bit_input)

        # 暴力破解状态标记
        self.brute_running = False

        # 主框架
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 标签页（3个功能页）
        self.tab_control = ttk.Notebook(self.main_frame)
        self.basic_tab = ttk.Frame(self.tab_control)  # 基本8位块加密
        self.text_tab = ttk.Frame(self.tab_control)   # 任意文本加密
        self.brute_tab = ttk.Frame(self.tab_control)  # 暴力破解
        self.tab_control.add(self.basic_tab, text="基本加密解密")
        self.tab_control.add(self.text_tab, text="文本加密解密")
        self.tab_control.add(self.brute_tab, text="暴力破解")
        self.tab_control.pack(expand=1, fill="both")

        # 初始化各标签页
        self.init_basic_tab()
        self.init_text_tab()
        self.init_brute_tab()

    def _check_8bit_input(self, new_value):
        """验证8位二进制输入（仅允许0/1，长度≤8）"""
        if not new_value:
            return True
        if not all(c in ["0", "1"] for c in new_value):
            return False
        return len(new_value) <= 8

    def _check_10bit_input(self, new_value):
        """验证10位二进制输入（仅允许0/1，长度≤10）"""
        if not new_value:
            return True
        if not all(c in ["0", "1"] for c in new_value):
            return False
        return len(new_value) <= 10

    def validate_binary_input(self, text, length):
        """按钮点击时的最终验证（确保长度和字符合法）"""
        if len(text) != length:
            return False, f"输入长度必须为{length}位（当前{len(text)}位）"
        for c in text:
            if c not in ['0', '1']:
                return False, "输入必须只包含0和1"
        return True, "输入有效"

    # ---------------------- 基本加密解密标签页 ----------------------
    def init_basic_tab(self):
        # 输入框架
        input_frame = ttk.LabelFrame(self.basic_tab, text="输入", padding="10")
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(input_frame, text="8位明文 (0/1):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.plaintext_entry = ttk.Entry(input_frame, width=10, validate="key", validatecommand=(self.vcmd_8bit, '%P'))
        self.plaintext_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        ttk.Label(input_frame, text="例如: 10101010").grid(row=0, column=2, sticky=tk.W, pady=5)

        ttk.Label(input_frame, text="10位密钥 (0/1):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(input_frame, width=12, validate="key", validatecommand=(self.vcmd_10bit, '%P'))
        self.key_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        ttk.Label(input_frame, text="例如: 1010101010").grid(row=1, column=2, sticky=tk.W, pady=5)

        ttk.Label(input_frame, text="8位密文 (0/1):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.ciphertext_entry = ttk.Entry(input_frame, width=10, validate="key", validatecommand=(self.vcmd_8bit, '%P'))
        self.ciphertext_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Label(input_frame, text="例如: 11001100").grid(row=2, column=2, sticky=tk.W, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(self.basic_tab, padding="10")
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="加密", command=self.basic_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="解密", command=self.basic_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_basic).pack(side=tk.LEFT, padx=5)

        # 结果框架
        result_frame = ttk.LabelFrame(self.basic_tab, text="结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.result_text = scrolledtext.ScrolledText(result_frame, height=10, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        self.result_text.config(state=tk.DISABLED)

    def basic_encrypt(self):
        """基本加密逻辑（8位明文→8位密文）"""
        try:
            plaintext = self.plaintext_entry.get().strip()
            key = self.key_entry.get().strip()

            # 输入验证
            valid, msg = self.validate_binary_input(plaintext, 8)
            if not valid:
                messagebox.showerror("输入错误", msg)
                return
            valid, msg = self.validate_binary_input(key, 10)
            if not valid:
                messagebox.showerror("输入错误", msg)
                return

            # 调用核心算法加密
            plain_bits = [int(c) for c in plaintext]
            key_bits = [int(c) for c in key]
            cipher_bits = self.sdes.encrypt_block(plain_bits, key_bits)
            ciphertext = ''.join(str(bit) for bit in cipher_bits)

            # 显示结果
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"明文: {plaintext}\n密钥: {key}\n加密结果: {ciphertext}\n")
            self.result_text.config(state=tk.DISABLED)
            self.ciphertext_entry.delete(0, tk.END)
            self.ciphertext_entry.insert(0, ciphertext)

        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def basic_decrypt(self):
        """基本解密逻辑（8位密文→8位明文）"""
        try:
            ciphertext = self.ciphertext_entry.get().strip()
            key = self.key_entry.get().strip()

            # 输入验证
            valid, msg = self.validate_binary_input(ciphertext, 8)
            if not valid:
                messagebox.showerror("输入错误", msg)
                return
            valid, msg = self.validate_binary_input(key, 10)
            if not valid:
                messagebox.showerror("输入错误", msg)
                return

            # 调用核心算法解密
            cipher_bits = [int(c) for c in ciphertext]
            key_bits = [int(c) for c in key]
            plain_bits = self.sdes.decrypt_block(cipher_bits, key_bits)
            plaintext = ''.join(str(bit) for bit in plain_bits)

            # 显示结果
            self.result_text.config(state=tk.NORMAL)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"密文: {ciphertext}\n密钥: {key}\n解密结果: {plaintext}\n")
            self.result_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def clear_basic(self):
        """清空基本标签页输入和结果"""
        self.plaintext_entry.delete(0, tk.END)
        self.key_entry.delete(0, tk.END)
        self.ciphertext_entry.delete(0, tk.END)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)

    # ---------------------- 文本加密解密标签页 ----------------------
    def init_text_tab(self):
        # 文本输入框架
        input_frame = ttk.LabelFrame(self.text_tab, text="文本输入", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.text_input = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD)
        self.text_input.pack(fill=tk.BOTH, expand=True)

        # 密钥框架
        key_frame = ttk.Frame(self.text_tab, padding="10")
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(key_frame, text="10位密钥 (0/1):").pack(side=tk.LEFT, padx=5)
        self.text_key_entry = ttk.Entry(key_frame, width=12, validate="key", validatecommand=(self.vcmd_10bit, '%P'))
        self.text_key_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(key_frame, text="例如: 1010101010").pack(side=tk.LEFT, padx=5)

        # 按钮框架
        button_frame = ttk.Frame(self.text_tab, padding="10")
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="加密文本", command=self.text_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="解密文本", command=self.text_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_text).pack(side=tk.LEFT, padx=5)

        # 结果框架
        result_frame = ttk.LabelFrame(self.text_tab, text="结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.text_result = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.text_result.pack(fill=tk.BOTH, expand=True)
        self.text_result.config(state=tk.DISABLED)

    def text_encrypt(self):
        """文本加密（任意文本→加密文本）"""
        try:
            text = self.text_input.get(1.0, tk.END).strip()
            key = self.text_key_entry.get().strip()

            # 输入验证
            if not text:
                messagebox.showerror("输入错误", "请输入要加密的文本")
                return
            valid, msg = self.validate_binary_input(key, 10)
            if not valid:
                messagebox.showerror("输入错误", msg)
                return

            # 调用核心算法加密
            key_bits = [int(c) for c in key]
            ciphertext = self.sdes.encrypt_text(text, key_bits)

            # 显示结果
            self.text_result.config(state=tk.NORMAL)
            self.text_result.delete(1.0, tk.END)
            self.text_result.insert(tk.END, f"加密结果:\n{ciphertext}\n\n注意：加密后的文本可能包含不可打印字符")
            self.text_result.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("错误", f"字符串加密失败: {str(e)}")

    def text_decrypt(self):
        """文本解密（加密文本→原始文本）"""
        try:
            text = self.text_input.get(1.0, tk.END).strip()
            key = self.text_key_entry.get().strip()

            # 输入验证
            if not text:
                messagebox.showerror("输入错误", "请输入要解密的文本")
                return
            valid, msg = self.validate_binary_input(key, 10)
            if not valid:
                messagebox.showerror("输入错误", msg)
                return

            # 调用核心算法解密
            key_bits = [int(c) for c in key]
            plaintext = self.sdes.decrypt_text(text, key_bits)

            # 显示结果
            self.text_result.config(state=tk.NORMAL)
            self.text_result.delete(1.0, tk.END)
            self.text_result.insert(tk.END, f"解密结果:\n{plaintext}")
            self.text_result.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("错误", f"字符串解密失败: {str(e)}")

    def clear_text(self):
        """清空文本标签页输入和结果"""
        self.text_input.delete(1.0, tk.END)
        self.text_key_entry.delete(0, tk.END)
        self.text_result.config(state=tk.NORMAL)
        self.text_result.delete(1.0, tk.END)
        self.text_result.config(state=tk.DISABLED)

    # ---------------------- 暴力破解标签页 ----------------------
    def init_brute_tab(self):
        # 输入框架（明密文对）
        input_frame = ttk.LabelFrame(self.brute_tab, text="明密文对", padding="10")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(input_frame, text="8位明文 (二进制):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.brute_plain_entry = ttk.Entry(input_frame, width=30, validate="key", validatecommand=(self.vcmd_8bit, '%P'))
        self.brute_plain_entry.grid(row=0, column=1, sticky=tk.W, pady=5, columnspan=2)

        ttk.Label(input_frame, text="8位密文 (二进制):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.brute_cipher_entry = ttk.Entry(input_frame, width=30, validate="key", validatecommand=(self.vcmd_8bit, '%P'))
        self.brute_cipher_entry.grid(row=1, column=1, sticky=tk.W, pady=5, columnspan=2)

        # 线程数选择
        ttk.Label(input_frame, text="线程数:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.thread_count = ttk.Combobox(input_frame, values=[1, 2, 4, 8, 16], width=10)
        self.thread_count.current(2)  # 默认4线程
        self.thread_count.grid(row=2, column=1, sticky=tk.W, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(self.brute_tab, padding="10")
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="开始破解", command=self.start_brute_force).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="停止破解", command=self.stop_brute_force).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_brute).pack(side=tk.LEFT, padx=5)

        # 状态框架
        status_frame = ttk.LabelFrame(self.brute_tab, text="状态", padding="10")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        self.brute_status = ttk.Label(status_frame, text="就绪", foreground="blue")
        self.brute_status.pack(anchor=tk.W)

        # 进度条
        ttk.Label(self.brute_tab, text="进度:").pack(anchor=tk.W, padx=10)
        self.brute_progress = ttk.Progressbar(self.brute_tab, orient="horizontal", length=100, mode="determinate")
        self.brute_progress.pack(fill=tk.X, padx=10, pady=5)

        # 结果框架
        result_frame = ttk.LabelFrame(self.brute_tab, text="破解结果 (密钥)", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.brute_result = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.brute_result.pack(fill=tk.BOTH, expand=True)
        self.brute_result.config(state=tk.DISABLED)

    def start_brute_force(self):
        """启动暴力破解（多线程）"""
        if self.brute_running:
            messagebox.showinfo("提示", "破解已在进行中")
            return

        # 获取输入
        plaintext = self.brute_plain_entry.get().strip()
        ciphertext = self.brute_cipher_entry.get().strip()
        num_threads = int(self.thread_count.get())

        # 输入验证
        if not plaintext or not ciphertext:
            messagebox.showerror("输入错误", "请输入明文和密文")
            return
        valid, msg = self.validate_binary_input(plaintext, 8)
        if not valid:
            messagebox.showerror("输入错误", f"明文{msg}")
            return
        valid, msg = self.validate_binary_input(ciphertext, 8)
        if not valid:
            messagebox.showerror("输入错误", f"密文{msg}")
            return
        if not (1 <= num_threads <= 16):
            messagebox.showerror("输入错误", "线程数必须为1~16之间的整数")
            return

        # 初始化状态
        self.brute_running = True
        self.brute_status.config(text="正在破解...", foreground="orange")
        self.brute_progress.config(value=0)
        self.brute_result.config(state=tk.NORMAL)
        self.brute_result.delete(1.0, tk.END)
        self.brute_result.config(state=tk.DISABLED)

        # 启动破解线程（避免阻塞GUI）
        def brute_thread():
            try:
                keys = self.sdes.brute_force(
                    plaintext, ciphertext, num_threads,
                    progress_callback=self.update_brute_progress,
                    stop_callback=lambda: not self.brute_running
                )
                self.root.after(0, self.finish_brute_force, keys)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", f"破解失败: {str(e)}"))
                self.root.after(0, self.finish_brute_force, [])

        threading.Thread(target=brute_thread, daemon=True).start()

    def stop_brute_force(self):
        """停止暴力破解"""
        if self.brute_running:
            self.brute_running = False
            self.brute_status.config(text="已停止", foreground="red")

    def update_brute_progress(self, value):
        """更新破解进度条（线程安全）"""
        def safe_update():
            self.brute_progress.config(value=value)
        self.root.after(0, safe_update)

    def finish_brute_force(self, keys):
        """完成破解并显示结果"""
        self.brute_running = False
        self.brute_status.config(text="破解完成", foreground="green")
        self.brute_progress.config(value=100)

        # 显示结果
        self.brute_result.config(state=tk.NORMAL)
        self.brute_result.delete(1.0, tk.END)
        if not keys:
            self.brute_result.insert(tk.END, "未找到匹配的密钥")
        else:
            self.brute_result.insert(tk.END, f"找到 {len(keys)} 个匹配的密钥:\n\n")
            for i, key in enumerate(keys, 1):
                self.brute_result.insert(tk.END, f"密钥 {i}: {key}\n")
        self.brute_result.config(state=tk.DISABLED)

    def clear_brute(self):
        """清空暴力破解标签页输入、状态和结果"""
        self.brute_plain_entry.delete(0, tk.END)
        self.brute_cipher_entry.delete(0, tk.END)
        self.thread_count.current(2)
        self.brute_status.config(text="就绪", foreground="blue")
        self.brute_progress.config(value=0)
        self.brute_result.config(state=tk.NORMAL)
        self.brute_result.delete(1.0, tk.END)
        self.brute_result.config(state=tk.DISABLED)
        self.brute_running = False


# 程序入口
if __name__ == "__main__":
    root = tk.Tk()
    app = S_DES_GUI(root)
    root.mainloop()
