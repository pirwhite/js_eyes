#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@File    :   scan.py
@Author  :   pharmaclist07 
@Version :   1.0
'''

import re
import os
import json
import time
import sys
import requests
from pathlib import Path
from typing import List, Dict, Optional, Set
from bs4 import BeautifulSoup


# 颜色控制常量（ANSI 转义序列）
class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class JSEncryptionDetector:
    def __init__(self):
        self.algorithms: Dict[str, List[str]] = {}  # 加载的特征库
        self.loaded_rules_path: Optional[str] = None  # 当前加载的规则文件路径
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        }
        self._load_default_rules()  # 初始加载默认规则

    # ------------------------------
    # 工具方法
    # ------------------------------
    @staticmethod
    def print_color(text: str, color: str = Color.WHITE, bold: bool = False) -> None:
        """带颜色的打印"""
        prefix = color + (Color.BOLD if bold else "")
        print(f"{prefix}{text}{Color.RESET}")

    @staticmethod
    def print_panel(title: str, content: str, border_char: str = "-") -> None:
        """打印面板"""
        lines = content.split("\n")
        max_len = max(len(line) for line in lines + [title])
        border = border_char * (max_len + 4)
        
        print(border)
        print(f"{border_char} {title.ljust(max_len)} {border_char}")
        print(border)
        for line in lines:
            print(f"{border_char} {line.ljust(max_len)} {border_char}")
        print(border + "\n")

    @staticmethod
    def print_table(headers: List[str], rows: List[List[str]], title: str = "") -> None:
        """打印表格"""
        if title:
            print(f"\n{Color.BOLD}{title}{Color.RESET}")
        
        # 计算每列最大宽度
        col_widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if len(cell) > col_widths[i]:
                    col_widths[i] = len(cell)
        
        # 打印表头
        header_row = "  ".join([h.ljust(w) for h, w in zip(headers, col_widths)])
        print(f"{Color.CYAN}{header_row}{Color.RESET}")
        
        # 打印分隔线
        print("-".join(["-" * w for w in col_widths]))
        
        # 打印内容行
        for row in rows:
            print("  ".join([c.ljust(w) for c, w in zip(row, col_widths)]))
        print()

    @staticmethod
    def prompt_input(message: str, default: Optional[str] = None) -> str:
        """输入提示"""
        prompt = f"{message} "
        if default is not None:
            prompt += f"[{default}] "
        return input(prompt) or default

    @staticmethod
    def confirm(message: str, default: bool = True) -> bool:
        """确认提示"""
        yes = "Y/n" if default else "y/N"
        resp = input(f"{message} ({yes}) ").strip().lower()
        if not resp:
            return default
        return resp in ("y", "yes")

    @staticmethod
    def show_progress(current: int, total: int, message: str) -> None:
        """显示进度"""
        percent = (current / total) * 100 if total > 0 else 100
        sys.stdout.write(f"\r{message} {current}/{total} ({percent:.1f}%)")
        sys.stdout.flush()
        if current == total:
            print()

    # ------------------------------
    # 特征库管理核心方法
    # ------------------------------
    def _load_default_rules(self) -> None:
        """加载内置默认规则"""
        self.algorithms = {
            "MD5": [r"\bmd5\b", r"createHash\s*\(\s*['\"]md5['\"]\s*\)"],
            "SHA-1": [r"\bsha1\b", r"createHash\s*\(\s*['\"]sha1['\"]\s*\)"],
            "SHA-256": [r"\bsha256\b", r"createHash\s*\(\s*['\"]sha256['\"]\s*\)"],
            "AES": [r"\baes\b", r"createCipher(iv)?\s*\(\s*['\"]aes-[^'\"\\)]+['\"]\s*\)", r"createDecipher(iv)?\s*\(\s*['\"]aes-[^'\"\\)]+['\"]\s*\)"],
            "RSA": [r"\brsa\b", r"createSign\s*\(\s*['\"]rsa-[^'\"\\)]+['\"]\s*\)", r"createVerify\s*\(\s*['\"]rsa-[^'\"\\)]+['\"]\s*\)"],
            "Base64": [r"\bbase64\b", r"\b(atob|btoa)\b", r"fromCharCode\s*\(\s*parseInt\s*\("],
            "DES": [r"\bdes\b", r"createCipher\s*\(\s*['\"]des['\"]\s*\)"]
        }
        self.loaded_rules_path = "内置默认规则"
        self.print_color(f"✅ 已加载默认特征库", Color.GREEN)
        self._print_rules_stats()

    def load_custom_rules(self, file_path: str) -> bool:
        """加载自定义特征库（JSON格式）"""
        # 先尝试查看规则文件内容
        if not self._view_rules_file(file_path, preview_only=True):
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)

            # 验证规则格式
            if not self._validate_rules(rules):
                return False

            # 询问是否确认加载
            if not self.confirm("是否确认加载该特征库？（当前特征库将被覆盖）"):
                self.print_color("⚠️ 已取消加载", Color.YELLOW)
                return False

            self.algorithms = rules
            self.loaded_rules_path = file_path
            self.print_color(f"✅ 成功加载自定义特征库: {file_path}", Color.GREEN)
            self._print_rules_stats()
            return True
        except Exception as e:
            self.print_color(f"❌ 加载规则失败: {str(e)}", Color.RED)
            return False

    def merge_rules(self, file_path: str) -> bool:
        """合并外部规则到当前特征库"""
        if not os.path.isfile(file_path):
            self.print_color(f"❌ 规则文件不存在: {file_path}", Color.RED)
            return False

        # 先查看要合并的规则
        if not self._view_rules_file(file_path, preview_only=True):
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                new_rules = json.load(f)

            if not isinstance(new_rules, dict):
                raise ValueError("合并的规则必须是JSON对象")

            # 验证规则格式
            if not self._validate_rules(new_rules):
                return False

            # 询问是否确认合并
            if not self.confirm("是否确认合并该特征库？"):
                self.print_color("⚠️ 已取消合并", Color.YELLOW)
                return False

            # 记录合并前状态用于统计
            prev_alg_count = len(self.algorithms)
            prev_pattern_count = sum(len(patterns) for patterns in self.algorithms.values())

            # 合并规则
            for alg, patterns in new_rules.items():
                if alg in self.algorithms:
                    # 去重合并
                    original_count = len(self.algorithms[alg])
                    self.algorithms[alg].extend(patterns)
                    self.algorithms[alg] = list(set(self.algorithms[alg]))
                    new_count = len(self.algorithms[alg])
                    self.print_color(f"  算法 {alg}: 合并前 {original_count} 个特征，合并后 {new_count} 个特征（去重 {original_count + len(patterns) - new_count} 个）", Color.BLUE)
                else:
                    self.algorithms[alg] = patterns
                    self.print_color(f"  新增算法 {alg}: {len(patterns)} 个特征", Color.GREEN)

            # 显示合并统计
            self.print_color(f"\n✅ 成功合并规则: {file_path}", Color.GREEN)
            self.print_color(f"  合并前: {prev_alg_count} 个算法，{prev_pattern_count} 个特征", Color.BLUE)
            self.print_color(f"  合并后: {len(self.algorithms)} 个算法，{sum(len(p) for p in self.algorithms.values())} 个特征", Color.BLUE)
            return True
        except Exception as e:
            self.print_color(f"❌ 合并规则失败: {str(e)}", Color.RED)
            return False

    def save_current_rules(self, output_path: str) -> bool:
        """保存当前加载的规则到文件"""
        # 保存前先显示当前规则统计
        self._print_rules_stats()
        
        if not self.confirm(f"是否确认将当前特征库保存到 {output_path}？"):
            self.print_color("⚠️ 已取消保存", Color.YELLOW)
            return False

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.algorithms, f, ensure_ascii=False, indent=2)
            self.print_color(f"✅ 规则已保存至: {output_path}", Color.GREEN)
            return True
        except Exception as e:
            self.print_color(f"❌ 保存规则失败: {str(e)}", Color.RED)
            return False

    def show_loaded_rules(self, detailed: bool = False) -> None:
        """展示当前加载的特征库信息，支持详细查看"""
        content = (
            f"当前加载: {self.loaded_rules_path}\n"
            f"包含算法: {len(self.algorithms)} 个\n"
            f"总特征数: {sum(len(patterns) for patterns in self.algorithms.values())} 个"
        )
        self.print_panel("特征库信息", content)
        
        # 询问是否需要详细查看
        if not detailed and self.confirm("是否查看详细特征信息？"):
            detailed = True
        
        if detailed:
            self._print_detailed_rules()

    def view_rules_file(self, file_path: str) -> bool:
        """查看特征库文件内容（不加载）"""
        return self._view_rules_file(file_path, preview_only=False)

    # 特征库辅助方法
    def _validate_rules(self, rules: Dict[str, List[str]]) -> bool:
        """验证规则格式是否有效"""
        if not isinstance(rules, dict):
            self.print_color("❌ 规则必须是JSON对象（键为算法名，值为特征列表）", Color.RED)
            return False
            
        for alg, patterns in rules.items():
            if not isinstance(alg, str) or not isinstance(patterns, list):
                self.print_color(f"❌ 算法 {alg} 的特征必须是字符串列表", Color.RED)
                return False
            for i, p in enumerate(patterns, 1):
                if not isinstance(p, str):
                    self.print_color(f"❌ 算法 {alg} 的第 {i} 个特征必须是字符串", Color.RED)
                    return False
                try:
                    re.compile(p)
                except re.error as e:
                    self.print_color(f"❌ 算法 {alg} 的第 {i} 个特征是无效正则表达式: {str(e)}", Color.RED)
                    return False
        return True

    def _print_rules_stats(self) -> None:
        """打印特征库统计信息"""
        alg_count = len(self.algorithms)
        pattern_count = sum(len(patterns) for patterns in self.algorithms.values())
        self.print_color(f"📊 特征库统计: {alg_count} 个算法，{pattern_count} 个特征", Color.BLUE)

    def _print_detailed_rules(self, max_patterns_per_alg: int = 5) -> None:
        """详细打印当前加载的规则"""
        for alg_idx, (alg, patterns) in enumerate(self.algorithms.items(), 1):
            self.print_color(f"\n{alg_idx}. 算法: {alg}", Color.CYAN, bold=True)
            self.print_color(f"   特征数: {len(patterns)} 个", Color.BLUE)
            
            # 显示特征，超过max_patterns_per_alg时截断
            for pat_idx, pattern in enumerate(patterns, 1):
                if pat_idx > max_patterns_per_alg:
                    self.print_color(f"   ... 还有 {len(patterns) - max_patterns_per_alg} 个特征未显示", Color.YELLOW)
                    break
                self.print_color(f"   {pat_idx}. {pattern}", Color.WHITE)

    def _view_rules_file(self, file_path: str, preview_only: bool = True) -> bool:
        """查看规则文件内容，preview_only=True时仅预览不加载"""
        if not os.path.isfile(file_path):
            self.print_color(f"❌ 规则文件不存在: {file_path}", Color.RED)
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    rules = json.load(f)
                except json.JSONDecodeError as e:
                    self.print_color(f"❌ JSON格式错误 (行 {e.lineno}, 列 {e.colno}): {e.msg}", Color.RED)
                    return False

            # 验证规则
            if not self._validate_rules(rules):
                return False

            # 显示规则统计
            alg_count = len(rules)
            pattern_count = sum(len(patterns) for patterns in rules.values())
            self.print_panel(
                f"{'预览' if preview_only else '查看'}特征库文件: {file_path}",
                f"算法数量: {alg_count}\n特征总数: {pattern_count}"
            )

            # 询问是否查看详细内容
            if self.confirm("是否查看详细内容？"):
                self._print_detailed_rules_from_dict(rules)

            return True
        except Exception as e:
            self.print_color(f"❌ 处理规则文件失败: {str(e)}", Color.RED)
            return False

    def _print_detailed_rules_from_dict(self, rules: Dict[str, List[str]], max_patterns_per_alg: int = 5) -> None:
        """从字典详细打印规则"""
        for alg_idx, (alg, patterns) in enumerate(rules.items(), 1):
            self.print_color(f"\n{alg_idx}. 算法: {alg}", Color.CYAN, bold=True)
            self.print_color(f"   特征数: {len(patterns)} 个", Color.BLUE)
            
            # 显示特征，超过max_patterns_per_alg时截断
            for pat_idx, pattern in enumerate(patterns, 1):
                if pat_idx > max_patterns_per_alg:
                    self.print_color(f"   ... 还有 {len(patterns) - max_patterns_per_alg} 个特征未显示", Color.YELLOW)
                    break
                self.print_color(f"   {pat_idx}. {pattern}", Color.WHITE)

    # ------------------------------
    # 代码预处理
    # ------------------------------
    def remove_comments(self, js_code: str) -> str:
        """移除JS代码中的注释"""
        code = re.sub(r"//.*?$", "", js_code, flags=re.MULTILINE)  # 单行注释
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)      # 多行注释
        return code

    @staticmethod
    def _extract_js_from_html(html_code: str) -> str:
        """从HTML中提取<script>标签内的JS代码"""
        soup = BeautifulSoup(html_code, 'html.parser')
        script_tags = soup.find_all('script')
        js_blocks = []
        for tag in script_tags:
            if tag.string:
                js_blocks.append(tag.string.strip())
        return "\n".join(js_blocks)

    # ------------------------------
    # 加密算法检测
    # ------------------------------
    def detect_in_code(self, js_code: str, source: str) -> List[Dict]:
        """检测代码中的加密算法（source为来源标识：文件路径或URL）"""
        results = []
        cleaned_code = self.remove_comments(js_code)
        lines = cleaned_code.splitlines()

        for alg_name, patterns in self.algorithms.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, cleaned_code, re.IGNORECASE)
                    for match in matches:
                        line_num = self._get_line_number(cleaned_code, match.start()) + 1
                        context = self._get_context(lines, line_num)
                        results.append({
                            "algorithm": alg_name,
                            "source": source,
                            "line": line_num,
                            "match": match.group(),
                            "context": context
                        })
                except re.error:
                    self.print_color(f"❌ 无效正则表达式: {pattern} (算法: {alg_name})", Color.RED)

        return self._deduplicate(results)

    @staticmethod
    def _get_line_number(code: str, position: int) -> int:
        """根据字符位置计算行号（0开始）"""
        return code[:position].count('\n')

    @staticmethod
    def _get_context(lines: List[str], line_num: int, context_lines: int = 2) -> str:
        """获取匹配行的上下文代码"""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        context = []
        for i in range(start, end):
            line = lines[i].strip()
            if line:
                context.append(f"Line {i+1}: {line}")
        return "\n".join(context)

    @staticmethod
    def _deduplicate(results: List[Dict]) -> List[Dict]:
        """去重结果（同一算法+来源+行号）"""
        seen = set()
        unique = []
        for res in results:
            key = (res["algorithm"], res["source"], res["line"])
            if key not in seen:
                seen.add(key)
                unique.append(res)
        return unique

    # ------------------------------
    # 本地文件检测
    # ------------------------------
    def detect_local_file(self, file_path: str) -> List[Dict]:
        """检测本地文件（JS/HTML）"""
        if not os.path.isfile(file_path):
            self.print_color(f"❌ 文件不存在: {file_path}", Color.RED)
            return []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # 处理HTML文件
            if file_path.endswith(('.html', '.htm')):
                js_code = self._extract_js_from_html(content)
            else:
                js_code = content

            return self.detect_in_code(js_code, file_path)
        except Exception as e:
            self.print_color(f"❌ 处理文件错误 {file_path}: {str(e)}", Color.RED)
            return []

    def detect_directory(self, dir_path: str) -> List[Dict]:
        """检测目录下所有JS/HTML文件"""
        if not os.path.isdir(dir_path):
            self.print_color(f"❌ 目录不存在: {dir_path}", Color.RED)
            return []

        results = []
        extensions = ('.js', '.mjs', '.cjs', '.html', '.htm')
        files = [str(f) for f in Path(dir_path).rglob('*') if f.suffix in extensions]
        total = len(files)

        if total == 0:
            self.print_color("⚠️ 未找到符合条件的文件", Color.YELLOW)
            return []

        for i, file in enumerate(files, 1):
            self.show_progress(i, total, f"正在处理: {os.path.basename(file)}")
            results.extend(self.detect_local_file(file))
            time.sleep(0.01)  # 避免输出过快

        return results

    # ------------------------------
    # 网页爬虫与检测
    # ------------------------------
    def crawl_and_detect(self, url: str, max_depth: int = 1) -> List[Dict]:
        """爬取网页并检测JS中的加密算法"""
        results = []
        visited: Set[str] = set()  # 已爬取的URL

        def _crawl(current_url: str, depth: int) -> None:
            if depth > max_depth or current_url in visited:
                return
            visited.add(current_url)
            print(f"\n{Color.BLUE}爬取: {current_url} (深度: {depth}){Color.RESET}")

            try:
                # 爬取页面
                response = self.session.get(current_url, timeout=10)
                response.raise_for_status()
                html = response.text

                # 提取内联JS并检测
                js_code = self._extract_js_from_html(html)
                if js_code:
                    results.extend(self.detect_in_code(js_code, f"内联JS: {current_url}"))

                # 提取外部JS链接并递归爬取
                soup = BeautifulSoup(html, 'html.parser')
                script_tags = soup.find_all('script', src=True)
                for tag in script_tags:
                    js_src = tag['src']
                    # 处理相对URL
                    js_url = requests.compat.urljoin(current_url, js_src)
                    if js_url.endswith('.js') and js_url not in visited:
                        # 爬取外部JS文件
                        try:
                            js_response = self.session.get(js_url, timeout=10)
                            js_response.raise_for_status()
                            results.extend(self.detect_in_code(js_response.text, f"外部JS: {js_url}"))
                            _crawl(js_url, depth + 1)  # 递归爬取（深度+1）
                        except Exception as e:
                            self.print_color(f"⚠️ 爬取JS失败 {js_url}: {str(e)}", Color.YELLOW)

            except Exception as e:
                self.print_color(f"⚠️ 爬取页面失败 {current_url}: {str(e)}", Color.YELLOW)

        # 开始爬取
        _crawl(url, depth=1)
        self.print_color(f"✅ 爬取完成，共处理 {len(visited)} 个URL", Color.GREEN)
        return results

    # ------------------------------
    # 结果展示
    # ------------------------------
    def display_results(self, results: List[Dict]) -> None:
        """用表格展示检测结果"""
        if not results:
            self.print_panel("结果", "未检测到加密算法")
            return

        # 按算法分组
        grouped = {}
        for res in results:
            alg = res["algorithm"]
            if alg not in grouped:
                grouped[alg] = []
            grouped[alg].append(res)

        # 展示每个算法的结果
        for alg, items in grouped.items():
            # 准备表格数据
            headers = ["来源", "行号", "匹配内容"]
            rows = []
            for item in items:
                rows.append([
                    item["source"],
                    str(item["line"]),
                    item["match"]
                ])
            self.print_table(headers, rows, title=f"{Color.MAGENTA}{alg} 算法 (共 {len(items)} 处){Color.RESET}")

            # 询问是否查看上下文
            if self.confirm(f"是否查看 {alg} 的匹配上下文？"):
                for i, item in enumerate(items):
                    print(f"\n{Color.BOLD}===== {item['source']} (行号: {item['line']}) ====={Color.RESET}")
                    print(item["context"])
                    if i < len(items) - 1 and not self.confirm("查看下一个？", default=True):
                        break

    # ------------------------------
    # 主交互菜单
    # ------------------------------
    def main_menu(self) -> None:
        """主菜单交互逻辑"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')  # 清屏
            self.print_panel(
                "主菜单",
                (f"{Color.GREEN}JS加密算法检测器{Color.RESET}\n"
                 f"当前特征库: {Color.CYAN}{self.loaded_rules_path}{Color.RESET}\n"
                 f"支持算法: {Color.YELLOW}{', '.join(self.algorithms.keys())}{Color.RESET}")
            )

            print("请选择操作:")
            print("1. 检测本地文件")
            print("2. 检测目录")
            print("3. 爬取网页检测")
            print("4. 特征库管理")
            print("5. 退出")

            choice = self.prompt_input("输入选项", "1").strip()

            if choice == "1":
                self._handle_local_file()
            elif choice == "2":
                self._handle_directory()
            elif choice == "3":
                self._handle_crawl()
            elif choice == "4":
                self._rules_management_menu()
            elif choice == "5":
                self.print_color("👋 再见！", Color.GREEN)
                break
            else:
                self.print_color("❌ 无效选择，请重试", Color.RED)
                time.sleep(1)

    def _handle_local_file(self) -> None:
        """处理本地文件检测"""
        file_path = self.prompt_input("请输入文件路径", "test.js")
        print("正在检测...")
        results = self.detect_local_file(file_path)
        self.display_results(results)
        input("按回车返回主菜单...")

    def _handle_directory(self) -> None:
        """处理目录检测"""
        dir_path = self.prompt_input("请输入目录路径", "./")
        results = self.detect_directory(dir_path)
        self.display_results(results)
        input("按回车返回主菜单...")

    def _handle_crawl(self) -> None:
        """处理网页爬取检测"""
        url = self.prompt_input("请输入网页URL", "https://example.com")
        max_depth = 1
        while True:
            try:
                depth_input = self.prompt_input("爬取深度 (1-3)", "1")
                max_depth = int(depth_input)
                if 1 <= max_depth <= 3:
                    break
                else:
                    self.print_color("请输入1-3之间的数字", Color.RED)
            except ValueError:
                self.print_color("请输入有效的数字", Color.RED)

        results = self.crawl_and_detect(url, max_depth)
        self.display_results(results)
        input("按回车返回主菜单...")

    def _rules_management_menu(self) -> None:
        """特征库管理子菜单（优化版）"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')  # 清屏
            self.show_loaded_rules()
            self.print_panel("特征库管理", "")
            
            print("1. 加载自定义规则")
            print("2. 合并规则")
            print("3. 保存当前规则")
            print("4. 查看特征库文件（不加载）")
            print("5. 详细查看当前特征库")
            print("6. 恢复默认规则")
            print("7. 返回主菜单")

            choice = self.prompt_input("输入选项", "7").strip()

            if choice == "1":
                path = self.prompt_input("请输入规则文件路径")
                self.load_custom_rules(path)
            elif choice == "2":
                path = self.prompt_input("请输入要合并的规则文件路径")
                self.merge_rules(path)
            elif choice == "3":
                path = self.prompt_input("请输入保存路径", "current_rules.json")
                self.save_current_rules(path)
            elif choice == "4":
                path = self.prompt_input("请输入要查看的规则文件路径")
                self.view_rules_file(path)
            elif choice == "5":
                self.show_loaded_rules(detailed=True)
            elif choice == "6":
                if self.confirm("确定要恢复默认规则吗？(当前规则将被覆盖)"):
                    self._load_default_rules()
            elif choice == "7":
                break
            else:
                self.print_color("❌ 无效选择，请重试", Color.RED)

            input("按回车继续...")


if __name__ == "__main__":
    try:
        detector = JSEncryptionDetector()
        detector.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}⚠️ 程序被中断{Color.RESET}")
    except Exception as e:
        print(f"{Color.RED}❌ 程序出错: {str(e)}{Color.RESET}")