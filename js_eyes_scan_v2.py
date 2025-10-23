#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@File    :   js_eyes_scan_v2.py
@Author  :   pharmaclist07 
@Version :   1.0
'''


import re
import os
import json
import time
import sys
import logging
from logging.handlers import RotatingFileHandler
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
        self._init_logger()  # 初始化日志系统
        self._load_default_rules()  # 初始加载默认规则
        self.current_detection_results: List[Dict] = []  # 存储当前检测结果

    # ------------------------------
    # 日志系统初始化
    # ------------------------------
    def _init_logger(self) -> None:
        """初始化日志系统，同时输出到控制台和文件"""
        self.logger = logging.getLogger("JSEncryptionDetector")
        self.logger.setLevel(logging.DEBUG)
        
        # 日志格式
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # 文件处理器（自动轮转，最大10MB，保留3个备份）
        file_handler = RotatingFileHandler(
            'debug.log',
            maxBytes=10*1024*1024,
            backupCount=3,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # 添加处理器
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
        self.logger.info("日志系统初始化完成")

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
        try:
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
            self.logger.info("成功加载默认特征库")
        except Exception as e:
            self.print_color(f"❌ 加载默认规则失败: {str(e)}", Color.RED)
            self.logger.error(f"加载默认规则失败: {str(e)}")

    def load_custom_rules(self, file_path: str) -> bool:
        """加载自定义特征库（增强JSON解析错误提示）"""
        self.logger.info(f"尝试加载自定义规则: {file_path}")
        if not os.path.isfile(file_path):
            self.print_color(f"❌ 规则文件不存在: {file_path}", Color.RED)
            return False

        try:
            # 读取文件内容（增加编码容错）
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                file_content = f.read()

            # 尝试解析JSON（分步处理，增强错误提示）
            try:
                rules = json.loads(file_content)
            except json.JSONDecodeError as e:
                # 提取错误位置附近的内容，帮助用户定位问题
                error_context = self._get_json_error_context(file_content, e.lineno, e.colno)
                self.print_color(f"\n❌ JSON解析失败 (行 {e.lineno}, 列 {e.colno}):", Color.RED)
                self.print_color(f"   错误原因: {e.msg}", Color.RED)
                self.print_color(f"   附近内容: {error_context}", Color.RED)
                self.print_color(f"   提示: 检查是否缺少引号、逗号或括号", Color.YELLOW)
                self.logger.error(f"JSON解析失败: {e}，文件: {file_path}")
                return False

            # 验证规则格式
            if not self._validate_rules(rules):
                self.logger.warning(f"规则文件格式无效: {file_path}")
                return False

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
            self.logger.error(f"加载规则失败: {str(e)}", exc_info=True)
            return False

    def merge_rules(self, file_path: str) -> bool:
        """合并外部规则到当前特征库"""
        self.logger.info(f"尝试合并规则文件: {file_path}")
        if not os.path.isfile(file_path):
            self.print_color(f"❌ 规则文件不存在: {file_path}", Color.RED)
            self.logger.error(f"规则文件不存在: {file_path}")
            return False

        if not self._view_rules_file(file_path, preview_only=True):
            self.logger.warning(f"规则文件预览失败: {file_path}")
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                new_rules = json.load(f)
            self.logger.debug(f"成功读取待合并规则: {file_path}")

            if not isinstance(new_rules, dict):
                raise ValueError("合并的规则必须是JSON对象")

            if not self._validate_rules(new_rules):
                self.logger.warning(f"待合并规则格式无效: {file_path}")
                return False

            if not self.confirm("是否确认合并该特征库？"):
                self.print_color("⚠️ 已取消合并", Color.YELLOW)
                self.logger.info("用户取消合并规则")
                return False

            prev_alg_count = len(self.algorithms)
            prev_pattern_count = sum(len(patterns) for patterns in self.algorithms.values())

            for alg, patterns in new_rules.items():
                if alg in self.algorithms:
                    original_count = len(self.algorithms[alg])
                    self.algorithms[alg].extend(patterns)
                    self.algorithms[alg] = list(set(self.algorithms[alg]))
                    new_count = len(self.algorithms[alg])
                    self.print_color(f"  算法 {alg}: 合并前 {original_count} 个特征，合并后 {new_count} 个特征（去重 {original_count + len(patterns) - new_count} 个）", Color.BLUE)
                    self.logger.debug(f"合并算法 {alg}: 原{original_count}个，新增{len(patterns)}个，去重后{new_count}个")
                else:
                    self.algorithms[alg] = patterns
                    self.print_color(f"  新增算法 {alg}: {len(patterns)} 个特征", Color.GREEN)
                    self.logger.debug(f"新增算法 {alg}: {len(patterns)} 个特征")

            self.print_color(f"\n✅ 成功合并规则: {file_path}", Color.GREEN)
            self.print_color(f"  合并前: {prev_alg_count} 个算法，{prev_pattern_count} 个特征", Color.BLUE)
            self.print_color(f"  合并后: {len(self.algorithms)} 个算法，{sum(len(p) for p in self.algorithms.values())} 个特征", Color.BLUE)
            self.logger.info(f"成功合并规则: {file_path}")
            return True
        except Exception as e:
            self.print_color(f"❌ 合并规则失败: {str(e)}", Color.RED)
            self.logger.error(f"合并规则失败: {str(e)}", exc_info=True)
            return False

    def save_current_rules(self, output_path: str) -> bool:
        """保存当前加载的规则到文件"""
        self.logger.info(f"尝试保存当前规则到: {output_path}")
        self._print_rules_stats()
        
        if not self.confirm(f"是否确认将当前特征库保存到 {output_path}？"):
            self.print_color("⚠️ 已取消保存", Color.YELLOW)
            self.logger.info("用户取消保存规则")
            return False

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.algorithms, f, ensure_ascii=False, indent=2)
            self.print_color(f"✅ 规则已保存至: {output_path}", Color.GREEN)
            self.logger.info(f"规则已保存至: {output_path}")
            return True
        except Exception as e:
            self.print_color(f"❌ 保存规则失败: {str(e)}", Color.RED)
            self.logger.error(f"保存规则失败: {str(e)}", exc_info=True)
            return False

    def show_loaded_rules(self, detailed: bool = False) -> None:
        """展示当前加载的特征库信息，支持详细查看"""
        self.logger.info("展示当前加载的特征库信息")
        content = (
            f"当前加载: {self.loaded_rules_path}\n"
            f"包含算法: {len(self.algorithms)} 个\n"
            f"总特征数: {sum(len(patterns) for patterns in self.algorithms.values())} 个"
        )
        self.print_panel("特征库信息", content)
        
        if not detailed and self.confirm("是否查看详细特征信息？"):
            detailed = True
        
        if detailed:
            self._print_detailed_rules()

    def view_rules_file(self, file_path: str) -> bool:
        """查看特征库文件内容（不加载）"""
        self.logger.info(f"查看规则文件: {file_path}")
        return self._view_rules_file(file_path, preview_only=False)

    # 特征库辅助方法
    def _validate_rules(self, rules: Dict[str, List[str]]) -> bool:
        """验证规则格式（增强正则表达式错误提示）"""
        if not isinstance(rules, dict):
            self.print_color("❌ 规则必须是JSON对象（键为算法名，值为特征列表）", Color.RED)
            return False
            
        for alg, patterns in rules.items():
            # 验证算法名和特征列表类型
            if not isinstance(alg, str):
                self.print_color(f"❌ 算法名必须是字符串，当前: {type(alg).__name__}", Color.RED)
                return False
            if not isinstance(patterns, list):
                self.print_color(f"❌ 算法 {alg} 的特征必须是列表，当前: {type(patterns).__name__}", Color.RED)
                return False
            
            # 验证每个特征是否为有效的正则表达式
            for i, pattern in enumerate(patterns, 1):
                if not isinstance(pattern, str):
                    self.print_color(f"❌ 算法 {alg} 的第 {i} 个特征必须是字符串，当前: {type(pattern).__name__}", Color.RED)
                    return False
                
                # 正则表达式验证（增加详细错误提示）
                try:
                    re.compile(pattern)
                except re.error as e:
                    self.print_color(f"\n❌ 算法 {alg} 的第 {i} 个特征是无效正则表达式:", Color.RED)
                    self.print_color(f"   特征内容: {pattern}", Color.RED)
                    self.print_color(f"   错误原因: {e.msg} (位置: {e.pos})", Color.RED)
                    self.print_color(f"   提示: 检查特殊字符是否转义（如引号、反斜杠）", Color.YELLOW)
                    return False
        
        return True
    @staticmethod
    def _get_json_error_context(content: str, lineno: int, colno: int) -> str:
        """提取JSON解析错误位置附近的内容，帮助用户定位问题"""
        lines = content.splitlines()
        # 取错误行及前后各1行
        start_line = max(0, lineno - 2)
        end_line = min(len(lines), lineno)
        
        context = []
        for i in range(start_line, end_line):
            line = lines[i].rstrip()
            # 标记错误位置
            if i == lineno - 1:  # JSON的行号是从1开始的
                # 截断过长的行，只显示错误位置附近
                max_context_len = 50
                start = max(0, colno - 20)
                end = min(len(line), colno + 30)
                snippet = line[start:end]
                # 在错误位置添加标记
                marker = " " * (min(colno - 1, 20)) + "^"
                context.append(f"第{i+1}行: {snippet}")
                context.append(f"错误位置: {marker}")
            else:
                context.append(f"第{i+1}行: {line[:50]}...")  # 只显示前50字符
        
        return "\n       ".join(context)

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
            
            for pat_idx, pattern in enumerate(patterns, 1):
                if pat_idx > max_patterns_per_alg:
                    self.print_color(f"   ... 还有 {len(patterns) - max_patterns_per_alg} 个特征未显示", Color.YELLOW)
                    break
                self.print_color(f"   {pat_idx}. {pattern}", Color.WHITE)

    def _view_rules_file(self, file_path: str, preview_only: bool = True) -> bool:
        """查看规则文件内容，preview_only=True时仅预览不加载"""
        if not os.path.isfile(file_path):
            self.print_color(f"❌ 规则文件不存在: {file_path}", Color.RED)
            self.logger.error(f"规则文件不存在: {file_path}")
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    rules = json.load(f)
                except json.JSONDecodeError as e:
                    self.print_color(f"❌ JSON格式错误 (行 {e.lineno}, 列 {e.colno}): {e.msg}", Color.RED)
                    self.logger.error(f"JSON格式错误 (行 {e.lineno}, 列 {e.colno}): {e.msg}")
                    return False

            if not self._validate_rules(rules):
                return False

            alg_count = len(rules)
            pattern_count = sum(len(patterns) for patterns in rules.values())
            self.print_panel(
                f"{'预览' if preview_only else '查看'}特征库文件: {file_path}",
                f"算法数量: {alg_count}\n特征总数: {pattern_count}"
            )

            if self.confirm("是否查看详细内容？"):
                self._print_detailed_rules_from_dict(rules)

            return True
        except Exception as e:
            self.print_color(f"❌ 处理规则文件失败: {str(e)}", Color.RED)
            self.logger.error(f"处理规则文件失败: {str(e)}", exc_info=True)
            return False

    def _print_detailed_rules_from_dict(self, rules: Dict[str, List[str]], max_patterns_per_alg: int = 5) -> None:
        """从字典详细打印规则"""
        for alg_idx, (alg, patterns) in enumerate(rules.items(), 1):
            self.print_color(f"\n{alg_idx}. 算法: {alg}", Color.CYAN, bold=True)
            self.print_color(f"   特征数: {len(patterns)} 个", Color.BLUE)
            
            for pat_idx, pattern in enumerate(patterns, 1):
                if pat_idx > max_patterns_per_alg:
                    self.print_color(f"   ... 还有 {len(patterns) - max_patterns_per_alg} 个特征未显示", Color.YELLOW)
                    break
                self.print_color(f"   {pat_idx}. {pattern}", Color.WHITE)

    # ------------------------------
    # 密钥信息保存相关方法
    # ------------------------------
    def _get_unique_key_filename(self) -> str:
        """生成唯一的key文件名，避免覆盖现有文件"""
        base_name = "key"
        ext = "json"
        counter = 1
        
        if not os.path.exists(f"{base_name}.{ext}"):
            return f"{base_name}.{ext}"
        
        while os.path.exists(f"{base_name}_{counter}.{ext}"):
            counter += 1
            if counter > 1000:
                raise Exception("已达到最大文件保存数量")
                
        return f"{base_name}_{counter}.{ext}"

    def save_detected_keys(self) -> bool:
        """保存检测到的算法和密钥信息到JSON文件"""
        if not self.current_detection_results:
            self.print_color("⚠️ 没有可保存的检测结果", Color.YELLOW)
            self.logger.warning("尝试保存空的检测结果")
            return False

        try:
            filename = self._get_unique_key_filename()
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "count": len(self.current_detection_results),
                    "results": self.current_detection_results
                }, f, ensure_ascii=False, indent=2)
            
            self.print_color(f"✅ 检测结果已保存至: {filename}", Color.GREEN)
            self.logger.info(f"检测结果已保存至: {filename}，共{len(self.current_detection_results)}条记录")
            return True
        except Exception as e:
            self.print_color(f"❌ 保存检测结果失败: {str(e)}", Color.RED)
            self.logger.error(f"保存检测结果失败: {str(e)}", exc_info=True)
            return False

    def view_saved_keys(self) -> None:
        """查看已保存的密钥信息文件（修复版）"""
        self.logger.info("查看已保存的密钥信息")
        try:
            # 修复1：使用fullmatch确保完整匹配文件名，避免匹配类似key.json.bak的文件
            key_files = [
                f for f in os.listdir('.') 
                if os.path.isfile(f) and re.fullmatch(r'key(_\d+)?\.json', f)
            ]
            
            if not key_files:
                self.print_color("⚠️ 未找到保存的密钥信息文件", Color.YELLOW)
                return
                
            # 修复2：按修改时间排序（最新的在前），增加异常处理
            try:
                key_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            except Exception as e:
                self.print_color(f"⚠️ 排序文件时出错，将使用原始顺序: {str(e)}", Color.YELLOW)
                self.logger.warning(f"排序文件失败: {str(e)}")
            
            # 修复3：显示文件列表时增加序号，方便用户选择
            self.print_panel("已保存的密钥信息文件（按修改时间排序）", 
                           "\n".join([f"{i+1}. {f}" for i, f in enumerate(key_files)]))
            
            # 修复4：优化用户选择流程，支持输入序号或文件名
            if self.confirm("是否查看某个文件的内容？"):
                choice = self.prompt_input(
                    f"请输入文件序号(1-{len(key_files)})或文件名", 
                    f"1"
                ).strip()
                
                # 处理序号输入
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(key_files):
                        filename = key_files[idx]
                    else:
                        self.print_color(f"❌ 无效序号，必须在1-{len(key_files)}之间", Color.RED)
                        return
                else:
                    filename = choice  # 处理文件名输入
                
                if not os.path.exists(filename):
                    self.print_color("❌ 文件不存在", Color.RED)
                    self.logger.error(f"用户指定的文件不存在: {filename}")
                    return
                
                # 修复5：增强JSON文件读取的错误处理
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        try:
                            data = json.load(f)
                        except json.JSONDecodeError as e:
                            self.print_color(f"❌ 文件格式错误（不是有效的JSON）: 行 {e.lineno}, 列 {e.colno}", Color.RED)
                            self.logger.error(f"文件 {filename} JSON格式错误: {str(e)}")
                            return
                    
                    # 验证文件结构
                    required_keys = ["timestamp", "count", "results"]
                    if not all(k in data for k in required_keys):
                        self.print_color("❌ 文件格式错误，缺少必要字段", Color.RED)
                        self.logger.error(f"文件 {filename} 结构无效")
                        return
                    
                    self.print_panel(
                        f"文件内容: {filename}", 
                        f"保存时间: {data['timestamp']}\n记录数量: {data['count']}"
                    )
                    
                    if self.confirm("是否查看详细内容？"):
                        for i, item in enumerate(data['results'], 1):
                            self.print_color(f"\n{i}. 算法: {item.get('algorithm', '未知')}", Color.MAGENTA, bold=True)
                            self.print_color(f"   来源: {item.get('source', '未知')}", Color.BLUE)
                            self.print_color(f"   行号: {item.get('line', '未知')}", Color.BLUE)
                            self.print_color(f"   匹配内容: {item.get('match', '未知')}", Color.WHITE)
                            if self.confirm("查看上下文？", default=False):
                                print(f"上下文:\n{item.get('context', '无上下文')}\n")
                except Exception as e:
                    self.print_color(f"❌ 查看文件失败: {str(e)}", Color.RED)
                    self.logger.error(f"查看文件 {filename} 失败: {str(e)}", exc_info=True)
        except Exception as e:
            self.print_color(f"❌ 查看保存的密钥信息时出错: {str(e)}", Color.RED)
            self.logger.error(f"查看保存的密钥信息失败: {str(e)}", exc_info=True)

    # ------------------------------
    # 代码预处理
    # ------------------------------
    def remove_comments(self, js_code: str) -> str:
        """移除JS代码中的注释"""
        try:
            code = re.sub(r"//.*?$", "", js_code, flags=re.MULTILINE)  # 单行注释
            code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)      # 多行注释
            self.logger.debug("成功移除JS注释")
            return code
        except Exception as e:
            self.logger.error(f"移除JS注释失败: {str(e)}", exc_info=True)
            return js_code

    @staticmethod
    def _extract_js_from_html(html_code: str) -> str:
        """从HTML中提取<script>标签内的JS代码"""
        try:
            soup = BeautifulSoup(html_code, 'html.parser')
            script_tags = soup.find_all('script')
            js_blocks = []
            for tag in script_tags:
                if tag.string:
                    js_blocks.append(tag.string.strip())
            return "\n".join(js_blocks)
        except Exception as e:
            logging.error(f"提取HTML中的JS代码失败: {str(e)}", exc_info=True)
            return ""

    # ------------------------------
    # 加密算法检测
    # ------------------------------
    def detect_in_code(self, js_code: str, source: str) -> List[Dict]:
        """检测代码中的加密算法（source为来源标识：文件路径或URL）"""
        self.logger.info(f"开始检测代码中的加密算法，来源: {source}")
        results = []
        cleaned_code = self.remove_comments(js_code)
        lines = cleaned_code.splitlines()

        for alg_name, patterns in self.algorithms.items():
            self.logger.debug(f"检测算法: {alg_name}，特征数: {len(patterns)}")
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, cleaned_code, re.IGNORECASE)
                    match_count = 0
                    for match in matches:
                        match_count += 1
                        line_num = self._get_line_number(cleaned_code, match.start()) + 1
                        context = self._get_context(lines, line_num)
                        result = {
                            "algorithm": alg_name,
                            "source": source,
                            "line": line_num,
                            "match": match.group(),
                            "context": context
                        }
                        results.append(result)
                    self.logger.debug(f"算法 {alg_name} 使用模式 {pattern} 匹配到 {match_count} 处")
                except re.error as e:
                    self.print_color(f"❌ 无效正则表达式: {pattern} (算法: {alg_name})", Color.RED)
                    self.logger.error(f"无效正则表达式 {pattern} (算法: {alg_name}): {str(e)}")

        unique_results = self._deduplicate(results)
        self.logger.info(f"代码检测完成，来源: {source}，共发现 {len(unique_results)} 处匹配")
        return unique_results

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
        self.logger.info(f"开始检测本地文件: {file_path}")
        if not os.path.isfile(file_path):
            self.print_color(f"❌ 文件不存在: {file_path}", Color.RED)
            self.logger.error(f"文件不存在: {file_path}")
            return []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.logger.debug(f"成功读取文件: {file_path}，大小: {len(content)} 字符")

            if file_path.endswith(('.html', '.htm')):
                js_code = self._extract_js_from_html(content)
                self.logger.debug(f"从HTML文件中提取JS代码，长度: {len(js_code)} 字符")
            else:
                js_code = content

            results = self.detect_in_code(js_code, file_path)
            self.logger.info(f"本地文件检测完成: {file_path}，发现 {len(results)} 处匹配")
            return results
        except Exception as e:
            self.print_color(f"❌ 处理文件错误 {file_path}: {str(e)}", Color.RED)
            self.logger.error(f"处理文件错误 {file_path}: {str(e)}", exc_info=True)
            return []

    def detect_directory(self, dir_path: str) -> List[Dict]:
        """检测目录下所有JS/HTML文件"""
        self.logger.info(f"开始检测目录: {dir_path}")
        if not os.path.isdir(dir_path):
            self.print_color(f"❌ 目录不存在: {dir_path}", Color.RED)
            self.logger.error(f"目录不存在: {dir_path}")
            return []

        results = []
        extensions = ('.js', '.mjs', '.cjs', '.html', '.htm')
        files = [str(f) for f in Path(dir_path).rglob('*') if f.suffix in extensions]
        total = len(files)

        if total == 0:
            self.print_color("⚠️ 未找到符合条件的文件", Color.YELLOW)
            self.logger.warning(f"目录 {dir_path} 中未找到符合条件的文件")
            return []

        self.logger.info(f"在目录 {dir_path} 中找到 {total} 个文件待检测")
        for i, file in enumerate(files, 1):
            self.show_progress(i, total, f"正在处理: {os.path.basename(file)}")
            file_results = self.detect_local_file(file)
            results.extend(file_results)
            time.sleep(0.01)

        self.logger.info(f"目录检测完成: {dir_path}，共发现 {len(results)} 处匹配")
        return results

    # ------------------------------
    # 网页爬虫与检测
    # ------------------------------
    def crawl_and_detect(self, url: str, max_depth: int = 1) -> List[Dict]:
        """爬取网页并检测JS中的加密算法"""
        self.logger.info(f"开始爬取并检测网页: {url}，最大深度: {max_depth}")
        results = []
        visited: Set[str] = set()

        def _crawl(current_url: str, depth: int) -> None:
            if depth > max_depth or current_url in visited:
                return
            visited.add(current_url)
            self.logger.info(f"爬取URL: {current_url}，深度: {depth}")
            print(f"\n{Color.BLUE}爬取: {current_url} (深度: {depth}){Color.RESET}")

            try:
                response = self.session.get(current_url, timeout=10)
                response.raise_for_status()
                html = response.text
                self.logger.debug(f"成功爬取 {current_url}，状态码: {response.status_code}")

                js_code = self._extract_js_from_html(html)
                if js_code:
                    self.logger.debug(f"从 {current_url} 提取内联JS代码，长度: {len(js_code)}")
                    inline_results = self.detect_in_code(js_code, f"内联JS: {current_url}")
                    results.extend(inline_results)

                soup = BeautifulSoup(html, 'html.parser')
                script_tags = soup.find_all('script', src=True)
                self.logger.debug(f"在 {current_url} 中找到 {len(script_tags)} 个外部JS链接")

                for tag in script_tags:
                    js_src = tag['src']
                    js_url = requests.compat.urljoin(current_url, js_src)
                    if js_url.endswith('.js') and js_url not in visited:
                        try:
                            self.logger.debug(f"尝试爬取外部JS: {js_url}")
                            js_response = self.session.get(js_url, timeout=10)
                            js_response.raise_for_status()
                            js_content = js_response.text
                            self.logger.debug(f"成功爬取外部JS: {js_url}")
                            
                            js_results = self.detect_in_code(js_content, f"外部JS: {js_url}")
                            results.extend(js_results)
                            
                            _crawl(js_url, depth + 1)
                        except Exception as e:
                            self.print_color(f"⚠️ 爬取JS失败 {js_url}: {str(e)}", Color.YELLOW)
                            self.logger.warning(f"爬取JS失败 {js_url}: {str(e)}")

            except Exception as e:
                self.print_color(f"⚠️ 爬取页面失败 {current_url}: {str(e)}", Color.YELLOW)
                self.logger.warning(f"爬取页面失败 {current_url}: {str(e)}")

        _crawl(url, depth=1)
        self.print_color(f"✅ 爬取完成，共处理 {len(visited)} 个URL", Color.GREEN)
        self.logger.info(f"爬取完成，共处理 {len(visited)} 个URL，发现 {len(results)} 处匹配")
        return results

    # ------------------------------
    # 结果展示
    # ------------------------------
    def display_results(self, results: List[Dict]) -> None:
        """用表格展示检测结果并更新当前结果列表"""
        self.current_detection_results = results
        self.logger.info(f"展示检测结果，共 {len(results)} 条记录")
        
        if not results:
            self.print_panel("结果", "未检测到加密算法")
            return

        grouped = {}
        for res in results:
            alg = res["algorithm"]
            if alg not in grouped:
                grouped[alg] = []
            grouped[alg].append(res)

        for alg, items in grouped.items():
            headers = ["来源", "行号", "匹配内容"]
            rows = []
            for item in items:
                rows.append([
                    item["source"],
                    str(item["line"]),
                    item["match"]
                ])
            self.print_table(headers, rows, title=f"{Color.MAGENTA}{alg} 算法 (共 {len(items)} 处){Color.RESET}")

            if self.confirm(f"是否查看 {alg} 的匹配上下文？"):
                for i, item in enumerate(items):
                    print(f"\n{Color.BOLD}===== {item['source']} (行号: {item['line']}) ====={Color.RESET}")
                    print(item["context"])
                    if i < len(items) - 1 and not self.confirm("查看下一个？", default=True):
                        break

        if self.confirm("是否保存本次检测结果？"):
            self.save_detected_keys()

    # ------------------------------
    # 主交互菜单
    # ------------------------------
    def main_menu(self) -> None:
        """主菜单交互逻辑"""
        self.logger.info("程序启动，显示主菜单")
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
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
            print("5. 查看保存的密钥信息")  # 功能5
            print("6. 退出")

            choice = self.prompt_input("输入选项", "1").strip()

            try:
                if choice == "1":
                    self._handle_local_file()
                elif choice == "2":
                    self._handle_directory()
                elif choice == "3":
                    self._handle_crawl()
                elif choice == "4":
                    self._rules_management_menu()
                elif choice == "5":  # 调用修复后的查看方法
                    self.view_saved_keys()
                elif choice == "6":
                    self.print_color("👋 再见！", Color.GREEN)
                    self.logger.info("用户选择退出程序")
                    break
                else:
                    self.print_color("❌ 无效选择，请重试", Color.RED)
                    time.sleep(1)
            except Exception as e:
                self.print_color(f"❌ 操作失败: {str(e)}", Color.RED)
                self.logger.error(f"操作失败: {str(e)}", exc_info=True)
                input("按回车继续...")

    def _handle_local_file(self) -> None:
        """处理本地文件检测"""
        file_path = self.prompt_input("请输入文件路径", "test.js")
        self.logger.info(f"用户选择检测本地文件: {file_path}")
        print("正在检测...")
        results = self.detect_local_file(file_path)
        self.display_results(results)
        input("按回车返回主菜单...")

    def _handle_directory(self) -> None:
        """处理目录检测"""
        dir_path = self.prompt_input("请输入目录路径", "./")
        self.logger.info(f"用户选择检测目录: {dir_path}")
        results = self.detect_directory(dir_path)
        self.display_results(results)
        input("按回车返回主菜单...")

    def _handle_crawl(self) -> None:
        """处理网页爬取检测"""
        url = self.prompt_input("请输入网页URL", "https://example.com")
        self.logger.info(f"用户选择爬取网页: {url}")
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
        """特征库管理子菜单"""
        self.logger.info("进入特征库管理菜单")
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
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

            try:
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
                    self.logger.info("退出特征库管理菜单")
                    break
                else:
                    self.print_color("❌ 无效选择，请重试", Color.RED)
            except Exception as e:
                self.print_color(f"❌ 操作失败: {str(e)}", Color.RED)
                self.logger.error(f"特征库管理操作失败: {str(e)}", exc_info=True)

            input("按回车继续...")


if __name__ == "__main__":
    try:
        detector = JSEncryptionDetector()
        detector.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}⚠️ 程序被中断{Color.RESET}")
        logging.error("程序被用户中断")
    except Exception as e:
        print(f"{Color.RED}❌ 程序出错: {str(e)}{Color.RESET}")
        logging.critical(f"程序出错: {str(e)}", exc_info=True)