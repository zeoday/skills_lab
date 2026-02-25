# 模板片段库

## 1. 概述

模板片段库是一个存储可复用报告段落的集合，用于在不同模板中重复使用常见的内容，如漏洞描述、修复建议等。通过使用片段库，可以确保报告内容的一致性和标准化，同时提高模板编辑的效率。

## 2. 片段分类

### 2.1 漏洞类型片段
- `sql_injection.md` - SQL 注入漏洞的标准描述和修复建议
- `xss.md` - 跨站脚本漏洞的标准描述和修复建议
- `csrf.md` - 跨站请求伪造漏洞的标准描述和修复建议
- `rce.md` - 远程代码执行漏洞的标准描述和修复建议
- `lfi.md` - 本地文件包含漏洞的标准描述和修复建议
- `rfi.md` - 远程文件包含漏洞的标准描述和修复建议
- `brute_force.md` - 暴力破解漏洞的标准描述和修复建议
- `weak_password.md` - 弱密码漏洞的标准描述和修复建议
- `information_disclosure.md` - 信息泄露漏洞的标准描述和修复建议
- `access_control.md` - 访问控制漏洞的标准描述和修复建议

### 2.2 行业特定片段
- `financial_compliance.md` - 金融行业合规要求
- `medical_compliance.md` - 医疗行业合规要求
- `government_compliance.md` - 政府行业合规要求
- `manufacturing_compliance.md` - 制造业合规要求
- `education_compliance.md` - 教育行业合规要求

### 2.3 通用片段
- `cvss_explanation.md` - CVSS 评分解释
- `remediation_steps.md` - 通用修复步骤
- `verification_methods.md` - 通用验证方法
- `security_best_practices.md` - 安全最佳实践
- `incident_response.md` - 事件响应流程

## 3. 使用方法

### 3.1 在模板中引用片段

在模板文件中，可以使用以下语法引用片段：

```markdown
{{> snippets/sql_injection.md}}
```

### 3.2 片段参数化

片段可以包含变量，在引用时可以传递参数：

```markdown
{{> snippets/remediation_steps.md severity="高"}}
```

### 3.3 片段组合

可以组合多个片段来创建完整的报告部分：

```markdown
## 漏洞描述
{{> snippets/sql_injection.md}}

## 修复建议
{{> snippets/remediation_steps.md}}
{{> snippets/verification_methods.md}}
```

## 4. 片段管理

### 4.1 添加新片段

1. 在 `snippets` 目录中创建新的 Markdown 文件
2. 按照标准格式编写片段内容
3. 在片段中使用变量占位符，以便在不同场景中重用
4. 更新 `README.md` 文件，添加新片段的说明

### 4.2 编辑现有片段

1. 编辑 `snippets` 目录中的相应文件
2. 确保修改后的片段仍然兼容所有使用它的模板
3. 考虑版本控制，记录片段的变更

### 4.3 片段版本控制

片段库也支持版本控制，通过在文件名中添加版本号：

```
snippets/sql_injection_v1.0.md
snippets/sql_injection_v1.1.md
```

## 5. 最佳实践

- **保持片段简洁**：每个片段应专注于一个特定的内容点
- **使用变量**：通过变量使片段更灵活，适应不同场景
- **标准化内容**：确保片段内容符合行业标准和最佳实践
- **定期更新**：根据新的安全威胁和修复技术更新片段内容
- **测试片段**：在使用新片段前，测试其在不同模板中的表现

## 6. 示例片段

### 6.1 SQL 注入片段示例

```markdown
# SQL 注入漏洞

## 漏洞描述
SQL 注入是一种常见的 Web 应用安全漏洞，攻击者通过在用户输入中插入恶意 SQL 代码，从而操纵数据库执行非授权操作。

## 漏洞原理
当应用程序直接将用户输入拼接到 SQL 查询语句中，而没有进行适当的验证和转义时，就可能导致 SQL 注入漏洞。

## 修复建议
- 使用参数化查询或预处理语句
- 实施输入验证和过滤
- 最小权限原则：限制数据库用户权限
- 使用 ORM 框架
```

### 6.2 修复步骤片段示例

```markdown
# 修复步骤

## 临时缓解措施
1. 实施输入验证和过滤
2. 启用 Web 应用防火墙 (WAF)
3. 限制受影响系统的访问

## 长期解决方案
1. {{#if severity="高"}}
   - 立即应用安全补丁
   - 进行全面的代码审查
{{/if}}
{{#if severity="中"}}
   - 在下次发布周期中修复
   - 进行有针对性的代码审查
{{/if}}
{{#if severity="低"}}
   - 在合适的时间进行修复
   - 记录漏洞，纳入常规安全维护
{{/if}}

## 验证方法
1. 执行漏洞扫描
2. 进行手动测试
3. 代码审查验证
```