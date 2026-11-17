# pairwise-password-kdf

用户改密码后旧会话还能继续用：Argon2 参数写死在代码里，升级内存成本后老哈希没有标记 rehash；pepper 和 salt 拼错顺序，跨环境迁移全部验不过；比较哈希用普通字符串相等，长度不同时提前返回；登录失败计数按用户名存，攻击者换大小写绕过；密码重置 token 只做 Base64 没有签名，过期时间在客户端校验；同一账户并发改密没有版本号，后写覆盖先写。auth/password_kdf.py 是核心，tests/test_password_kdf.py 15个红。要修的是：参数版本与 rehash；pepper/salt 顺序；常量时间比较；规范化账户键；签名重置 token；并发版本号。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
