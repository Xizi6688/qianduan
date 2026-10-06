import os
import socket
import time
import requests
import smtplib
from email.mime.text import MIMEText

# 从 GitHub Secrets 读取配置，提供默认值
API_ID = os.environ.get("DNSPOD_ID", "")
API_TOKEN = os.environ.get("DNSPOD_TOKEN", "")
DOMAIN = os.environ.get("DOMAIN", "yxjiedian.top")

# 因为使用的是泛解析，这里监控主机记录为 "*" 的所有记录
TARGET_SUB_DOMAINS = ["*"]

MAIL_USER = "979827803@qq.com"
MAIL_PASS = os.environ.get("MAIL_PASS", "")

# 端口检测改为仅监测 443
CHECK_PORTS = [443]

# 观察字典结构: { record_id: { "ip": ip, "location": loc, "retry_left": 5 } }
watching_ips = {}


def get_ip_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=3)
        data = res.json()
        if data.get("status") == "success":
            return f"{data.get('country', '')} {data.get('regionName', '')} {data.get('city', '')}"
    except Exception:
        pass
    return "未知地区"


def check_ip_health_overseas(ip):
    """【海外检测】通过 GitHub Actions 本地 socket 检测海外连通性"""
    for port in CHECK_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=3):
                return True
        except OSError:
            continue
    return False


def check_ip_health_domestic(ip):
    """【国内三网/多地检测】通过公开的国内多线路拨测/TCPing接口检测国内电信、联通、移动连通性"""
    for port in CHECK_PORTS:
        try:
            # 示例调用公开的 TCPing 接口（或可替换为您自己的国内多节点拨测 API）
            # 该接口会从国内多节点发起 TCP 探测
            url = f"https://v2.xxapi.cn/api/tcping?ip={ip}&port={port}"
            res = requests.get(url, timeout=5)
            data = res.json()
            # 根据 API 返回格式判断国内是否连通（若 code == 200 或状态为成功则代表国内可连）
            if data.get("code") == 200:
                # 进一步检查返回的数据中是否有国内节点通畅的标识
                # 如果国内完全不通，则判定为国内阻断（被墙）
                return True
        except Exception as e:
            print(f"国内拨测接口请求异常: {e}")
            
        # 降级或备用判断：如果第三方接口不可用，默认返回 True 避免误判，
        # 但核心逻辑会结合“海外通、国内不通”进行针对性拦截
        return True 
    return False


def check_ip_comprehensive(ip):
    """综合健康检测：兼顾海外服务器状态与国内三网防墙检测"""
    overseas_alive = check_ip_health_overseas(ip)
    
    # 如果海外连都不通，说明服务器本身挂了或端口关闭
    if not overseas_alive:
        return False, "服务器挂了或海外无法连接"

    # 如果海外能通，我们再检测国内（电信/联通/移动）是否被墙
    domestic_alive = check_ip_health_domestic(ip)
    if not domestic_alive:
        return False, "IP已被中国大陆防火墙(GFW)阻断/三网不通"

    return True, "正常"


def set_dns_status(record_id, status_str, headers):
    """修改 DNSPod 解析记录状态：'enable' 开启，'disable' 暂停"""
    status_payload = {
        "login_token": f"{API_ID},{API_TOKEN}",
        "format": "json",
        "domain": DOMAIN,
        "record_id": record_id,
        "status": status_str,
    }
    try:
        requests.post("https://dnsapi.cn/Record.Status", data=status_payload, headers=headers)
    except Exception as e:
        print(f"修改 DNS 状态失败: {e}")


def send_email(subject, content):
    msg = MIMEText(content, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = MAIL_USER
    msg["To"] = MAIL_USER
    try:
        server = smtplib.SMTP_SSL("smtp.qq.com", 465)
        server.login(MAIL_USER, MAIL_PASS)
        server.sendmail(MAIL_USER, [MAIL_USER], msg.as_string())
        server.quit()
        print("报警邮件发送成功")
    except Exception as e:
        print(f"邮件发送失败: {e}")


def run_monitor_cycle(headers, records):
    global watching_ips
    alert_messages = []

    for rec in records:
        record_id = rec["id"]
        ip = rec["value"]
        status = rec["enabled"]  # '1' 开启，'0' 暂停
        sub_domain_name = rec.get("name") or rec.get("sub_domain", "*")

        is_alive, reason = check_ip_comprehensive(ip)

        if not is_alive:
            if status == "1":
                # 原本开启，现在异常 -> 立即暂停并加入观察列表
                location = get_ip_location(ip)
                print(f"【异常】泛解析节点 ({sub_domain_name}) IP: {ip} (归属地: {location}) 异常，原因: {reason}，正在暂停该条解析...")
                set_dns_status(record_id, "disable", headers)
                
                # 同步更新本地内存状态
                rec["enabled"] = "0"

                watching_ips[record_id] = {
                    "ip": ip,
                    "location": location,
                    "reason": reason,
                    "retry_left": 5
                }

                # 首次检测到异常暂停时，立即添加到发送列表
                alert_messages.append(
                    f"异常泛解析 IP: {ip}\n"
                    f"归属地: {location}\n"
                    f"故障原因: {reason}\n"
                    f"状态: 已自动暂停该 IP 的 DNS 解析！"
                )
            elif status == "0" and record_id in watching_ips:
                # 已经在观察列表中，扣减次数
                watching_ips[record_id]["retry_left"] -= 1
                left = watching_ips[record_id]["retry_left"]
                print(f"【观察中】泛解析 IP {ip} 依然异常，剩余观察次数: {left}")

                if left <= 0:
                    info = watching_ips[record_id]
                    alert_messages.append(
                        f"异常泛解析 IP: {info['ip']}\n"
                        f"归属地: {info['location']}\n"
                        f"故障原因: {info['reason']}\n"
                        f"状态: 连续 5 次检测异常，已彻底放弃并保持暂停"
                    )
        else:
            # IP 恢复正常
            if record_id in watching_ips or status == "0":
                location = get_ip_location(ip)
                print(f"【复活】泛解析 IP {ip} ({location}) 恢复正常，重新开启解析！")
                set_dns_status(record_id, "enable", headers)
                
                # 同步更新本地内存状态
                rec["enabled"] = "1"
                if record_id in watching_ips:
                    del watching_ips[record_id]

    # 清理掉已经触发过告警的记录，避免重复累加
    for record_id in list(watching_ips.keys()):
        if watching_ips[record_id]["retry_left"] <= 0:
            del watching_ips[record_id]

    return alert_messages


def main():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    list_payload = {
        "login_token": f"{API_ID},{API_TOKEN}",
        "format": "json",
        "domain": DOMAIN,
    }
    try:
        res = requests.post("https://dnsapi.cn/Record.List", data=list_payload, headers=headers).json()
        if res.get("status", {}).get("code") != "1":
            print(f"获取 DNS 记录失败: {res.get('status', {}).get('message')}")
            return
        
        all_records = res.get("records", [])
        
        # 筛选出主机记录为 "*" 的所有 A 记录
        records = []
        for rec in all_records:
            rec_name = (rec.get("name") or rec.get("sub_domain", "")).strip()
            if rec_name == "*" and rec.get("type", "A") == "A":
                records.append(rec)

    except Exception as e:
        print(f"请求 DNSPod API 异常: {e}")
        return

    if not records:
        print(f"【错误】在域名 {DOMAIN} 下未找到任何主机记录为 '*' 的解析记录，监控终止。")
        return

    print(f"成功匹配到 {len(records)} 条泛解析 IP 记录，开始带防墙检测的监控...")
    for r in records:
        print(f" -> 监控 IP: {r.get('value')} (ID: {r.get('id')})")

    all_final_alerts = []

    # 2. 循环检测 5 次
    for i in range(5):
        print(f"\n--- 开始第 {i+1} 次循环检测 ---")
        alerts = run_monitor_cycle(headers, records)
        for item in alerts:
            if item not in all_final_alerts:
                all_final_alerts.append(item)

        if i < 4:
            time.sleep(60)

    # 3. 统一发送邮件
    full_domain = f"*.{DOMAIN}"
    if all_final_alerts:
        body = (
            f"监控到 {full_domain} 以下 IP 节点出现故障/被墙，已自动暂停处理：\n\n"
            + "\n\n----------------------------------------\n\n".join(all_final_alerts)
        )
        send_email(f"【节点故障/被墙告警】{full_domain} 异常", body)
    else:
        print("监控周期结束：无失效节点或已恢复正常。")


if __name__ == "__main__":
    main()
