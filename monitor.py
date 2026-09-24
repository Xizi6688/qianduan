import os
import socket
import time
import requests
import smtplib
from email.mime.text import MIMEText

# 从 GitHub Secrets 读取配置
API_ID = os.environ["DNSPOD_ID"]
API_TOKEN = os.environ["DNSPOD_TOKEN"]
DOMAIN = os.environ["DOMAIN"]
SUB_DOMAIN = os.environ["SUB_DOMAIN"]
MAIL_USER = "979827803@qq.com"
MAIL_PASS = os.environ["MAIL_PASS"]

# 多端口支持：你可以把需要检测的端口都写在这里（目前只写了 35001，你可以随时往后加）
CHECK_PORTS = [35001, 57464, 26500, 48003]

# 用于内存记录进入“观察复活期”的 IP 状态：{ "IP:端口": 剩余观察次数 }
# 注意：GitHub Actions 每次运行是独立的，如果需要跨运行周期记忆，通常需要配合文件缓存，
# 但配合我们前面写的“单次运行内部 5 次循环”，这足以在短时间内完成观察。
watching_ips = {}


def get_ip_location(ip):
  try:
    res = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=3)
    data = res.json()
    if data["status"] == "success":
      return f"{data.get('country', '')} {data.get('regionName', '')} {data.get('city', '')}"
  except:
    pass
  return "未知地区"


def check_tcp_port(ip, port):
  """通过 TCP Socket 连通性检测指定端口"""
  try:
    with socket.create_connection((ip, port), timeout=3):
      return True  # 连通成功
  except OSError:
    return False


def set_dns_status(record_id, status_str, headers):
  """修改 DNSPod 解析记录状态：'enable' 开启，'disable' 暂停"""
  status_payload = {
      "login_token": f"{API_ID},{API_TOKEN}",
      "format": "json",
      "domain": DOMAIN,
      "record_id": record_id,
      "status": status_str,
  }
  requests.post(
      "https://dnsapi.cn/Record.Status", data=status_payload, headers=headers
  )


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
  """执行单轮检测，返回本轮产生的告警信息"""
  global watching_ips
  alert_messages = []
  current_round_down = set()

  for rec in records:
    record_id = rec["id"]
    ip = rec["value"]
    status = rec["enabled"]  # '1' 为启用，'0' 为暂停

    for port in CHECK_PORTS:
      target_key = f"{ip}:{port}"
      is_alive = check_tcp_port(ip, port)

      if not is_alive:
        # 端口不通
        if status == "1":
          # 如果原本是开启的，现在不通了 -> 立即暂停
          location = get_ip_location(ip)
          print(
              f"【异常】IP {target_key} ({location}) 无法连接，正在暂停该解析记录..."
          )
          set_dns_status(record_id, "disable", headers)

          # 进入 5 次观察期
          if target_key not in watching_ips:
            watching_ips[target_key] = {
                "record_id": record_id,
                "ip": ip,
                "port": port,
                "location": location,
                "retry_left": 5,
            }
          current_round_down.add(target_key)
        elif status == "0":
          # 如果本来就是暂停的，且已经在观察列表中，扣减剩余观察次数
          if target_key in watching_ips:
            watching_ips[target_key]["retry_left"] -= 1
            print(
                f"【观察中】IP {target_key} 依然不通，剩余观察次数:"
                f" {watching_ips[target_key]['retry_left']}"
            )

            # 如果 5 次机会用完依然不通 -> 彻底放弃，加入报警列表
            if watching_ips[target_key]["retry_left"] <= 0:
              info = watching_ips[target_key]
              alert_messages.append(
                  f"异常IP: {info['ip']}\n归属地:"
                  f" {info['location']}\n状态: 端口 {info['port']}"
                  " 连续 5 次检测不通，已彻底放弃并保持暂停"
              )
              # 从观察列表中移除，避免重复报警
              del watching_ips[target_key]
      else:
        # 端口通了
        if target_key in watching_ips:
          # 之前因为不通而被我们盯上的 IP，现在居然通了 -> 触发复活机制！
          info = watching_ips[target_key]
          print(f"【复活】IP {target_key} 恢复正常，重新开启解析！")
          set_dns_status(info["record_id"], "enable", headers)
          del watching_ips[target_key]

  return alert_messages


def main():
  headers = {"Content-Type": "application/x-www-form-urlencoded"}

  # 1. 获取解析记录列表
  list_payload = {
      "login_token": f"{API_ID},{API_TOKEN}",
      "format": "json",
      "domain": DOMAIN,
      "sub_domain": SUB_DOMAIN,
  }
  res = requests.post(
      "https://dnsapi.cn/Record.List", data=list_payload, headers=headers
  ).json()

  if res.get("status", {}).get("code") != "1":
    print("获取DNS记录失败")
    return

  records = res.get("records", [])
  all_final_alerts = []

  # 2. 内部循环 5 次（每次间隔 60 秒），在一分钟级别的精度下完成多次重试与观察
  for i in range(5):
    print(f"\n--- 开始第 {i+1} 次循环检测 ---")
    alerts = run_monitor_cycle(headers, records)
    if alerts:
      for item in alerts:
        if item not in all_final_alerts:
          all_final_alerts.append(item)

    if i < 4:
      time.sleep(60)

  # 3. 循环结束后，如果有些 IP 连续 5 次都没救回来，统一发送一次报警邮件
  if all_final_alerts:
    body = (
        "监控到以下 DNS 解析节点故障，且经多次重试无法恢复，已做最终处理：\n\n"
        + "\n\n".join(all_final_alerts)
    )
    send_email(
        f"【最终告警】{SUB_DOMAIN}.{DOMAIN} 有节点故障并已放弃", body
    )
  else:
    print("监控周期结束：无彻底失效节点，或已自动恢复。")


if __name__ == "__main__":
  main()
