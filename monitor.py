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

# 指定监测的端口
CHECK_PORT = 35001


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
  """通过 TCP Socket 连通性检测指定端口，连续失败 2 次才视为不通"""
  for _ in range(2):
    try:
      with socket.create_connection((ip, port), timeout=3):
        return True  # 连通成功
    except OSError:
      pass
    time.sleep(1)
  return False  # 两次连接都失败，判定为不通


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
  except Exception as e:
    print(f"邮件发送失败: {e}")


def run_monitor():
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
  alert_messages = []

  for rec in records:
    record_id = rec["id"]
    ip = rec["value"]
    status = rec["enabled"]  # '1' 为启用，'0' 为暂停

    # 只检测当前启用的记录
    if status == "1":
      is_alive = check_tcp_port(ip, CHECK_PORT)
      if not is_alive:
        location = get_ip_location(ip)
        print(f"IP {ip}:{CHECK_PORT} ({location}) 无法连接，开始暂停...")

        # 2. 暂停不通的解析记录
        status_payload = {
            "login_token": f"{API_ID},{API_TOKEN}",
            "format": "json",
            "domain": DOMAIN,
            "record_id": record_id,
            "status": "disable",
        }
        requests.post(
            "https://dnsapi.cn/Record.Status",
            data=status_payload,
            headers=headers,
        )
        alert_messages.append(
            f"异常IP: {ip}\n归属地: {location}\n状态: 端口 {CHECK_PORT}"
            " 无法连接，已自动暂停"
        )

  # 3. 发送邮件
  if alert_messages:
    body = (
        "监控到以下 DNS 解析节点故障，已自动处理：\n\n" + "\n\n".join(alert_messages)
    )
    send_email(
        f"【告警】{SUB_DOMAIN}.{DOMAIN} 有 IP 解析异常并已暂停", body
    )


def main():
  # 通过循环 5 次，每次间隔 60 秒，实现单次 GitHub Actions 运行覆盖 5 分钟的“1分钟一次”监控
  for i in range(5):
    print(f"--- 开始第 {i+1} 次循环检测 ---")
    run_monitor()
    if i < 4:
      time.sleep(60)


if __name__ == "__main__":
  main()
