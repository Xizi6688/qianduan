import os
import subprocess
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


def get_ip_location(ip):
  try:
    res = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=3)
    data = res.json()
    if data["status"] == "success":
      return f"{data.get('country', '')} {data.get('regionName', '')} {data.get('city', '')}"
  except:
    pass
  return "未知地区"


def ping_ip(ip):
  """使用系统自带的 ping 命令检测 IP，连续失败 2 次才视为真正不通，防止瞬时网络波动"""
  fail_count = 0
  for _ in range(2):
    # -c 1: 发送1个包, -W 2: 超时时间2秒
    command = ["ping", "-c", "1", "-W", "2", ip]
    result = subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
      fail_count += 1
    else:
      # 只要有一次成功，就说明通
      return True
  return False


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
      is_alive = ping_ip(ip)
      if not is_alive:
        location = get_ip_location(ip)
        print(f"IP {ip} ({location}) Ping 不通，开始暂停...")

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
        alert_messages.append(f"异常IP: {ip}\n归属地: {location}\n状态: 已自动暂停")

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
