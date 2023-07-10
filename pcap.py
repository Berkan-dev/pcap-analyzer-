import matplotlib.pyplot as plt
import pandas as pd
import requests
import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "-f",type=argparse.FileType('r')
)
args = parser.parse_args()
open_file = args.f

df = pd.read_csv(open_file)
dst_ip_counts = df["dst_ip"].value_counts()
df_dst_ip = pd.DataFrame(dst_ip_counts)
df_dst_ip = df_dst_ip.reset_index()
df_dst_ip.columns = ["dst_ip", "count"]

x = []
x = df_dst_ip.loc[:4, "dst_ip"]
y = []
y = df_dst_ip.loc[:4, "count"]
print(df_dst_ip.head())

plt.bar(x, y, label="dst ip addresses")
plt.xlabel("ip addresses")
plt.ylabel("counts")
plt.legend()
plt.show()

meanValue = df_dst_ip["count"].head().mean()

dst_port_counts = df["dst_port"].value_counts()
df_dst_port = pd.DataFrame(dst_port_counts)
df_dst_port = df_dst_port.reset_index()
df_dst_port.columns = ["dst_ports", "count"]

x = []
x = df_dst_port.loc[:4, "dst_ports"]
y = []
y = df_dst_port.loc[:4, "count"]
print(df_dst_port.head())

plt.bar(x, y, label="dst ports", width=100)
plt.xlabel("ports")
plt.ylabel("counts")
plt.legend()
plt.show()

mean_of_dst_port = df_dst_port["count"].head().mean()
for cnt in df_dst_port["count"].head():
    if cnt > 2 * mean_of_dst_port:
        print("abnormal traffic detected")

src_ip_counts = df["src_ip"].value_counts()
df_src_ip_counts = pd.DataFrame(src_ip_counts)
df_src_ip_counts = df_src_ip_counts.reset_index()
df_src_ip_counts.columns = ["src_ip", "count"]

x = []
x = df_src_ip_counts.loc[:4, "src_ip"]
y = []
y = df_src_ip_counts.loc[:4, "count"]
print(df_src_ip_counts.head())

plt.bar(x, y, label="src ip addressses")
plt.xlabel("ip addresses")
plt.ylabel("counts")
plt.legend()
plt.show()

mean_of_src_ip = df_src_ip_counts["count"].head().mean()
for cnt in df_src_ip_counts["count"].head():
    if cnt > 2 * mean_of_src_ip:
        print("abnormal traffic detected")

src_port_counts = df["src_port"].value_counts()
df_src_port_counts = pd.DataFrame(src_port_counts)
df_src_port_counts = df_src_port_counts.reset_index()
df_src_port_counts.columns = ["src_port", "count"]

x = []
x = df_src_port_counts.loc[:4, "src_port"]
y = []
y = df_src_port_counts.loc[:4, "count"]
print(df_src_port_counts.head())

mean_of_src_port = df_src_port_counts["count"].head().mean()
for cnt in df_src_port_counts["count"].head():
    if cnt > 2 * mean_of_src_port:
        print("abnormal traffic detected")

plt.bar(x, y, label="src ports", width=1000)
plt.xlabel("src ports")
plt.ylabel("counts")
plt.legend()
plt.show()

for cnt in df_dst_ip["count"].head():
    if cnt > 2 * meanValue:
        ip_add = []
        ip_add.append(df_dst_ip[df_dst_ip["count"] == cnt]["dst_ip"].item())
        print(ip_add)
        for j in ip_add:
            ip = j
            url1 = "https://www.virustotal.com/api/v3/ip_addresses/"
            url = []
            url = url1 + str(ip)
            print(url)
            headers = {
                "accept": "application/json",
                "x-apikey": "REPLACE IT WİTH YOURS" #### API KEY 
            }
            response = requests.get(url, headers=headers)
            response = response.text
            responseList = []
            responseList = response
            with open('vtoutput.json', 'a+') as f:
                f.write(str(response))
            print(ip_add)

with open('vtoutput.json', "+r") as jsonfile:
    for line in jsonfile:
        x = "malicious"
        ip_add = "id"
        last_analysis = "last_analysis_stats"
        if x in line or ip_add in line or last_analysis in line:
            print(line)
print("virus total results written on vtoutput.json file ")