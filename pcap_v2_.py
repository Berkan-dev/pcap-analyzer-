import matplotlib.pyplot as plt
import pandas as pd
import requests
import argparse
from sklearn.cluster import KMeans
import numpy as np

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

# Calculate statistics for destination IP counts
mean_dst_ip_count = df_dst_ip["count"].mean()
median_dst_ip_count = df_dst_ip["count"].median()
std_dev_dst_ip_count = df_dst_ip["count"].std()

print("Statistical Analysis for Destination IP Counts:")
print(f"Mean: {mean_dst_ip_count:.2f}")
print(f"Median: {median_dst_ip_count}")
print(f"Standard Deviation: {std_dev_dst_ip_count:.2f}")

# Visualize statistical analysis results
plt.figure()
plt.bar(x, y, label="dst ip addresses")
plt.xlabel("ip addresses")
plt.ylabel("counts")
plt.legend()
plt.title("Top Destination IP Addresses and Counts")
plt.show()

# Extract destination IP counts as a feature for clustering
X = df_dst_ip[["count"]]

# Perform K-Means clustering
num_clusters = 3 
n_init_value = 10 # You can adjust the number of clusters based on your data
kmeans = KMeans(n_clusters=num_clusters, n_init=n_init_value, random_state=0)
df_dst_ip["cluster"] = kmeans.fit_predict(X)

# Visualize the clusters
plt.figure()
for cluster_id in range(num_clusters):
    cluster_data = df_dst_ip[df_dst_ip["cluster"] == cluster_id]
    plt.bar(cluster_data["dst_ip"], cluster_data["count"], label=f"Cluster {cluster_id}")
plt.xlabel("ip addresses")
plt.ylabel("counts")
plt.legend()
plt.title("Clustering of Destination IP Addresses")
plt.xticks(rotation=45)
plt.tight_layout()
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

# Calculate statistics for destination Port counts
mean_dst_port_count = df_dst_port["count"].mean()
median_dst_port_count = df_dst_port["count"].median()
std_dev_dst_port_count = df_dst_port["count"].std()

print("Statistical Analysis for Destination Port Counts:")
print(f"Mean: {mean_dst_port_count:.2f}")
print(f"Median: {median_dst_port_count}")
print(f"Standard Deviation: {std_dev_dst_port_count:.2f}")

# Visualize statistical analysis results
plt.figure()
plt.bar(x, y, label="dst ports", width=1000)
plt.xlabel("dest ports")
plt.ylabel("counts")
plt.legend()
plt.title("Top Destination Ports and Counts")
plt.show()

Y = df_dst_port[["count"]]

# Perform K-Means clustering
num_clusters = 3  # You can adjust the number of clusters based on your data
n_init_value = 10  # Explicitly set n_init to avoid the warning
kmeans = KMeans(n_clusters=num_clusters, n_init=n_init_value, random_state=0)
df_dst_port["cluster"] = kmeans.fit_predict(Y)

# Visualize the clusters
plt.figure()
for cluster_id in range(num_clusters):
    cluster_data = df_dst_port[df_dst_port["cluster"] == cluster_id]
    plt.bar(cluster_data["dst_ports"], cluster_data["count"], width=1000, label=f"Cluster {cluster_id}")
plt.xlabel("ports")
plt.ylabel("counts")
plt.legend()
plt.title("Clustering of Destination Ports")
plt.xticks(rotation=45)
plt.tight_layout()
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

# Calculate statistics for source ip counts
mean_src_ip_count = df_src_ip_counts["count"].mean()
median_src_ip_count = df_src_ip_counts["count"].median()
std_dev_src_ip_count = df_src_ip_counts["count"].std()

print("Statistical Analysis for Source IP Counts:")
print(f"Mean: {mean_src_ip_count:.2f}")
print(f"Median: {median_src_ip_count}")
print(f"Standard Deviation: {std_dev_src_ip_count:.2f}")

# Visualize statistical analysis results
plt.figure()
plt.bar(x, y, label="src ip addressses")
plt.xlabel("ip addresses")
plt.ylabel("counts")
plt.legend()
plt.title("Top Source IP Addresses and Counts")
plt.show()

Z = df_src_ip_counts[["count"]]

# Perform K-Means clustering
num_clusters = 3 
n_init_value = 10 # You can adjust the number of clusters based on your data
kmeans = KMeans(n_clusters=num_clusters, n_init=n_init_value, random_state=0)
df_src_ip_counts["cluster"] = kmeans.fit_predict(Z)

# Visualize the clusters
plt.figure()
for cluster_id in range(num_clusters):
    cluster_data = df_src_ip_counts[df_src_ip_counts["cluster"] == cluster_id]
    plt.bar(cluster_data["src_ip"], cluster_data["count"], label=f"Cluster {cluster_id}")
plt.xlabel("ip addresses")
plt.ylabel("counts")
plt.legend()
plt.title("Clustering of Source IP Addresses")
plt.xticks(rotation=45)
plt.tight_layout()
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

# Calculate statistics for source port counts
mean_src_port_count = df_src_port_counts["count"].mean()
median_src_port_count = df_src_port_counts["count"].median()
std_dev_src_port_count = df_src_port_counts["count"].std()

print("Statistical Analysis for Destination Port Counts:")
print(f"Mean: {mean_src_port_count:.2f}")
print(f"Median: {median_src_port_count}")
print(f"Standard Deviation: {std_dev_dst_port_count:.2f}")

# Visualize statistical analysis results
plt.figure()
plt.bar(x, y, label="src ports", width=1000)
plt.xlabel("ports")
plt.ylabel("counts")
plt.legend()
plt.title("Top Source Ports and Counts")
plt.show()

B = df_src_port_counts[["count"]]

# Perform K-Means clustering
num_clusters = 3  # You can adjust the number of clusters based on your data
n_init_value = 10  # Explicitly set n_init to avoid the warning
kmeans = KMeans(n_clusters=num_clusters, n_init=n_init_value, random_state=0)
df_src_port_counts["cluster"] = kmeans.fit_predict(B)

# Visualize the clusters
plt.figure()
for cluster_id in range(num_clusters):
    cluster_data = df_src_port_counts[df_src_port_counts["cluster"] == cluster_id]
    plt.bar(cluster_data["src_port"], cluster_data["count"], width=1000, label=f"Cluster {cluster_id}")
plt.xlabel("ports")
plt.ylabel("counts")
plt.legend()
plt.title("Clustering of Source Ports")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# Create a grouped bar chart to visualize multidimensional clusters
cluster_labels = [f"Cluster {cluster_id}" for cluster_id in range(num_clusters)]
bar_width = 0.35
x = np.arange(len(cluster_labels))

plt.figure(figsize=(10, 6))
ip_counts = df_dst_ip.groupby("cluster")["count"].sum()
port_counts = df_dst_port.groupby("cluster")["count"].sum()

plt.bar(x - bar_width/2, ip_counts, bar_width, label="Destination IP Counts")
plt.bar(x + bar_width/2, port_counts, bar_width, label="Destination Port Counts")
plt.xlabel("Clusters")
plt.ylabel("Counts")
plt.title("Multidimensional Clustering using Grouped Bar Chart")
plt.xticks(x, cluster_labels)
plt.legend()
plt.tight_layout()
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