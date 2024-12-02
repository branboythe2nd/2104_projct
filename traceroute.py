import sys
import json
import time
import os
import webbrowser
import requests
from scapy.layers.inet import socket, traceroute
import gmplot

def get_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        print(f"The IP address for {hostname} is {ip}")
        return ip
    except Exception as e:
        print(f"Error resolving hostname {hostname}: {e}")
        sys.exit(1)

def perform_traceroute(ip):
    print(f"Performing traceroute to {ip}...")
    res, _ = traceroute(ip, maxttl=64, verbose=0)
    ips = []
    for item in res.get_trace()[ip]:
        hop_ip = res.get_trace()[ip][item][0]
        if hop_ip:
            ips.append(hop_ip)
    return ips

def fetch_coordinates(ip):
    url = f"http://dazzlepod.com/ip/{ip}.json"
    print(f"Fetching coordinates for {ip}: {url}")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if 'latitude' in data and 'longitude' in data:
                print(f"Coordinates for {ip}: {data['latitude']}, {data['longitude']}")
                return data['latitude'], data['longitude']
    except Exception as e:
        print(f"Error fetching data for {ip}: {e}")
    return None, None

def plot_lat_long(latitudes, longitudes):
    if not latitudes or not longitudes:
        print("No valid coordinates to plot.")
        return
    gmap = gmplot.GoogleMapPlotter(latitudes[0], longitudes[0], 3)
    if ":\\" in gmap.coloricon:
        gmap.coloricon = gmap.coloricon.replace('/', '\\')
        gmap.coloricon = gmap.coloricon.replace('\\', '\\\\')
    gmap.scatter(latitudes, longitudes, '#FF00FF', size=40000, marker=False)
    cwd = os.getcwd()
    map = os.path.join(cwd, "traceroute_map.html")
    gmap.draw(map)
    webbrowser.open(f"file:///{map}")
    print(f"Map saved as: {map}")

def main():
    hostname = input("Enter the hostname or URL for traceroute: ")
    ip = get_ip(hostname)
    hops = perform_traceroute(ip)
    latitudes = []
    longitudes = []
    for hop in hops:
        lat, lon = fetch_coordinates(hop)
        if lat and lon:
            latitudes.append(lat)
            longitudes.append(lon)
    plot_lat_long(latitudes, longitudes)

if __name__ == "__main__":
    main()
