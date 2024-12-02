"""
Traceroute Visualization Tool

This program performs a traceroute to a specified hostname or URL, retrieves geographic
information (latitude and longitude) for the routers along the path, and plots these locations
on a Google Map using gmplot. 

Features:
- Ensures all plotted locations are unique.
- Labels all locations with city, country, IP, and sequence number.
- Draws a path connecting all the points to represent the traceroute sequence.
"""

import sys
import time
import os
import webbrowser
import requests
from scapy.layers.inet import socket, traceroute
import gmplot

def get_ip(hostname):
    """
    Resolves the hostname or URL to its corresponding IP address.

    Args:
        hostname (str): The hostname or URL to resolve.

    Returns:
        str: The IP address of the hostname.
    """
    try:
        ip = socket.gethostbyname(hostname)
        print(f"The IP address for {hostname} is {ip}")
        return ip
    except Exception as e:
        print(f"Error resolving hostname {hostname}: {e}")
        sys.exit(1)

def perform_traceroute(ip):
    """
    Performs a traceroute to the specified IP and retrieves the list of hops.

    Args:
        ip (str): The IP address to perform the traceroute on.

    Returns:
        list: A list of IP addresses corresponding to the hops along the route.
    """
    print(f"Performing traceroute to {ip}...")
    res, _ = traceroute(ip, maxttl=64, verbose=0)
    ips = []
    for item in res.get_trace()[ip]:
        hop_ip = res.get_trace()[ip][item][0]
        if hop_ip:
            ips.append(hop_ip)
    return ips

def fetch_coordinates(ip):
    """
    Fetches the geographic coordinates (latitude and longitude) of an IP address.

    Args:
        ip (str): The IP address to fetch geographic data for.

    Returns:
        tuple: A tuple containing latitude, longitude, city, and country of the IP address.
    """
    url = f"http://dazzlepod.com/ip/{ip}.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if 'latitude' in data and 'longitude' in data:
                return data['latitude'], data['longitude'], data.get('city', 'Unknown'), data.get('country', 'Unknown')
    except Exception as e:
        print(f"Error fetching data for {ip}: {e}")
    return None, None, None, None

def plot_lat_long(locations):
    """
    Plots the geographic coordinates of the traceroute hops on a Google Map.

    Args:
        locations (list): A list of dictionaries containing latitude, longitude, and labels for each location.
    """
    if not locations:
        print("No valid coordinates to plot.")
        return

    latitudes, longitudes = [], []
    gmap = gmplot.GoogleMapPlotter(locations[0]['lat'], locations[0]['lon'], 3)

    for i, loc in enumerate(locations):
        latitudes.append(loc['lat'])
        longitudes.append(loc['lon'])
        gmap.marker(loc['lat'], loc['lon'], title=f"{loc['label']}", label=str(i + 1))

    gmap.plot(latitudes, longitudes, "blue", edge_width=2.5)
    cwd = os.getcwd()
    map = os.path.join(cwd, "traceroute_map.html")
    gmap.draw(map)
    webbrowser.open(f"file:///{map}")
    print(f"Map saved as: {map}")

def main():
    """
    Main function to execute the traceroute, retrieve geographic data, and plot the results.
    """
    hostname = input("Enter the hostname or URL for traceroute: ")
    ip = get_ip(hostname)
    hops = perform_traceroute(ip)

    locations = []
    for i, hop in enumerate(hops):
        lat, lon, city, country = fetch_coordinates(hop)
        if lat and lon:
            if not any(loc['lat'] == lat and loc['lon'] == lon for loc in locations):
                locations.append({
                    'lat': lat,
                    'lon': lon,
                    'label': f"Hop {i + 1}: {city}, {country} ({hop})"
                })
        time.sleep(1)

    plot_lat_long(locations)

if __name__ == "__main__":
    main()
